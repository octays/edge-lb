//! Real TCP/UDP sockets. UDP replies report the received inner TTL and TOS.

use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use super::topology::Topology;

const TIMEOUT: Duration = Duration::from_secs(3);

fn option(socket: &impl AsRawFd, name: i32, value: i32) {
    // SAFETY: value is a live int of the length supplied to setsockopt.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                name,
                (&value as *const i32).cast(),
                std::mem::size_of_val(&value) as _,
            )
        },
        0,
        "setsockopt {name}: {}",
        io::Error::last_os_error()
    );
}

fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

struct Datagram {
    reply: [u8; 16],
    peer: SocketAddr,
}

fn receive(socket: &UdpSocket) -> io::Result<Datagram> {
    let mut payload = [0u8; 8192];
    let mut control = [0u64; 16];
    // SAFETY: sockaddr_in/msghdr are valid zero-initialized C data structures.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    let mut vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    message.msg_name = (&mut address as *mut libc::sockaddr_in).cast();
    message.msg_namelen = std::mem::size_of_val(&address) as _;
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    // SAFETY: all msghdr buffers remain live and writable for their stated lengths.
    let length = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    assert!(length >= 4 && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0);
    assert_eq!(address.sin_family, libc::AF_INET as libc::sa_family_t);
    let mut ttl = None;
    let mut tos = None;
    // SAFETY: CMSG helpers walk the initialized, aligned control buffer returned
    // by recvmsg; each payload size is checked before reading it.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::IPPROTO_IP {
                match (*header).cmsg_type {
                    libc::IP_TTL => {
                        assert!((*header).cmsg_len >= libc::CMSG_LEN(4) as usize);
                        ttl = Some(
                            std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>()) as u32,
                        );
                    }
                    libc::IP_TOS => {
                        assert!((*header).cmsg_len >= libc::CMSG_LEN(1) as usize);
                        tos = Some(*libc::CMSG_DATA(header) as u32);
                    }
                    _ => {}
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    let peer = SocketAddr::from((
        Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(address.sin_port),
    ));
    assert_eq!(
        peer.ip(),
        Ipv4Addr::new(198, 51, 100, 2),
        "backend must retain client source"
    );
    let mut reply = [0; 16];
    reply[..4].copy_from_slice(&payload[..4]);
    reply[4..8].copy_from_slice(&(length as u32).to_be_bytes());
    reply[8..12].copy_from_slice(&ttl.expect("IP_RECVTTL metadata").to_be_bytes());
    reply[12..16].copy_from_slice(&tos.expect("IP_RECVTOS metadata").to_be_bytes());
    Ok(Datagram { reply, peer })
}

pub(super) struct Servers {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Servers {
    pub(super) fn new(topology: &Topology) -> Self {
        let (udp, tcp) = topology.backend.run(|| {
            let udp = UdpSocket::bind("203.0.113.20:8080").unwrap();
            option(&udp, libc::IP_RECVTTL, 1);
            option(&udp, libc::IP_RECVTOS, 1);
            udp.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let tcp = TcpListener::bind("203.0.113.20:8080").unwrap();
            tcp.set_nonblocking(true).unwrap();
            (udp, tcp)
        });
        let stop = Arc::new(AtomicBool::new(false));
        let udp_stop = stop.clone();
        let udp_thread = thread::spawn(move || {
            while !udp_stop.load(Ordering::Acquire) {
                match receive(&udp) {
                    Ok(datagram) => {
                        udp.send_to(&datagram.reply, datagram.peer).unwrap();
                    }
                    Err(error) if retry(&error) => {}
                    Err(error) => panic!("UDP server: {error}"),
                }
            }
        });
        let tcp_stop = stop.clone();
        let tcp_thread = thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            while !tcp_stop.load(Ordering::Acquire) {
                let (mut stream, peer) = match tcp.accept() {
                    Ok(connection) => connection,
                    Err(error) if retry(&error) => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("TCP accept: {error}"),
                };
                assert_eq!(peer.ip(), Ipv4Addr::new(198, 51, 100, 2));
                stream
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                stream.set_write_timeout(Some(TIMEOUT)).unwrap();
                while !tcp_stop.load(Ordering::Acquire) {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(length) => stream.write_all(&buffer[..length]).unwrap(),
                        Err(error) if retry(&error) => {}
                        Err(error) => panic!("TCP read: {error}"),
                    }
                }
            }
        });
        Self {
            stop,
            threads: vec![udp_thread, tcp_thread],
        }
    }
}

impl Drop for Servers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            let result = thread.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

pub(super) struct Clients {
    udp: UdpSocket,
    tcp: TcpStream,
    sequence: u32,
}

fn udp_socket(port: u16) -> UdpSocket {
    let udp = UdpSocket::bind((Ipv4Addr::new(198, 51, 100, 2), port)).unwrap();
    udp.connect("203.0.113.100:5060").unwrap();
    udp.set_read_timeout(Some(TIMEOUT)).unwrap();
    udp.set_ttl(64).unwrap();
    option(&udp, libc::IP_TOS, 3);
    option(&udp, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_DONT);
    udp
}

pub(super) fn new_udp_probe(topology: &Topology, port: u16, expected_success: bool) {
    topology.client.run(move || {
        let udp = udp_socket(port);
        if expected_success {
            exchange_udp(&udp, 1, 96);
        } else {
            udp.send(&[0x5a; 96]).unwrap();
            let error = udp
                .recv(&mut [0; 16])
                .expect_err("unhealthy target must not serve a new flow");
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ),
                "{error}"
            );
        }
    });
}

impl Clients {
    pub(super) fn new(topology: &Topology) -> io::Result<Self> {
        topology.client.run(|| {
            let udp = udp_socket(40000);
            let tcp = TcpStream::connect_timeout(&"203.0.113.100:5060".parse().unwrap(), TIMEOUT)?;
            tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
            tcp.set_write_timeout(Some(TIMEOUT)).unwrap();
            tcp.set_nodelay(true).unwrap();
            Ok(Self {
                udp,
                tcp,
                sequence: 0,
            })
        })
    }

    pub(super) fn exchange_udp(&mut self, size: usize) {
        self.sequence += 1;
        exchange_udp(&self.udp, self.sequence, size);
    }

    pub(super) fn exchange_tcp(&mut self, size: usize) {
        self.try_exchange_tcp(size)
            .expect("VIP TCP response on same connection");
    }

    pub(super) fn try_exchange_tcp(&mut self, size: usize) -> io::Result<()> {
        let payload = vec![0x4b; size];
        self.tcp.write_all(&payload)?;
        let mut reply = vec![0; size];
        self.tcp.read_exact(&mut reply)?;
        assert_eq!(reply, payload);
        Ok(())
    }
}

fn exchange_udp(socket: &UdpSocket, sequence: u32, size: usize) {
    let mut payload = vec![0x5a; size];
    payload[..4].copy_from_slice(&sequence.to_be_bytes());
    socket.send(&payload).unwrap();
    let mut reply = [0; 16];
    let length = socket.recv(&mut reply).expect("VIP UDP response");
    assert_eq!(length, reply.len());
    assert_eq!(&reply[..4], &sequence.to_be_bytes());
    assert_eq!(
        u32::from_be_bytes(reply[4..8].try_into().unwrap()),
        size as u32
    );
    assert_eq!(
        u32::from_be_bytes(reply[8..12].try_into().unwrap()),
        63,
        "inner TTL decremented exactly once"
    );
    assert_eq!(
        u32::from_be_bytes(reply[12..16].try_into().unwrap()),
        (46 << 2) | 3,
        "DSCP and ECN"
    );
}
