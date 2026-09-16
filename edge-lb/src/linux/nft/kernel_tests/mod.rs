//! Native DSCP return path: requests use the business address, replies use VXLAN.
//! No gateway NAT/HA or backend redirect is installed by these tests.

mod lifecycle;
mod nat;
mod packets;
mod topology;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::fd::AsRawFd,
    time::Duration,
};

use topology::{Peer, Topology};

const TIMEOUT: Duration = Duration::from_secs(2);

fn dscp(socket: &impl AsRawFd, value: u32) {
    let tos = ((value << 2) | 3) as libc::c_int;
    // SAFETY: setsockopt receives a live integer with its exact size.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TOS,
                (&tos as *const libc::c_int).cast(),
                std::mem::size_of_val(&tos) as _,
            )
        },
        0
    );
}

fn udp(address: &str) -> UdpSocket {
    let socket = UdpSocket::bind(address).unwrap();
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    socket.set_write_timeout(Some(TIMEOUT)).unwrap();
    socket
}

fn destination(_peer: &Peer, port: u16) -> SocketAddr {
    (std::net::Ipv4Addr::new(198, 18, 0, 2), port).into()
}

fn client(peer: &Peer, port: u16, codepoint: u32) -> UdpSocket {
    peer.ns.run(move || {
        let socket = udp(&format!("198.51.100.2:{port}"));
        dscp(&socket, codepoint);
        socket
    })
}

fn request(client: &UdpSocket, server: &UdpSocket, to: SocketAddr, payload: &[u8]) -> SocketAddr {
    client.send_to(payload, to).unwrap();
    let mut bytes = [0; 128];
    let (size, source) = server.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..size], payload);
    assert_eq!(
        source,
        client.local_addr().unwrap(),
        "original client tuple"
    );
    source
}

fn reply(server: &UdpSocket, client: &UdpSocket, source: SocketAddr, expected: SocketAddr) {
    server.send_to(b"response", source).unwrap();
    let mut bytes = [0; 128];
    let (size, from) = client.recv_from(&mut bytes).expect("UDP return via VXLAN");
    assert_eq!(&bytes[..size], b"response");
    assert_eq!(from, expected, "business source must be preserved");
}

fn tcp(peer: &Peer, server: &TcpListener) -> (TcpStream, TcpStream) {
    let to = destination(peer, server.local_addr().unwrap().port());
    let codepoint = peer.path.dscp;
    // Set TOS before connect so the SYN establishes the conntrack mark.
    let outgoing = peer.ns.run(move || {
        // SAFETY: arguments are valid socket constants; success returns an owned fd.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        use std::os::fd::FromRawFd;
        // SAFETY: fd was just created and has no other owner.
        let socket = unsafe { TcpStream::from_raw_fd(fd) };
        dscp(&socket, codepoint);
        let SocketAddr::V4(to) = to else {
            unreachable!()
        };
        let source = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([198, 51, 100, 2]),
            },
            sin_zero: [0; 8],
        };
        let destination = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: to.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(to.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(TIMEOUT)).unwrap();
        // SAFETY: both initialized IPv4 structures remain live for the syscalls.
        assert_eq!(
            unsafe {
                libc::bind(
                    fd,
                    (&source as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&source) as _,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                libc::connect(
                    fd,
                    (&destination as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&destination) as _,
                )
            },
            0,
            "connect: {}",
            std::io::Error::last_os_error()
        );
        socket
    });
    let (incoming, source) = server.accept().unwrap();
    assert_eq!(source.ip(), outgoing.local_addr().unwrap().ip());
    incoming.set_read_timeout(Some(TIMEOUT)).unwrap();
    incoming.set_write_timeout(Some(TIMEOUT)).unwrap();
    (outgoing, incoming)
}

fn tcp_exchange((outgoing, incoming): &mut (TcpStream, TcpStream)) {
    outgoing.write_all(b"tcp echo").unwrap();
    let mut payload = [0; 8];
    incoming.read_exact(&mut payload).unwrap();
    incoming.write_all(&payload).unwrap();
    outgoing.read_exact(&mut payload).unwrap();
    assert_eq!(&payload, b"tcp echo");
}

#[test]
fn forwarded_container_reply_keeps_business_source_and_original_connection_mark() {
    std::thread::spawn(|| {
        use crate::linux::test_support::{self as net, Namespace};
        let topology = Topology::new();
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        let container = Namespace::new();
        net::veth("container0", "service0");
        net::move_link("service0", container.tid);
        net::address("container0", "10.88.0.1/24");
        net::set_link(net::link("container0").up());
        container.run(|| {
            net::address("service0", "10.88.0.2/24");
            net::set_link(net::link("service0").up());
            net::add_route(net::route("0.0.0.0/0", "service0", Some("10.88.0.1")));
        });
        topology.peers[0].ns.run(|| {
            net::add_route(net::route("10.88.0.0/24", "uplink", Some("198.18.0.2")));
        });
        let server = container.run(|| {
            let server = udp("10.88.0.2:8080");
            // A reply's DSCP must not overwrite the original request's gateway.
            dscp(&server, 40);
            server
        });
        let peer = &topology.peers[0];
        let client = client(peer, 40000, 46);
        let to = "10.88.0.2:8080".parse().unwrap();
        let source = request(&client, &server, to, b"forwarded request");
        let before = topology.peers.each_ref().map(Peer::received);
        reply(&server, &client, source, to);
        assert!(peer.received() > before[0]);
        assert_eq!(topology.peers[1].received(), before[1]);
    })
    .join()
    .unwrap();
}

#[test]
fn host_tcp_and_wildcard_udp_follow_each_dscp_return_path() {
    std::thread::spawn(|| {
        let topology = Topology::new();
        for bind in ["0.0.0.0", "198.18.0.2"] {
            let server = udp(&format!("{bind}:8080"));
            let tcp_server = TcpListener::bind(format!("{bind}:8080")).unwrap();
            for (slot, peer) in topology.peers.iter().enumerate() {
                let client = client(peer, 40000 + slot as u16, peer.path.dscp);
                let to = destination(peer, 8080);
                let source = request(&client, &server, to, b"underlay request");
                let before = peer.received();
                reply(&server, &client, source, to);
                assert!(peer.received() > before, "reply must traverse VXLAN");
                client.connect(to).unwrap();
                let source = request(&client, &server, to, b"connected client");
                reply(&server, &client, source, to);
                let before = peer.received();
                tcp_exchange(&mut tcp(peer, &tcp_server));
                assert!(peer.received() > before);
            }
        }
    })
    .join()
    .unwrap();
}

#[test]
fn udp_same_client_port_on_different_services_keeps_distinct_return_paths() {
    std::thread::spawn(|| {
        let topology = Topology::new();
        let a = client(&topology.peers[0], 40000, 46);
        let b = client(&topology.peers[1], 40000, 40);
        let server_a = udp("0.0.0.0:8080");
        let server_b = udp("0.0.0.0:8081");
        let to_a = destination(&topology.peers[0], 8080);
        let to_b = destination(&topology.peers[1], 8081);
        let source_b = request(&b, &server_b, to_b, b"B");
        let source_a = request(&a, &server_a, to_a, b"A");
        reply(&server_a, &a, source_a, to_a);
        reply(&server_b, &b, source_b, to_b);
    })
    .join()
    .unwrap();
}

#[test]
fn udp_identical_five_tuple_follows_latest_classified_request_not_rule_order() {
    std::thread::spawn(|| {
        let topology = Topology::new();
        let server = udp("0.0.0.0:8080");
        let clients = [
            client(&topology.peers[0], 40000, 46),
            client(&topology.peers[1], 40000, 40),
        ];
        for slot in [1, 0, 1, 0] {
            let peer = &topology.peers[slot];
            let to = destination(peer, 8080);
            let source = request(&clients[slot], &server, to, b"current gateway");
            let before = peer.received();
            reply(&server, &clients[slot], source, to);
            assert!(peer.received() > before);
            lifecycle::no_reply(&clients[1 - slot]);
        }
    })
    .join()
    .unwrap();
}
