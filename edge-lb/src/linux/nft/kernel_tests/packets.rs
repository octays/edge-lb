//! Inject complete IPv4 replies through OUTPUT, inspect after real VXLAN receive.

use super::*;
use crate::linux::test_support::packet::checksum;
use std::os::fd::{FromRawFd, OwnedFd};

const CLIENT: [u8; 4] = [198, 51, 100, 2];
const UNDERLAY: [u8; 4] = [198, 18, 0, 2];

fn address(ip: [u8; 4]) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as _,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip),
        },
        sin_zero: [0; 8],
    }
}

fn raw_socket(protocol: i32) -> OwnedFd {
    // SAFETY: valid socket constants, success transfers a fresh fd to OwnedFd.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol) };
    assert!(fd >= 0, "raw socket: {}", std::io::Error::last_os_error());
    // SAFETY: fd has no other owner.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: TIMEOUT.as_secs() as _,
        tv_usec: 0,
    };
    // SAFETY: initialized timeval lives through setsockopt.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of_val(&timeout) as _,
            )
        },
        0
    );
    socket
}

fn receiver(peer: &Peer) -> OwnedFd {
    peer.ns.run(|| {
        let socket = raw_socket(libc::IPPROTO_UDP);
        let address = address(CLIENT);
        // Bind the inner destination, excluding outer VXLAN UDP datagrams.
        // SAFETY: initialized IPv4 address and a live socket.
        assert_eq!(
            unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    (&address as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            },
            0
        );
        socket
    })
}

fn udp_checksum(packet: &[u8]) -> u16 {
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&packet[24..26]);
    pseudo.extend_from_slice(&packet[20..]);
    checksum(&pseudo)
}

fn packet(source: [u8; 4], port: u16, payload: &[u8], zero: bool) -> Vec<u8> {
    let mut bytes = vec![0; 28 + payload.len()];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&source);
    bytes[16..20].copy_from_slice(&CLIENT);
    bytes[20..22].copy_from_slice(&8080u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&port.to_be_bytes());
    bytes[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes[28..].copy_from_slice(payload);
    if !zero {
        let sum = udp_checksum(&bytes);
        bytes[26..28].copy_from_slice(&(if sum == 0 { u16::MAX } else { sum }).to_be_bytes());
    }
    // IPPROTO_RAW fills the IPv4 checksum; UDP is already fully checksummed.
    bytes
}

fn transmit(socket: &OwnedFd, packet: &[u8]) {
    let destination = address(CLIENT);
    // SAFETY: valid buffers and address, no pointer retained by sendto.
    assert_eq!(
        unsafe {
            libc::sendto(
                socket.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&destination as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&destination) as _,
            )
        },
        packet.len() as isize,
        "raw send: {}",
        std::io::Error::last_os_error()
    );
}

fn receive(socket: &OwnedFd) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    // SAFETY: writable buffer with its exact capacity, live socket with timeout.
    let size = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            libc::MSG_TRUNC,
        )
    };
    assert!(
        size >= 28 && size as usize <= bytes.len(),
        "raw receive: size={size}, {}",
        std::io::Error::last_os_error()
    );
    bytes.truncate(size as usize);
    bytes
}

#[test]
fn native_udp_return_preserves_business_source_and_checksums() {
    std::thread::spawn(|| {
        let topology = Topology::new();
        let server = udp("0.0.0.0:8080");
        let sender = raw_socket(libc::IPPROTO_RAW);
        for (slot, peer) in topology.peers.iter().enumerate() {
            let port = 40000 + slot as u16;
            let client = client(peer, port, peer.path.dscp);
            let to = destination(peer, 8080);
            request(&client, &server, to, b"establish conntrack");
            let capture = receiver(peer);
            // Include a payload whose UDP checksum is mathematically zero.
            let zero_sum = udp_checksum(&packet(UNDERLAY, port, &[0; 2], true));
            let payloads = [
                Vec::new(),
                b"odd".to_vec(),
                b"even".to_vec(),
                zero_sum.to_be_bytes().to_vec(),
            ];
            for (case, payload) in payloads.iter().enumerate() {
                for zero in [true, false] {
                    let input = packet(UNDERLAY, port, payload, zero);
                    if !zero {
                        assert_eq!(udp_checksum(&input), 0);
                    }
                    let before = peer.received();
                    transmit(&sender, &input);
                    let output = receive(&capture);
                    assert_eq!(output[0], 0x45);
                    assert_eq!(output.len(), input.len());
                    assert_eq!(
                        u16::from_be_bytes(output[2..4].try_into().unwrap()) as usize,
                        output.len()
                    );
                    assert_eq!(checksum(&output[..20]), 0, "IPv4 checksum");
                    assert_eq!(&output[12..16], &UNDERLAY);
                    assert_eq!(
                        &output[16..26],
                        &input[16..26],
                        "destination, ports, UDP length"
                    );
                    assert_eq!(&output[28..], payload);
                    if zero {
                        assert_eq!(&output[26..28], &[0, 0]);
                    } else {
                        assert_ne!(&output[26..28], &[0, 0]);
                        assert_eq!(udp_checksum(&output), 0, "UDP pseudo-header checksum");
                        if case == 3 {
                            assert_eq!(&output[26..28], &[255, 255], "computed zero uses 0xffff");
                        }
                    }
                    let mut received = [0; 128];
                    let (size, from) = client.recv_from(&mut received).unwrap();
                    assert_eq!(&received[..size], payload);
                    assert_eq!(from, to);
                    assert!(peer.received() > before, "reply traverses VXLAN");
                }
            }
        }
    })
    .join()
    .unwrap();
}
