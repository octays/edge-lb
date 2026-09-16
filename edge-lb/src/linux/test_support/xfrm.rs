//! Fixed policy fixtures encoded against include/uapi/linux/xfrm.h.
//! This is test-only mutation, separate from the read-only policy observer.

use rtnetlink::{
    packet_core::{NETLINK_HEADER_LEN, NLM_F_ACK, NLM_F_REQUEST, NetlinkBuffer},
    sys::{Socket, SocketAddr},
};
use std::os::fd::AsRawFd;

fn send(kind: u16, payload: &[u8]) {
    let mut socket = Socket::new(libc::NETLINK_XFRM as isize).unwrap();
    socket.bind_auto().unwrap();
    let mut message = vec![0; NETLINK_HEADER_LEN + payload.len()];
    let mut header = NetlinkBuffer::new(&mut message);
    header.set_length((NETLINK_HEADER_LEN + payload.len()) as u32);
    header.set_message_type(kind);
    header.set_sequence_number(1);
    header.set_flags(NLM_F_REQUEST | NLM_F_ACK);
    header.payload_mut().copy_from_slice(payload);
    assert_eq!(
        socket.send_to(&message, &SocketAddr::new(0, 0), 0).unwrap(),
        message.len()
    );
    let mut poll = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized poll descriptor backed by the live socket.
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 3000) }, 1);
    let mut response = [0; 4096];
    let (len, sender) = socket.recv_from(&mut &mut response[..], 0).unwrap();
    assert_eq!(sender.port_number(), 0);
    let header = NetlinkBuffer::new_checked(&response[..len]).unwrap();
    assert_eq!(header.message_type(), libc::NLMSG_ERROR as u16);
    assert_eq!(header.sequence_number(), 1);
    assert_eq!(
        i32::from_ne_bytes(header.payload()[..4].try_into().unwrap()),
        0,
        "XFRM mutation ACK"
    );
}

pub(in crate::linux) fn default_forward(block: bool) {
    send(0x27, &[2, if block { 1 } else { 2 }, 2]);
}

pub(in crate::linux) fn block_forward(add: bool) {
    // selector=56, policy_info=168, policy_id=64; all padding explicitly zero.
    let mut body = vec![0; if add { 168 } else { 64 }];
    body[..4].copy_from_slice(&[203, 0, 113, 0]);
    body[16..20].copy_from_slice(&[192, 0, 2, 0]);
    body[40..42].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    body[42..44].copy_from_slice(&[24, 24]);
    if add {
        for offset in [56, 64, 72, 80] {
            body[offset..offset + 8].copy_from_slice(&u64::MAX.to_ne_bytes());
        }
        body[160] = 2; // XFRM_POLICY_FWD
        body[161] = 1; // XFRM_POLICY_BLOCK
    } else {
        body[60] = 2;
    }
    send(if add { 0x13 } else { 0x14 }, &body);
}
