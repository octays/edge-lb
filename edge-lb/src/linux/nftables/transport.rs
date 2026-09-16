//! Bounded netfilter transactions; success requires every requested ACK.

use anyhow::{Result, ensure};
use rtnetlink::{
    packet_core::{NLM_F_ACK, NLM_F_DUMP_INTR, NetlinkBuffer},
    sys::{Socket, SocketAddr},
};
use std::{
    collections::BTreeSet,
    io,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

fn frames(mut data: &[u8]) -> Result<Vec<NetlinkBuffer<&[u8]>>> {
    let mut result = Vec::new();
    while !data.is_empty() {
        let frame = NetlinkBuffer::new_checked(data)?;
        let size = super::align(frame.length() as usize);
        ensure!(size <= data.len(), "truncated nf_tables frame");
        result.push(frame);
        data = &data[size..];
    }
    Ok(result)
}

fn open(request: &[u8]) -> Result<Socket> {
    let mut socket = Socket::new(libc::NETLINK_NETFILTER as isize)?;
    socket.bind_auto()?;
    socket.set_non_blocking(true)?;
    ensure!(
        socket.send_to(request, &SocketAddr::new(0, 0), 0)? == request.len(),
        "short nf_tables send"
    );
    Ok(socket)
}

fn receive(socket: &Socket, deadline: Instant) -> Result<Vec<u8>> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "nf_tables response timed out");
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized descriptor backed by a live socket.
        let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        ensure!(
            ready > 0 && poll.revents == libc::POLLIN,
            "nf_tables socket timeout/error"
        );
        let mut bytes = vec![0; 65536];
        let (len, sender) = socket.recv_from(&mut &mut bytes[..], libc::MSG_TRUNC)?;
        ensure!(
            sender.port_number() == 0 && len > 0 && len <= bytes.len(),
            "invalid/truncated nf_tables response"
        );
        bytes.truncate(len);
        return Ok(bytes);
    }
}

fn acknowledge(bytes: &[u8], pending: &mut BTreeSet<u32>) -> Result<()> {
    for frame in frames(bytes)? {
        ensure!(
            frame.flags() & NLM_F_DUMP_INTR == 0,
            "interrupted nf_tables response"
        );
        if frame.message_type() == libc::NLMSG_ERROR as u16 {
            ensure!(frame.payload().len() >= 4, "short nf_tables ACK");
            let code = i32::from_ne_bytes(frame.payload()[..4].try_into()?);
            ensure!(
                code <= 0 && code != i32::MIN,
                "invalid nf_tables ACK error code: {code}"
            );
            ensure!(
                code == 0,
                "nf_tables request {} failed: {}",
                frame.sequence_number(),
                io::Error::from_raw_os_error(-code)
            );
            ensure!(
                pending.remove(&frame.sequence_number()),
                "unexpected/duplicate nf_tables ACK"
            );
        } else {
            ensure!(
                pending.contains(&frame.sequence_number()),
                "unexpected nf_tables sequence"
            );
            ensure!(
                frame.message_type() == super::nft_msg_type(libc::NFT_MSG_NEWTABLE as u16),
                "unexpected nf_tables response type"
            );
        }
    }
    Ok(())
}

pub(super) fn transact(request: &[u8]) -> Result<()> {
    let mut pending: BTreeSet<_> = frames(request)?
        .iter()
        .filter(|m| m.flags() & NLM_F_ACK != 0)
        .map(|m| m.sequence_number())
        .collect();
    ensure!(
        !pending.is_empty(),
        "nf_tables transaction has no ACK requests"
    );
    let socket = open(request)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while !pending.is_empty() {
        acknowledge(&receive(&socket, deadline)?, &mut pending)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ack(seq: u32, error: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        super::super::push_nlmsg(
            &mut bytes,
            libc::NLMSG_ERROR as u16,
            0,
            seq,
            &error.to_ne_bytes(),
        );
        bytes
    }
    #[test]
    fn every_ack_is_required_and_later_errors_are_not_hidden() {
        let mut pending = BTreeSet::from([1, 2]);
        acknowledge(&ack(1, 0), &mut pending).unwrap();
        assert_eq!(pending, BTreeSet::from([2]));
        assert!(acknowledge(&ack(2, -libc::EINVAL), &mut pending).is_err());
        acknowledge(&ack(2, 0), &mut pending).unwrap();
        assert!(pending.is_empty());
        assert!(acknowledge(&ack(2, 0), &mut pending).is_err());
        assert!(acknowledge(&[0; 4], &mut pending).is_err());
    }

    #[test]
    fn malformed_ack_error_codes_are_rejected_without_panicking() {
        for code in [i32::MIN, 1, i32::MAX] {
            let mut pending = BTreeSet::from([1]);
            let error = acknowledge(&ack(1, code), &mut pending).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("invalid nf_tables ACK error code")
            );
            assert_eq!(pending, BTreeSet::from([1]));
        }
    }

    #[test]
    fn coalesced_out_of_order_acks_complete_only_known_requests() {
        let mut pending = BTreeSet::from([1, 2, 3]);
        let mut bytes = ack(3, 0);
        bytes.extend(ack(1, 0));
        acknowledge(&bytes, &mut pending).unwrap();
        assert_eq!(pending, BTreeSet::from([2]));
        assert!(acknowledge(&ack(4, 0), &mut pending).is_err());
        assert_eq!(pending, BTreeSet::from([2]));
        acknowledge(&ack(2, 0), &mut pending).unwrap();
        assert!(pending.is_empty());

        let mut bytes = ack(1, 0);
        bytes.extend(ack(2, -libc::EPERM));
        let error = acknowledge(&bytes, &mut BTreeSet::from([1, 2])).unwrap_err();
        assert!(error.to_string().contains("request 2 failed"));
    }

    #[test]
    fn malformed_or_interrupted_messages_cannot_complete_a_transaction() {
        let valid = ack(1, 0);
        for size in [0, 1, 15, 19, 21, u32::MAX] {
            let mut bytes = valid.clone();
            NetlinkBuffer::new(&mut bytes).set_length(size);
            let mut pending = BTreeSet::from([1]);
            assert!(acknowledge(&bytes, &mut pending).is_err(), "length={size}");
            assert_eq!(pending, BTreeSet::from([1]));
        }
        let mut interrupted = valid.clone();
        NetlinkBuffer::new(&mut interrupted).set_flags(NLM_F_DUMP_INTR);
        let mut wrong_type = valid.clone();
        NetlinkBuffer::new(&mut wrong_type).set_message_type(libc::NLMSG_DONE as u16);
        let mut truncated_tail = valid;
        truncated_tail.extend([0; 3]);
        for bytes in [interrupted, wrong_type, truncated_tail] {
            let mut pending = BTreeSet::from([1]);
            assert!(acknowledge(&bytes, &mut pending).is_err());
            assert_eq!(pending, BTreeSet::from([1]));
        }
    }
}
