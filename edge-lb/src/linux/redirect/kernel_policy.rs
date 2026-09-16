//! Conservative, read-only netfilter/XFRM admission. No command execution.

use std::{
    fs, io,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use rtnetlink::{
    packet_core::{NETLINK_HEADER_LEN, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkBuffer},
    sys::{Socket, SocketAddr},
};
use serde::Serialize;

// include/uapi/linux/xfrm.h. GETPOLICY is a dump of xfrm_userpolicy_id;
// GETDEFAULT replies with three XFRM_USERPOLICY_* bytes (in/fwd/out).
const XFRM_MSG_NEWPOLICY: u16 = 0x13;
const XFRM_MSG_GETPOLICY: u16 = 0x15;
const XFRM_MSG_GETDEFAULT: u16 = 0x28;
const XFRM_USERPOLICY_ACCEPT: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelPolicyState {
    Clear,
    NftTables,
    LegacyTables,
    XfrmPolicies,
    XfrmDefault,
}

pub fn observe_kernel_policy() -> Result<KernelPolicyState> {
    let tables = query(
        libc::NETLINK_NETFILTER,
        nft_type(libc::NFT_MSG_GETTABLE),
        nft_type(libc::NFT_MSG_NEWTABLE),
        &[0; 4],
        true,
    )?;
    if !tables.is_empty() {
        return Ok(KernelPolicyState::NftTables);
    }
    for file in ["ip_tables_names", "ip6_tables_names", "arp_tables_names"] {
        match fs::read_to_string(format!("/proc/net/{file}")) {
            Ok(names) if !names.trim().is_empty() => return Ok(KernelPolicyState::LegacyTables),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("reading legacy netfilter tables"),
        }
    }
    let policies = query(
        libc::NETLINK_XFRM,
        XFRM_MSG_GETPOLICY,
        XFRM_MSG_NEWPOLICY,
        &[0; 64],
        true,
    )?;
    if !policies.is_empty() {
        return Ok(KernelPolicyState::XfrmPolicies);
    }
    let defaults = query(
        libc::NETLINK_XFRM,
        XFRM_MSG_GETDEFAULT,
        XFRM_MSG_GETDEFAULT,
        &[0; 3],
        false,
    )?;
    ensure!(defaults.len() == 1, "missing XFRM default policy");
    default_policy(&defaults[0])
}

fn default_policy(payload: &[u8]) -> Result<KernelPolicyState> {
    // nlmsg_end can include NLMSG_ALIGN padding in nlmsg_len. Only the three
    // struct fields carry policy; padding is not a fourth policy direction.
    ensure!(
        matches!(payload.len(), 3 | 4),
        "invalid XFRM default policy size"
    );
    Ok(if payload[..3] == [XFRM_USERPOLICY_ACCEPT; 3] {
        KernelPolicyState::Clear
    } else {
        KernelPolicyState::XfrmDefault
    })
}

fn nft_type(kind: i32) -> u16 {
    ((libc::NFNL_SUBSYS_NFTABLES as u16) << 8) | kind as u16
}

fn query(
    protocol: i32,
    kind: u16,
    response_type: u16,
    payload: &[u8],
    dump: bool,
) -> Result<Vec<Vec<u8>>> {
    let mut socket = Socket::new(protocol as isize)?;
    socket.bind_auto()?;
    socket.set_non_blocking(true)?;
    let mut request = vec![0; NETLINK_HEADER_LEN + payload.len()];
    let mut header = NetlinkBuffer::new(&mut request);
    header.set_length((NETLINK_HEADER_LEN + payload.len()) as u32);
    header.set_message_type(kind);
    header.set_flags(NLM_F_REQUEST | if dump { NLM_F_DUMP } else { 0 });
    header.set_sequence_number(1);
    header.payload_mut().copy_from_slice(payload);
    ensure!(
        socket.send_to(&request, &SocketAddr::new(0, 0), 0)? == request.len(),
        "short kernel policy query"
    );
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut result = Vec::new();
    let mut received = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "kernel policy query timed out");
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points at one initialized descriptor for a live socket.
        let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("polling kernel policy query");
        }
        ensure!(
            ready > 0 && poll.revents == libc::POLLIN,
            "kernel policy query timeout/socket error"
        );
        let mut buffer = [0u8; 65536];
        let (length, sender) = socket.recv_from(&mut &mut buffer[..], 0)?;
        ensure!(
            sender.port_number() == 0 && length > 0 && length < buffer.len(),
            "invalid/truncated kernel policy reply"
        );
        received += length;
        ensure!(received <= 1024 * 1024, "kernel policy dump too large");
        if parse_reply(&buffer[..length], response_type, dump, &mut result)? {
            return Ok(result);
        }
    }
}

fn parse_reply(
    mut bytes: &[u8],
    response_type: u16,
    dump: bool,
    result: &mut Vec<Vec<u8>>,
) -> Result<bool> {
    let mut done = false;
    while !bytes.is_empty() {
        ensure!(!done, "messages after terminal policy reply");
        let message = NetlinkBuffer::new_checked(bytes)?;
        ensure!(
            message.sequence_number() == 1,
            "foreign kernel policy sequence"
        );
        ensure!(
            message.flags() & NLM_F_DUMP_INTR == 0,
            "kernel policy dump interrupted"
        );
        match message.message_type() {
            value if value == libc::NLMSG_DONE as u16 && dump => {
                ensure!(message.payload().len() >= 4, "short policy dump completion");
                ensure!(
                    i32::from_ne_bytes(message.payload()[..4].try_into()?) == 0,
                    "kernel policy dump failed"
                );
                done = true;
            }
            value if value == libc::NLMSG_ERROR as u16 => {
                ensure!(message.payload().len() >= 4, "short kernel policy error");
                let code = i32::from_ne_bytes(message.payload()[..4].try_into()?);
                bail!("kernel policy query error {code}");
            }
            value if value == response_type => {
                result.push(message.payload().to_vec());
                done = !dump;
            }
            _ => bail!("unexpected kernel policy reply"),
        }
        let aligned = (message.length() as usize + 3) & !3;
        ensure!(aligned <= bytes.len(), "truncated kernel policy alignment");
        bytes = &bytes[aligned..];
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let length = NETLINK_HEADER_LEN + payload.len();
        let mut bytes = vec![0; (length + 3) & !3];
        let mut header = NetlinkBuffer::new(&mut bytes);
        header.set_length(length as u32);
        header.set_message_type(kind);
        header.set_sequence_number(1);
        header.set_flags(flags);
        header.payload_mut().copy_from_slice(payload);
        bytes
    }

    #[test]
    fn dump_requires_successful_completion_not_just_no_objects() {
        let mut results = Vec::new();
        assert!(!parse_reply(&[], 100, true, &mut results).unwrap());
        assert!(
            parse_reply(
                &reply(libc::NLMSG_DONE as u16, 0, &[0; 4]),
                100,
                true,
                &mut results
            )
            .unwrap()
        );
        for bytes in [
            reply(libc::NLMSG_DONE as u16, NLM_F_DUMP_INTR, &[0; 4]),
            reply(libc::NLMSG_DONE as u16, 0, &(-libc::EINTR).to_ne_bytes()),
            reply(libc::NLMSG_ERROR as u16, 0, &(-libc::EPERM).to_ne_bytes()),
            reply(libc::NLMSG_OVERRUN as u16, 0, &[]),
            vec![0; 4],
        ] {
            assert!(parse_reply(&bytes, 100, true, &mut results).is_err());
        }
    }

    #[test]
    fn default_policy_reply_preserves_all_three_directions() {
        let mut results = Vec::new();
        assert!(
            parse_reply(
                &reply(XFRM_MSG_GETDEFAULT, 0, &[2, 1, 2]),
                XFRM_MSG_GETDEFAULT,
                false,
                &mut results
            )
            .unwrap()
        );
        assert_eq!(results, vec![vec![2, 1, 2]]);
        for payload in [vec![2, 2, 2], vec![2, 2, 2, 0]] {
            assert_eq!(default_policy(&payload).unwrap(), KernelPolicyState::Clear);
        }
        for payload in [[1, 2, 2, 0], [2, 1, 2, 0], [2, 2, 1, 0], [0, 2, 2, 0]] {
            assert_eq!(
                default_policy(&payload).unwrap(),
                KernelPolicyState::XfrmDefault
            );
        }
        assert!(default_policy(&[2, 2]).is_err());
        assert!(default_policy(&[2; 5]).is_err());
    }
}
