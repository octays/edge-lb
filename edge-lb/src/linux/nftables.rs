//! Minimal nf_tables netlink helpers for legacy-state diagnostics.

use std::{ffi::CString, mem::size_of};

use anyhow::Result;

use crate::config::Config;

mod transport;

const NLM_F_REQUEST: u16 = libc::NLM_F_REQUEST as u16;
const NLM_F_ACK: u16 = libc::NLM_F_ACK as u16;
#[cfg(test)]
const NLM_F_CREATE: u16 = libc::NLM_F_CREATE as u16;

const NFNL_SUBSYS_NFTABLES: u16 = libc::NFNL_SUBSYS_NFTABLES as u16;
const NFNETLINK_V0: u8 = libc::NFNETLINK_V0 as u8;
#[cfg(test)]
const NFPROTO_UNSPEC: u8 = libc::NFPROTO_UNSPEC as u8;
const NFPROTO_INET: u8 = libc::NFPROTO_INET as u8;

#[cfg(test)]
const NFT_MSG_NEWTABLE: u16 = libc::NFT_MSG_NEWTABLE as u16;
const NFT_MSG_GETTABLE: u16 = libc::NFT_MSG_GETTABLE as u16;
#[cfg(test)]
const NFT_MSG_DELTABLE: u16 = libc::NFT_MSG_DELTABLE as u16;
#[cfg(test)]
const NFNL_MSG_BATCH_BEGIN: u16 = libc::NFNL_MSG_BATCH_BEGIN as u16;
#[cfg(test)]
const NFNL_MSG_BATCH_END: u16 = libc::NFNL_MSG_BATCH_END as u16;

const NFTA_TABLE_NAME: u16 = 1;
#[cfg(test)]
const NFTA_TABLE_FLAGS: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct NfGenMsg {
    nfgen_family: u8,
    version: u8,
    res_id: u16,
}

pub fn table_exists(cfg: &Config) -> bool {
    named_table_exists(&cfg.backend_cfg().nft_table)
}

pub fn named_table_exists(table: &str) -> bool {
    let mut msg = Message::new();
    msg.nft_msg(
        NFT_MSG_GETTABLE,
        NLM_F_REQUEST | NLM_F_ACK,
        table_name_body_named(table),
        1,
    );
    msg.send().is_ok()
}

#[cfg(test)]
pub(super) fn create_probe_table(table: &str) -> Result<()> {
    let mut message = Message::new();
    let mut seq = 0;
    message.begin_batch(&mut seq);
    message.nft_msg(
        NFT_MSG_NEWTABLE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        table_create_body_named(table),
        next_seq(&mut seq),
    );
    message.end_batch(&mut seq);
    message.send()
}

#[cfg(test)]
pub(super) fn delete_named_table(table: &str) -> Result<()> {
    let mut msg = Message::new();
    let mut seq = 0;
    msg.begin_batch(&mut seq);
    msg.nft_msg(
        NFT_MSG_DELTABLE,
        NLM_F_REQUEST | NLM_F_ACK,
        table_name_body_named(table),
        next_seq(&mut seq),
    );
    msg.end_batch(&mut seq);
    msg.send()
}

fn table_name_body_named(table: &str) -> Vec<u8> {
    let mut body = Vec::new();
    push_str(&mut body, NFTA_TABLE_NAME, table);
    body
}

#[cfg(test)]
fn table_create_body_named(table: &str) -> Vec<u8> {
    let mut body = table_name_body_named(table);
    push_u32(&mut body, NFTA_TABLE_FLAGS, 0);
    body
}

struct Message {
    buf: Vec<u8>,
}

impl Message {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn nft_msg(&mut self, msg_type: u16, flags: u16, mut body: Vec<u8>, seq: u32) {
        let mut payload = nfgen_body(NFPROTO_INET);
        payload.append(&mut body);
        push_nlmsg(&mut self.buf, nft_msg_type(msg_type), flags, seq, &payload);
    }

    #[cfg(test)]
    fn begin_batch(&mut self, seq: &mut u32) {
        self.batch_msg(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, *seq);
    }

    #[cfg(test)]
    fn end_batch(&mut self, seq: &mut u32) {
        self.batch_msg(NFNL_MSG_BATCH_END, NLM_F_REQUEST, next_seq(seq));
    }

    #[cfg(test)]
    fn batch_msg(&mut self, msg_type: u16, flags: u16, seq: u32) {
        let payload = nfgen_body_for_batch();
        push_nlmsg(&mut self.buf, msg_type, flags, seq, &payload);
    }

    fn send(self) -> Result<()> {
        transport::transact(&self.buf)
    }
}

#[cfg(test)]
fn next_seq(seq: &mut u32) -> u32 {
    *seq += 1;
    *seq
}

fn nft_msg_type(msg_type: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg_type
}

fn nfgen_body(family: u8) -> Vec<u8> {
    bytes_of(&NfGenMsg {
        nfgen_family: family,
        version: NFNETLINK_V0,
        res_id: 0_u16.to_be(),
    })
}

#[cfg(test)]
fn nfgen_body_for_batch() -> Vec<u8> {
    bytes_of(&NfGenMsg {
        nfgen_family: NFPROTO_UNSPEC,
        version: NFNETLINK_V0,
        res_id: NFNL_SUBSYS_NFTABLES.to_be(),
    })
}

fn push_nlmsg(out: &mut Vec<u8>, msg_type: u16, flags: u16, seq: u32, payload: &[u8]) {
    let len = size_of::<libc::nlmsghdr>() + payload.len();
    out.extend_from_slice(&bytes_of(&libc::nlmsghdr {
        nlmsg_len: len as u32,
        nlmsg_type: msg_type,
        nlmsg_flags: flags,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    }));
    out.extend_from_slice(payload);
    pad(out);
}

fn push_str(out: &mut Vec<u8>, typ: u16, value: &str) {
    let cstr = CString::new(value).expect("nftables strings must not contain NUL");
    push_raw_attr(out, typ, cstr.as_bytes_with_nul());
}

#[cfg(test)]
fn push_u32(out: &mut Vec<u8>, typ: u16, value: u32) {
    push_raw_attr(out, typ, &value.to_be_bytes());
}

fn push_raw_attr(out: &mut Vec<u8>, typ: u16, payload: &[u8]) {
    let len = size_of::<libc::nlattr>() + payload.len();
    out.extend_from_slice(&bytes_of(&libc::nlattr {
        nla_len: len as u16,
        nla_type: typ,
    }));
    out.extend_from_slice(payload);
    pad(out);
}

fn pad(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

fn bytes_of<T>(value: &T) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()).to_vec() }
}

fn align(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_table_lifecycle_when_privileged() {
        if !can_open_netfilter_socket() {
            eprintln!("skipping nf_tables probe: missing NET_ADMIN/CAP_NET_ADMIN");
            return;
        }

        let table = format!("edge_lb_test_{}", std::process::id());
        delete_named_table(&table).ok();
        create_probe_table(&table).expect("nf_tables table create must succeed");
        assert!(named_table_exists(&table));
        delete_named_table(&table).expect("nf_tables table delete must succeed");
        assert!(!named_table_exists(&table));
    }

    fn can_open_netfilter_socket() -> bool {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            return false;
        }
        unsafe {
            libc::close(fd);
        }
        true
    }

    #[test]
    fn netlink_attrs_are_aligned() {
        let mut body = Vec::new();
        push_str(&mut body, NFTA_TABLE_NAME, "edge_lb_test");
        assert_eq!(body.len() % 4, 0);
        assert_eq!(align(5), 8);
    }
}
