//! Minimal nf_tables netlink encoder for edge-lb owned tables.

use std::{ffi::CString, mem::size_of};

#[cfg(test)]
use anyhow::Context;
use anyhow::Result;

use crate::config::Config;
#[cfg(test)]
use crate::config::GatewayReturnPath;

mod transport;

const NLM_F_REQUEST: u16 = libc::NLM_F_REQUEST as u16;
const NLM_F_ACK: u16 = libc::NLM_F_ACK as u16;
const NLM_F_CREATE: u16 = libc::NLM_F_CREATE as u16;

const NFNL_SUBSYS_NFTABLES: u16 = libc::NFNL_SUBSYS_NFTABLES as u16;
const NFNETLINK_V0: u8 = libc::NFNETLINK_V0 as u8;
const NFPROTO_UNSPEC: u8 = libc::NFPROTO_UNSPEC as u8;
const NFPROTO_INET: u8 = libc::NFPROTO_INET as u8;
const NFPROTO_IPV4: u8 = libc::NFPROTO_IPV4 as u8;
const NF_ACCEPT: u32 = libc::NF_ACCEPT as u32;
const NF_IP_PRI_MANGLE: i32 = libc::NF_IP_PRI_MANGLE;

const NFT_MSG_NEWTABLE: u16 = libc::NFT_MSG_NEWTABLE as u16;
const NFT_MSG_GETTABLE: u16 = libc::NFT_MSG_GETTABLE as u16;
const NFT_MSG_DELTABLE: u16 = libc::NFT_MSG_DELTABLE as u16;
const NFT_MSG_NEWCHAIN: u16 = libc::NFT_MSG_NEWCHAIN as u16;
const NFT_MSG_NEWRULE: u16 = libc::NFT_MSG_NEWRULE as u16;
const NFNL_MSG_BATCH_BEGIN: u16 = libc::NFNL_MSG_BATCH_BEGIN as u16;
const NFNL_MSG_BATCH_END: u16 = libc::NFNL_MSG_BATCH_END as u16;

const NFT_REG_1: u32 = libc::NFT_REG_1 as u32;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = libc::NFT_PAYLOAD_NETWORK_HEADER as u32;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = libc::NFT_PAYLOAD_TRANSPORT_HEADER as u32;
const NFT_CMP_EQ: u32 = libc::NFT_CMP_EQ as u32;
const NFT_BITWISE_BOOL: u32 = 0;
const NFT_META_MARK: u32 = libc::NFT_META_MARK as u32;
const NFT_META_OIFNAME: u32 = libc::NFT_META_OIFNAME as u32;
const NFT_META_NFPROTO: u32 = libc::NFT_META_NFPROTO as u32;
const NFT_META_L4PROTO: u32 = libc::NFT_META_L4PROTO as u32;
const NFT_CT_DIRECTION: u32 = libc::NFT_CT_DIRECTION as u32;
const NFT_CT_MARK: u32 = libc::NFT_CT_MARK as u32;
const NFT_EXTHDR_OP_TCPOPT: u32 = 1;
const TCP_OPT_MAXSEG: u8 = 2;
const IP_CT_DIR_REPLY: u8 = 1;

// The libc crate exposes the nf_tables message IDs and core enum values used
// above, but it does not currently expose nf_tables expression attribute IDs.
// Keep the remaining values aligned with Linux include/uapi/linux/netfilter/
// nf_tables.h and avoid duplicating constants that libc already provides.
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_BITWISE_OP: u16 = 6;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_META_SREG: u16 = 3;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFTA_CT_SREG: u16 = 4;
const NFTA_EXTHDR_TYPE: u16 = 2;
const NFTA_EXTHDR_OFFSET: u16 = 3;
const NFTA_EXTHDR_LEN: u16 = 4;
const NFTA_EXTHDR_OP: u16 = 6;
const NFTA_EXTHDR_SREG: u16 = 7;

const NLA_F_NESTED: u16 = libc::NLA_F_NESTED as u16;

#[repr(C)]
#[derive(Clone, Copy)]
struct NfGenMsg {
    nfgen_family: u8,
    version: u8,
    res_id: u16,
}

#[cfg(test)]
pub fn apply_return_path(cfg: &Config) -> Result<()> {
    cfg.validate_backend_return_paths()?;
    let mut msg = Message::new();
    let mut seq = 0;
    msg.begin_batch(&mut seq);
    msg.nft_msg(
        NFT_MSG_NEWTABLE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        table_create_body(cfg),
        next_seq(&mut seq),
    );
    msg.nft_msg(
        NFT_MSG_DELTABLE,
        NLM_F_REQUEST | NLM_F_ACK,
        table_name_body(cfg),
        next_seq(&mut seq),
    );
    msg.nft_msg(
        NFT_MSG_NEWTABLE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        table_create_body(cfg),
        next_seq(&mut seq),
    );
    for chain in base_chains(cfg) {
        msg.nft_msg(
            NFT_MSG_NEWCHAIN,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
            chain_body(cfg, chain),
            next_seq(&mut seq),
        );
    }
    let paths = cfg.backend_return_paths();
    for path in &paths {
        msg.nft_msg(
            NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
            rule_body(cfg, "prerouting", forward_mark_exprs(cfg, path)?),
            next_seq(&mut seq),
        );
    }
    for chain in ["prerouting", "output"] {
        for mark in return_marks(cfg) {
            msg.nft_msg(
                NFT_MSG_NEWRULE,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
                rule_body(cfg, chain, reply_mark_exprs(mark)),
                next_seq(&mut seq),
            );
        }
    }
    msg.nft_msg(
        NFT_MSG_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
        rule_body(cfg, "forward", mss_clamp_exprs(cfg)),
        next_seq(&mut seq),
    );
    msg.end_batch(&mut seq);
    msg.send().with_context(|| {
        format!(
            "applying nftables return-path batch for table inet {}",
            cfg.backend_cfg().nft_table
        )
    })
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
pub fn delete_table(cfg: &Config) -> Result<()> {
    delete_named_table(&cfg.backend_cfg().nft_table)
}

#[cfg(test)]
pub fn delete_named_table(table: &str) -> Result<()> {
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

const NLM_F_APPEND: u16 = libc::NLM_F_APPEND as u16;

#[derive(Clone, Copy)]
struct BaseChain {
    name: &'static str,
    chain_type: &'static str,
    hook: u32,
    priority: i32,
}

fn base_chains(_cfg: &Config) -> [BaseChain; 3] {
    [
        BaseChain {
            name: "prerouting",
            chain_type: "filter",
            hook: 0,
            priority: NF_IP_PRI_MANGLE,
        },
        BaseChain {
            name: "output",
            chain_type: "route",
            hook: 3,
            priority: NF_IP_PRI_MANGLE,
        },
        BaseChain {
            name: "forward",
            chain_type: "filter",
            hook: 2,
            priority: NF_IP_PRI_MANGLE,
        },
    ]
}

fn table_name_body(cfg: &Config) -> Vec<u8> {
    table_name_body_named(&cfg.backend_cfg().nft_table)
}

fn table_name_body_named(table: &str) -> Vec<u8> {
    let mut body = Vec::new();
    push_str(&mut body, NFTA_TABLE_NAME, table);
    body
}

#[cfg(test)]
fn table_create_body(cfg: &Config) -> Vec<u8> {
    table_create_body_named(&cfg.backend_cfg().nft_table)
}

#[cfg(test)]
fn table_create_body_named(table: &str) -> Vec<u8> {
    let mut body = table_name_body_named(table);
    push_u32(&mut body, NFTA_TABLE_FLAGS, 0);
    body
}

#[cfg(test)]
fn chain_body(cfg: &Config, chain: BaseChain) -> Vec<u8> {
    chain_body_in_table(&cfg.backend_cfg().nft_table, chain)
}

#[cfg(test)]
fn chain_body_in_table(table: &str, chain: BaseChain) -> Vec<u8> {
    let mut body = Vec::new();
    push_str(&mut body, NFTA_CHAIN_TABLE, table);
    push_str(&mut body, NFTA_CHAIN_NAME, chain.name);
    push_str(&mut body, NFTA_CHAIN_TYPE, chain.chain_type);
    push_nested(&mut body, NFTA_CHAIN_HOOK, |hook| {
        push_u32(hook, NFTA_HOOK_HOOKNUM, chain.hook);
        push_i32(hook, NFTA_HOOK_PRIORITY, chain.priority);
    });
    push_u32(&mut body, NFTA_CHAIN_POLICY, NF_ACCEPT);
    body
}

#[cfg(test)]
fn rule_body(cfg: &Config, chain: &str, exprs: Vec<Vec<u8>>) -> Vec<u8> {
    rule_body_in_table(&cfg.backend_cfg().nft_table, chain, exprs)
}

#[cfg(test)]
fn rule_body_in_table(table: &str, chain: &str, exprs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut body = Vec::new();
    push_str(&mut body, NFTA_RULE_TABLE, table);
    push_str(&mut body, NFTA_RULE_CHAIN, chain);
    push_nested(&mut body, NFTA_RULE_EXPRESSIONS, |list| {
        for expr in exprs {
            push_raw_attr(list, NFTA_LIST_ELEM | NLA_F_NESTED, &expr);
        }
    });
    body
}

#[cfg(test)]
fn forward_mark_exprs(_cfg: &Config, path: &GatewayReturnPath) -> Result<Vec<Vec<u8>>> {
    let mut expressions = ingress_match_exprs(path)?;
    expressions.extend([counter(), immediate_mark(path.mark), ct_set(NFT_CT_MARK)]);
    Ok(expressions)
}

#[cfg(test)]
fn ingress_match_exprs(path: &GatewayReturnPath) -> Result<Vec<Vec<u8>>> {
    let dscp = path.dscp;
    // Out-of-range dscp used to be truncated to a DSCP-0 match here, which
    // silently matched nothing and dropped the connection into the main
    // table. Fail loudly instead.
    let tos = u8::try_from(dscp << 2)
        .with_context(|| format!("gateway return path dscp {dscp} out of range 0..=63"))?;
    Ok(vec![
        ct_load(NFT_CT_DIRECTION),
        cmp_u8(0),
        meta_load(NFT_META_NFPROTO),
        cmp_u8(NFPROTO_IPV4),
        payload_load(NFT_PAYLOAD_NETWORK_HEADER, 1, 1),
        bitwise_and(1, &[0xfc]),
        cmp_bytes(&[tos]),
    ])
}

#[cfg(test)]
fn reply_mark_exprs(mark: u32) -> Vec<Vec<u8>> {
    vec![
        ct_load(NFT_CT_MARK),
        cmp_mark(mark),
        ct_load(NFT_CT_DIRECTION),
        cmp_u8(IP_CT_DIR_REPLY),
        counter(),
        immediate_mark(mark),
        meta_set(NFT_META_MARK),
    ]
}

#[cfg(test)]
fn return_marks(cfg: &Config) -> Vec<u32> {
    let mut marks = cfg
        .backend_return_paths()
        .into_iter()
        .map(|path| path.mark)
        .collect::<Vec<_>>();
    marks.sort_unstable();
    marks.dedup();
    marks
}

#[cfg(test)]
fn mss_clamp_exprs(cfg: &Config) -> Vec<Vec<u8>> {
    vec![
        meta_load(NFT_META_OIFNAME),
        cmp_bytes(&ifname_bytes(&cfg.network().vxlan_dev)),
        meta_load(NFT_META_L4PROTO),
        cmp_u8(6),
        payload_load(NFT_PAYLOAD_TRANSPORT_HEADER, 13, 1),
        bitwise_and(1, &[0x17]),
        cmp_u8(0x02),
        counter(),
        immediate_bytes(&cfg.backend_cfg().mss.to_be_bytes()[2..]),
        exthdr_tcpopt_write(TCP_OPT_MAXSEG, 2, 2),
    ]
}

#[cfg(test)]
fn expr(name: &str, build: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = Vec::new();
    push_str(&mut body, NFTA_EXPR_NAME, name);
    push_nested(&mut body, NFTA_EXPR_DATA, build);
    body
}

#[cfg(test)]
fn meta_load(key: u32) -> Vec<u8> {
    expr("meta", |data| {
        push_u32(data, NFTA_META_DREG, NFT_REG_1);
        push_u32(data, NFTA_META_KEY, key);
    })
}

#[cfg(test)]
fn meta_set(key: u32) -> Vec<u8> {
    expr("meta", |data| {
        push_u32(data, NFTA_META_SREG, NFT_REG_1);
        push_u32(data, NFTA_META_KEY, key);
    })
}

#[cfg(test)]
fn ct_load(key: u32) -> Vec<u8> {
    expr("ct", |data| {
        push_u32(data, NFTA_CT_DREG, NFT_REG_1);
        push_u32(data, NFTA_CT_KEY, key);
    })
}

#[cfg(test)]
fn ct_set(key: u32) -> Vec<u8> {
    expr("ct", |data| {
        push_u32(data, NFTA_CT_SREG, NFT_REG_1);
        push_u32(data, NFTA_CT_KEY, key);
    })
}

#[cfg(test)]
fn payload_load(base: u32, offset: u32, len: u32) -> Vec<u8> {
    expr("payload", |data| {
        push_u32(data, NFTA_PAYLOAD_DREG, NFT_REG_1);
        push_u32(data, NFTA_PAYLOAD_BASE, base);
        push_u32(data, NFTA_PAYLOAD_OFFSET, offset);
        push_u32(data, NFTA_PAYLOAD_LEN, len);
    })
}

#[cfg(test)]
fn bitwise_and(len: u32, mask: &[u8]) -> Vec<u8> {
    expr("bitwise", |data| {
        push_u32(data, NFTA_BITWISE_SREG, NFT_REG_1);
        push_u32(data, NFTA_BITWISE_DREG, NFT_REG_1);
        push_u32(data, NFTA_BITWISE_LEN, len);
        push_data(data, NFTA_BITWISE_MASK, mask);
        push_data(data, NFTA_BITWISE_XOR, &vec![0; mask.len()]);
        push_u32(data, NFTA_BITWISE_OP, NFT_BITWISE_BOOL);
    })
}

#[cfg(test)]
fn cmp_u8(value: u8) -> Vec<u8> {
    cmp_bytes(&[value])
}

#[cfg(test)]
fn cmp_mark(value: u32) -> Vec<u8> {
    cmp_bytes(&mark_register_bytes(value))
}

#[cfg(test)]
fn cmp_bytes(value: &[u8]) -> Vec<u8> {
    expr("cmp", |data| {
        push_u32(data, NFTA_CMP_SREG, NFT_REG_1);
        push_u32(data, NFTA_CMP_OP, NFT_CMP_EQ);
        push_data(data, NFTA_CMP_DATA, value);
    })
}

#[cfg(test)]
fn immediate_mark(value: u32) -> Vec<u8> {
    immediate_bytes(&mark_register_bytes(value))
}

#[cfg(test)]
fn immediate_bytes(value: &[u8]) -> Vec<u8> {
    expr("immediate", |data| {
        push_u32(data, NFTA_IMMEDIATE_DREG, NFT_REG_1);
        push_data(data, NFTA_IMMEDIATE_DATA, value);
    })
}

#[cfg(test)]
fn mark_register_bytes(value: u32) -> [u8; 4] {
    // nf_tables register data follows the host representation for packet
    // marks. Netlink attributes still use big-endian helpers above.
    value.to_ne_bytes()
}

#[cfg(test)]
fn counter() -> Vec<u8> {
    expr("counter", |_| {})
}

#[cfg(test)]
fn exthdr_tcpopt_write(kind: u8, offset: u32, len: u32) -> Vec<u8> {
    expr("exthdr", |data| {
        push_u32(data, NFTA_EXTHDR_SREG, NFT_REG_1);
        push_u8(data, NFTA_EXTHDR_TYPE, kind);
        push_u32(data, NFTA_EXTHDR_OFFSET, offset);
        push_u32(data, NFTA_EXTHDR_LEN, len);
        push_u32(data, NFTA_EXTHDR_OP, NFT_EXTHDR_OP_TCPOPT);
    })
}

#[cfg(test)]
fn push_data(out: &mut Vec<u8>, typ: u16, value: &[u8]) {
    push_nested(out, typ, |data| {
        push_raw_attr(data, NFTA_DATA_VALUE, value);
    });
}

#[cfg(test)]
fn ifname_bytes(name: &str) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    let raw = name.as_bytes();
    let len = raw.len().min(bytes.len() - 1);
    bytes[..len].copy_from_slice(&raw[..len]);
    bytes
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

    fn begin_batch(&mut self, seq: &mut u32) {
        self.batch_msg(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, *seq);
    }

    fn end_batch(&mut self, seq: &mut u32) {
        self.batch_msg(NFNL_MSG_BATCH_END, NLM_F_REQUEST, next_seq(seq));
    }

    fn batch_msg(&mut self, msg_type: u16, flags: u16, seq: u32) {
        let payload = nfgen_body_for_batch();
        push_nlmsg(&mut self.buf, msg_type, flags, seq, &payload);
    }

    fn send(self) -> Result<()> {
        transport::transact(&self.buf)
    }
}

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

fn push_u8(out: &mut Vec<u8>, typ: u16, value: u8) {
    push_raw_attr(out, typ, &[value]);
}

fn push_u32(out: &mut Vec<u8>, typ: u16, value: u32) {
    push_raw_attr(out, typ, &value.to_be_bytes());
}

fn push_i32(out: &mut Vec<u8>, typ: u16, value: i32) {
    push_raw_attr(out, typ, &value.to_be_bytes());
}

fn push_nested(out: &mut Vec<u8>, typ: u16, build: impl FnOnce(&mut Vec<u8>)) {
    let mut nested = Vec::new();
    build(&mut nested);
    push_raw_attr(out, typ | NLA_F_NESTED, &nested);
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
    use std::path::PathBuf;

    use super::*;
    use crate::config::{FileConfig, GatewayReturnPath, NetworkConfig};

    #[test]
    fn failed_native_batch_preserves_existing_table() {
        std::thread::spawn(|| {
            crate::linux::test_support::private_namespace(false);
            let cfg = Config {
                path: "/unused/test.toml".into(),
                file: FileConfig::default(),
            };
            create_probe_table(&cfg.backend_cfg().nft_table).unwrap();
            let mut message = Message::new();
            let mut seq = 0;
            message.begin_batch(&mut seq);
            message.nft_msg(
                NFT_MSG_DELTABLE,
                NLM_F_REQUEST | NLM_F_ACK,
                table_name_body(&cfg),
                next_seq(&mut seq),
            );
            message.nft_msg(
                NFT_MSG_NEWRULE,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
                rule_body(&cfg, "missing-chain", vec![counter()]),
                next_seq(&mut seq),
            );
            message.end_batch(&mut seq);
            assert!(message.send().is_err());
            assert!(table_exists(&cfg), "failed batch must roll back deletion");
        })
        .join()
        .unwrap();
    }

    #[test]
    fn applies_and_deletes_probe_table_when_privileged() {
        let mut file = FileConfig {
            network: NetworkConfig {
                vxlan_dev: "edge-lb-test-vxlan".to_string(),
                dscp: 46,
                ..NetworkConfig::default()
            },
            ..FileConfig::default()
        };
        file.backend.nft_table = format!("edge_lb_test_{}", std::process::id());
        file.backend.ct_mark = 1;
        file.backend.mss = 1410;
        file.backend_return_paths = vec![
            GatewayReturnPath {
                gateway: Some("gateway-a".to_string()),
                gateway_underlay_ip: "192.0.2.1".parse().unwrap(),
                gateway_overlay_ip: "10.44.0.1".parse().unwrap(),
                backend_overlay_ip: Some("10.44.0.2/24".to_string()),
                dscp: 46,
                mark: crate::config::return_mark(46, 0),
                route_table_id: crate::config::return_table_id(46, 0),
            },
            GatewayReturnPath {
                gateway: Some("gateway-b".to_string()),
                gateway_underlay_ip: "192.0.2.2".parse().unwrap(),
                gateway_overlay_ip: "10.45.0.1".parse().unwrap(),
                backend_overlay_ip: Some("10.45.0.2/24".to_string()),
                dscp: 40,
                mark: crate::config::return_mark(40, 1),
                route_table_id: crate::config::return_table_id(40, 1),
            },
        ];
        let cfg = Config {
            file,
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
        };

        if !can_open_netfilter_socket() {
            eprintln!("skipping nf_tables probe: missing NET_ADMIN/CAP_NET_ADMIN");
            return;
        }

        delete_table(&cfg).ok();
        apply_return_path(&cfg).expect("nf_tables apply must succeed");
        assert!(table_exists(&cfg));
        delete_table(&cfg).expect("nf_tables delete must succeed");
        assert!(!table_exists(&cfg));
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
    fn mark_register_values_use_native_endian() {
        assert_eq!(mark_register_bytes(1), 1_u32.to_ne_bytes());
    }
}
