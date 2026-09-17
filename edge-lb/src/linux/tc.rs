//! Common helpers for TC qdisc and filter operations.

use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterInfo {
    pub pref: u16,
    pub handle: u32,
    pub kind: String,
    pub name: Option<String>,
    pub prog_id: Option<u32>,
}

pub fn show_ingress(dev: &str) -> Result<String> {
    format_filters(imp::dump_filters(dev, Direction::Ingress)?)
}

fn format_filters(filters: Vec<FilterInfo>) -> Result<String> {
    Ok(filters
        .into_iter()
        .map(|filter| {
            let name = filter.name.unwrap_or_default();
            let id = filter
                .prog_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string());
            format!(
                "filter pref {} handle {} {} name {} id {}",
                filter.pref, filter.handle, filter.kind, name, id
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

pub fn add_clsact_best_effort(dev: &str) {
    imp::add_clsact(dev).ok();
}

#[allow(dead_code)]
pub fn replace_clsact_best_effort(dev: &str) {
    imp::delete_clsact(dev).ok();
    imp::add_clsact(dev).ok();
}

#[allow(dead_code)]
pub fn delete_clsact_best_effort(dev: &str) {
    imp::delete_clsact(dev).ok();
}

pub fn delete_ingress_pref_best_effort(dev: &str, pref: u16) {
    imp::delete_pref(dev, Direction::Ingress, pref).ok();
}

pub fn delete_egress_pref_best_effort(dev: &str, pref: u16) {
    imp::delete_pref(dev, Direction::Egress, pref).ok();
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Ingress,
    Egress,
}

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        ffi::CStr,
        io, mem,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        ptr,
    };

    use anyhow::{Context, Result};
    use libc::{
        AF_NETLINK, AF_UNSPEC, NETLINK_CAP_ACK, NETLINK_EXT_ACK, NETLINK_ROUTE, NLA_F_NESTED,
        NLA_TYPE_MASK, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_MULTI, NLM_F_REQUEST,
        NLMSG_DONE, NLMSG_ERROR, RTM_DELQDISC, RTM_DELTFILTER, RTM_GETTFILTER, RTM_NEWQDISC,
        SOCK_RAW, SOL_NETLINK, bind, getsockname, nlattr, nlmsgerr, nlmsghdr, recv, send,
        setsockopt, sockaddr_nl, socket,
    };

    use super::{Direction, FilterInfo};
    use crate::linux::net;

    const NLMSG_ALIGNTO: usize = 4;
    const NLA_ALIGNTO: usize = 4;
    const NLMSG_HDR_LEN: usize = mem::size_of::<nlmsghdr>();
    const NLA_HDR_LEN: usize = mem::size_of::<nlattr>();

    const TCA_KIND: u16 = 1;
    const TCA_OPTIONS: u16 = 2;
    const TCA_BPF_NAME: u16 = 7;
    const TCA_BPF_ID: u16 = 11;

    const TC_H_MAJ_MASK: u32 = 0xffff_0000;
    const TC_H_MIN_MASK: u32 = 0x0000_ffff;
    const TC_H_CLSACT: u32 = 0xffff_fff1;
    const TC_H_INGRESS: u32 = 0xffff_fff1;
    const TC_H_UNSPEC: u32 = 0;
    const TC_H_MIN_INGRESS: u32 = 0xfff2;
    const TC_H_MIN_EGRESS: u32 = 0xfff3;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct TcMsg {
        tcm_family: u8,
        tcm_pad1: u8,
        tcm_pad2: u16,
        tcm_ifindex: i32,
        tcm_handle: u32,
        tcm_parent: u32,
        tcm_info: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct TcRequest {
        header: nlmsghdr,
        tc: TcMsg,
        attrs: [u8; 128],
    }

    impl Default for TcRequest {
        fn default() -> Self {
            // SAFETY: TcRequest is plain netlink request storage.
            unsafe { mem::zeroed() }
        }
    }

    #[derive(Debug)]
    struct NetlinkMessage {
        header: nlmsghdr,
        data: Vec<u8>,
        error: Option<nlmsgerr>,
    }

    #[derive(Debug)]
    struct Attr<'a> {
        typ: u16,
        data: &'a [u8],
    }

    pub fn add_clsact(dev: &str) -> Result<()> {
        let ifindex = net::ifindex(dev)? as i32;
        let mut req = TcRequest::default();
        req.header.nlmsg_len = (NLMSG_HDR_LEN + mem::size_of::<TcMsg>()) as u32;
        req.header.nlmsg_type = RTM_NEWQDISC;
        req.header.nlmsg_flags = (NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) as u16;
        req.tc.tcm_family = AF_UNSPEC as u8;
        req.tc.tcm_ifindex = ifindex;
        req.tc.tcm_handle = tc_handler_make(TC_H_CLSACT, TC_H_UNSPEC);
        req.tc.tcm_parent = tc_handler_make(TC_H_CLSACT, TC_H_INGRESS);
        append_attr_bytes(&mut req, TCA_KIND, b"clsact\0")?;
        send_ack(&req).with_context(|| format!("adding clsact qdisc on {dev}"))
    }

    pub fn delete_clsact(dev: &str) -> Result<()> {
        let ifindex = net::ifindex(dev)? as i32;
        let mut req = TcRequest::default();
        req.header.nlmsg_len = (NLMSG_HDR_LEN + mem::size_of::<TcMsg>()) as u32;
        req.header.nlmsg_type = RTM_DELQDISC;
        req.header.nlmsg_flags = (NLM_F_REQUEST | NLM_F_ACK) as u16;
        req.tc.tcm_family = AF_UNSPEC as u8;
        req.tc.tcm_ifindex = ifindex;
        req.tc.tcm_handle = tc_handler_make(TC_H_CLSACT, TC_H_UNSPEC);
        req.tc.tcm_parent = tc_handler_make(TC_H_CLSACT, TC_H_INGRESS);
        send_ack(&req).with_context(|| format!("deleting clsact qdisc on {dev}"))
    }

    pub fn delete_pref(dev: &str, direction: Direction, pref: u16) -> Result<()> {
        let filters = dump_filters(dev, direction)?;
        for filter in filters.into_iter().filter(|filter| filter.pref == pref) {
            delete_filter(dev, direction, pref, filter.handle)?;
        }
        Ok(())
    }

    fn delete_filter(dev: &str, direction: Direction, pref: u16, handle: u32) -> Result<()> {
        let ifindex = net::ifindex(dev)? as i32;
        let mut req = TcRequest::default();
        req.header.nlmsg_len = (NLMSG_HDR_LEN + mem::size_of::<TcMsg>()) as u32;
        req.header.nlmsg_type = RTM_DELTFILTER;
        req.header.nlmsg_flags = (NLM_F_REQUEST | NLM_F_ACK) as u16;
        req.tc.tcm_family = AF_UNSPEC as u8;
        req.tc.tcm_ifindex = ifindex;
        req.tc.tcm_parent = tc_parent(direction);
        req.tc.tcm_handle = handle;
        req.tc.tcm_info = (pref as u32) << 16;
        append_attr_bytes(&mut req, TCA_KIND, b"bpf\0")?;
        send_ack(&req)
            .with_context(|| format!("deleting {dev} {direction:?} pref {pref} handle {handle}"))
    }

    pub fn dump_filters(dev: &str, direction: Direction) -> Result<Vec<FilterInfo>> {
        let ifindex = net::ifindex(dev)? as i32;
        let mut req = TcRequest::default();
        req.header.nlmsg_len = (NLMSG_HDR_LEN + mem::size_of::<TcMsg>()) as u32;
        req.header.nlmsg_type = RTM_GETTFILTER;
        req.header.nlmsg_flags = (NLM_F_REQUEST | NLM_F_DUMP) as u16;
        req.tc.tcm_family = AF_UNSPEC as u8;
        req.tc.tcm_ifindex = ifindex;
        req.tc.tcm_parent = tc_parent(direction);
        let sock = NetlinkSocket::open()?;
        sock.send(request_bytes(&req))?;
        let mut filters = Vec::new();
        for msg in sock.recv()? {
            if msg.header.nlmsg_type != libc::RTM_NEWTFILTER {
                continue;
            }
            if let Some(filter) = parse_filter(&msg.data)? {
                filters.push(filter);
            }
        }
        Ok(filters)
    }

    fn parse_filter(data: &[u8]) -> Result<Option<FilterInfo>> {
        let Some((tc_buf, attrs)) = data.split_at_checked(mem::size_of::<TcMsg>()) else {
            return Ok(None);
        };
        // SAFETY: tcmsg payload can be unaligned in the netlink byte buffer.
        let tc: TcMsg = unsafe { ptr::read_unaligned(tc_buf.as_ptr().cast()) };
        let mut kind = String::new();
        let mut name = None;
        let mut prog_id = None;
        for attr in attrs_iter(attrs) {
            let attr = attr?;
            match attr.typ {
                TCA_KIND => kind = cstr_lossy(attr.data),
                TCA_OPTIONS => {
                    for opt in attrs_iter(attr.data) {
                        let opt = opt?;
                        match opt.typ {
                            TCA_BPF_NAME => name = Some(cstr_lossy(opt.data)),
                            TCA_BPF_ID if opt.data.len() >= 4 => {
                                prog_id = Some(u32::from_ne_bytes(opt.data[..4].try_into()?));
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Some(FilterInfo {
            pref: (tc.tcm_info >> 16) as u16,
            handle: tc.tcm_handle,
            kind,
            name,
            prog_id,
        }))
    }

    struct NetlinkSocket {
        fd: OwnedFd,
    }

    impl NetlinkSocket {
        fn open() -> Result<Self> {
            // SAFETY: libc socket call.
            let fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
            if fd < 0 {
                return Err(io::Error::last_os_error()).context("opening netlink route socket");
            }
            // SAFETY: socket returns an owned file descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let enable = 1i32;
            // SAFETY: setsockopt accepts a pointer to `enable` for these integer options.
            unsafe {
                setsockopt(
                    fd.as_raw_fd(),
                    SOL_NETLINK,
                    NETLINK_EXT_ACK,
                    ptr::from_ref(&enable).cast(),
                    mem::size_of_val(&enable) as u32,
                );
                setsockopt(
                    fd.as_raw_fd(),
                    SOL_NETLINK,
                    NETLINK_CAP_ACK,
                    ptr::from_ref(&enable).cast(),
                    mem::size_of_val(&enable) as u32,
                );
                let mut addr: sockaddr_nl = mem::zeroed();
                addr.nl_family = AF_NETLINK as u16;
                if bind(
                    fd.as_raw_fd(),
                    ptr::from_ref(&addr).cast(),
                    mem::size_of::<sockaddr_nl>() as u32,
                ) < 0
                {
                    return Err(io::Error::last_os_error()).context("binding netlink route socket");
                }
                let mut addr_len = mem::size_of::<sockaddr_nl>() as u32;
                if getsockname(
                    fd.as_raw_fd(),
                    ptr::from_mut(&mut addr).cast(),
                    ptr::from_mut(&mut addr_len).cast(),
                ) < 0
                {
                    return Err(io::Error::last_os_error()).context("reading netlink socket name");
                }
            }
            Ok(Self { fd })
        }

        fn send(&self, msg: &[u8]) -> Result<()> {
            // SAFETY: send reads the immutable buffer for the provided length.
            let ret = unsafe { send(self.fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
            if ret < 0 {
                Err(io::Error::last_os_error()).context("sending netlink message")
            } else {
                Ok(())
            }
        }

        fn recv(&self) -> Result<Vec<NetlinkMessage>> {
            let mut messages = Vec::new();
            let mut multipart = true;
            while multipart {
                let mut buf = vec![0u8; 65536];
                // SAFETY: recv writes at most buf.len() bytes into the buffer.
                let len =
                    unsafe { recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
                if len < 0 {
                    return Err(io::Error::last_os_error()).context("receiving netlink message");
                }
                if len == 0 {
                    break;
                }
                let mut offset = 0usize;
                let len = len as usize;
                while offset < len {
                    let Some(msg) = read_message(&buf[offset..len])? else {
                        break;
                    };
                    offset += nlmsg_align(msg.header.nlmsg_len as usize);
                    multipart = msg.header.nlmsg_flags & NLM_F_MULTI as u16 != 0;
                    match msg.header.nlmsg_type {
                        typ if typ == NLMSG_DONE as u16 => return Ok(messages),
                        typ if typ == NLMSG_ERROR as u16 => {
                            if let Some(err) = msg.error {
                                if err.error == 0 {
                                    continue;
                                }
                                let code = -err.error;
                                return Err(io::Error::from_raw_os_error(code))
                                    .context("netlink returned error");
                            }
                        }
                        _ => messages.push(msg),
                    }
                }
            }
            Ok(messages)
        }
    }

    fn send_ack(req: &TcRequest) -> Result<()> {
        let sock = NetlinkSocket::open()?;
        sock.send(request_bytes(req))?;
        for msg in sock.recv()? {
            if msg.header.nlmsg_type == NLMSG_ERROR as u16
                && let Some(err) = msg.error
                && err.error != 0
            {
                let code = -err.error;
                return Err(io::Error::from_raw_os_error(code)).context("netlink returned error");
            }
        }
        Ok(())
    }

    fn read_message(buf: &[u8]) -> Result<Option<NetlinkMessage>> {
        if buf.len() < NLMSG_HDR_LEN {
            return Ok(None);
        }
        // SAFETY: nlmsghdr can be unaligned in the received byte buffer.
        let header: nlmsghdr = unsafe { ptr::read_unaligned(buf.as_ptr().cast()) };
        let msg_len = header.nlmsg_len as usize;
        if msg_len < NLMSG_HDR_LEN || msg_len > buf.len() {
            return Ok(None);
        }
        let data = &buf[nlmsg_align(NLMSG_HDR_LEN)..msg_len];
        let (data, error) = if header.nlmsg_type == NLMSG_ERROR as u16 {
            if data.len() < mem::size_of::<nlmsgerr>() {
                (data.to_vec(), None)
            } else {
                // SAFETY: nlmsgerr can be unaligned in the received byte buffer.
                let err: nlmsgerr = unsafe { ptr::read_unaligned(data.as_ptr().cast()) };
                (data[mem::size_of::<nlmsgerr>()..].to_vec(), Some(err))
            }
        } else {
            (data.to_vec(), None)
        };
        Ok(Some(NetlinkMessage {
            header,
            data,
            error,
        }))
    }

    fn request_bytes(req: &TcRequest) -> &[u8] {
        // SAFETY: TcRequest is repr(C) and we only expose the populated nlmsg_len prefix.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (req as *const TcRequest).cast::<u8>(),
                mem::size_of::<TcRequest>(),
            )
        };
        &bytes[..req.header.nlmsg_len as usize]
    }

    fn append_attr_bytes(req: &mut TcRequest, typ: u16, value: &[u8]) -> Result<()> {
        let offset = nlmsg_align(req.header.nlmsg_len as usize);
        let attr_len = NLA_HDR_LEN + value.len();
        let padded = nla_align(attr_len);
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                (req as *mut TcRequest).cast::<u8>(),
                mem::size_of::<TcRequest>(),
            )
        };
        if offset + padded > bytes.len() {
            anyhow::bail!("netlink request attribute buffer is too small");
        }
        let attr = nlattr {
            nla_len: attr_len as u16,
            nla_type: typ,
        };
        // SAFETY: destination has enough bytes and accepts unaligned writes.
        unsafe {
            ptr::write_unaligned(bytes[offset..].as_mut_ptr().cast::<nlattr>(), attr);
        }
        let start = offset + NLA_HDR_LEN;
        bytes[start..start + value.len()].copy_from_slice(value);
        req.header.nlmsg_len = (offset + padded) as u32;
        Ok(())
    }

    fn attrs_iter(mut data: &[u8]) -> impl Iterator<Item = Result<Attr<'_>>> {
        std::iter::from_fn(move || {
            if data.is_empty() {
                return None;
            }
            if data.len() < NLA_HDR_LEN {
                return Some(Err(anyhow::anyhow!("netlink attr buffer too small")));
            }
            // SAFETY: nlattr can be unaligned in the netlink byte buffer.
            let header: nlattr = unsafe { ptr::read_unaligned(data.as_ptr().cast()) };
            let len = header.nla_len as usize;
            if len < NLA_HDR_LEN || len > data.len() {
                return Some(Err(anyhow::anyhow!("invalid netlink attr length {len}")));
            }
            let payload_len = len - NLA_HDR_LEN;
            let payload = &data[NLA_HDR_LEN..NLA_HDR_LEN + payload_len];
            let padded = nla_align(len);
            data = if padded <= data.len() {
                &data[padded..]
            } else {
                &[]
            };
            Some(Ok(Attr {
                typ: header.nla_type & !(NLA_F_NESTED as u16) & NLA_TYPE_MASK as u16,
                data: payload,
            }))
        })
    }

    fn cstr_lossy(data: &[u8]) -> String {
        CStr::from_bytes_with_nul(data)
            .map(|v| v.to_string_lossy().to_string())
            .unwrap_or_else(|_| {
                String::from_utf8_lossy(data)
                    .trim_end_matches('\0')
                    .to_string()
            })
    }

    const fn tc_handler_make(major: u32, minor: u32) -> u32 {
        (major & TC_H_MAJ_MASK) | (minor & TC_H_MIN_MASK)
    }

    const fn tc_parent(direction: Direction) -> u32 {
        match direction {
            Direction::Ingress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_INGRESS),
            Direction::Egress => tc_handler_make(TC_H_CLSACT, TC_H_MIN_EGRESS),
        }
    }

    const fn nlmsg_align(len: usize) -> usize {
        (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
    }

    const fn nla_align(len: usize) -> usize {
        (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use anyhow::Result;

    use super::FilterInfo;

    pub fn add_clsact(_dev: &str) -> Result<()> {
        anyhow::bail!("TC netlink is only available on Linux")
    }

    pub fn delete_clsact(_dev: &str) -> Result<()> {
        anyhow::bail!("TC netlink is only available on Linux")
    }

    pub fn delete_pref(_dev: &str, _direction: super::Direction, _pref: u16) -> Result<()> {
        anyhow::bail!("TC netlink is only available on Linux")
    }

    pub fn dump_filters(_dev: &str, _direction: super::Direction) -> Result<Vec<FilterInfo>> {
        anyhow::bail!("TC netlink is only available on Linux")
    }
}
