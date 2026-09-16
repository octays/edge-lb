//! Host policy observations for conservative automatic redirect admission.

use std::{collections::BTreeSet, fs, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use aya::{
    maps::MapData,
    programs::{ProgramError, SchedClassifier, TcAttachType, loaded_programs},
    util::KernelVersion,
};
use futures_util::StreamExt;
use rtnetlink::{
    packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload},
    packet_route::{
        RouteNetlinkMessage,
        tc::{TcAttribute, TcHandle, TcMessage, TcOption},
    },
    packet_utils::{
        nla::{Nla, NlasIterator},
        parsers::parse_u32,
    },
};

use super::{
    kernel_policy::{KernelPolicyState, observe_kernel_policy},
    netlink::observe_routing_policy,
    policy::RoutingPolicyState,
};

pub(super) fn check_host(ingress: &str) -> Result<()> {
    super::netlink::check_ingress_and_route_context(ingress)?;
    check_network_policy(ingress)
}

pub(super) fn check_network_policy(ingress: &str) -> Result<()> {
    ensure!(
        observe_routing_policy()? == RoutingPolicyState::StandardRules,
        "nonstandard routing rules"
    );
    ensure!(
        observe_kernel_policy()? == KernelPolicyState::Clear,
        "netfilter/XFRM policy present"
    );
    ensure!(
        read_sysctl("/proc/sys/net/ipv4/ip_forward")? == 1,
        "IPv4 forwarding disabled"
    );
    ensure!(
        read_sysctl(&format!("/proc/sys/net/ipv4/conf/{ingress}/forwarding"))? == 1,
        "ingress IPv4 forwarding disabled"
    );
    // Reverse path validation is not replicated in the destination route cache.
    for dev in ["all", ingress] {
        ensure!(
            read_sysctl(&format!("/proc/sys/net/ipv4/conf/{dev}/rp_filter"))? == 0,
            "rp_filter requires kernel path"
        );
    }
    // LSM/XFRM security labels are not part of the initial admission contract.
    let lsms =
        fs::read_to_string("/sys/kernel/security/lsm").context("LSM inventory unavailable")?;
    ensure!(
        lsms.split(',').all(|name| matches!(
            name.trim(),
            "capability" | "landlock" | "lockdown" | "yama" | "integrity" | "apparmor"
        )),
        "unsupported network security module"
    );
    Ok(())
}

pub(super) fn read_sysctl(path: &str) -> Result<u32> {
    fs::read_to_string(path)
        .with_context(|| format!("reading {path}"))?
        .trim()
        .parse()
        .with_context(|| format!("parsing {path}"))
}

/// Only our DSCP marker and forward classifier may be on ingress. Check
/// program map identities, not just names that an unrelated program can share.
pub(super) fn check_tc(
    ingress_index: u32,
    outputs: &BTreeSet<u32>,
    pref: u16,
    pin: &Path,
    marker_pin: &Path,
) -> Result<()> {
    check_tcx(ingress_index, TcAttachType::Ingress)?;
    let route_id = MapData::from_pin(pin)?.info()?.id();
    let marker_id = MapData::from_pin(marker_pin)?.info()?.id();
    let filters = read_filters(ingress_index, TcHandle::MIN_INGRESS)?;
    let programs = ingress_programs(&filters, 2)?;
    let mut expected = Vec::new();
    for filter in programs {
        ensure!(
            filter.header.info as u16 == (libc::ETH_P_ALL as u16).to_be(),
            "TC protocol selector dependency"
        );
        let priority = (filter.header.info >> 16) as u16;
        let map_id = if priority == pref {
            marker_id
        } else {
            ensure!(
                Some(priority) == pref.checked_add(10),
                "unexpected TC priority"
            );
            route_id
        };
        expected.push((bpf_id(filter)?, map_id));
    }
    ensure!(expected[0].1 != expected[1].1, "duplicate ingress priority");
    check_program_maps(expected)?;
    check_outputs(outputs)
}

pub(super) fn check_return_tc(
    ingress_index: u32,
    outputs: &BTreeSet<u32>,
    priority: u16,
    pin: &Path,
) -> Result<()> {
    check_tcx(ingress_index, TcAttachType::Ingress)?;
    let filters = read_filters(ingress_index, TcHandle::MIN_INGRESS)?;
    let programs = ingress_programs(&filters, 1)?;
    let filter = programs[0];
    ensure!(
        filter.header.info as u16 == (libc::ETH_P_ALL as u16).to_be()
            && (filter.header.info >> 16) as u16 == priority,
        "unexpected return TC selector/priority"
    );
    check_program_maps(vec![(
        bpf_id(filter)?,
        MapData::from_pin(pin)?.info()?.id(),
    )])?;
    check_outputs(outputs)
}

fn check_program_maps(mut expected: Vec<(u32, u32)>) -> Result<()> {
    for info in loaded_programs() {
        let info = info?;
        if let Some(index) = expected.iter().position(|(id, _)| *id == info.id()) {
            let maps = info.map_ids()?.context("program map IDs unavailable")?;
            ensure!(
                maps.contains(&expected[index].1),
                "TC program does not own expected map"
            );
            expected.swap_remove(index);
        }
        if expected.is_empty() {
            break;
        }
    }
    ensure!(expected.is_empty(), "TC program disappeared");
    Ok(())
}

fn check_outputs(outputs: &BTreeSet<u32>) -> Result<()> {
    for output in outputs {
        check_tcx(*output, TcAttachType::Egress)?;
        ensure!(
            read_filters(*output, TcHandle::MIN_EGRESS)?.is_empty(),
            "egress TC dependency"
        );
    }
    Ok(())
}

fn check_tcx(index: u32, attach: TcAttachType) -> Result<()> {
    let mut name = [0u8; libc::IFNAMSIZ];
    // SAFETY: the buffer is IF_NAMESIZE bytes and remains live through CStr use.
    ensure!(
        !unsafe { libc::if_indextoname(index, name.as_mut_ptr().cast()) }.is_null(),
        "TCX interface disappeared"
    );
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr().cast()) }.to_str()?;
    match SchedClassifier::query_tcx(name, attach) {
        Ok((_, programs)) => ensure!(programs.is_empty(), "TCX program dependency"),
        Err(ProgramError::SyscallError(error))
            if error.io_error.raw_os_error() == Some(libc::EINVAL)
                && KernelVersion::current().map_err(|error| anyhow::anyhow!("{error}"))?
                    < KernelVersion::new(6, 6, 0) => {}
        Err(error) => return Err(error).context("querying TCX programs"),
    }
    Ok(())
}

fn ingress_programs(filters: &[TcMessage], count: usize) -> Result<Vec<&TcMessage>> {
    // RTM_GETTFILTER dumps one handle-zero classifier summary before its
    // concrete filters. Account for both, without hiding foreign classifiers.
    let mut summaries = BTreeSet::new();
    let mut programs = Vec::new();
    for filter in filters {
        if filter.header.handle == TcHandle::from(0) {
            ensure!(
                filter.attributes.iter().all(|attr| matches!(
                    attr, TcAttribute::Kind(kind) if kind == "bpf"
                ) || matches!(attr, TcAttribute::Chain(0))),
                "unexpected TC summary"
            );
            ensure!(summaries.insert(filter.header.info), "duplicate TC summary");
        } else {
            programs.push(filter);
        }
    }
    ensure!(
        summaries.len() == count && programs.len() == count,
        "foreign or missing ingress TC filters"
    );
    for program in &programs {
        ensure!(
            summaries.remove(&program.header.info),
            "TC summary/filter mismatch"
        );
    }
    Ok(programs)
}

fn bpf_id(filter: &TcMessage) -> Result<u32> {
    let mut id = None;
    let mut flags = None;
    ensure!(
        filter
            .attributes
            .iter()
            .any(|attr| matches!(attr, TcAttribute::Kind(kind) if kind == "bpf")),
        "non-BPF TC filter"
    );
    for attr in &filter.attributes {
        match attr {
            TcAttribute::Chain(chain) => ensure!(*chain == 0, "TC chain dependency"),
            TcAttribute::Options(options) => {
                for option in options {
                    let TcOption::Other(raw) = option else {
                        anyhow::bail!("unexpected BPF options");
                    };
                    // rtnetlink retains unknown classifier options as one NLA.
                    let mut bytes = vec![0; raw.value_len()];
                    raw.emit_value(&mut bytes);
                    for nla in NlasIterator::new(&bytes) {
                        let nla = nla?;
                        match nla.kind() {
                            8 => flags = Some(parse_u32(nla.value())?), // TCA_BPF_FLAGS
                            11 => id = Some(parse_u32(nla.value())?),   // TCA_BPF_ID
                            9 => ensure!(
                                parse_u32(nla.value())? & !0x0d == 0,
                                "TC offload-only/unknown flags"
                            ),
                            3 => ensure!(parse_u32(nla.value())? == 0, "TC class dependency"),
                            1 | 2 => anyhow::bail!("TC action/police dependency"),
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
    ensure!(flags == Some(1), "TC requires direct-action mode");
    id.context("BPF program ID missing")
}

fn read_filters(index: u32, parent: u16) -> Result<Vec<TcMessage>> {
    super::super::net::run_netlink(async move {
        tokio::time::timeout(Duration::from_millis(500), async move {
            let (connection, mut handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(connection);
            let mut message = TcMessage::default();
            message.header.index = i32::try_from(index)?;
            message.header.parent = TcHandle {
                major: u16::MAX,
                minor: parent,
            };
            let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetTrafficFilter(message));
            request.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
            let mut stream = handle.request(request)?;
            let mut filters = Vec::new();
            while let Some(message) = stream.next().await {
                ensure!(
                    message.header.flags & rtnetlink::packet_core::NLM_F_DUMP_INTR == 0,
                    "TC dump interrupted"
                );
                match message.payload {
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewTrafficFilter(filter)) => {
                        filters.push(filter)
                    }
                    NetlinkPayload::Done(done) => ensure!(done.code == 0, "TC dump failed"),
                    NetlinkPayload::Error(error) => anyhow::bail!("TC query: {}", error.to_io()),
                    _ => anyhow::bail!("unexpected TC query reply"),
                }
            }
            Ok(filters)
        })
        .await
        .context("TC observation timed out")?
    })
}
