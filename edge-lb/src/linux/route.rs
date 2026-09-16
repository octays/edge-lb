//! Backend policy routing via rtnetlink.

use std::{
    collections::BTreeMap,
    ffi::CString,
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, RawFd},
};

use anyhow::{Context, Result, bail};

use serde::{Deserialize, Serialize};

use crate::config::Config;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;

const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;

const RTN_UNICAST: u8 = 1;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;

const FR_ACT_TO_TBL: u8 = 1;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_SUPPRESS_IFGROUP: u16 = 13;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_PROTOCOL: u16 = 21;

const EDGE_DSCP_LIMIT: u32 = 63;
const RULE_BAND: u32 = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FibRuleHdr {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    res1: u8,
    res2: u8,
    action: u8,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgErr {
    error: i32,
}

pub fn ensure_policy_routing(cfg: &Config) -> Result<()> {
    let _lock = ownership_lock(cfg)?;
    let mut ownership = RouteOwnership::load()?;
    let local = cfg.local_backend()?;
    let vxlan_ifindex = ifindex(&cfg.network().vxlan_dev)?;
    let underlay_ifindex = ifindex(&cfg.network().underlay_dev)?;

    let routes = return_routes(cfg)?;
    let fd = socket()?;
    let result = reconcile_on_socket(
        fd,
        cfg,
        &routes,
        &mut ownership,
        vxlan_ifindex,
        underlay_ifindex,
        local.underlay_ip,
    );
    unsafe {
        libc::close(fd);
    }
    result
}

pub fn policy_rule_present(cfg: &Config) -> bool {
    let Ok(desired) = return_routes(cfg) else {
        return false;
    };
    let Ok(ownership) = RouteOwnership::load() else {
        return false;
    };
    let Ok(fd) = socket() else {
        return false;
    };
    let present = dump_policy_rules_on_socket(fd).is_ok_and(|rules| {
        desired.iter().all(|route| {
            rules.iter().any(|rule| {
                ownership.owns_rule(rule)
                    && rule.mark == Some(route.mark)
                    && rule.mask == Some(u32::MAX)
                    && rule.table == route.table
            })
        })
    });
    unsafe { libc::close(fd) };
    present
}

/// Human-readable snapshots for diagnostics and preflight checks. The data is
/// obtained from the same rtnetlink dumps used by reconciliation.
pub fn route_descriptions(cfg: &Config, table: u32) -> Result<Vec<String>> {
    let fd = socket()?;
    let result = dump_routes_in_table_on_socket(fd, table).map(|routes| {
        routes
            .iter()
            .map(|route| route.describe(&cfg.network().vxlan_dev, &cfg.network().underlay_dev))
            .collect()
    });
    unsafe { libc::close(fd) };
    result
}

/// Ownership is local to this boot and network namespace, never HA-replicated.
/// Save only after an acknowledged create. A crash before the save can leave an
/// unclaimed object, which is deliberately refused rather than adopted.
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RouteOwnership {
    scope: String,
    rules: Vec<PolicyRule>,
    routes: Vec<RouteEntry>,
}

impl RouteOwnership {
    fn load() -> Result<Self> {
        let scope = format!(
            "{}:{}",
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
            std::fs::read_link("/proc/thread-self/ns/net")?.display()
        );
        let stored = crate::storage::repository()?.get("route_ownership", "local")?;
        Self::decode(stored.as_deref(), scope)
    }

    fn decode(payload: Option<&str>, scope: String) -> Result<Self> {
        let stored: Self = payload
            .map(serde_json::from_str)
            .transpose()
            .context("parsing route ownership")?
            .unwrap_or_default();
        if stored.scope == scope {
            Ok(stored)
        } else {
            Ok(Self {
                scope,
                ..Self::default()
            })
        }
    }

    fn save(&self) -> Result<()> {
        crate::storage::repository()?.put(
            "route_ownership",
            "local",
            crate::storage::next_revision(),
            serde_json::to_string(self)?,
        )
    }

    fn owns_rule(&self, rule: &PolicyRule) -> bool {
        rule.supported && self.rules.contains(rule)
    }

    fn owns_route(&self, route: &RouteEntry) -> bool {
        route.supported && self.routes.contains(route)
    }
}

fn ownership_lock(cfg: &Config) -> Result<std::fs::File> {
    std::fs::create_dir_all(&cfg.state_dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(cfg.state_dir.join("route-ownership.lock"))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error()).context("locking route ownership");
    }
    Ok(file)
}

fn validate_rules(
    rules: &[PolicyRule],
    desired: &[ReturnRoute],
    ownership: &RouteOwnership,
) -> Result<()> {
    for rule in rules {
        if ownership.owns_rule(rule) {
            continue;
        }
        for want in desired {
            // Unmarked rules (e.g. lookup local/main) are not fwmark claims.
            let matches_mark = rule.mark.is_some_and(|mark| {
                let mask = rule.mask.unwrap_or(u32::MAX);
                want.mark & mask == mark & mask
            });
            if rule.table == want.table || matches_mark {
                bail!(
                    "unowned policy rule conflicts with return path: pref {} mark {:?}/{:?} table {}",
                    rule.priority,
                    rule.mark,
                    rule.mask,
                    rule.table
                );
            }
        }
    }
    Ok(())
}

fn validate_table(current: &[RouteEntry], ownership: &RouteOwnership) -> Result<()> {
    for entry in current {
        if !ownership.owns_route(entry) {
            bail!(
                "return table contains unowned route: {}",
                entry.describe("", "")
            );
        }
    }
    Ok(())
}

pub(super) fn ownership_conflicts(cfg: &Config) -> Result<Vec<super::conflict::NodeConflict>> {
    let _lock = ownership_lock(cfg)?;
    let ownership = RouteOwnership::load()?;
    let desired = return_routes(cfg)?;
    let fd = socket()?;
    let result = (|| {
        let mut conflicts = Vec::new();
        let rules = dump_policy_rules_on_socket(fd)?;
        for rule in &rules {
            if let Err(error) = validate_rules(std::slice::from_ref(rule), &desired, &ownership) {
                conflicts.push(super::conflict::NodeConflict::warning(
                    "route_rule",
                    format!("priority {}", rule.priority),
                    error.to_string(),
                ));
            }
        }
        let mut tables = std::collections::BTreeSet::new();
        for route in &desired {
            if tables.insert(route.table) {
                for entry in dump_routes_in_table_on_socket(fd, route.table)? {
                    if let Err(error) = validate_table(std::slice::from_ref(&entry), &ownership) {
                        conflicts.push(super::conflict::NodeConflict::warning(
                            "route_table",
                            format!("table {}", route.table),
                            error.to_string(),
                        ));
                    }
                }
            }
        }
        Ok(conflicts)
    })();
    unsafe { libc::close(fd) };
    result
}

#[allow(clippy::too_many_arguments)]
fn reconcile_on_socket(
    fd: RawFd,
    cfg: &Config,
    routes: &[ReturnRoute],
    ownership: &mut RouteOwnership,
    vxlan_ifindex: u32,
    underlay_ifindex: u32,
    local_underlay: IpAddr,
) -> Result<()> {
    let mut rules = dump_policy_rules_on_socket(fd).context("dumping policy rules")?;
    validate_rules(&rules, routes, ownership)?;
    let mut tables = BTreeMap::new();
    for table in routes
        .iter()
        .map(|route| route.table)
        .chain(ownership.routes.iter().map(|route| route.table))
    {
        if let std::collections::btree_map::Entry::Vacant(entry) = tables.entry(table) {
            entry.insert(dump_routes_in_table_on_socket(fd, table)?);
        }
    }
    // Validate every desired table before the first mutation, including when an
    // expected-looking route already exists without a creation record.
    for route in routes {
        if route.table == 0 || (253..=255).contains(&route.table) {
            bail!("return route cannot use reserved table {}", route.table);
        }
        if routes
            .iter()
            .any(|other| other.mark == route.mark && other.table != route.table)
        {
            bail!("return mark 0x{:x} selects multiple tables", route.mark);
        }
        validate_table(&tables[&route.table], ownership)?;
    }
    let mut expected = Vec::new();
    for route in routes {
        if routes.iter().any(|other| {
            other.table == route.table && other.gateway_overlay != route.gateway_overlay
        }) {
            bail!(
                "multiple gateways would own default route in table {}",
                route.table
            );
        }
        for entry in
            expected_table_entries(cfg, route, vxlan_ifindex, underlay_ifindex, local_underlay)
        {
            if !expected.contains(&entry) {
                expected.push(entry);
            }
        }
    }
    let old = ownership.clone();
    ownership.rules.retain(|rule| rules.contains(rule));
    ownership.routes.retain(|route| {
        tables
            .get(&route.table)
            .is_some_and(|entries| entries.contains(route))
    });
    if *ownership != old {
        ownership.save()?;
    }

    for rule in ownership.rules.clone() {
        if !routes.iter().any(|route| {
            rule.mark == Some(route.mark)
                && rule.mask == Some(u32::MAX)
                && rule.table == route.table
        }) {
            delete_policy_rule_on_socket(fd, &rule)?;
            ownership.rules.retain(|value| value != &rule);
            ownership.save()?;
            rules.retain(|value| value != &rule);
        }
    }
    for entry in ownership.routes.clone() {
        if !expected.contains(&entry) {
            match delete_route_entry_on_socket(fd, &entry) {
                Ok(()) => (),
                Err(error) if is_absent_route_error(&error) => (),
                Err(error) => return Err(error),
            }
            ownership.routes.retain(|value| value != &entry);
            ownership.save()?;
        }
    }
    for want in expected {
        if !ownership.routes.contains(&want) {
            // EXCL prevents overwriting a foreign route added after the dump.
            add_route_exclusive_on_socket(fd, &want)?;
            ownership.routes.push(want);
            ownership.save()?;
        }
    }
    for route in routes {
        if rules.iter().any(|rule| {
            ownership.owns_rule(rule)
                && rule.mark == Some(route.mark)
                && rule.mask == Some(u32::MAX)
                && rule.table == route.table
        }) {
            continue;
        }
        let rule = ensure_rule_at_or_after_on_socket(
            fd,
            cfg.backend_cfg().rule_priority,
            route.mark,
            u32::MAX,
            route.table,
            &rules,
        )?;
        ownership.rules.push(rule.clone());
        ownership.save()?;
        rules.push(rule);
    }
    Ok(())
}

pub fn cleanup_policy_routing(cfg: &Config) {
    let result = (|| -> Result<()> {
        let _lock = ownership_lock(cfg)?;
        let mut ownership = RouteOwnership::load()?;
        let fd = socket()?;
        // Cleanup uses recorded identities, so deleted/renamed devices and
        // removed gateways do not prevent clearing surviving owned objects.
        let result = reconcile_on_socket(
            fd,
            cfg,
            &[],
            &mut ownership,
            0,
            0,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        );
        unsafe { libc::close(fd) };
        result
    })();
    if let Err(error) = result {
        tracing::warn!("[route] policy routing cleanup incomplete: {error:#}");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReturnRoute {
    gateway_underlay: IpAddr,
    gateway_overlay: IpAddr,
    mark: u32,
    table: u32,
}

fn return_routes(cfg: &Config) -> Result<Vec<ReturnRoute>> {
    let mut routes = Vec::new();
    for path in cfg.backend_return_paths() {
        let dscp = path.dscp;
        if dscp > EDGE_DSCP_LIMIT {
            bail!(
                "gateway return path has dscp {dscp} outside 0..=63; \
                 the nft match would silently degrade",
            );
        }
        routes.push(ReturnRoute {
            gateway_underlay: path.gateway_underlay_ip,
            gateway_overlay: path.gateway_overlay_ip,
            mark: path.mark,
            table: path.route_table_id,
        });
    }
    routes.sort_by_key(|route| {
        (
            ip_sort_key(route.gateway_underlay),
            ip_sort_key(route.gateway_overlay),
            route.mark,
            route.table,
        )
    });
    routes.dedup();
    Ok(routes)
}

fn ip_sort_key(ip: IpAddr) -> (u8, u128) {
    match ip {
        IpAddr::V4(ip) => (4, u32::from_be_bytes(ip.octets()) as u128),
        IpAddr::V6(ip) => (6, u128::from(ip)),
    }
}

/// Entries a converged return table must hold: one default via the owning
/// gateway's overlay plus a host route per gateway underlay (so VXLAN outer
/// packets never recurse into the tunnel).
fn expected_table_entries(
    cfg: &Config,
    route: &ReturnRoute,
    vxlan_ifindex: u32,
    underlay_ifindex: u32,
    local_underlay: IpAddr,
) -> Vec<RouteEntry> {
    let mut entries = vec![default_entry(
        route.table,
        route.gateway_overlay,
        vxlan_ifindex,
    )];
    for gw in &cfg.gateway_nodes {
        entries.push(host_entry(
            route.table,
            gw.underlay_ip,
            underlay_ifindex,
            local_underlay,
        ));
    }
    entries
}

fn default_entry(table: u32, gateway_overlay: IpAddr, oif: u32) -> RouteEntry {
    RouteEntry {
        supported: true,
        family: family(gateway_overlay),
        table,
        dst_len: 0,
        dst: None,
        gateway: Some(gateway_overlay),
        oif: Some(oif),
        prefsrc: None,
    }
}

fn host_entry(table: u32, dst: IpAddr, oif: u32, preferred_src: IpAddr) -> RouteEntry {
    RouteEntry {
        supported: true,
        family: family(dst),
        table,
        dst_len: prefix_len(dst),
        dst: Some(dst),
        gateway: None,
        oif: Some(oif),
        prefsrc: Some(preferred_src),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RouteEntry {
    supported: bool,
    family: u8,
    table: u32,
    dst_len: u8,
    dst: Option<IpAddr>,
    gateway: Option<IpAddr>,
    oif: Option<u32>,
    prefsrc: Option<IpAddr>,
}

impl RouteEntry {
    fn describe(&self, vxlan_dev: &str, underlay_dev: &str) -> String {
        let dst = self
            .dst
            .map(|ip| format!("{ip}/{}", self.dst_len))
            .unwrap_or_else(|| "default".to_string());
        let gateway = self
            .gateway
            .map(|ip| format!(" via {ip}"))
            .unwrap_or_default();
        let oif = self.oif.map(|index| {
            let dev = if Some(index) == ifindex(vxlan_dev).ok() {
                vxlan_dev
            } else if Some(index) == ifindex(underlay_dev).ok() {
                underlay_dev
            } else {
                "ifindex"
            };
            format!(" dev {dev}({index})")
        });
        let prefsrc = self
            .prefsrc
            .map(|ip| format!(" src {ip}"))
            .unwrap_or_default();
        format!(
            "{dst}{gateway}{}{} table {}",
            oif.unwrap_or_default(),
            prefsrc,
            self.table
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PolicyRule {
    supported: bool,
    protocol: u8,
    priority: u32,
    mark: Option<u32>,
    mask: Option<u32>,
    table: u32,
}

fn ensure_rule_at_or_after_on_socket(
    fd: RawFd,
    start: u32,
    mark: u32,
    mask: u32,
    table: u32,
    rules: &[PolicyRule],
) -> Result<PolicyRule> {
    for offset in 0..RULE_BAND {
        let Some(priority) = start.checked_add(offset) else {
            break;
        };
        if rules.iter().any(|rule| rule.priority == priority) {
            continue;
        }
        match send_ack_on_socket(
            fd,
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            rule_body(mark, mask, priority, table),
        ) {
            Ok(()) => {
                return Ok(PolicyRule {
                    supported: true,
                    protocol: RTPROT_STATIC,
                    priority,
                    mark: Some(mark),
                    mask: Some(mask),
                    table,
                });
            }
            Err(e) if is_errno(&e, libc::EEXIST) => continue,
            Err(e) => return Err(e),
        }
    }
    bail!("no free policy-rule priority within {RULE_BAND} slots after {start}");
}

fn delete_policy_rule_on_socket(fd: RawFd, rule: &PolicyRule) -> Result<()> {
    let matches: Vec<_> = dump_policy_rules_on_socket(fd)?
        .into_iter()
        .filter(|value| {
            value.priority == rule.priority
                && value.mark == rule.mark
                && value.mask == rule.mask
                && value.table == rule.table
                && value.protocol == rule.protocol
        })
        .collect();
    if matches.is_empty() {
        return Ok(());
    }
    if matches.len() != 1 || matches[0] != *rule {
        bail!(
            "refusing ambiguous policy rule deletion at priority {}",
            rule.priority
        );
    }
    let mut body = bytes_of(&FibRuleHdr {
        family: libc::AF_INET as u8,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: table_field(rule.table),
        res1: 0,
        res2: 0,
        action: FR_ACT_TO_TBL,
        flags: 0,
    });
    push_attr_u32(&mut body, FRA_PRIORITY, rule.priority);
    push_attr_u32(&mut body, FRA_TABLE, rule.table);
    push_attr(&mut body, FRA_PROTOCOL, &[rule.protocol]);
    if let Some(mark) = rule.mark {
        push_attr_u32(&mut body, FRA_FWMARK, mark);
    }
    if let Some(mask) = rule.mask {
        push_attr_u32(&mut body, FRA_FWMASK, mask);
    }
    match send_ack_on_socket(fd, RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, body) {
        Err(error) if is_absent_route_error(&error) => Ok(()),
        result => result,
    }
}

fn rule_body(mark: u32, mask: u32, priority: u32, table: u32) -> Vec<u8> {
    let mut body = bytes_of(&FibRuleHdr {
        family: libc::AF_INET as u8,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: table_field(table),
        res1: 0,
        res2: 0,
        action: FR_ACT_TO_TBL,
        flags: 0,
    });
    push_attr_u32(&mut body, FRA_PRIORITY, priority);
    push_attr_u32(&mut body, FRA_FWMARK, mark);
    push_attr_u32(&mut body, FRA_FWMASK, mask);
    push_attr_u32(&mut body, FRA_TABLE, table);
    push_attr(&mut body, FRA_PROTOCOL, &[RTPROT_STATIC]);
    body
}

fn add_route_exclusive_on_socket(fd: RawFd, entry: &RouteEntry) -> Result<()> {
    let scope = if entry.dst_len == 0 {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };
    let mut body = route_body(entry.table, entry.family, entry.dst_len, scope);
    if let Some(dst) = entry.dst {
        push_attr_ip(&mut body, RTA_DST, dst);
    }
    if let Some(oif) = entry.oif {
        push_attr_u32(&mut body, RTA_OIF, oif);
    }
    if let Some(gateway) = entry.gateway {
        push_attr_ip(&mut body, RTA_GATEWAY, gateway);
    }
    if let Some(prefsrc) = entry.prefsrc {
        push_attr_ip(&mut body, RTA_PREFSRC, prefsrc);
    }
    push_attr_u32(&mut body, RTA_TABLE, entry.table);
    // Never replace an object that appeared after our ownership check.
    send_ack_on_socket(
        fd,
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        body,
    )
}

fn delete_route_entry_on_socket(fd: RawFd, entry: &RouteEntry) -> Result<()> {
    let matches: Vec<_> = dump_routes_in_table_on_socket(fd, entry.table)?
        .into_iter()
        .filter(|value| {
            value.family == entry.family
                && value.dst_len == entry.dst_len
                && value.dst == entry.dst
                && value.gateway == entry.gateway
                && value.oif == entry.oif
                && value.prefsrc == entry.prefsrc
        })
        .collect();
    if matches.is_empty() {
        return Ok(());
    }
    if matches.len() != 1 || matches[0] != *entry {
        bail!("refusing ambiguous route deletion in table {}", entry.table);
    }
    let scope = if entry.dst_len == 0 {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };
    let mut body = route_body(entry.table, entry.family, entry.dst_len, scope);
    if let Some(dst) = entry.dst {
        push_attr_ip(&mut body, RTA_DST, dst);
    }
    if let Some(oif) = entry.oif {
        push_attr_u32(&mut body, RTA_OIF, oif);
    }
    if let Some(gateway) = entry.gateway {
        push_attr_ip(&mut body, RTA_GATEWAY, gateway);
    }
    if let Some(prefsrc) = entry.prefsrc {
        push_attr_ip(&mut body, RTA_PREFSRC, prefsrc);
    }
    push_attr_u32(&mut body, RTA_TABLE, entry.table);
    send_ack_on_socket(fd, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, body)
}

fn dump_policy_rules_on_socket(fd: RawFd) -> Result<Vec<PolicyRule>> {
    let seq = 1;
    let body = bytes_of(&FibRuleHdr {
        family: libc::AF_UNSPEC as u8,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: 0,
        res1: 0,
        res2: 0,
        action: FR_ACT_TO_TBL,
        flags: 0,
    });
    send_netlink_on_socket(fd, RTM_GETRULE, NLM_F_REQUEST | NLM_F_DUMP, body, seq)?;
    read_rule_dump(fd, seq)
}

fn read_rule_dump(fd: RawFd, seq: u32) -> Result<Vec<PolicyRule>> {
    let mut rules = Vec::new();
    let mut buf = vec![0u8; 32768];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_TRUNC) };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("reading rtnetlink rule dump");
        }
        let mut offset = 0usize;
        let n = n as usize;
        if n > buf.len() {
            bail!("truncated rtnetlink rule dump");
        }
        while offset + size_of::<NlMsghdr>() <= n {
            let hdr = read_struct::<NlMsghdr>(&buf[offset..])?;
            if (hdr.nlmsg_len as usize) < size_of::<NlMsghdr>()
                || offset + hdr.nlmsg_len as usize > n
            {
                bail!("short rtnetlink rule dump");
            }
            if hdr.nlmsg_seq != seq {
                offset += align(hdr.nlmsg_len as usize);
                continue;
            }
            if hdr.nlmsg_flags & NLM_F_DUMP_INTR != 0 {
                bail!("rtnetlink rule dump interrupted; refusing incomplete ownership snapshot");
            }
            let start = offset + size_of::<NlMsghdr>();
            let end = offset + hdr.nlmsg_len as usize;
            match hdr.nlmsg_type {
                NLMSG_DONE => return Ok(rules),
                NLMSG_ERROR => {
                    let err = read_struct::<NlMsgErr>(&buf[start..])?.error;
                    if err == 0 {
                        return Ok(rules);
                    }
                    return Err(io::Error::from_raw_os_error(-err))
                        .context("rtnetlink rule dump failed");
                }
                RTM_NEWRULE => {
                    if let Some(rule) = parse_policy_rule(&buf[start..end]) {
                        rules.push(rule);
                    }
                }
                _ => {}
            }
            offset += align(hdr.nlmsg_len as usize);
        }
    }
}

fn parse_policy_rule(data: &[u8]) -> Option<PolicyRule> {
    if data.len() < size_of::<FibRuleHdr>() {
        return None;
    }
    let msg = read_struct::<FibRuleHdr>(data).ok()?;
    if msg.family != libc::AF_INET as u8 {
        return None;
    }
    let mut rule = PolicyRule {
        supported: msg.action == FR_ACT_TO_TBL
            && msg.dst_len == 0
            && msg.src_len == 0
            && msg.tos == 0
            && msg.flags == 0,
        protocol: 0,
        priority: 0,
        mark: None,
        mask: None,
        table: msg.table as u32,
    };
    let mut offset = align(size_of::<FibRuleHdr>());
    while offset + size_of::<RtAttr>() <= data.len() {
        let Ok(attr) = read_struct::<RtAttr>(&data[offset..]) else {
            return None;
        };
        let len = attr.rta_len as usize;
        if len < size_of::<RtAttr>() || offset + len > data.len() {
            return None;
        }
        let payload = &data[offset + size_of::<RtAttr>()..offset + len];
        match attr.rta_type {
            FRA_PRIORITY => rule.priority = parse_u32_attr(payload)?,
            FRA_FWMARK => rule.mark = parse_u32_attr(payload),
            FRA_FWMASK => rule.mask = parse_u32_attr(payload),
            FRA_TABLE => {
                if let Some(table) = parse_u32_attr(payload) {
                    rule.table = table;
                }
            }
            FRA_PROTOCOL => rule.protocol = *payload.first()?,
            FRA_SUPPRESS_IFGROUP | FRA_SUPPRESS_PREFIXLEN
                if parse_u32_attr(payload) == Some(u32::MAX) => {}
            _ => rule.supported = false,
        }
        offset += align(len);
    }
    Some(rule)
}

fn dump_routes_in_table_on_socket(fd: RawFd, table: u32) -> Result<Vec<RouteEntry>> {
    let seq = 1;
    let mut body = bytes_of(&RtMsg {
        rtm_family: libc::AF_UNSPEC as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: table_field(table),
        rtm_protocol: 0,
        rtm_scope: 0,
        rtm_type: 0,
        rtm_flags: 0,
    });
    push_attr_u32(&mut body, RTA_TABLE, table);
    send_netlink_on_socket(fd, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, body, seq)?;
    read_route_dump(fd, seq, table)
}

fn route_body(table: u32, family: u8, dst_len: u8, scope: u8) -> Vec<u8> {
    bytes_of(&RtMsg {
        rtm_family: family,
        rtm_dst_len: dst_len,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: table_field(table),
        rtm_protocol: RTPROT_STATIC,
        rtm_scope: scope,
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    })
}

fn socket() -> Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("opening rtnetlink socket");
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    let rc = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err).context("binding rtnetlink socket");
    }
    Ok(fd)
}

fn send_ack_on_socket(fd: RawFd, kind: u16, flags: u16, body: Vec<u8>) -> Result<()> {
    let seq = 1;
    send_netlink_on_socket(fd, kind, flags, body, seq)?;
    read_ack(fd, seq)
}

fn send_netlink_on_socket(fd: RawFd, kind: u16, flags: u16, body: Vec<u8>, seq: u32) -> Result<()> {
    let mut msg = bytes_of(&NlMsghdr {
        nlmsg_len: (size_of::<NlMsghdr>() + body.len()) as u32,
        nlmsg_type: kind,
        nlmsg_flags: flags,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    });
    msg.extend_from_slice(&body);

    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    kernel.nl_pid = 0;
    kernel.nl_groups = 0;
    let sent = unsafe {
        libc::sendto(
            fd,
            msg.as_ptr().cast(),
            msg.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error()).context("sending rtnetlink request");
    }
    Ok(())
}

fn read_ack(fd: RawFd, seq: u32) -> Result<()> {
    let mut buf = vec![0u8; 8192];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("reading rtnetlink ack");
        }
        let mut offset = 0usize;
        let n = n as usize;
        while offset + size_of::<NlMsghdr>() <= n {
            let hdr = read_struct::<NlMsghdr>(&buf[offset..])?;
            if hdr.nlmsg_len as usize <= size_of::<NlMsghdr>()
                || offset + hdr.nlmsg_len as usize > n
            {
                bail!("short rtnetlink ack");
            }
            if hdr.nlmsg_seq == seq && hdr.nlmsg_type == NLMSG_ERROR {
                let start = offset + size_of::<NlMsghdr>();
                let err = read_struct::<NlMsgErr>(&buf[start..])?.error;
                if err == 0 {
                    return Ok(());
                }
                return Err(io::Error::from_raw_os_error(-err)).context("rtnetlink request failed");
            }
            offset += align(hdr.nlmsg_len as usize);
        }
    }
}

fn read_route_dump(fd: RawFd, seq: u32, table: u32) -> Result<Vec<RouteEntry>> {
    let mut routes = Vec::new();
    let mut buf = vec![0u8; 32768];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_TRUNC) };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("reading rtnetlink route dump");
        }
        let mut offset = 0usize;
        let n = n as usize;
        if n > buf.len() {
            bail!("truncated rtnetlink route dump");
        }
        while offset + size_of::<NlMsghdr>() <= n {
            let hdr = read_struct::<NlMsghdr>(&buf[offset..])?;
            if (hdr.nlmsg_len as usize) < size_of::<NlMsghdr>()
                || offset + hdr.nlmsg_len as usize > n
            {
                bail!("short rtnetlink route dump");
            }
            if hdr.nlmsg_seq != seq {
                offset += align(hdr.nlmsg_len as usize);
                continue;
            }
            if hdr.nlmsg_flags & NLM_F_DUMP_INTR != 0 {
                bail!("rtnetlink route dump interrupted; refusing incomplete ownership snapshot");
            }
            let start = offset + size_of::<NlMsghdr>();
            let end = offset + hdr.nlmsg_len as usize;
            match hdr.nlmsg_type {
                NLMSG_DONE => return Ok(routes),
                NLMSG_ERROR => {
                    let err = read_struct::<NlMsgErr>(&buf[start..])?.error;
                    if err == 0 {
                        return Ok(routes);
                    }
                    return Err(io::Error::from_raw_os_error(-err))
                        .context("rtnetlink route dump failed");
                }
                RTM_NEWROUTE => {
                    let route = parse_route_entry(&buf[start..end])?;
                    if route.table == table {
                        routes.push(route);
                    }
                }
                _ => {}
            }
            offset += align(hdr.nlmsg_len as usize);
        }
    }
}

fn parse_route_entry(data: &[u8]) -> Result<RouteEntry> {
    if data.len() < size_of::<RtMsg>() {
        bail!("short rtnetlink route entry");
    }
    let msg = read_struct::<RtMsg>(data)?;
    let mut route = RouteEntry {
        supported: msg.rtm_src_len == 0
            && msg.rtm_tos == 0
            && msg.rtm_flags == 0
            && msg.rtm_protocol == RTPROT_STATIC
            && msg.rtm_type == RTN_UNICAST
            && msg.rtm_scope
                == if msg.rtm_dst_len == 0 {
                    RT_SCOPE_UNIVERSE
                } else {
                    RT_SCOPE_LINK
                },
        family: msg.rtm_family,
        table: msg.rtm_table as u32,
        dst_len: msg.rtm_dst_len,
        dst: None,
        gateway: None,
        oif: None,
        prefsrc: None,
    };
    let mut offset = align(size_of::<RtMsg>());
    while offset + size_of::<RtAttr>() <= data.len() {
        let attr = read_struct::<RtAttr>(&data[offset..])?;
        let len = attr.rta_len as usize;
        if len < size_of::<RtAttr>() || offset + len > data.len() {
            bail!("short rtnetlink route attribute");
        }
        let payload_start = offset + size_of::<RtAttr>();
        let payload = &data[payload_start..offset + len];
        match attr.rta_type {
            RTA_DST => route.dst = parse_ip_attr(route.family, payload),
            RTA_GATEWAY => route.gateway = parse_ip_attr(route.family, payload),
            RTA_PREFSRC => route.prefsrc = parse_ip_attr(route.family, payload),
            RTA_OIF => route.oif = parse_u32_attr(payload),
            RTA_TABLE => {
                if let Some(table) = parse_u32_attr(payload) {
                    route.table = table;
                }
            }
            _ => route.supported = false,
        }
        offset += align(len);
    }
    Ok(route)
}

fn parse_ip_attr(family: u8, payload: &[u8]) -> Option<IpAddr> {
    match family as i32 {
        libc::AF_INET if payload.len() >= 4 => Some(IpAddr::V4(Ipv4Addr::new(
            payload[0], payload[1], payload[2], payload[3],
        ))),
        libc::AF_INET6 if payload.len() >= 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[..16]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn parse_u32_attr(payload: &[u8]) -> Option<u32> {
    let bytes = payload.get(..4)?;
    Some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

fn ifindex(dev: &str) -> Result<u32> {
    let dev = CString::new(dev).context("interface name contains NUL")?;
    let index = unsafe { libc::if_nametoindex(dev.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error()).context("resolving interface ifindex");
    }
    Ok(index)
}

fn table_field(table: u32) -> u8 {
    u8::try_from(table).unwrap_or(0)
}

fn family(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    }
}

fn prefix_len(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn push_attr_u32(buf: &mut Vec<u8>, kind: u16, value: u32) {
    push_attr(buf, kind, &value.to_ne_bytes());
}

fn push_attr_ip(buf: &mut Vec<u8>, kind: u16, value: IpAddr) {
    match value {
        IpAddr::V4(ip) => push_attr(buf, kind, &ipv4_bytes(ip)),
        IpAddr::V6(ip) => push_attr(buf, kind, &ipv6_bytes(ip)),
    }
}

fn ipv4_bytes(ip: Ipv4Addr) -> [u8; 4] {
    ip.octets()
}

fn ipv6_bytes(ip: Ipv6Addr) -> [u8; 16] {
    ip.octets()
}

fn push_attr(buf: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = size_of::<RtAttr>() + payload.len();
    buf.extend_from_slice(&bytes_of(&RtAttr {
        rta_len: len as u16,
        rta_type: kind,
    }));
    buf.extend_from_slice(payload);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

fn bytes_of<T: Copy>(value: &T) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()).to_vec() }
}

fn read_struct<T: Copy>(bytes: &[u8]) -> Result<T> {
    if bytes.len() < size_of::<T>() {
        bail!("short rtnetlink message");
    }
    let mut out = std::mem::MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            out.as_mut_ptr().cast::<u8>(),
            size_of::<T>(),
        );
        Ok(out.assume_init())
    }
}

fn align(len: usize) -> usize {
    let align = 4;
    (len + align - 1) & !(align - 1)
}

fn is_errno(err: &anyhow::Error, code: i32) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            == Some(code)
    })
}

fn is_absent_route_error(err: &anyhow::Error) -> bool {
    is_errno(err, libc::ESRCH) || is_errno(err, libc::ENOENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FileConfig, GatewayNode, GatewayReturnPath, return_mark, return_table_id};
    use std::path::PathBuf;
    #[test]
    fn return_routes_derive_gateway_slotted_mark_and_table() {
        let cfg = Config {
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
            file: FileConfig {
                gateway_nodes: vec![
                    GatewayNode {
                        name: "gateway-a".to_string(),
                        public_ip: "203.0.113.10".parse().unwrap(),
                        underlay_ip: "192.168.0.12".parse().unwrap(),
                        overlay_ip: "10.255.12.1/24".to_string(),
                    },
                    GatewayNode {
                        name: "gateway-b".to_string(),
                        public_ip: "203.0.113.11".parse().unwrap(),
                        underlay_ip: "192.168.0.16".parse().unwrap(),
                        overlay_ip: "10.255.16.1/24".to_string(),
                    },
                ],
                backend_return_paths: vec![
                    GatewayReturnPath {
                        gateway: Some("gateway-b".to_string()),
                        gateway_underlay_ip: "192.168.0.16".parse().unwrap(),
                        gateway_overlay_ip: "10.255.16.1".parse().unwrap(),
                        backend_overlay_ip: None,
                        dscp: 40,
                        mark: crate::config::return_mark(40, 1),
                        route_table_id: crate::config::return_table_id(40, 1),
                    },
                    GatewayReturnPath {
                        gateway: Some("gateway-a".to_string()),
                        gateway_underlay_ip: "192.168.0.12".parse().unwrap(),
                        gateway_overlay_ip: "10.255.12.1".parse().unwrap(),
                        backend_overlay_ip: None,
                        dscp: 46,
                        mark: crate::config::return_mark(46, 0),
                        route_table_id: crate::config::return_table_id(46, 0),
                    },
                ],
                ..FileConfig::default()
            },
        };

        assert_eq!(
            return_routes(&cfg)
                .unwrap()
                .iter()
                .map(|route| (route.mark, route.table))
                .collect::<Vec<_>>(),
            vec![(0x106e, 1110), (0x10a8, 1168)]
        );
    }

    fn v4(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    #[test]
    fn kernel_reconcile_preserves_foreign_objects_and_persists_ownership() {
        std::thread::spawn(|| {
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) },
                0,
                "requires privileged Linux container: {}",
                io::Error::last_os_error()
            );
            use crate::linux::test_support as net;
            net::dummy("test-underlay");
            net::set_link(net::link("test-underlay").up());
            net::address("test-underlay", "192.0.2.10/24");
            net::dummy("test-return");
            net::set_link(net::link("test-return").up());
            net::address("test-return", "10.44.0.2/24");
            net::address("test-return", "10.45.0.2/24");
            let vxlan = ifindex("test-return").unwrap();
            let underlay = ifindex("test-underlay").unwrap();
            let local = v4("192.0.2.10");
            let state_dir =
                std::env::temp_dir().join(format!("edge-route-kernel-{}", std::process::id()));
            crate::storage::initialize(&state_dir).unwrap();
            let cfg = Config {
                path: state_dir.join("config.toml"),
                file: FileConfig {
                    state_dir: state_dir.clone(),
                    gateway_nodes: vec![GatewayNode {
                        name: "gateway-a".into(),
                        public_ip: v4("203.0.113.1"),
                        underlay_ip: v4("192.0.2.1"),
                        overlay_ip: "10.44.0.1/24".into(),
                    }],
                    backend_return_paths: vec![GatewayReturnPath {
                        gateway: Some("gateway-a".into()),
                        gateway_underlay_ip: v4("192.0.2.1"),
                        gateway_overlay_ip: v4("10.44.0.1"),
                        backend_overlay_ip: None,
                        dscp: 46,
                        mark: crate::config::return_mark(46, 0),
                        route_table_id: crate::config::return_table_id(46, 0),
                    }],
                    ..Default::default()
                },
            };
            let fd = socket().unwrap();
            let mut ownership = RouteOwnership::load().unwrap();
            ownership.save().unwrap();
            let want = desired_route();
            let foreign_rule =
                ensure_rule_at_or_after_on_socket(fd, 100, 9, u32::MAX, 999, &[]).unwrap();
            let foreign_route = host_entry(want.table, v4("192.0.2.99"), underlay, local);
            add_route_exclusive_on_socket(fd, &foreign_route).unwrap();
            assert_eq!(ownership_conflicts(&cfg).unwrap().len(), 1);
            let before = dump_policy_rules_on_socket(fd).unwrap();
            assert!(
                reconcile_on_socket(fd, &cfg, &[want], &mut ownership, vxlan, underlay, local)
                    .is_err()
            );
            assert_eq!(dump_policy_rules_on_socket(fd).unwrap(), before);
            assert_eq!(
                dump_routes_in_table_on_socket(fd, want.table).unwrap(),
                vec![foreign_route.clone()]
            );
            delete_route_entry_on_socket(fd, &foreign_route).unwrap();

            reconcile_on_socket(fd, &cfg, &[want], &mut ownership, vxlan, underlay, local).unwrap();
            let stored = crate::storage::repository()
                .unwrap()
                .get_document("route_ownership", "local")
                .unwrap();
            for _ in 0..3 {
                ownership = RouteOwnership::load().unwrap();
                reconcile_on_socket(fd, &cfg, &[want], &mut ownership, vxlan, underlay, local)
                    .unwrap();
                assert_eq!(
                    crate::storage::repository()
                        .unwrap()
                        .get_document("route_ownership", "local")
                        .unwrap(),
                    stored
                );
            }
            assert_eq!(ownership.rules.len(), 1);
            assert_eq!(ownership.rules[0].priority, 101);
            assert_eq!(ownership.routes.len(), 2);
            assert!(ownership_conflicts(&cfg).unwrap().is_empty());
            assert!(policy_rule_present(&cfg));
            assert!(
                dump_policy_rules_on_socket(fd)
                    .unwrap()
                    .contains(&foreign_rule)
            );

            // A gateway re-IP removes the old recorded default even though it
            // is not in the new topology anymore.
            let moved = ReturnRoute {
                gateway_overlay: v4("10.45.0.1"),
                ..want
            };
            reconcile_on_socket(fd, &cfg, &[moved], &mut ownership, vxlan, underlay, local)
                .unwrap();
            assert!(
                !dump_routes_in_table_on_socket(fd, want.table)
                    .unwrap()
                    .contains(&default_entry(want.table, want.gateway_overlay, vxlan))
            );
            let replacement = default_entry(want.table, v4("10.44.0.1"), vxlan);
            assert!(add_route_exclusive_on_socket(fd, &replacement).is_err());
            assert!(
                dump_routes_in_table_on_socket(fd, want.table)
                    .unwrap()
                    .contains(&default_entry(want.table, moved.gateway_overlay, vxlan))
            );

            // Cleanup protects unrelated entries even in a previously used table.
            add_route_exclusive_on_socket(fd, &foreign_route).unwrap();
            let second = ReturnRoute {
                gateway_underlay: v4("192.0.2.2"),
                gateway_overlay: v4("10.45.0.1"),
                mark: return_mark(40, 1),
                table: return_table_id(40, 1),
            };
            reconcile_on_socket(fd, &cfg, &[second], &mut ownership, vxlan, underlay, local)
                .unwrap();
            assert_eq!(
                dump_routes_in_table_on_socket(fd, want.table).unwrap(),
                vec![foreign_route.clone()]
            );
            assert!(
                ownership
                    .routes
                    .iter()
                    .all(|entry| entry.table == second.table)
            );
            reconcile_on_socket(fd, &cfg, &[], &mut ownership, 0, 0, local).unwrap();
            assert!(ownership.routes.is_empty());
            assert!(ownership.rules.is_empty());
            assert_eq!(
                dump_routes_in_table_on_socket(fd, want.table).unwrap(),
                vec![foreign_route]
            );
            assert_eq!(dump_policy_rules_on_socket(fd).unwrap(), before);
            assert_eq!(RouteOwnership::load().unwrap(), ownership);
            // Same mark/table with additional selectors must never be deleted
            // through a partially specified netlink key.
            let selector_rule =
                ensure_rule_at_or_after_on_socket(fd, 200, want.mark, u32::MAX, want.table, &[])
                    .unwrap();
            net::rule(200, want.mark, want.table, Some("198.51.100.0/24"));
            let collision_before = dump_policy_rules_on_socket(fd).unwrap();
            assert!(delete_policy_rule_on_socket(fd, &selector_rule).is_err());
            assert_eq!(dump_policy_rules_on_socket(fd).unwrap(), collision_before);
            unsafe { libc::close(fd) };
        })
        .join()
        .unwrap();
    }

    fn test_rule() -> PolicyRule {
        parse_policy_rule(&rule_body(
            return_mark(46, 0),
            u32::MAX,
            100,
            return_table_id(46, 0),
        ))
        .unwrap()
    }

    fn desired_route() -> ReturnRoute {
        ReturnRoute {
            gateway_underlay: v4("192.0.2.1"),
            gateway_overlay: v4("10.44.0.1"),
            mark: return_mark(46, 0),
            table: return_table_id(46, 0),
        }
    }

    #[test]
    fn numeric_ranges_and_expected_shape_do_not_establish_ownership() {
        let ownership = RouteOwnership::default();
        let route = default_entry(return_table_id(46, 0), v4("10.44.0.1"), 11);
        assert!(!ownership.owns_rule(&test_rule()));
        assert!(!ownership.owns_route(&route));
        assert!(validate_table(&[route], &ownership).is_err());
        assert!(validate_rules(&[test_rule()], &[desired_route()], &ownership).is_err());
    }

    #[test]
    fn ownership_requires_exact_rule_identity() {
        let rule = test_rule();
        let ownership = RouteOwnership {
            rules: vec![rule.clone()],
            ..Default::default()
        };
        assert!(ownership.owns_rule(&rule));
        let variants = [
            PolicyRule {
                mark: Some(9),
                ..rule.clone()
            },
            PolicyRule {
                mask: Some(0xff),
                ..rule.clone()
            },
            PolicyRule {
                table: 999,
                ..rule.clone()
            },
            PolicyRule {
                priority: 101,
                ..rule.clone()
            },
            PolicyRule {
                protocol: 99,
                ..rule.clone()
            },
            PolicyRule {
                supported: false,
                ..rule.clone()
            },
        ];
        for foreign in variants {
            assert!(!ownership.owns_rule(&foreign));
            assert!(validate_rules(&[foreign], &[desired_route()], &ownership).is_err());
        }
    }

    #[test]
    fn unrelated_priority_is_not_a_conflict_but_mask_overlap_is() {
        let mut foreign = test_rule();
        foreign.mark = Some(9);
        foreign.table = 999;
        assert!(
            validate_rules(
                &[foreign.clone()],
                &[desired_route()],
                &RouteOwnership::default()
            )
            .is_ok()
        );
        foreign.mark = Some(0x1000);
        foreign.mask = Some(0xf000);
        assert!(
            validate_rules(&[foreign], &[desired_route()], &RouteOwnership::default()).is_err()
        );
    }

    #[test]
    fn previous_gateway_routes_remain_owned_but_foreign_host_routes_do_not() {
        let old = host_entry(1110, v4("192.0.2.1"), 2, v4("192.0.2.10"));
        let ownership = RouteOwnership {
            routes: vec![old.clone()],
            ..Default::default()
        };
        assert!(validate_table(std::slice::from_ref(&old), &ownership).is_ok());
        for foreign in [
            host_entry(1110, v4("192.0.2.99"), 2, v4("192.0.2.10")),
            host_entry(1110, v4("192.0.2.1"), 3, v4("192.0.2.10")),
            RouteEntry {
                supported: false,
                ..old
            },
        ] {
            assert!(validate_table(&[foreign], &ownership).is_err());
        }
    }

    #[test]
    fn journal_round_trip_and_boot_namespace_scope() {
        let ownership = RouteOwnership {
            scope: "boot:netns".into(),
            rules: vec![test_rule()],
            routes: vec![default_entry(1110, v4("10.44.0.1"), 11)],
        };
        let json = serde_json::to_string(&ownership).unwrap();
        assert_eq!(
            RouteOwnership::decode(Some(&json), ownership.scope.clone()).unwrap(),
            ownership
        );
        assert!(
            RouteOwnership::decode(Some(&json), "new-boot:netns".into())
                .unwrap()
                .rules
                .is_empty()
        );
        assert!(
            RouteOwnership::decode(Some(&json), "boot:other-netns".into())
                .unwrap()
                .routes
                .is_empty()
        );
        assert!(RouteOwnership::decode(Some("broken"), "boot:netns".into()).is_err());
    }

    #[test]
    fn rule_selectors_and_route_attributes_cannot_be_ignored_for_ownership() {
        let mut body = rule_body(0x106e, u32::MAX, 100, 1110);
        push_attr_u32(&mut body, 3, 42); // FRA_IIFNAME, unrecognized selector.
        assert!(!parse_policy_rule(&body).unwrap().supported);
        let mut body = route_body(1110, libc::AF_INET as u8, 0, RT_SCOPE_UNIVERSE);
        push_attr_u32(&mut body, 6, 10); // RTA_PRIORITY (metric).
        assert!(!parse_route_entry(&body).unwrap().supported);
    }

    fn dump_error(message: &[u8], route_dump: bool) -> String {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) },
            0
        );
        assert_eq!(
            unsafe { libc::send(fds[0], message.as_ptr().cast(), message.len(), 0) },
            message.len() as isize
        );
        let result = if route_dump {
            read_route_dump(fds[1], 1, 1110).map(|_| ())
        } else {
            read_rule_dump(fds[1], 1).map(|_| ())
        };
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        };
        result.unwrap_err().to_string()
    }

    #[test]
    fn interrupted_dump_is_not_an_empty_ownership_snapshot() {
        let message = bytes_of(&NlMsghdr {
            nlmsg_len: size_of::<NlMsghdr>() as u32,
            nlmsg_type: NLMSG_DONE,
            nlmsg_flags: NLM_F_DUMP_INTR,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        });
        for route_dump in [false, true] {
            assert!(dump_error(&message, route_dump).contains("interrupted"));
        }
    }

    #[test]
    fn truncated_dump_is_not_an_empty_ownership_snapshot() {
        for route_dump in [false, true] {
            assert!(dump_error(&vec![0u8; 40000], route_dump).contains("truncated"));
        }
    }

    #[test]
    fn parses_route_entry_extended_table_attr() {
        let mut body = route_body(1001, libc::AF_INET as u8, 32, RT_SCOPE_LINK);
        push_attr_ip(&mut body, RTA_DST, "192.168.0.12".parse().unwrap());
        push_attr_u32(&mut body, RTA_OIF, 2);
        push_attr_ip(&mut body, RTA_PREFSRC, "192.168.0.14".parse().unwrap());
        push_attr_u32(&mut body, RTA_TABLE, 1001);

        let route = parse_route_entry(&body).unwrap();
        assert_eq!(route.table, 1001);
        assert_eq!(route.dst, Some("192.168.0.12".parse().unwrap()));
        assert_eq!(route.oif, Some(2));
        assert_eq!(route.prefsrc, Some("192.168.0.14".parse().unwrap()));
    }
}
