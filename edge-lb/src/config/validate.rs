use std::{collections::HashSet, net::IpAddr};

use anyhow::{Context, Result, bail};
use edge_lb_common::{NATIVE_CONSISTENT_HASH_BUCKET_MAP_CAPACITY, NATIVE_CONSISTENT_HASH_BUCKETS};

use super::{
    ActiveSource, ControlPlaneMode, FileConfig, LbSelect, Listener, NodeRole, Protocol,
    overlay::{parse_prefix, same_subnet, validate_overlay_capacity},
};

pub(super) fn validate(file: &FileConfig) -> Result<()> {
    let n = &file.network;
    let b = &file.backend;
    let g = &file.gateway;
    if file.log_level.trim().is_empty() {
        bail!("log_level must not be empty");
    }
    for (index, server) in file.discovery.stun_servers.iter().enumerate() {
        validate_stun_server(index, server)?;
    }
    let _ = g;
    if !(1..=63).contains(&n.dscp) {
        bail!("network.dscp must be in 1..63, got {}", n.dscp);
    }
    if n.vni == 0 || n.vni > 0xff_ffff {
        bail!("network.vni must be in 1..16777215, got {}", n.vni);
    }
    if n.vxlan_port == 0 {
        bail!("network.vxlan_port must not be 0");
    }
    if n.vxlan_mtu < 576 {
        bail!("network.vxlan_mtu {0} is implausibly small", n.vxlan_mtu);
    }
    if b.mss == 0 || b.mss > n.vxlan_mtu.saturating_sub(40) {
        bail!(
            "backend.mss {} does not fit vxlan_mtu {}",
            b.mss,
            n.vxlan_mtu
        );
    }
    if b.ct_mark == 0 || b.ct_mark > 0xff {
        bail!("backend.ct_mark must be in 1..255 (fwmark mask is /0xff)");
    }
    if !b.fwmark.starts_with("0x") || !b.fwmark.contains('/') {
        bail!("backend.fwmark must look like 0x1/0xff, got {}", b.fwmark);
    }
    if b.route_table_id == 0 {
        bail!("backend.route_table_id must not be 0");
    }
    if n.underlay_dev == n.vxlan_dev {
        bail!("underlay_dev and vxlan_dev must differ");
    }
    if file.ha.watch_interval_secs == 0 {
        bail!(
            "gateway.reconcile.interval_secs or backend.xds.reconnect_interval_secs must be at least 1"
        );
    }
    if matches!(file.node_role, NodeRole::Backend) {
        // Bootstrap gateway inventory is not a received return-path contract.
        if !file.backend_return_paths.is_empty() {
            file.validate_backend_return_paths()?;
        }
        let xds_gateways = effective_backend_xds_gateways(file);
        if xds_gateways.len() > 2 {
            bail!(
                "backend.xds.gateways supports at most 2 entries for active-backup HA, got {}",
                xds_gateways.len()
            );
        }
    }
    if matches!(file.ha.active_source, ActiveSource::Xds)
        && (!file.control_plane.enabled || file.control_plane.mode != ControlPlaneMode::Xds)
    {
        bail!("active source xds requires control_plane.enabled = true and mode = xds");
    }
    let backends = file.backend_nodes_effective();
    let overlay_cidr = parse_prefix(&n.overlay_cidr)
        .with_context(|| format!("bad network.overlay_cidr {}", n.overlay_cidr))?;
    validate_overlay_capacity(overlay_cidr, backends.len() + 1)?;
    let own_overlay = parse_prefix(&g.overlay_ip)
        .with_context(|| format!("bad gateway.overlay_ip {}", g.overlay_ip))?;
    if !same_subnet(overlay_cidr, own_overlay) {
        bail!(
            "gateway.overlay_ip {} is not in network.overlay_cidr {}",
            g.overlay_ip,
            n.overlay_cidr
        );
    }
    for (idx, gw) in file.gateway_nodes.iter().enumerate() {
        parse_prefix(&gw.overlay_ip)
            .with_context(|| format!("bad overlay_ip on gateway_nodes[{idx}]"))?;
        if !gw.underlay_ip.is_unspecified()
            && backends.iter().any(|b| b.underlay_ip == gw.underlay_ip)
        {
            bail!("gateway_nodes[{idx}] underlay_ip equals a backend underlay_ip");
        }
    }
    let mut backend_names = HashSet::new();
    let mut backend_underlays = HashSet::new();
    let mut backend_overlays = HashSet::new();
    let allow_backend_inventory_cross_overlay =
        matches!(file.node_role, NodeRole::Backend) && file.ha.active_source == ActiveSource::Xds;
    for (idx, backend) in backends.iter().enumerate() {
        if backend.name.trim().is_empty() {
            bail!("backend_nodes[{idx}] has an empty name");
        }
        if !backend_names.insert(backend.name.clone()) {
            bail!("duplicate backend node name {}", backend.name);
        }
        if !backend.underlay_ip.is_unspecified() && !backend_underlays.insert(backend.underlay_ip) {
            bail!("duplicate backend underlay_ip {}", backend.underlay_ip);
        }
        if !backend_overlays.insert(backend.overlay_ip.clone()) {
            bail!("duplicate backend overlay_ip {}", backend.overlay_ip);
        }
        let backend_overlay = parse_prefix(&backend.overlay_ip)
            .with_context(|| format!("bad overlay_ip on backend_nodes[{idx}]"))?;
        if !allow_backend_inventory_cross_overlay && !same_subnet(overlay_cidr, backend_overlay) {
            bail!(
                "backend_nodes[{idx}] overlay {} is not in network.overlay_cidr {}",
                backend.overlay_ip,
                n.overlay_cidr
            );
        }
    }
    if let Some(standby) = n.standby_gateway_ip
        && standby == n.gateway_ip
    {
        bail!("network.standby_gateway_ip equals gateway_ip");
    }

    if matches!(file.node_role, NodeRole::Gateway) {
        let mut target_group_names = HashSet::new();
        for (idx, group) in file.target_groups.iter().enumerate() {
            if group.name.trim().is_empty() {
                bail!("target_groups[{idx}] has an empty name");
            }
            if !target_group_names.insert(group.name.clone()) {
                bail!("duplicate target group name {}", group.name);
            }
            if group.monitor {
                validate_probe_config(
                    &format!("target group {}", group.name),
                    ProbeConfig {
                        probe_type: group.probe_type.as_deref(),
                        probe_port: group.probe_port,
                        probe_req: group.probe_req.as_deref(),
                        probe_resp: group.probe_resp.as_deref(),
                        probe_status: group.probe_status,
                        skip_tls_verify: group.probe_skip_tls_verify,
                        period_secs: group.period_secs,
                        retries: group.retries,
                    },
                )?;
            }
            for (target_idx, target) in group.targets.iter().enumerate() {
                if target.weight == 0 {
                    bail!(
                        "target group {} target {target_idx} weight must be at least 1",
                        group.name
                    );
                }
                if target.address.is_unspecified() {
                    bail!(
                        "target group {} target {target_idx} address must not be unspecified",
                        group.name
                    );
                }
                if let Some(backend) = target.backend.as_deref()
                    && !backends.iter().any(|node| node.name == backend)
                {
                    bail!(
                        "target group {} target {target_idx} references unknown backend {}",
                        group.name,
                        backend
                    );
                }
            }
        }

        let mut listener_names = HashSet::new();
        let mut listener_keys = HashSet::new();
        for (idx, listener) in file.listeners.iter().enumerate() {
            if listener.name.trim().is_empty() {
                bail!("listeners[{idx}] has an empty name");
            }
            if !listener_names.insert(listener.name.clone()) {
                bail!("duplicate listener name {}", listener.name);
            }
            if listener.port == 0 {
                bail!("listener {} port must not be 0", listener.name);
            }
            if listener.target_port == 0 {
                bail!("listener {} target_port must not be 0", listener.name);
            }
            validate_native_listener(listener)?;
            for vip in &listener.vip_ips {
                if vip.is_unspecified() {
                    bail!(
                        "listener {} vip_ips cannot contain an unspecified address",
                        listener.name
                    );
                }
            }
            let unique_vips = listener.vip_ips.iter().collect::<HashSet<_>>();
            if unique_vips.len() != listener.vip_ips.len() {
                bail!("listener {} vip_ips contains duplicates", listener.name);
            }
            if !target_group_names.contains(&listener.target_group) {
                bail!(
                    "listener {} target_group {:?} is not listed in [[target_groups]]",
                    listener.name,
                    listener.target_group
                );
            }
            if listener.protocols.is_empty() {
                bail!("listener {} needs at least one protocol", listener.name);
            }
            for protocol in &listener.protocols {
                if !listener_keys.insert((listener.port, *protocol)) {
                    bail!(
                        "duplicate listener port/protocol {}:{}",
                        protocol.as_str(),
                        listener.port
                    );
                }
            }
        }
        validate_consistent_hash_listener_capacity(file, configured_listener_expansion_count)?;
    }

    if let Some(token) = &file.api.auth_token
        && token.len() < 16
    {
        bail!("gateway.api.auth_token must be at least 16 characters");
    }
    for cidr in &file.api.trusted_source_cidrs {
        parse_prefix(cidr)
            .with_context(|| format!("bad gateway.api.trusted_source_cidrs entry {cidr:?}"))?;
    }
    if matches!(file.node_role, NodeRole::Gateway) {
        let listen: std::net::SocketAddr = file
            .api
            .listen
            .parse()
            .with_context(|| format!("bad gateway.api.listen {}", file.api.listen))?;
        let loopback = match listen.ip() {
            IpAddr::V4(v) => v.is_loopback(),
            IpAddr::V6(v) => v.is_loopback(),
        };
        if !loopback && file.api.auth_token.is_none() {
            bail!("gateway.api.auth_token is required when listening on non-loopback address");
        }
        if let Some(metrics) = &file.gateway.metrics {
            if metrics.enabled {
                let _listen: std::net::SocketAddr = metrics
                    .listen
                    .parse()
                    .with_context(|| format!("bad gateway.metrics.listen {}", metrics.listen))?;
            }
            for cidr in &metrics.trusted_source_cidrs {
                parse_prefix(cidr).with_context(|| {
                    format!("bad gateway.metrics.trusted_source_cidrs entry {cidr:?}")
                })?;
            }
        }
    }
    if file.control_plane.enabled {
        let listen: std::net::SocketAddr =
            file.control_plane.listen.parse().with_context(|| {
                format!("bad control_plane.listen {}", file.control_plane.listen)
            })?;
        let loopback = match listen.ip() {
            IpAddr::V4(v) => v.is_loopback(),
            IpAddr::V6(v) => v.is_loopback(),
        };
        if !loopback && file.control_plane.token.is_none() {
            bail!("control_plane.token is required when listening on non-loopback address");
        }
        if let Some(token) = &file.control_plane.token
            && token.len() < 16
        {
            bail!("control_plane.token must be at least 16 characters");
        }
        if matches!(file.node_role, NodeRole::Backend)
            && matches!(file.ha.active_source, ActiveSource::Xds)
            && file.control_plane.gateway_port == Some(0)
        {
            bail!("control_plane.gateway_port must not be 0");
        }
        for cidr in &file.control_plane.trusted_source_cidrs {
            parse_prefix(cidr).with_context(|| {
                format!("bad control_plane.trusted_source_cidrs entry {cidr:?}")
            })?;
        }
    }
    Ok(())
}

fn validate_stun_server(index: usize, server: &str) -> Result<()> {
    let server = server.trim();
    if server.is_empty() {
        bail!("discovery.stun_servers[{index}] must not be empty");
    }
    let port = if let Some(rest) = server.strip_prefix('[') {
        let (_, port) = rest.split_once("]:").ok_or_else(|| {
            anyhow::anyhow!("discovery.stun_servers[{index}] must use [ipv6]:port")
        })?;
        port
    } else {
        server
            .rsplit_once(':')
            .map(|(_, port)| port)
            .ok_or_else(|| anyhow::anyhow!("discovery.stun_servers[{index}] must use host:port"))?
    };
    let port = port.parse::<u16>().map_err(|_| {
        anyhow::anyhow!("discovery.stun_servers[{index}] has invalid port {port:?}")
    })?;
    if port == 0 {
        bail!("discovery.stun_servers[{index}] port must be in 1..=65535");
    }
    Ok(())
}

fn effective_backend_xds_gateways(file: &FileConfig) -> Vec<String> {
    let Some(xds) = file.backend.xds.as_ref() else {
        return Vec::new();
    };
    let mut gateways = xds.gateways.clone();
    if gateways.is_empty() && !xds.gateway.trim().is_empty() {
        gateways.push(xds.gateway.clone());
    }
    gateways
}

fn validate_native_listener(listener: &super::Listener) -> Result<()> {
    if let Some(timeout) = listener.inactive_timeout
        && timeout == 0
    {
        bail!(
            "listener {} inactive_timeout must be omitted or greater than 0",
            listener.name
        );
    }
    Ok(())
}

pub(crate) fn max_consistent_hash_datapath_listeners() -> usize {
    (NATIVE_CONSISTENT_HASH_BUCKET_MAP_CAPACITY / NATIVE_CONSISTENT_HASH_BUCKETS) as usize
}

pub(crate) fn validate_consistent_hash_listener_capacity(
    file: &FileConfig,
    mut listener_expansion_count: impl FnMut(&FileConfig, &Listener) -> Result<usize>,
) -> Result<()> {
    let max = max_consistent_hash_datapath_listeners();
    let mut expanded = 0usize;
    for listener in &file.listeners {
        if listener.select != LbSelect::ConsistentHash {
            continue;
        }
        expanded = expanded
            .checked_add(listener_expansion_count(file, listener)?)
            .context("consistent_hash listener expansion overflowed usize")?;
    }
    if expanded > max {
        bail!(
            "consistent_hash listener expansion uses {expanded} datapath listeners but native bucket map supports at most {max} ({} buckets each, {} map entries)",
            NATIVE_CONSISTENT_HASH_BUCKETS,
            NATIVE_CONSISTENT_HASH_BUCKET_MAP_CAPACITY
        );
    }
    Ok(())
}

fn configured_listener_expansion_count(file: &FileConfig, listener: &Listener) -> Result<usize> {
    let mut vip_count = 1usize;
    let mut explicit_vips = HashSet::new();
    for vip in &listener.vip_ips {
        if *vip != file.network.gateway_ip && explicit_vips.insert(*vip) {
            vip_count += 1;
        }
    }
    Ok(vip_count * unique_protocol_count(&listener.protocols))
}

pub(crate) fn unique_protocol_count(protocols: &[Protocol]) -> usize {
    protocols.iter().copied().collect::<HashSet<_>>().len()
}

struct ProbeConfig<'a> {
    probe_type: Option<&'a str>,
    probe_port: Option<u16>,
    probe_req: Option<&'a str>,
    probe_resp: Option<&'a str>,
    probe_status: Option<u16>,
    skip_tls_verify: bool,
    period_secs: Option<u32>,
    retries: Option<u32>,
}

fn validate_probe_config(label: &str, probe: ProbeConfig<'_>) -> Result<()> {
    let normalized = probe.probe_type.unwrap_or("").trim().to_ascii_lowercase();
    if !normalized.is_empty()
        && !matches!(
            normalized.as_str(),
            "none" | "ping" | "tcp" | "udp" | "http" | "https"
        )
    {
        bail!("{label} probe_type {normalized:?} is not supported");
    }
    if let Some(port) = probe.probe_port {
        if port == 0 {
            bail!("{label} probe_port must be in range 1..=65535");
        }
        if matches!(normalized.as_str(), "none" | "ping") {
            bail!("{label} probe_port is not valid for probe_type {normalized:?}");
        }
    }
    if let Some(period) = probe.period_secs
        && period == 0
    {
        bail!("{label} period_secs must not be 0");
    }
    let _ = probe.retries;
    let has_payload = probe.probe_req.is_some_and(|v| !v.trim().is_empty())
        || probe.probe_resp.is_some_and(|v| !v.trim().is_empty());
    if has_payload && !matches!(normalized.as_str(), "tcp" | "udp" | "http" | "https") {
        bail!("{label} probe_req/probe_resp are only valid for tcp/udp/http/https probes");
    }
    if let Some(status) = probe.probe_status
        && !(100..=599).contains(&status)
    {
        bail!("{label} probe_status must be in range 100..=599");
    }
    if probe.probe_status.is_some() && !matches!(normalized.as_str(), "http" | "https") {
        bail!("{label} probe_status is only valid for http/https probes");
    }
    if probe.skip_tls_verify && normalized != "https" {
        bail!("{label} probe_skip_tls_verify is only valid for https probes");
    }
    Ok(())
}
