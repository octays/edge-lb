//! Backend node: VXLAN return tunnel, DSCP/ct-mark steering and policy
//! routing, mirroring the verified procedure in docs/vxlan-dscp-verified.md.
//!
//! Original-direction connections with a subscribed DSCP select a VXLAN
//! return path. DSCP is a trusted-network classifier, not authentication.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    thread::sleep,
    time::Duration,
};

use anyhow::{Context, Result};

use crate::{
    config::{ActiveSource, Config, GatewayNode},
    linux::{
        net::{self, VxlanSpec},
        privilege, return_path,
    },
    runtime::shutdown,
};

pub fn apply(cfg: &Config) -> Result<()> {
    apply_with(cfg, false, None).map(|_| ())
}

pub fn apply_managed(cfg: &Config) -> Result<return_path::ManagedReturnPath> {
    apply_managed_reusing(cfg, None)
}

pub fn apply_managed_reusing(
    cfg: &Config,
    existing: Option<return_path::ManagedReturnPath>,
) -> Result<return_path::ManagedReturnPath> {
    apply_with(cfg, true, existing).map(|guard| guard.expect("managed return path guard"))
}

fn apply_with(
    cfg: &Config,
    managed: bool,
    existing: Option<return_path::ManagedReturnPath>,
) -> Result<Option<return_path::ManagedReturnPath>> {
    cfg.validate_backend_return_paths()?;
    privilege::require_root()?;
    // xDS backends install the return path for every gateway snapshot.  The
    // gateway active/backup election is intentionally not consulted here.
    let gw = backend_gateway_reference(cfg)?;
    let local = cfg.local_backend().context("resolving local backend")?;
    let n = cfg.network();
    let return_paths = cfg.backend_return_paths();
    // A backend may forward replies from a container, bridge, or another
    // local address. Forwarding is required and capacity knobs are raised
    // conservatively for production.
    crate::linux::sysctl::ensure_backend_datapath_tuning()
        .with_context(|| "applying backend datapath sysctl tuning")?;
    tracing::info!(
        "[backend] apply node={} return_dev={} underlay_dev={} underlay_ip={} public_ip={} overlay={} gateway_reference={} gateway_underlay={} gateway_overlay={} overlay_cidr={} vni={} vxlan_port={} mtu={} return_paths={} return_engine=nftables",
        cfg.node_name,
        n.vxlan_dev,
        n.underlay_dev,
        local.underlay_ip,
        local.public_ip,
        local.overlay_ip,
        gw.name,
        gw.underlay_ip,
        gw.overlay_ip,
        n.overlay_cidr,
        n.vni,
        n.vxlan_port,
        n.vxlan_mtu,
        return_paths.len(),
    );
    let created = ensure_vxlan(cfg, gw.underlay_ip)?;
    if let Some((local_addrs, peers)) = multipoint_return_vxlan(cfg) {
        tracing::info!(
            "[backend] {} {} (multipoint addrs={:?} peers={:?} vni {} dstport {})",
            n.vxlan_dev,
            if created {
                "created"
            } else {
                "already present"
            },
            local_addrs,
            peers,
            n.vni,
            n.vxlan_port,
        );
    } else {
        tracing::info!(
            "[backend] {} {} (remote {} vni {} dstport {})",
            n.vxlan_dev,
            if created {
                "created"
            } else {
                "already present"
            },
            gw.underlay_ip,
            n.vni,
            n.vxlan_port,
        );
    }
    net::ensure_rt_tables(cfg)?;
    let return_path_guard = if managed {
        Some(return_path::apply_managed_reusing(cfg, existing)?)
    } else {
        let _ = existing;
        return_path::apply(cfg)?;
        None
    };
    if return_paths.is_empty() {
        tracing::info!("[backend] return-path engine nftables cleared: no gateway return paths");
    } else {
        tracing::info!(
            "[backend] return-path engine nftables applied (nft table inet {})",
            cfg.backend_cfg().nft_table
        );
    }
    return_path::ensure_policy_routing(cfg)?;
    if return_paths.is_empty() {
        tracing::info!("[backend] policy routing cleared: no gateway return paths");
    } else if let Some((_, peers)) = multipoint_return_vxlan(cfg) {
        tracing::info!(
            "[backend] policy routing: per-gateway return paths applied for {} gateway peer(s)",
            peers.len()
        );
    } else {
        tracing::info!(
            "[backend] policy routing: fwmark {} -> table {} via {}",
            cfg.backend_cfg().fwmark,
            cfg.backend_cfg().route_table,
            cfg.gateway_overlay_ip()?,
        );
    }
    Ok(return_path_guard)
}

pub fn run(cfg: &Config) -> Result<()> {
    privilege::require_root()?;
    shutdown::install();
    if cfg.ha.active_source == ActiveSource::Xds {
        return crate::control::run_backend(cfg);
    }
    // Converge once so the daemon is useful immediately after boot.
    let _return_path_guard = apply_managed(cfg)?;
    let mut last: Option<String> = None;
    let mut failovers = 0u64;
    let mut heals = 0u64;
    tracing::info!(
        "[backend] watching active gateway ({:?}, {}s interval)",
        cfg.ha.active_source,
        cfg.ha.watch_interval_secs
    );
    while !shutdown::requested() {
        match cfg.active_gateway() {
            Ok(gw) => {
                let key = gw.name.clone();
                match &last {
                    None => {
                        tracing::info!("[backend] active gateway: {}", gw.name);
                        last = Some(key);
                    }
                    Some(prev) if *prev != key => {
                        failovers += 1;
                        tracing::info!(
                            "[backend] failover: {prev} -> {}: switching VXLAN remote to {}",
                            gw.name,
                            gw.underlay_ip
                        );
                        if let Err(e) = switch_active(cfg, &gw) {
                            tracing::error!("[backend] switching return path failed: {e:#}");
                        } else {
                            last = Some(key);
                        }
                    }
                    _ => {
                        if let Err(e) = heal(cfg, gw.underlay_ip) {
                            tracing::warn!("[backend] heal failed: {e:#}");
                        } else {
                            heals += 1;
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("[backend] cannot resolve active gateway: {e:#}"),
        }
        write_metrics(cfg, &last, failovers, heals);
        sleep(Duration::from_secs(cfg.ha.watch_interval_secs));
    }
    tracing::info!("[backend] shutdown requested");
    Ok(())
}

pub fn show(cfg: &Config) -> Result<()> {
    let n = cfg.network();
    section("gateway control planes");
    if cfg.gateway_nodes.is_empty() {
        println!("none configured");
    } else {
        for gateway in &cfg.gateway_nodes {
            println!(
                "{} (underlay {}, public {}, overlay {})",
                gateway.name, gateway.underlay_ip, gateway.public_ip, gateway.overlay_ip
            );
        }
    }
    section("vxlan device");
    println!(
        "{}: exists={} up={} mtu={} remote={:?}",
        n.vxlan_dev,
        net::link_exists(&n.vxlan_dev),
        net::is_up(&n.vxlan_dev),
        net::link_mtu(&n.vxlan_dev).unwrap_or_default(),
        net::vxlan_remote(&n.vxlan_dev)
    );
    section("policy routing");
    println!(
        "managed rule present={}",
        crate::linux::route::policy_rule_present(cfg)
    );
    let b = cfg.backend_cfg();
    section(&format!("route table {}", b.route_table));
    println!("managed return routes are reconciled through rtnetlink");
    section(&format!("nft table inet {}", b.nft_table));
    println!("present={}", crate::linux::nftables::table_exists(cfg));
    Ok(())
}

fn backend_gateway_reference(cfg: &Config) -> Result<GatewayNode> {
    if matches!(cfg.ha.active_source, ActiveSource::Xds) {
        return cfg
            .gateway_nodes
            .first()
            .cloned()
            .context("no gateway control-plane endpoint is configured");
    }
    cfg.active_gateway().context("resolving gateway reference")
}

pub fn cleanup(cfg: &Config) -> Result<()> {
    privilege::require_root()?;
    let n = cfg.network();
    let b = cfg.backend_cfg();
    return_path::cleanup(cfg)?;
    tracing::info!("[backend] nft table inet {} deleted", b.nft_table);
    tracing::info!("[backend] ip rule {} removed", b.rule_priority);
    tracing::info!("[backend] route table {} cleaned", b.route_table);
    if net::link_exists(&n.vxlan_dev) {
        net::delete_link(&n.vxlan_dev)
            .with_context(|| format!("failed to delete {}", n.vxlan_dev))?;
        tracing::info!("[backend] {} deleted", n.vxlan_dev);
    } else {
        tracing::info!("[backend] {} not present", n.vxlan_dev);
    }
    let _ = std::fs::remove_file(metrics_path(cfg));
    // Application-owned NAT rules and /etc/iproute2/rt_tables are intentionally
    // left alone.
    Ok(())
}

/// Create or reuse the tunnel toward `remote`.
fn ensure_vxlan(cfg: &Config, remote: IpAddr) -> Result<bool> {
    if let Some((local_addrs, peers)) = multipoint_return_vxlan(cfg) {
        let first = local_addrs.first().cloned().unwrap_or_else(|| {
            cfg.local_backend()
                .map(|b| b.overlay_ip)
                .unwrap_or_default()
        });
        let spec = vxlan_spec(cfg, remote, &first);
        return net::ensure_vxlan_multipoint(&spec, &local_addrs, &peers);
    }
    let overlay = cfg.local_backend()?.overlay_ip.clone();
    let spec = vxlan_spec(cfg, remote, &overlay);
    net::ensure_vxlan(&spec)
}

fn multipoint_return_vxlan(cfg: &Config) -> Option<(Vec<String>, Vec<IpAddr>)> {
    let mut local_addrs = Vec::new();
    let mut peers = Vec::new();
    for path in cfg.backend_return_paths() {
        if let Some(addr) = path.backend_overlay_ip {
            local_addrs.push(addr);
        }
        peers.push(path.gateway_underlay_ip);
    }
    if local_addrs.is_empty()
        && matches!(cfg.ha.active_source, ActiveSource::Xds)
        && cfg.gateway_nodes.len() > 1
    {
        for addr in ha_backend_overlay_addrs(cfg) {
            local_addrs.push(addr);
        }
        for gateway in &cfg.gateway_nodes {
            peers.push(gateway.underlay_ip);
        }
    }
    if local_addrs.is_empty() || peers.is_empty() {
        return None;
    }
    local_addrs.sort();
    local_addrs.dedup();
    peers.sort();
    peers.dedup();
    Some((local_addrs, peers))
}

fn ha_backend_overlay_addrs(cfg: &Config) -> Vec<String> {
    let Ok(local) = cfg.local_backend() else {
        return Vec::new();
    };
    let Ok((local_ip, local_prefix)) = parse_ipv4_cidr(&local.overlay_ip) else {
        return Vec::new();
    };
    let local_offset = host_offset(local_ip, local_prefix);
    // Claiming an address another node (or the gateway itself) already holds
    // wins ARP on the shared VNI and steals that node's return traffic, so
    // the mirror list skips every address assigned elsewhere in the inventory.
    let taken: Vec<Ipv4Addr> = cfg
        .backend_nodes_effective()
        .iter()
        .filter(|node| node.name != local.name)
        .filter_map(|node| parse_ipv4_cidr(&node.overlay_ip).ok().map(|(ip, _)| ip))
        .collect();
    let mut addrs = Vec::new();
    let mut warned_collisions = HashSet::new();
    for gateway in &cfg.gateway_nodes {
        let Ok((gateway_ip, prefix)) = parse_ipv4_cidr(&gateway.overlay_ip) else {
            continue;
        };
        let network = network_addr(gateway_ip, prefix);
        let candidate = network.saturating_add(local_offset);
        let candidate_ip = Ipv4Addr::from(candidate);
        if candidate_ip == gateway_ip {
            tracing::warn!(
                "[backend] overlay mirror {} collides with gateway {}; skipping",
                candidate_ip,
                gateway.name
            );
            continue;
        }
        if taken.contains(&candidate_ip) {
            if warned_collisions.insert(candidate_ip) {
                tracing::warn!(
                    "[backend] overlay mirror {} collides with another backend node; skipping",
                    candidate_ip
                );
            }
            continue;
        }
        if candidate == network {
            // offset 0 is the network address, never claimable
            continue;
        }
        addrs.push(format!("{candidate_ip}/{prefix}"));
    }
    addrs
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("missing prefix in overlay address {value:?}"))?;
    let ip = ip
        .parse::<Ipv4Addr>()
        .with_context(|| format!("bad overlay address {value:?}"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("bad overlay prefix {value:?}"))?;
    Ok((ip, prefix))
}

fn host_offset(ip: Ipv4Addr, prefix: u8) -> u32 {
    u32::from(ip) & !mask(prefix)
}

fn network_addr(ip: Ipv4Addr, prefix: u8) -> u32 {
    u32::from(ip) & mask(prefix)
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    }
}

fn vxlan_spec<'a>(cfg: &'a Config, remote: IpAddr, overlay: &'a str) -> VxlanSpec<'a> {
    let n = cfg.network();
    VxlanSpec {
        dev: &n.vxlan_dev,
        vni: n.vni,
        dstport: n.vxlan_port,
        remote: Some(remote),
        underlay_dev: &n.underlay_dev,
        local_addr: overlay,
        mtu: n.vxlan_mtu,
    }
}

/// Switch the return path to a new active gateway (remote + routes only;
/// nft rules and the rule itself are gateway-agnostic).
fn switch_active(cfg: &Config, gw: &GatewayNode) -> Result<()> {
    let overlay = cfg.local_backend()?.overlay_ip.clone();
    let spec = vxlan_spec(cfg, gw.underlay_ip, &overlay);
    net::set_vxlan_remote(&spec, gw.underlay_ip)?;
    return_path::ensure_policy_routing(cfg)?;
    Ok(())
}

/// Best-effort drift check used by `run` between failovers.
fn heal(cfg: &Config, active: IpAddr) -> Result<()> {
    let n = cfg.network();
    if !net::link_exists(&n.vxlan_dev) {
        anyhow::bail!("{} missing; re-apply required", n.vxlan_dev);
    }
    if !net::is_up(&n.vxlan_dev) {
        net::set_link(&n.vxlan_dev, n.vxlan_mtu, true).context("bringing vxlan back up")?;
    }
    // VXLAN FDB entries are runtime kernel state and can disappear after a
    // link reset, network reload, or cloud-network event. Re-append only the
    // peers owned by this backend; existing learned entries remain intact.
    if let Some((local_addrs, peers)) = multipoint_return_vxlan(cfg) {
        net::ensure_local_addrs(&n.vxlan_dev, &local_addrs)
            .context("healing backend VXLAN local addresses")?;
        net::sync_vxlan_peers(&n.vxlan_dev, &peers)
            .context("healing backend VXLAN peer FDB entries")?;
        tracing::debug!(
            "[backend] VXLAN peer reachability healed dev={} peers={:?}",
            n.vxlan_dev,
            peers
        );
    } else {
        let local = cfg.local_backend()?;
        let spec = vxlan_spec(cfg, active, &local.overlay_ip);
        net::ensure_vxlan(&spec).context("healing backend VXLAN remote")?;
    }
    return_path::heal(cfg)?;
    Ok(())
}

fn metrics_path(cfg: &Config) -> std::path::PathBuf {
    std::path::Path::new(&*cfg.state_dir).join("edge-lb-backend.prom")
}

fn write_metrics(cfg: &Config, active: &Option<String>, failovers: u64, heals: u64) {
    let mut text = String::new();
    if let Some(name) = active
        && let Ok(gw) = cfg.active_gateway()
    {
        text.push_str(&format!(
            "# TYPE edge_lb_backend_active_gateway gauge\n\
             edge_lb_backend_active_gateway{{gateway=\"{name}\",underlay=\"{}\"}} 1\n",
            gw.underlay_ip
        ));
    }
    text.push_str(&format!(
        "# TYPE edge_lb_backend_failovers_total counter\n\
         edge_lb_backend_failovers_total {failovers}\n\
         # TYPE edge_lb_backend_heals_total counter\n\
         edge_lb_backend_heals_total {heals}\n"
    ));
    let _ = std::fs::create_dir_all(&*cfg.state_dir);
    let tmp = metrics_path(cfg).with_extension("tmp");
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, metrics_path(cfg));
    }
}

fn section(title: &str) {
    println!("\n=== {title} ===");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BackendNode, FileConfig, HaConfig, NetworkConfig};
    use std::path::PathBuf;

    #[test]
    fn ha_backend_overlay_addrs_follow_gateway_cidrs() {
        let cfg = Config {
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
            file: FileConfig {
                node_name: "backend-1".to_string(),
                ha: HaConfig {
                    active_source: ActiveSource::Xds,
                    ..HaConfig::default()
                },
                network: NetworkConfig {
                    vxlan_dev: "edge-return".to_string(),
                    ..NetworkConfig::default()
                },
                gateway_nodes: vec![
                    GatewayNode {
                        name: "gateway-a".to_string(),
                        public_ip: "203.0.113.10".parse().unwrap(),
                        underlay_ip: "192.0.2.12".parse().unwrap(),
                        overlay_ip: "10.255.12.1/24".to_string(),
                    },
                    GatewayNode {
                        name: "gateway-b".to_string(),
                        public_ip: "203.0.113.11".parse().unwrap(),
                        underlay_ip: "192.0.2.16".parse().unwrap(),
                        overlay_ip: "10.255.16.1/24".to_string(),
                    },
                ],
                backend_nodes: vec![BackendNode {
                    name: "backend-1".to_string(),
                    public_ip: "198.51.100.20".parse().unwrap(),
                    underlay_ip: "192.0.2.14".parse().unwrap(),
                    overlay_ip: "10.255.16.2/24".to_string(),
                }],
                ..FileConfig::default()
            },
        };

        let addrs = ha_backend_overlay_addrs(&cfg);

        assert_eq!(
            addrs,
            vec!["10.255.12.2/24".to_string(), "10.255.16.2/24".to_string()]
        );
    }
}
