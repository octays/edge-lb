use super::{FileConfig, IpDiscoveryConfig, NodeRole, defaults::default_node_name};

pub(super) fn render_user_toml(file: &FileConfig) -> String {
    let mut out = String::new();
    out.push_str(&format!("node_role = {:?}\n", role_str(file.node_role),));
    if file.node_name != default_node_name() {
        out.push_str(&format!("node_name = {:?}\n", file.node_name));
    }
    out.push_str(&format!(
        "public_ip = \"auto\"\nunderlay_ip = \"auto\"\nlog_level = {:?}\nstate_dir = {:?}\n\n",
        file.log_level,
        file.state_dir.display().to_string(),
    ));
    render_discovery(&mut out, &file.discovery);
    match file.node_role {
        NodeRole::Gateway => {
            render_gateway_sections(file, &mut out);
        }
        NodeRole::Backend => {
            render_backend_sections(file, &mut out);
        }
    }
    out
}

fn render_discovery(out: &mut String, d: &IpDiscoveryConfig) {
    out.push_str("[discovery]\n");
    if let Some(value) = &d.public_ip_env {
        out.push_str(&format!("public_ip_env = {value:?}\n"));
    }
    if let Some(value) = &d.underlay_ip_env {
        out.push_str(&format!("underlay_ip_env = {value:?}\n"));
    }
    if let Some(value) = &d.underlay_dev_env {
        out.push_str(&format!("underlay_dev_env = {value:?}\n"));
    }
    out.push_str(&format!(
        "stun_servers = {:?}\nudp_probe_addr = {:?}\n\n",
        d.stun_servers, d.udp_probe_addr
    ));
}

fn render_gateway_sections(file: &FileConfig, out: &mut String) {
    let n = &file.network;
    out.push_str("[gateway.reconcile]\n");
    out.push_str(&format!(
        "interval_secs = {}\n\n",
        file.ha.watch_interval_secs
    ));

    out.push_str("[gateway.xds]\n");
    out.push_str(&format!("listen = {:?}\n", file.control_plane.listen));
    if let Some(token) = &file.control_plane.token {
        out.push_str(&format!("token = {token:?}\n"));
    }
    out.push_str(&format!(
        "trusted_source_cidrs = {:?}\n",
        file.control_plane.trusted_source_cidrs
    ));
    out.push('\n');

    out.push_str("[gateway.network]\n");
    let vxlan_mtu = if n.vxlan_mtu_auto {
        "\"auto\"".to_string()
    } else {
        n.vxlan_mtu.to_string()
    };
    out.push_str(&format!(
        "overlay_cidr = {:?}\nunderlay_dev = \"auto\"\nvxlan_dev = {:?}\nvni = {}\nvxlan_port = {}\nvxlan_mtu = {}\ndscp = {}\n\n",
        n.overlay_cidr, n.vxlan_dev, n.vni, n.vxlan_port, vxlan_mtu, n.dscp
    ));

    out.push_str("[gateway.api]\n");
    out.push_str(&format!("listen = {:?}\n", file.api.listen));
    if let Some(token) = &file.api.auth_token {
        out.push_str(&format!("auth_token = {token:?}\n"));
    }
    out.push_str(&format!(
        "trusted_source_cidrs = {:?}\n",
        file.api.trusted_source_cidrs
    ));
    out.push('\n');

    let metrics = file.gateway.metrics.clone().unwrap_or_default();
    out.push_str("[gateway.metrics]\n");
    out.push_str(&format!("enabled = {}\n", metrics.enabled));
    out.push_str(&format!("listen = {:?}\n", metrics.listen));
    out.push_str(&format!(
        "trusted_source_cidrs = {:?}\n",
        metrics.trusted_source_cidrs
    ));
    out.push('\n');
}

fn render_backend_sections(file: &FileConfig, out: &mut String) {
    out.push_str("[backend.xds]\n");
    let gateway_addrs = file
        .gateway_nodes
        .iter()
        .map(|gateway| {
            format!(
                "{}:{}",
                gateway.underlay_ip,
                file.control_plane.gateway_port.unwrap_or(22222)
            )
        })
        .collect::<Vec<_>>();
    if gateway_addrs.len() > 1 {
        out.push_str(&format!("gateways = {:?}\n", gateway_addrs));
    } else if let Some(gateway) = gateway_addrs.first() {
        out.push_str(&format!("gateway = {gateway:?}\n"));
    } else {
        out.push_str("gateway = \"\"\n");
    }
    if let Some(token) = &file.control_plane.token {
        out.push_str(&format!("token = {token:?}\n"));
    }
    out.push_str(&format!(
        "reconnect_interval_secs = {}\n\n",
        file.ha.watch_interval_secs
    ));

    out.push_str("[backend.return_path]\n");
    out.push_str(&format!(
        "vxlan_dev = {:?}\nnft_table = {:?}\nmss = {}\n",
        file.network.vxlan_dev, file.backend.nft_table, file.backend.mss
    ));
}

fn role_str(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Backend => "backend",
        NodeRole::Gateway => "gateway",
    }
}
