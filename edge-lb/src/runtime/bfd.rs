//! Small native BFD-style liveness engine for the gateway HA pair.

use std::{
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    path::Path,
    sync::{Mutex, OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{
    config::Config,
    events::{self, EdgeEvent, Severity},
    runtime::{ha, shutdown},
};
use wren_bfd::{ControlPacket, Session, SessionConfig, State};

const AUTH_LEN: usize = 32;
const BFD_PACKET_LEN: usize = wren_bfd::MANDATORY_LEN + AUTH_LEN;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct BfdStatus {
    pub peer_ip: Option<String>,
    pub source_ip: Option<String>,
    pub state: String,
    pub last_rx_ms: Option<u128>,
    pub last_error: Option<String>,
}

static STATUS: OnceLock<Mutex<BfdStatus>> = OnceLock::new();

fn status() -> &'static Mutex<BfdStatus> {
    STATUS.get_or_init(|| {
        Mutex::new(BfdStatus {
            peer_ip: None,
            source_ip: None,
            state: "disabled".to_string(),
            last_rx_ms: None,
            last_error: None,
        })
    })
}

pub fn snapshot() -> BfdStatus {
    status().lock().expect("bfd status mutex poisoned").clone()
}

pub fn spawn(cfg: &Config) {
    let cfg = cfg.clone();
    let (election_tx, election_rx) = mpsc::sync_channel::<ElectionRequest>(8);
    thread::Builder::new()
        .name("edge-lb-ha-election".to_string())
        .stack_size(256 * 1024)
        .spawn(move || election_worker(election_rx))
        .expect("spawn HA election worker");
    thread::Builder::new()
        .name("edge-lb-bfd".to_string())
        .stack_size(256 * 1024)
        .spawn(move || {
            while !shutdown::requested() {
                run(&cfg, &election_tx);
                if !shutdown::requested() {
                    thread::sleep(Duration::from_secs(1));
                }
            }
        })
        .expect("spawn BFD worker");
}

#[derive(Debug)]
struct ElectionRequest {
    cfg: Config,
    ha_cfg: ha::GatewayHaRuntimeConfig,
    peer_was_up: bool,
}

fn election_worker(receiver: mpsc::Receiver<ElectionRequest>) {
    while !shutdown::requested() {
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(request) => reconcile_election(&request.cfg, &request.ha_cfg, request.peer_was_up),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn run(cfg: &Config, election_tx: &mpsc::SyncSender<ElectionRequest>) {
    let ha_cfg = match ha::load_for_state_dir(Path::new(&*cfg.state_dir)) {
        Ok(value) => value,
        Err(error) => {
            set_error(format!("loading HA config: {error:#}"));
            return;
        }
    };
    if !ha_cfg.enabled || !matches!(ha_cfg.failover, ha::FailoverMode::BfdAuto) {
        set_state("disabled", None, Some(cfg.underlay_ip.to_string()));
        return;
    }
    let Some(peer) = ha_cfg.peers.first() else {
        set_state("unconfigured", None, Some(cfg.underlay_ip.to_string()));
        return;
    };
    let Ok(peer_ip) = peer.underlay_ip.parse::<IpAddr>() else {
        set_error(format!("invalid BFD peer address {}", peer.underlay_ip));
        return;
    };
    let bind = format!("{}:{}", ha_cfg.bfd.bind_addr, ha_cfg.bfd.port);
    let socket = match UdpSocket::bind(&bind) {
        Ok(socket) => socket,
        Err(error) => {
            set_error(format!("binding {bind}: {error}"));
            return;
        }
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(ha_cfg.bfd.interval_ms.max(50))));
    let destination = SocketAddr::new(peer_ip, ha_cfg.bfd.port);
    let local_disc = discriminator(cfg.underlay_ip);
    let tx_token = match ha::load_secrets_for_state_dir(Path::new(&*cfg.state_dir)) {
        Ok(Some(secret)) if !secret.session_token.is_empty() => secret.session_token,
        Ok(_) => {
            set_error("BFD peer token is unavailable".to_string());
            return;
        }
        Err(error) => {
            set_error(format!("loading BFD peer token: {error:#}"));
            return;
        }
    };
    let rx_token = tx_token.clone();
    let mut last_rx = None;
    let mut last_tx = Instant::now() - Duration::from_secs(1);
    let mut session = Session::new(
        local_disc,
        SessionConfig {
            desired_min_tx_us: u32::try_from(ha_cfg.bfd.interval_ms.max(50).saturating_mul(1000))
                .unwrap_or(u32::MAX),
            required_min_rx_us: u32::try_from(ha_cfg.bfd.interval_ms.max(50).saturating_mul(1000))
                .unwrap_or(u32::MAX),
            detect_mult: u8::try_from(ha_cfg.bfd.detect_multiplier.max(1)).unwrap_or(u8::MAX),
        },
    );
    let detection = Duration::from_millis(
        ha_cfg.bfd.interval_ms.max(50) * u64::from(ha_cfg.bfd.detect_multiplier.max(1)),
    );
    let mut was_up = false;
    set_state(
        "down",
        Some(peer_ip.to_string()),
        Some(cfg.underlay_ip.to_string()),
    );
    while !shutdown::requested() {
        if last_tx.elapsed() >= Duration::from_millis(ha_cfg.bfd.interval_ms.max(50)) {
            let packet = authenticated_packet(&session.build_control(), &tx_token);
            if let Err(error) = socket.send_to(&packet, destination) {
                tracing::warn!(
                    "[bfd] peer={} send {} -> {} failed: {}",
                    peer.name,
                    bind,
                    destination,
                    error
                );
                set_error(format!("sending BFD packet: {error}"));
            }
            last_tx = Instant::now();
        }
        let mut buffer = [0_u8; 64];
        match socket.recv_from(&mut buffer) {
            Ok((size, source)) if source.ip() == peer_ip => {
                if let Some(control) = parse(&buffer[..size], &rx_token) {
                    let transition = session.on_packet(&control);
                    last_rx = Some(Instant::now());
                    was_up = matches!(session.state(), State::Up);
                    set_state(
                        if was_up { "up" } else { "negotiating" },
                        Some(peer_ip.to_string()),
                        Some(cfg.underlay_ip.to_string()),
                    );
                    if let Some(transition) = transition {
                        tracing::debug!(
                            "[bfd] peer={} state={}->{} discriminator={}",
                            peer.name,
                            transition.from.label(),
                            transition.to.label(),
                            control.my_discr
                        );
                        publish_bfd_transition(
                            cfg,
                            &peer.name,
                            peer_ip,
                            transition.from.label(),
                            transition.to.label(),
                        );
                        // Election and VIP updates may perform filesystem,
                        // netlink, and peer API work. Run them only on an FSM
                        // transition; invoking them for every heartbeat can
                        // block this receive loop and make BFD flap.
                        queue_election(election_tx, cfg, &ha_cfg, was_up);
                    }
                }
            }
            Ok((_size, source)) => {
                tracing::debug!(
                    "[bfd] ignored packet from unexpected source {}",
                    source.ip()
                );
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => set_error(format!("receiving BFD packet: {error}")),
        }
        if last_rx.is_none_or(|received| received.elapsed() > detection) {
            if was_up {
                tracing::warn!("[bfd] peer={} down after {:?}", peer.name, detection);
            }
            let peer_was_up = was_up;
            was_up = false;
            session.on_detect_timeout();
            set_state(
                "down",
                Some(peer_ip.to_string()),
                Some(cfg.underlay_ip.to_string()),
            );
            if peer_was_up {
                publish_bfd_transition(cfg, &peer.name, peer_ip, "up", "down");
                queue_election(election_tx, cfg, &ha_cfg, peer_was_up);
            }
        }
    }
    set_state(
        "stopped",
        Some(peer_ip.to_string()),
        Some(cfg.underlay_ip.to_string()),
    );
}

fn queue_election(
    election_tx: &mpsc::SyncSender<ElectionRequest>,
    cfg: &Config,
    ha_cfg: &ha::GatewayHaRuntimeConfig,
    peer_was_up: bool,
) {
    if let Err(error) = election_tx.try_send(ElectionRequest {
        cfg: cfg.clone(),
        ha_cfg: ha_cfg.clone(),
        peer_was_up,
    }) {
        tracing::warn!("[bfd] HA election request dropped: {error}");
    }
}

fn reconcile_election(cfg: &Config, ha_cfg: &ha::GatewayHaRuntimeConfig, peer_was_up: bool) {
    let state = snapshot().state;
    let already_local = cfg
        .active_gateway()
        .map(|gateway| gateway.name == cfg.node_name || gateway.underlay_ip == cfg.underlay_ip)
        .unwrap_or(false);
    let active_is_peer = cfg
        .active_gateway()
        .ok()
        .zip(ha_cfg.peers.first())
        .is_some_and(|(active, peer)| {
            active.name == peer.name || active.underlay_ip.to_string() == peer.underlay_ip
        });
    let active_peer_reachable = active_is_peer
        && !peer_was_up
        && ha_cfg
            .peers
            .first()
            .is_some_and(|peer| peer_control_plane_reachable(cfg, ha_cfg, peer));

    if state == "up"
        && already_local
        && let Some(peer) = ha_cfg.peers.first()
        && peer_reports_newer_master(cfg, peer)
    {
        tracing::info!(
            "[bfd] adopting newer active gateway state from peer {}",
            peer.name
        );
        if let Err(error) = crate::provider::native::ha::switch_active_gateway(cfg, &peer.name) {
            tracing::warn!(
                "[bfd] failed to adopt newer active gateway state from {}: {error:#}",
                peer.name
            );
            publish_ha_state_change(
                cfg,
                events::HA_SWITCHOVER_FAILED,
                Severity::Critical,
                "HA state adoption failed",
                format!(
                    "Failed to adopt newer active gateway state from {}: {error:#}.",
                    peer.name
                ),
                serde_json::json!({ "target": peer.name, "source": "bfd" }),
            );
        } else {
            publish_ha_state_change(
                cfg,
                events::HA_STATE_CHANGED,
                Severity::Warning,
                "HA state changed",
                format!("Adopted newer active gateway state from {}.", peer.name),
                serde_json::json!({ "active_gateway": peer.name, "source": "bfd" }),
            );
        }
        return;
    }

    let should_promote = should_promote_local(
        &cfg.node_name,
        ha_cfg.preferred_active.as_deref(),
        &state,
        peer_was_up,
        active_is_peer,
        active_peer_reachable,
    );
    if should_promote && !already_local {
        tracing::info!(
            "[bfd] promoting local gateway {} state={} peer_was_up={} active_is_peer={} active_peer_reachable={} preferred_active={:?}",
            cfg.node_name,
            state,
            peer_was_up,
            active_is_peer,
            active_peer_reachable,
            ha_cfg.preferred_active
        );
        if let Err(error) = crate::provider::native::ha::switch_active_gateway(cfg, &cfg.node_name)
        {
            tracing::warn!("[bfd] failed to promote {}: {error:#}", cfg.node_name);
            publish_ha_state_change(
                cfg,
                events::HA_SWITCHOVER_FAILED,
                Severity::Critical,
                "HA BFD promotion failed",
                format!(
                    "Failed to promote {} after BFD peer failure: {error:#}.",
                    cfg.node_name
                ),
                serde_json::json!({ "target": cfg.node_name, "source": "bfd" }),
            );
        } else {
            publish_ha_state_change(
                cfg,
                events::HA_STATE_CHANGED,
                Severity::Critical,
                "HA BFD promotion",
                format!("{} became MASTER after BFD peer failure.", cfg.node_name),
                serde_json::json!({ "active_gateway": cfg.node_name, "source": "bfd" }),
            );
        }
    }
}

fn publish_bfd_transition(cfg: &Config, peer_name: &str, peer_ip: IpAddr, from: &str, to: &str) {
    if from == to {
        return;
    }
    let severity = if to.eq_ignore_ascii_case("up") {
        Severity::Info
    } else if to.eq_ignore_ascii_case("down") {
        Severity::Warning
    } else {
        Severity::Info
    };
    events::publish(
        EdgeEvent::new(
            events::BFD_STATE_CHANGED,
            severity,
            &cfg.node_name,
            "gateway",
            "BFD state changed",
            format!("BFD peer {peer_name} changed from {from} to {to}."),
        )
        .with_details(serde_json::json!({
            "peer": peer_name,
            "peer_ip": peer_ip.to_string(),
            "from": from,
            "to": to,
        })),
    );
}

fn publish_ha_state_change(
    cfg: &Config,
    kind: &str,
    severity: Severity,
    title: impl Into<String>,
    text: impl Into<String>,
    details: serde_json::Value,
) {
    events::publish(
        EdgeEvent::new(kind, severity, &cfg.node_name, "gateway", title, text)
            .with_details(details),
    );
}

fn should_promote_local(
    local_name: &str,
    preferred_active: Option<&str>,
    bfd_state: &str,
    peer_was_up: bool,
    active_is_peer: bool,
    active_peer_reachable: bool,
) -> bool {
    match bfd_state {
        // A healthy session is not an election trigger.  In particular, do
        // not let the preferred node reclaim MASTER after a manual failover;
        // that creates a dual-master window while both peers are healthy.
        "up" => false,
        "down" => {
            // Before a session has ever been established, only the preferred
            // gateway may become MASTER, and only when the active record does
            // not already point at the peer. If the recorded active gateway is
            // the peer, the non-preferred survivor may take over after the
            // peer control plane is unreachable. A preferred gateway that is
            // recovering after failover must not use the startup Down window
            // to preempt the current active peer; it may only take back over
            // after it first observed the peer Up and then timed out.
            peer_was_up
                || (active_is_peer
                    && !active_peer_reachable
                    && preferred_active != Some(local_name))
                || (!active_is_peer && preferred_active == Some(local_name))
        }
        _ => false,
    }
}

fn peer_control_plane_reachable(
    cfg: &Config,
    ha_cfg: &ha::GatewayHaRuntimeConfig,
    peer: &ha::GatewayHaPeer,
) -> bool {
    let target = peer.xds_addr.as_deref().and_then(|addr| addr.parse().ok());
    let target = target.or_else(|| {
        let port = cfg
            .control_plane
            .listen
            .parse::<SocketAddr>()
            .map(|addr| addr.port())
            .unwrap_or(ha_cfg.xsync.port);
        let ip = peer.underlay_ip.parse::<IpAddr>().ok()?;
        Some(SocketAddr::new(ip, port))
    });
    let Some(target) = target else {
        return false;
    };
    TcpStream::connect_timeout(&target, Duration::from_millis(250)).is_ok()
}

fn peer_reports_newer_master(cfg: &Config, peer: &ha::GatewayHaPeer) -> bool {
    let local_revision = cfg.active_gateway_revision().ok().flatten().unwrap_or(0);
    let Ok(response) = crate::runtime::ha_write::get_peer(cfg, peer, "/api/v1/ha/peer/status")
    else {
        return false;
    };
    if !(200..300).contains(&response.status) {
        return false;
    }
    peer_status_is_newer_master(&response.body, peer, local_revision)
}

fn peer_status_is_newer_master(body: &str, peer: &ha::GatewayHaPeer, local_revision: i64) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(native) = value.get("native") else {
        return false;
    };
    let state = native.get("state").and_then(|value| value.as_str());
    if state != Some("MASTER") {
        return false;
    }
    let active = native
        .get("active_gateway")
        .and_then(|value| value.as_str());
    let node = native.get("node").and_then(|value| value.as_str());
    let peer_is_active = active
        .zip(node)
        .is_some_and(|(active, node)| active == node && (node == peer.name || active == peer.name));
    if !peer_is_active {
        return false;
    }
    let peer_revision = native
        .get("active_revision")
        .and_then(|value| value.as_i64())
        .unwrap_or(0);
    peer_revision > local_revision
}

fn authenticated_packet(control: &ControlPacket, token: &str) -> [u8; BFD_PACKET_LEN] {
    let encoded = control.encode();
    let mut packet = [0_u8; BFD_PACKET_LEN];
    packet[..wren_bfd::MANDATORY_LEN].copy_from_slice(&encoded);
    let mut mac = HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC accepts any key");
    mac.update(&encoded);
    packet[wren_bfd::MANDATORY_LEN..].copy_from_slice(&mac.finalize().into_bytes());
    packet
}

fn parse(packet: &[u8], token: &str) -> Option<ControlPacket> {
    if packet.len() < BFD_PACKET_LEN {
        tracing::debug!(
            "[bfd] discarded short packet len={} expected={}",
            packet.len(),
            BFD_PACKET_LEN
        );
        return None;
    }
    let Ok(mut mac) = HmacSha256::new_from_slice(token.as_bytes()) else {
        return None;
    };
    mac.update(&packet[..wren_bfd::MANDATORY_LEN]);
    if mac
        .verify_slice(&packet[wren_bfd::MANDATORY_LEN..BFD_PACKET_LEN])
        .is_err()
    {
        tracing::debug!(
            "[bfd] discarded packet with invalid authentication peer payload_len={} token_id={}",
            packet.len(),
            token_id(token)
        );
        return None;
    }
    // The HMAC is an edge-lb transport trailer, not part of the standard
    // wren_bfd control packet. Decode only the mandatory BFD header.
    let decoded = ControlPacket::decode(&packet[..wren_bfd::MANDATORY_LEN]);
    if decoded.is_none() {
        tracing::debug!("[bfd] discarded authenticated malformed control packet");
    }
    decoded
}

fn token_id(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn discriminator(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(ip) => u32::from(ip),
        IpAddr::V6(ip) => ip
            .segments()
            .iter()
            .fold(0_u32, |hash, part| hash.rotate_left(5) ^ u32::from(*part)),
    }
}

fn set_state(state_value: &str, peer_ip: Option<String>, source_ip: Option<String>) {
    let mut value = status().lock().expect("bfd status mutex poisoned");
    value.state = state_value.to_string();
    value.peer_ip = peer_ip;
    value.source_ip = source_ip;
    value.last_error = None;
    if state_value == "up" {
        value.last_rx_ms = Some(0);
    }
}

fn set_error(error: String) {
    let mut value = status().lock().expect("bfd status mutex poisoned");
    value.state = "error".to_string();
    value.last_error = Some(error);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, time::SystemTime};

    use crate::config::{
        ActiveSource, Config, FileConfig, GatewayNode, HaConfig, NetworkConfig, NodeRole,
    };

    #[test]
    fn packet_round_trip() {
        let control = ControlPacket {
            diag: wren_bfd::Diag::None,
            state: State::Down,
            poll: false,
            final_: false,
            cpi: false,
            demand: false,
            detect_mult: 3,
            my_discr: 12,
            your_discr: 0,
            desired_min_tx: 1_000_000,
            required_min_rx: 1_000_000,
            required_min_echo_rx: 0,
            auth_present: false,
        };
        let packet = authenticated_packet(&control, "secret");
        assert_eq!(parse(&packet, "secret").map(|p| p.my_discr), Some(12));
        assert_eq!(parse(&packet, "wrong").map(|p| p.my_discr), None);
    }

    #[test]
    fn invalid_packet_is_ignored() {
        assert_eq!(parse(b"invalid", "secret"), None);
    }

    #[test]
    fn preferred_gateway_wins_initial_election() {
        assert!(should_promote_local(
            "gateway-a",
            Some("gateway-a"),
            "down",
            false,
            false,
            false
        ));
        assert!(!should_promote_local(
            "gateway-b",
            Some("gateway-a"),
            "down",
            false,
            false,
            false
        ));
    }

    #[test]
    fn backup_promotes_after_established_peer_failure() {
        assert!(should_promote_local(
            "gateway-b",
            Some("gateway-a"),
            "down",
            true,
            false,
            false
        ));
    }

    #[test]
    fn bfd_promotion_marks_native_proxy_dirty_when_owner_changes() {
        let (cfg, ha_cfg, dir) = test_gateway_config("bfd-promote");
        ha::save_for_state_dir(&dir, &ha_cfg).unwrap();
        fs::write(&cfg.ha.active_state_file, "gateway-a\n").unwrap();
        set_state(
            "down",
            Some("192.0.2.12".to_string()),
            Some("192.0.2.16".to_string()),
        );
        let _ = crate::provider::native::take_state_dirty();

        reconcile_election(&cfg, &ha_cfg, true);

        assert_eq!(cfg.active_gateway().unwrap().name, "gateway-b");
        assert!(crate::provider::native::take_state_dirty());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn backup_promotes_when_recorded_active_peer_is_down() {
        assert!(should_promote_local(
            "gateway-b",
            Some("gateway-a"),
            "down",
            false,
            true,
            false
        ));
    }

    #[test]
    fn preferred_gateway_does_not_preempt_reachable_active_peer() {
        assert!(!should_promote_local(
            "gateway-a",
            Some("gateway-a"),
            "down",
            false,
            true,
            true
        ));
    }

    #[test]
    fn preferred_gateway_does_not_preempt_unreachable_active_peer_before_observed_up() {
        assert!(!should_promote_local(
            "gateway-a",
            Some("gateway-a"),
            "down",
            false,
            true,
            false
        ));
    }

    #[test]
    fn healthy_peer_does_not_preempt_manual_failover() {
        assert!(!should_promote_local(
            "gateway-a",
            Some("gateway-a"),
            "up",
            true,
            false,
            false
        ));
    }

    #[test]
    fn healthy_peer_does_not_revert_non_preferred_master() {
        assert!(!should_promote_local(
            "gateway-b",
            Some("gateway-a"),
            "up",
            true,
            false,
            false
        ));
    }

    #[test]
    fn peer_status_revision_controls_stale_master_convergence() {
        let peer = ha::GatewayHaPeer {
            name: "gateway-b".to_string(),
            underlay_ip: "192.0.2.2".to_string(),
            ..Default::default()
        };
        let newer = r#"{
            "native": {
                "node": "gateway-b",
                "active_gateway": "gateway-b",
                "active_revision": 20,
                "state": "MASTER"
            }
        }"#;
        assert!(peer_status_is_newer_master(newer, &peer, 10));
        assert!(!peer_status_is_newer_master(newer, &peer, 20));

        let backup = r#"{
            "native": {
                "node": "gateway-b",
                "active_gateway": "gateway-b",
                "active_revision": 30,
                "state": "BACKUP"
            }
        }"#;
        assert!(!peer_status_is_newer_master(backup, &peer, 10));

        let other_active = r#"{
            "native": {
                "node": "gateway-b",
                "active_gateway": "gateway-a",
                "active_revision": 30,
                "state": "MASTER"
            }
        }"#;
        assert!(!peer_status_is_newer_master(other_active, &peer, 10));
    }

    #[test]
    fn bfd_authentication_uses_one_session_token_for_both_directions() {
        let peer = ha::GatewayIdentity {
            name: "gateway-b".to_string(),
            underlay_ip: "192.0.2.2".to_string(),
            public_ip: "198.51.100.2".to_string(),
            api_addr: "192.0.2.2:18080".to_string(),
            xds_addr: "192.0.2.2:22222".to_string(),
            overlay_cidr: "10.1.0.0/24".to_string(),
            overlay_ip: "10.1.0.1/24".to_string(),
            dscp: 40,
            vni: 100,
            vxlan_port: 4789,
            mtu: 1450,
            version: "test".to_string(),
            capabilities: Vec::new(),
        };
        let secret = ha::new_session_token_secret(&peer, "ha-session-token".to_string());
        assert_eq!(secret.session_token, "ha-session-token");
    }

    fn test_gateway_config(name: &str) -> (Config, ha::GatewayHaRuntimeConfig, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "edge-lb-bfd-datapath-contract-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let active_state_file = dir.join("active-gateway");
        let file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-b".to_string(),
            public_ip: "198.51.100.16".parse().unwrap(),
            underlay_ip: "192.0.2.16".parse().unwrap(),
            state_dir: dir.clone(),
            ha: HaConfig {
                active_source: ActiveSource::File,
                active_state_file,
                ..HaConfig::default()
            },
            network: NetworkConfig {
                gateway_public_ip: "198.51.100.16".parse().unwrap(),
                gateway_ip: "192.0.2.16".parse().unwrap(),
                underlay_dev: "eth0".to_string(),
                vxlan_dev: "edge-hub".to_string(),
                overlay_cidr: "10.255.16.0/24".to_string(),
                dscp: 40,
                ..NetworkConfig::default()
            },
            gateway_nodes: vec![
                GatewayNode {
                    name: "gateway-a".to_string(),
                    public_ip: "198.51.100.12".parse().unwrap(),
                    underlay_ip: "192.0.2.12".parse().unwrap(),
                    overlay_ip: "10.255.12.1/24".to_string(),
                },
                GatewayNode {
                    name: "gateway-b".to_string(),
                    public_ip: "198.51.100.16".parse().unwrap(),
                    underlay_ip: "192.0.2.16".parse().unwrap(),
                    overlay_ip: "10.255.16.1/24".to_string(),
                },
            ],
            ..FileConfig::default()
        };
        let ha_cfg = ha::GatewayHaRuntimeConfig {
            enabled: true,
            peers: vec![ha::GatewayHaPeer {
                name: "gateway-a".to_string(),
                underlay_ip: "192.0.2.12".to_string(),
                ..ha::GatewayHaPeer::default()
            }],
            vip: ha::VipConfig {
                provider: ha::VipProvider::Hook,
                ..ha::VipConfig::default()
            },
            ..ha::GatewayHaRuntimeConfig::default()
        };
        (
            Config {
                file,
                path: dir.join("config.toml"),
            },
            ha_cfg,
            dir,
        )
    }
}
