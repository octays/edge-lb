use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::config::{Config, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeProtocol {
    Tcp,
    Udp,
}

impl NativeProtocol {
    pub fn ip_proto(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

impl TryFrom<Protocol> for NativeProtocol {
    type Error = anyhow::Error;

    fn try_from(value: Protocol) -> Result<Self> {
        match value {
            Protocol::Tcp => Ok(Self::Tcp),
            Protocol::Udp => Ok(Self::Udp),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeListenerKey {
    pub vip_ip: Ipv4Addr,
    pub vip_port: u16,
    pub protocol: NativeProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTarget {
    /// Backend target address in the native datapath map.
    pub address: Ipv4Addr,
    /// Forwarding port owned by the listener configuration.
    pub port: u16,
    pub weight: u32,
    pub state: NativeTargetState,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NativeTargetState {
    #[default]
    Active,
    Inactive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeListener {
    pub name: String,
    pub target_group: String,
    pub key: NativeListenerKey,
    pub select: u32,
    pub inactive_timeout_secs: u32,
    pub dscp: u32,
    pub targets: Vec<NativeTarget>,
}

pub fn listeners_from_config(cfg: &Config) -> Result<Vec<NativeListener>> {
    if !cfg.listeners.is_empty() {
        let mut out = Vec::new();
        for listener in &cfg.listeners {
            let group = cfg
                .target_groups
                .iter()
                .find(|group| group.name == listener.target_group)
                .with_context(|| {
                    format!(
                        "listener {} references missing target group {}",
                        listener.name, listener.target_group
                    )
                })?;
            out.extend(listener_from_target_group(cfg, listener, group)?);
        }
        return Ok(out);
    }

    Ok(Vec::new())
}

fn listener_from_target_group(
    cfg: &Config,
    listener: &crate::config::Listener,
    group: &crate::config::TargetGroup,
) -> Result<Vec<NativeListener>> {
    let targets = group
        .targets
        .iter()
        .map(|target| {
            let address = ipv4_addr(cfg.resolve_backend_target_address(target))?;
            Ok(NativeTarget {
                address,
                port: listener.target_port,
                weight: target.weight,
                state: NativeTargetState::Active,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if targets.is_empty() {
        // Automatic target groups may legitimately be empty while no backend
        // matches their filter. Keep the control-plane resource, but omit it
        // from the native datapath until a backend appears.
        return Ok(Vec::new());
    }

    let mut listeners = Vec::new();
    let listener_vips = effective_vip_ips(cfg, &listener.vip_ips)?;
    for vip_ip in listener_vips {
        for protocol in &listener.protocols {
            listeners.push(NativeListener {
                name: listener.name.clone(),
                target_group: group.name.clone(),
                key: NativeListenerKey {
                    vip_ip,
                    vip_port: listener.port,
                    protocol: NativeProtocol::try_from(*protocol)?,
                },
                select: listener.select.code(),
                inactive_timeout_secs: listener.inactive_timeout.unwrap_or(240),
                dscp: cfg.network().dscp,
                targets: targets.clone(),
            });
        }
    }
    Ok(listeners)
}

pub fn effective_vip_ips(cfg: &Config, configured: &[IpAddr]) -> Result<Vec<Ipv4Addr>> {
    let gateway = ipv4_addr(cfg.network().gateway_ip)
        .context("native datapath needs an IPv4 gateway address")?;
    let shared = crate::runtime::ha::load_for_state_dir(Path::new(&*cfg.state_dir))
        .ok()
        .filter(|ha| ha.enabled && matches!(ha.vip.provider, crate::runtime::ha::VipProvider::L2))
        .and_then(|ha| ha.vip.private_vip)
        .and_then(|vip| vip.parse::<IpAddr>().ok())
        .and_then(|vip| ipv4_addr(vip).ok());
    merge_vip_ips(gateway, configured, shared)
}

fn merge_vip_ips(
    gateway: Ipv4Addr,
    configured: &[IpAddr],
    shared: Option<Ipv4Addr>,
) -> Result<Vec<Ipv4Addr>> {
    let mut values = vec![gateway];
    for vip in configured {
        let vip = ipv4_addr(*vip)?;
        if !values.contains(&vip) {
            values.push(vip);
        }
    }
    if let Some(vip) = shared
        && !values.contains(&vip)
    {
        values.push(vip);
    }
    Ok(values)
}

fn ipv4_addr(value: IpAddr) -> Result<Ipv4Addr> {
    match value {
        IpAddr::V4(v4) if !v4.is_unspecified() => Ok(v4),
        IpAddr::V4(_) => bail!("IP address must not be 0.0.0.0"),
        IpAddr::V6(v6) => bail!("native datapath does not support IPv6 yet: {v6}"),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{
        BackendNode, BackendTarget, Config, DEFAULT_CONFIG_PATH, FileConfig, LbMode, Listener,
        Protocol, TargetGroup,
    };

    use super::*;

    #[test]
    fn registered_backend_does_not_replace_service_address_with_overlay() {
        let mut file = FileConfig::default();
        file.network.gateway_ip = "192.0.2.10".parse().unwrap();
        file.backend_nodes.push(BackendNode {
            name: "backend-1".into(),
            public_ip: "198.51.100.20".parse().unwrap(),
            underlay_ip: "192.0.2.20".parse().unwrap(),
            overlay_ip: "10.255.255.2/24".into(),
        });
        file.target_groups.push(TargetGroup {
            name: "service".into(),
            targets: vec![BackendTarget {
                backend: Some("backend-1".into()),
                address: "192.0.2.20".parse().unwrap(),
                weight: 1,
            }],
            ..TargetGroup::default()
        });
        file.listeners.push(Listener {
            name: "service".into(),
            port: 80,
            target_port: 8080,
            target_group: "service".into(),
            protocols: vec![Protocol::Tcp, Protocol::Udp],
            ..Listener::default()
        });
        let mut cfg = Config {
            file,
            path: DEFAULT_CONFIG_PATH.into(),
        };
        for select in [
            crate::config::LbSelect::Rr,
            crate::config::LbSelect::Hash,
            crate::config::LbSelect::ConsistentHash,
        ] {
            cfg.file.listeners[0].select = select;
            let listeners = listeners_from_config(&cfg).unwrap();
            assert_eq!(listeners.len(), 2);
            for listener in listeners {
                assert_eq!(listener.targets[0].address, Ipv4Addr::new(192, 0, 2, 20));
                assert_eq!(listener.targets[0].port, 8080);
            }
        }
    }

    #[test]
    fn listener_conversion_preserves_default_dnat_shape() {
        let mut cfg = FileConfig::default();
        cfg.network.gateway_ip = "192.0.2.10".parse().unwrap();
        cfg.network.dscp = 46;
        cfg.target_groups.push(TargetGroup {
            name: "tcp-8080-targets".to_string(),
            targets: vec![BackendTarget {
                backend: None,
                address: Ipv4Addr::new(192, 0, 2, 20).into(),
                weight: 3,
            }],
            ..TargetGroup::default()
        });
        cfg.listeners.push(Listener {
            name: "tcp-8080".to_string(),
            port: 8080,
            target_port: 18080,
            target_group: "tcp-8080-targets".to_string(),
            protocols: vec![Protocol::Tcp],
            mode: LbMode::Default,
            ..Listener::default()
        });

        let cfg = Config {
            file: cfg,
            path: DEFAULT_CONFIG_PATH.into(),
        };
        let listeners = listeners_from_config(&cfg).unwrap();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].key.vip_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(listeners[0].key.vip_port, 8080);
        assert_eq!(listeners[0].key.protocol, NativeProtocol::Tcp);
        assert_eq!(listeners[0].dscp, 46);
        assert_eq!(
            listeners[0].targets[0].address,
            Ipv4Addr::new(192, 0, 2, 20)
        );
        assert_eq!(listeners[0].targets[0].port, 18080);
        assert_eq!(listeners[0].targets[0].weight, 3);
    }

    #[test]
    fn empty_target_group_is_not_a_datapath_error() {
        let mut cfg = Config {
            path: std::path::PathBuf::from("/tmp/edge-lb-test.toml"),
            file: FileConfig::default(),
        };
        cfg.file.target_groups.push(TargetGroup {
            name: "empty".to_string(),
            ..TargetGroup::default()
        });
        cfg.file.listeners.push(Listener {
            name: "tcp-80".to_string(),
            port: 80,
            target_port: 8080,
            target_group: "empty".to_string(),
            ..Listener::default()
        });
        assert!(listeners_from_config(&cfg).unwrap().is_empty());
    }

    #[test]
    fn target_group_targets_are_expanded_with_weights() {
        let mut file = FileConfig::default();
        file.network.gateway_ip = "192.0.2.10".parse().unwrap();
        file.target_groups.push(TargetGroup {
            name: "api-targets".to_string(),
            targets: vec![
                BackendTarget {
                    backend: None,
                    address: "192.0.2.20".parse().unwrap(),
                    weight: 2,
                },
                BackendTarget {
                    backend: None,
                    address: "192.0.2.21".parse().unwrap(),
                    weight: 5,
                },
            ],
            ..TargetGroup::default()
        });
        file.listeners.push(crate::config::Listener {
            name: "api".to_string(),
            port: 8080,
            target_group: "api-targets".to_string(),
            protocols: vec![Protocol::Tcp],
            mode: LbMode::Default,
            ..crate::config::Listener::default()
        });

        let cfg = Config {
            file,
            path: DEFAULT_CONFIG_PATH.into(),
        };
        let listeners = listeners_from_config(&cfg).unwrap();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].targets.len(), 2);
        assert_eq!(listeners[0].targets[0].weight, 2);
        assert_eq!(listeners[0].targets[1].weight, 5);
    }

    #[test]
    fn listener_vip_list_expands_to_independent_runtime_keys() {
        let mut file = FileConfig::default();
        file.network.gateway_ip = "192.0.2.1".parse().unwrap();
        file.target_groups.push(TargetGroup {
            name: "api-targets".to_string(),
            targets: vec![BackendTarget {
                address: "192.0.2.20".parse().unwrap(),
                weight: 1,
                ..BackendTarget::default()
            }],
            ..TargetGroup::default()
        });
        file.listeners.push(crate::config::Listener {
            name: "api".to_string(),
            port: 8080,
            target_group: "api-targets".to_string(),
            vip_ips: vec!["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()],
            ..crate::config::Listener::default()
        });

        let cfg = Config {
            file,
            path: DEFAULT_CONFIG_PATH.into(),
        };
        let listeners = listeners_from_config(&cfg).unwrap();

        assert_eq!(listeners.len(), 3);
        assert_eq!(listeners[0].key.vip_ip, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(listeners[1].key.vip_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(listeners[2].key.vip_ip, Ipv4Addr::new(192, 0, 2, 11));
    }

    #[test]
    fn shared_vip_is_installed_for_backup_datapath() {
        let values = merge_vip_ips(
            Ipv4Addr::new(192, 0, 2, 1),
            &[],
            Some(Ipv4Addr::new(192, 0, 2, 100)),
        )
        .unwrap();
        assert_eq!(
            values,
            vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 100)]
        );
    }
}
