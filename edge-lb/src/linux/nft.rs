//! Backend nftables ruleset generation and application.

use anyhow::{Context, Result};

use crate::config::Config;

use super::nftables;

#[cfg(test)]
mod kernel_tests;

/// Diagnostic rendering only; runtime uses a native netlink transaction.
/// Business source/destination addresses are never replaced by tunnel addresses.
pub fn ruleset(cfg: &Config) -> String {
    let mut forward_rules = String::new();
    let mut reply_rules = String::new();
    for path in cfg.backend_return_paths() {
        forward_rules.push_str(&format!(
            "        meta nfproto ipv4 ct direction original ip dscp {dscp} counter ct mark set {mark:#x}\n",
            dscp = path.dscp,
            mark = path.mark,
        ));
        reply_rules.push_str(&format!(
            "        ct direction reply ct mark {mark:#x} counter meta mark set {mark:#x}\n",
            mark = path.mark,
        ));
    }
    format!(
        "table inet {table}\ndelete table inet {table}\n\ntable inet {table} {{\n\
         chain prerouting {{\n\
         type filter hook prerouting priority mangle; policy accept;\n\
{forward_rules}\
{reply_rules}\
         }}\n\
         chain output {{\n\
         type route hook output priority mangle; policy accept;\n\
{reply_rules}\
         }}\n\
         chain forward {{\n\
         type filter hook forward priority mangle; policy accept;\n\
         oifname \"{vx}\" tcp flags & (fin | syn | rst | ack) == syn counter tcp option maxseg size set {mss}\n\
         }}\n\
         }}\n",
        table = cfg.backend_cfg().nft_table,
        vx = cfg.network().vxlan_dev,
        mss = cfg.backend_cfg().mss,
    )
}

pub fn apply(cfg: &Config) -> Result<()> {
    cfg.validate_backend_return_paths()?;
    let dir = std::path::Path::new(&*cfg.state_dir);
    std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let file = dir.join("backend-return.nft");
    std::fs::write(&file, ruleset(cfg)).with_context(|| format!("writing {}", file.display()))?;
    nftables::apply_return_path(cfg)
}

pub fn table_exists(cfg: &Config) -> bool {
    nftables::table_exists(cfg)
}

pub fn delete_table(cfg: &Config) {
    nftables::delete_table(cfg).ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FileConfig, GatewayReturnPath};

    #[test]
    fn return_rules_preserve_business_addresses_and_use_original_direction_dscp() {
        let mut file = FileConfig::default();
        file.backend_return_paths = vec![GatewayReturnPath {
            gateway: None,
            gateway_underlay_ip: "192.0.2.1".parse().unwrap(),
            gateway_overlay_ip: "10.44.0.1".parse().unwrap(),
            backend_overlay_ip: Some("10.44.0.2/24".into()),
            dscp: 46,
            mark: crate::config::return_mark(46, 0),
            route_table_id: crate::config::return_table_id(46, 0),
        }];
        let cfg = Config {
            file,
            path: "/unused/test.toml".into(),
        };
        let rules = ruleset(&cfg);
        assert!(rules.contains("ct direction original ip dscp 46"));
        assert!(rules.contains("ct direction reply ct mark 0x106e"));
        assert!(!rules.contains("iifname"));
        assert!(!rules.contains("ip saddr set"));
        assert!(!rules.contains("udp_reply"));
        assert!(!rules.contains("udp sport"));
        assert!(!rules.contains("udp dport"));
    }
}
