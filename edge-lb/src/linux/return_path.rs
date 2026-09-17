//! Backend nftables return-path facade.

use anyhow::Result;

use crate::config::{Config, GatewayReturnPath};

use super::{nft, route};

pub struct ManagedReturnPath {
    signature: ReturnPathSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReturnPathSignature {
    nft_table: String,
    vxlan_dev: String,
    mss: u32,
    paths: Vec<GatewayReturnPath>,
}

impl ManagedReturnPath {
    fn nft(signature: ReturnPathSignature) -> Self {
        Self { signature }
    }
}

pub fn apply(cfg: &Config) -> Result<()> {
    if cfg.backend_return_paths().is_empty() {
        nft::delete_table(cfg);
        return Ok(());
    }
    nft::apply(cfg)
}

pub fn apply_managed_reusing(
    cfg: &Config,
    existing: Option<ManagedReturnPath>,
) -> Result<ManagedReturnPath> {
    let signature = signature(cfg);
    if signature.paths.is_empty() {
        nft::delete_table(cfg);
    } else {
        let current = existing.as_ref().map(|managed| &managed.signature);
        if current != Some(&signature) || !nft::table_exists(cfg) {
            nft::apply(cfg)?;
        } else {
            tracing::debug!("[backend] return-path nft unchanged; skipping table rebuild");
        }
    }
    Ok(ManagedReturnPath::nft(signature))
}

pub fn ensure_policy_routing(cfg: &Config) -> Result<()> {
    route::ensure_policy_routing(cfg)
}

pub fn cleanup(cfg: &Config) -> Result<()> {
    nft::delete_table(cfg);
    route::cleanup_policy_routing(cfg);
    Ok(())
}

pub fn heal(cfg: &Config) -> Result<()> {
    if cfg.backend_return_paths().is_empty() {
        nft::delete_table(cfg);
    } else if !nft::table_exists(cfg) {
        nft::apply(cfg)?;
    }
    route::ensure_policy_routing(cfg)
}

fn signature(cfg: &Config) -> ReturnPathSignature {
    ReturnPathSignature {
        nft_table: cfg.backend_cfg().nft_table.clone(),
        vxlan_dev: cfg.network().vxlan_dev.clone(),
        mss: cfg.backend_cfg().mss,
        paths: cfg.backend_return_paths(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FileConfig, GatewayReturnPath};

    fn cfg() -> Config {
        let mut file = FileConfig::default();
        file.backend.nft_table = "edge_lb_backend_test".to_string();
        file.backend.mss = 1400;
        file.network.vxlan_dev = "edge-return".to_string();
        file.backend_return_paths = vec![GatewayReturnPath {
            gateway: Some("gateway-a".to_string()),
            gateway_underlay_ip: "192.0.2.1".parse().unwrap(),
            gateway_overlay_ip: "10.44.0.1".parse().unwrap(),
            backend_overlay_ip: Some("10.44.0.2/24".to_string()),
            dscp: 46,
            mark: crate::config::return_mark(46, 0),
            route_table_id: crate::config::return_table_id(46, 0),
        }];
        Config {
            path: "/unused/test.toml".into(),
            file,
        }
    }

    #[test]
    fn managed_signature_tracks_nft_ruleset_inputs() {
        let base = cfg();
        let base_sig = signature(&base);

        let mut changed_mss = cfg();
        changed_mss.file.backend.mss = 1360;
        assert_ne!(base_sig, signature(&changed_mss));

        let mut changed_dev = cfg();
        changed_dev.file.network.vxlan_dev = "edge-return-2".to_string();
        assert_ne!(base_sig, signature(&changed_dev));

        let mut changed_path = cfg();
        changed_path.file.backend_return_paths[0].dscp = 40;
        changed_path.file.backend_return_paths[0].mark = crate::config::return_mark(40, 0);
        changed_path.file.backend_return_paths[0].route_table_id =
            crate::config::return_table_id(40, 0);
        assert_ne!(base_sig, signature(&changed_path));
    }
}
