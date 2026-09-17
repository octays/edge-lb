//! Backend Redirect-only return-path facade.

use anyhow::Result;

use crate::config::{Config, GatewayReturnPath};

use super::backend_redirect;

pub struct ManagedReturnPath {
    signature: ReturnPathSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReturnPathSignature {
    vxlan_dev: String,
    underlay_dev: String,
    paths: Vec<GatewayReturnPath>,
}

impl ManagedReturnPath {
    fn redirect(signature: ReturnPathSignature) -> Self {
        Self { signature }
    }
}

pub fn apply(cfg: &Config) -> Result<()> {
    if cfg.backend_return_paths().is_empty() {
        backend_redirect::cleanup(cfg);
        return Ok(());
    }
    backend_redirect::apply(cfg)
}

pub fn apply_managed_reusing(
    cfg: &Config,
    existing: Option<ManagedReturnPath>,
) -> Result<ManagedReturnPath> {
    let signature = signature(cfg);
    let current = existing.as_ref().map(|managed| &managed.signature);
    if signature.paths.is_empty() {
        backend_redirect::cleanup(cfg);
    } else {
        if current != Some(&signature) {
            backend_redirect::apply(cfg)?;
        } else {
            backend_redirect::apply(cfg)?;
            tracing::debug!("[backend] return-path Redirect unchanged; attachment retained");
        }
    }
    Ok(ManagedReturnPath::redirect(signature))
}

pub fn cleanup(cfg: &Config) -> Result<()> {
    backend_redirect::cleanup(cfg);
    Ok(())
}

pub fn heal(cfg: &Config) -> Result<()> {
    if cfg.backend_return_paths().is_empty() {
        backend_redirect::cleanup(cfg);
    } else {
        backend_redirect::apply(cfg)?;
    }
    Ok(())
}

fn signature(cfg: &Config) -> ReturnPathSignature {
    ReturnPathSignature {
        vxlan_dev: cfg.network().vxlan_dev.clone(),
        underlay_dev: cfg.network().underlay_dev.clone(),
        paths: cfg.backend_return_paths(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FileConfig, GatewayReturnPath};

    fn cfg() -> Config {
        let mut file = FileConfig::default();
        file.network.vxlan_dev = "edge-return".to_string();
        file.network.underlay_dev = "eth-test".to_string();
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
    fn managed_signature_tracks_redirect_inputs() {
        let base = cfg();
        let base_sig = signature(&base);

        let mut changed_underlay = cfg();
        changed_underlay.file.network.underlay_dev = "eth-alt".to_string();
        assert_ne!(base_sig, signature(&changed_underlay));

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
