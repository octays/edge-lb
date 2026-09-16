//! Validation of the DSCP-only backend return-path contract.

use std::collections::HashSet;

use anyhow::{Result, ensure};

use super::GatewayReturnPath;

pub(super) fn validate(paths: &[GatewayReturnPath]) -> Result<()> {
    let mut dscps = HashSet::new();
    let mut marks = HashSet::new();
    let mut tables = HashSet::new();
    for path in paths {
        ensure!(
            (1..=63).contains(&path.dscp),
            "return-path DSCP must be in 1..=63, got {}",
            path.dscp
        );
        ensure!(path.mark != 0, "return-path mark must not be zero");
        ensure!(
            path.route_table_id != 0,
            "return-path table must not be zero"
        );
        ensure!(
            dscps.insert(path.dscp),
            "ambiguous return-path DSCP {}",
            path.dscp
        );
        ensure!(
            marks.insert(path.mark),
            "ambiguous return-path mark {}",
            path.mark
        );
        ensure!(
            tables.insert(path.route_table_id),
            "ambiguous return-path table {}",
            path.route_table_id
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(dscp: u32, slot: u32) -> GatewayReturnPath {
        GatewayReturnPath {
            gateway: None,
            gateway_underlay_ip: "192.0.2.1".parse().unwrap(),
            gateway_overlay_ip: "10.44.0.1".parse().unwrap(),
            backend_overlay_ip: Some("10.44.0.2/24".into()),
            dscp,
            mark: crate::config::return_mark(dscp, slot),
            route_table_id: crate::config::return_table_id(dscp, slot),
        }
    }

    #[test]
    fn rejects_ambiguous_or_unmarked_contracts() {
        assert!(validate(&[]).is_ok());
        assert!(validate(&[path(46, 0), path(40, 1)]).is_ok());
        for value in [0, 64, u32::MAX] {
            assert!(validate(&[path(value, 0)]).is_err());
        }
        assert!(validate(&[path(46, 0), path(46, 1)]).is_err());
        let a = path(46, 0);
        for field in 0..4 {
            let mut b = path(40, 1);
            match field {
                0 => b.mark = 0,
                1 => b.mark = a.mark,
                2 => b.route_table_id = 0,
                _ => b.route_table_id = a.route_table_id,
            }
            assert!(validate(&[a.clone(), b]).is_err());
        }
    }
}
