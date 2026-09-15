use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result, anyhow, bail};

use crate::config::Config;

pub fn underlay_device_cidr(cfg: &Config) -> Result<String> {
    crate::linux::net::interface_ipv4_cidr(&cfg.network().underlay_dev, cfg.underlay_ip).ok_or_else(
        || {
            anyhow!(
                "cannot derive trusted source CIDR from underlay_dev={} underlay_ip={}",
                cfg.network().underlay_dev,
                cfg.underlay_ip
            )
        },
    )
}

pub fn api_trusted_source_cidrs(cfg: &Config) -> Vec<String> {
    if !cfg.api.trusted_source_cidrs.is_empty() {
        return cfg.api.trusted_source_cidrs.clone();
    }
    crate::linux::net::interface_ipv4_cidr(&cfg.network().underlay_dev, cfg.underlay_ip)
        .or_else(|| fallback_underlay_cidr(cfg.underlay_ip))
        .into_iter()
        .collect()
}

pub fn metrics_trusted_source_cidrs(cfg: &Config) -> Result<Vec<String>> {
    let Some(metrics) = cfg.gateway.metrics.as_ref() else {
        return Ok(Vec::new());
    };
    if !metrics.trusted_source_cidrs.is_empty() {
        return Ok(metrics.trusted_source_cidrs.clone());
    }
    Ok(vec![underlay_device_cidr(cfg)?])
}

pub fn source_allowed(ip: IpAddr, cidrs: &[String]) -> Result<bool> {
    for cidr in cidrs {
        if ip_in_cidr(ip, cidr)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn ip_in_cidr(ip: IpAddr, cidr: &str) -> Result<bool> {
    let (base, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("CIDR missing prefix"))?;
    let base: IpAddr = base.parse().context("bad CIDR address")?;
    let prefix: u8 = prefix.parse().context("bad CIDR prefix")?;
    match (ip, base) {
        (IpAddr::V4(ip), IpAddr::V4(base)) => {
            if prefix > 32 {
                bail!("IPv4 prefix out of range");
            }
            Ok(masked_v4(ip, prefix) == masked_v4(base, prefix))
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) => {
            if prefix > 128 {
                bail!("IPv6 prefix out of range");
            }
            Ok(masked_v6(ip, prefix) == masked_v6(base, prefix))
        }
        _ => Ok(false),
    }
}

fn fallback_underlay_cidr(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v) if !v.is_unspecified() => {
            let octets = v.octets();
            Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
        }
        IpAddr::V6(v) if !v.is_unspecified() => Some(format!("{v}/64")),
        _ => None,
    }
}

fn masked_v4(ip: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    u32::from(ip) & mask
}

fn masked_v6(ip: std::net::Ipv6Addr, prefix: u8) -> u128 {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    };
    u128::from(ip) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matches_ipv4_boundaries() {
        assert!(ip_in_cidr("192.168.0.12".parse().unwrap(), "192.168.0.0/24").unwrap());
        assert!(!ip_in_cidr("192.168.1.12".parse().unwrap(), "192.168.0.0/24").unwrap());
        assert!(ip_in_cidr("10.1.2.3".parse().unwrap(), "0.0.0.0/0").unwrap());
        assert!(ip_in_cidr("10.1.2.3".parse().unwrap(), "10.1.2.3/32").unwrap());
    }

    #[test]
    fn cidr_matches_ipv6_boundaries() {
        assert!(ip_in_cidr("2001:db8::1".parse().unwrap(), "2001:db8::/64").unwrap());
        assert!(!ip_in_cidr("2001:db9::1".parse().unwrap(), "2001:db8::/64").unwrap());
        assert!(ip_in_cidr("2001:db8::1".parse().unwrap(), "::/0").unwrap());
    }

    #[test]
    fn mixed_ip_families_do_not_match() {
        assert!(!ip_in_cidr("192.168.0.12".parse().unwrap(), "2001:db8::/64").unwrap());
    }

    #[test]
    fn source_allowed_accepts_any_matching_cidr() {
        let cidrs = vec!["10.0.0.0/8".to_string(), "192.168.0.0/24".to_string()];
        assert!(source_allowed("192.168.0.12".parse().unwrap(), &cidrs).unwrap());
        assert!(!source_allowed("172.16.0.12".parse().unwrap(), &cidrs).unwrap());
    }
}
