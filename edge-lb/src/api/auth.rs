use std::net::IpAddr;

use crate::config::Config;

pub(super) fn trusted_api_remote(cfg: &Config, ip: IpAddr) -> bool {
    if matches!(ip, IpAddr::V4(v) if v.is_loopback())
        || matches!(ip, IpAddr::V6(v) if v.is_loopback())
    {
        return true;
    }
    crate::runtime::access::source_allowed(ip, &api_trusted_source_cidrs(cfg)).unwrap_or(false)
}

pub(super) fn api_trusted_source_cidrs(cfg: &Config) -> Vec<String> {
    crate::runtime::access::api_trusted_source_cidrs(cfg)
}
