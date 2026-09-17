use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Result, bail};

use super::model::*;

pub fn normalize_config(mut config: AutomationConfig) -> Result<AutomationConfig> {
    for template in &mut config.templates {
        normalize_template(template)?;
    }
    validate_unique_templates(&config)?;
    Ok(config)
}

pub fn normalize_template(template: &mut AutomationTemplate) -> Result<()> {
    template.target_group.name = template.target_group.name.trim().to_string();
    if template.target_group.name.is_empty() {
        bail!("target group name is required");
    }
    template.name = format!("template-{}", template.target_group.name);
    if template.target_group.monitor {
        let probe_type = template
            .target_group
            .probe_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| "tcp".to_string());
        if !matches!(
            probe_type.as_str(),
            "none" | "ping" | "tcp" | "udp" | "http" | "https"
        ) {
            bail!("unsupported probe_type {probe_type}");
        }
        template.target_group.probe_type = Some(probe_type.clone());
        if matches!(probe_type.as_str(), "http" | "https") {
            let req = template
                .target_group
                .probe_req
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            if req.is_none() {
                bail!("HTTP/HTTPS probe request is required");
            }
            template.target_group.probe_req = req;
            template.target_group.probe_resp = template
                .target_group
                .probe_resp
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            if template.target_group.probe_skip_tls_verify && probe_type != "https" {
                bail!("skip TLS verification is only valid for HTTPS probes");
            }
        } else if matches!(probe_type.as_str(), "tcp" | "udp") {
            template.target_group.probe_req = template
                .target_group
                .probe_req
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            template.target_group.probe_resp = template
                .target_group
                .probe_resp
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            template.target_group.probe_skip_tls_verify = false;
        } else {
            template.target_group.probe_req = None;
            template.target_group.probe_resp = None;
            template.target_group.probe_skip_tls_verify = false;
        }
        if !matches!(probe_type.as_str(), "ping") && template.target_group.probe_port.is_none() {
            bail!("probe port is required for this probe type");
        }
        if template.target_group.period_secs.unwrap_or(15) == 0 {
            bail!("probe period must be in range 1..=65535");
        }
        template.target_group.period_secs = Some(template.target_group.period_secs.unwrap_or(15));
        template.target_group.retries = Some(template.target_group.retries.unwrap_or(3));
    } else {
        template.target_group.probe_type = Some("none".to_string());
        template.target_group.probe_req = None;
        template.target_group.probe_resp = None;
        template.target_group.probe_skip_tls_verify = false;
    }
    validate_template(template)
}

pub fn validate_template(template: &AutomationTemplate) -> Result<()> {
    if let Some(probe_port) = template.target_group.probe_port
        && probe_port == 0
    {
        bail!("probe port must be in range 1..=65535");
    }
    validate_filter(template.node_filter.as_ref())?;
    Ok(())
}

pub fn validate_unique_templates(config: &AutomationConfig) -> Result<()> {
    let mut seen_names = Vec::new();
    let mut seen_ports = Vec::new();
    for template in &config.templates {
        if seen_names.contains(&template.name) {
            bail!("duplicate automation template {}", template.name);
        }
        seen_names.push(template.name.clone());
        let key = template.target_group.name.clone();
        if let Some(owner) = seen_ports.iter().find(|(seen, _)| seen == &key) {
            bail!(
                "duplicate automation target group {} owned by {} and {}",
                key,
                owner.1,
                template.name
            );
        }
        seen_ports.push((key, template.name.clone()));
    }
    Ok(())
}

pub fn generated_target_group_name(template: &AutomationTemplate) -> String {
    template.target_group.name.clone()
}

fn validate_filter(filter: Option<&NodeFilter>) -> Result<()> {
    let Some(filter) = filter else {
        return Ok(());
    };
    for condition in &filter.conditions {
        let value = condition.value.trim();
        if value.is_empty() {
            bail!("filter condition value must not be empty");
        }
        match condition.op {
            FilterOp::Regex => {
                regex::Regex::new(value)?;
            }
            FilterOp::InCidr | FilterOp::NotInCidr => {
                validate_cidr(value)?;
            }
            _ => {}
        }
        match condition.field {
            FilterField::UnderlayIp | FilterField::PublicIp => {}
            _ if matches!(condition.op, FilterOp::InCidr | FilterOp::NotInCidr) => {
                bail!("CIDR filter operators are only valid for IP fields");
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_cidr(value: &str) -> Result<()> {
    let Some((ip, prefix)) = value.split_once('/') else {
        bail!("CIDR must include prefix");
    };
    if !matches!(ip.parse::<IpAddr>()?, IpAddr::V4(_)) {
        bail!("only IPv4 CIDR is supported");
    }
    let prefix: u8 = prefix.parse()?;
    if prefix > 32 {
        bail!("IPv4 CIDR prefix out of range");
    }
    Ok(())
}

pub fn ipv4_in_cidr(ip: Ipv4Addr, cidr: &str) -> Result<bool> {
    let (base, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR must include prefix"))?;
    let base: Ipv4Addr = base.parse()?;
    let prefix: u8 = prefix.parse()?;
    if prefix > 32 {
        bail!("IPv4 CIDR prefix out of range");
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    Ok(u32::from(ip) & mask == u32::from(base) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_and_target_group_names_use_target_group_name() {
        let mut template = AutomationTemplate {
            target_group: TargetGroupTemplate {
                name: "targets-a".to_string(),
                ..TargetGroupTemplate::default()
            },
            ..AutomationTemplate::default()
        };

        normalize_template(&mut template).unwrap();

        assert_eq!(template.name, "template-targets-a");
        assert_eq!(generated_target_group_name(&template), "targets-a");
    }

    #[test]
    fn duplicate_target_group_is_rejected_across_templates() {
        let mut config = AutomationConfig {
            templates: vec![
                AutomationTemplate {
                    target_group: TargetGroupTemplate {
                        name: "targets-a".to_string(),
                        ..TargetGroupTemplate::default()
                    },
                    ..AutomationTemplate::default()
                },
                AutomationTemplate {
                    target_group: TargetGroupTemplate {
                        name: "targets-a".to_string(),
                        ..TargetGroupTemplate::default()
                    },
                    ..AutomationTemplate::default()
                },
            ],
        };
        for template in &mut config.templates {
            normalize_template(template).unwrap();
        }

        assert!(validate_unique_templates(&config).is_err());
    }

    #[test]
    fn ipv4_cidr_matching_works() {
        assert!(ipv4_in_cidr("192.168.0.14".parse().unwrap(), "192.168.0.0/24").unwrap());
        assert!(!ipv4_in_cidr("192.168.1.14".parse().unwrap(), "192.168.0.0/24").unwrap());
    }

    #[test]
    fn tcp_probe_payload_is_trimmed_and_preserved() {
        let mut template = AutomationTemplate {
            target_group: TargetGroupTemplate {
                name: "targets-a".to_string(),
                monitor: true,
                probe_type: Some("tcp".to_string()),
                probe_port: Some(9999),
                probe_req: Some(" health ".to_string()),
                probe_resp: Some(" ok ".to_string()),
                probe_skip_tls_verify: true,
                ..TargetGroupTemplate::default()
            },
            ..AutomationTemplate::default()
        };

        normalize_template(&mut template).unwrap();

        assert_eq!(template.target_group.probe_req.as_deref(), Some("health"));
        assert_eq!(template.target_group.probe_resp.as_deref(), Some("ok"));
        assert!(!template.target_group.probe_skip_tls_verify);
    }
}
