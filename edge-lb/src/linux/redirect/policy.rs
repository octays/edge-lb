//! Pure routing-rule admission. This is not firewall or TC authorization.

use rtnetlink::packet_route::{
    AddressFamily,
    rule::{RuleAction, RuleAttribute, RuleMessage},
};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingPolicyState {
    StandardRules,
    UnsupportedRule,
    NonstandardOrder,
    IncompleteRules,
}

/// Accept only unconditional local/main[/default] lookups at canonical
/// priorities. Metadata is allowed, but unknown selectors must fail closed.
pub(super) fn inspect_rules(rules: &[RuleMessage]) -> RoutingPolicyState {
    let mut seen = [false; 3];
    for rule in rules {
        let header = &rule.header;
        if header.family != AddressFamily::Inet
            || header.src_len != 0
            || header.dst_len != 0
            || header.tos != 0
            || header.action != RuleAction::ToTable
            || !header.flags.is_empty()
        {
            return RoutingPolicyState::UnsupportedRule;
        }
        let mut table = None;
        let mut priority = None;
        for attribute in &rule.attributes {
            match attribute {
                RuleAttribute::Table(value) if table.is_none() => table = Some(*value),
                RuleAttribute::Priority(value) if priority.is_none() => priority = Some(*value),
                RuleAttribute::Protocol(_) => {}
                // Kernel uses this sentinel to mean no prefix suppression.
                RuleAttribute::SuppressPrefixLen(u32::MAX) => {}
                _ => return RoutingPolicyState::UnsupportedRule,
            }
        }
        let table = table.unwrap_or(u32::from(header.table));
        if header.table != 0 && u32::from(header.table) != table {
            return RoutingPolicyState::UnsupportedRule;
        }
        let slot = match (table, priority.unwrap_or(0)) {
            (255, 0) => 0,
            (254, 32766) => 1,
            (253, 32767) => 2,
            _ => return RoutingPolicyState::NonstandardOrder,
        };
        if seen[slot] {
            return RoutingPolicyState::NonstandardOrder;
        }
        seen[slot] = true;
    }
    if seen[0] && seen[1] {
        RoutingPolicyState::StandardRules
    } else {
        RoutingPolicyState::IncompleteRules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::packet_route::{
        route::RouteProtocol,
        rule::{RuleFlags, RulePortRange, RuleUidRange},
    };

    fn rules() -> Vec<RuleMessage> {
        [(255, 0), (254, 32766), (253, 32767)]
            .into_iter()
            .map(|(table, priority)| {
                let mut rule = RuleMessage::default();
                rule.header.family = AddressFamily::Inet;
                rule.header.action = RuleAction::ToTable;
                rule.header.table = table;
                rule.attributes = vec![
                    RuleAttribute::Table(u32::from(table)),
                    RuleAttribute::Priority(priority),
                    RuleAttribute::Protocol(RouteProtocol::Kernel),
                    RuleAttribute::SuppressPrefixLen(u32::MAX),
                ];
                rule
            })
            .collect()
    }

    #[test]
    fn standard_rules_allow_optional_default_and_omitted_zero_priority() {
        let mut rules = rules();
        assert_eq!(inspect_rules(&rules), RoutingPolicyState::StandardRules);
        rules.pop();
        rules[0]
            .attributes
            .retain(|attr| !matches!(attr, RuleAttribute::Priority(_)));
        rules.reverse();
        assert_eq!(inspect_rules(&rules), RoutingPolicyState::StandardRules);
    }

    #[test]
    fn selectors_cannot_authorize_destination_only_routes() {
        for attribute in [
            RuleAttribute::Source("192.0.2.1".parse().unwrap()),
            RuleAttribute::Destination("192.0.2.2".parse().unwrap()),
            RuleAttribute::FwMark(1),
            RuleAttribute::FwMask(0),
            RuleAttribute::Iifname("eth0".into()),
            RuleAttribute::Oifname("eth1".into()),
            RuleAttribute::L3MDev(true),
            RuleAttribute::UidRange(RuleUidRange { start: 0, end: 100 }),
            RuleAttribute::SourcePortRange(RulePortRange { start: 1, end: 2 }),
            RuleAttribute::DestinationPortRange(RulePortRange { start: 80, end: 80 }),
            RuleAttribute::SuppressPrefixLen(0),
        ] {
            let mut rules = rules();
            rules[1].attributes.push(attribute);
            assert_eq!(inspect_rules(&rules), RoutingPolicyState::UnsupportedRule);
        }
    }

    #[test]
    fn changed_headers_and_actions_fail_closed() {
        for index in 0..6 {
            let mut rules = rules();
            let header = &mut rules[1].header;
            match index {
                0 => header.family = AddressFamily::Inet6,
                1 => header.src_len = 8,
                2 => header.dst_len = 8,
                3 => header.tos = 184,
                4 => header.action = RuleAction::Blackhole,
                _ => header.flags = RuleFlags::from_bits_retain(2),
            }
            assert_eq!(inspect_rules(&rules), RoutingPolicyState::UnsupportedRule);
        }
    }

    #[test]
    fn incomplete_duplicate_and_reprioritized_rules_are_rejected() {
        assert_eq!(inspect_rules(&[]), RoutingPolicyState::IncompleteRules);
        assert_eq!(
            inspect_rules(&rules()[1..]),
            RoutingPolicyState::IncompleteRules
        );
        let mut duplicate = rules();
        duplicate.push(duplicate[1].clone());
        assert_eq!(
            inspect_rules(&duplicate),
            RoutingPolicyState::NonstandardOrder
        );
        let mut changed = rules();
        changed[1].attributes[1] = RuleAttribute::Priority(100);
        assert_eq!(
            inspect_rules(&changed),
            RoutingPolicyState::NonstandardOrder
        );
        changed[1].attributes[0] = RuleAttribute::Table(100);
        assert_eq!(inspect_rules(&changed), RoutingPolicyState::UnsupportedRule);
    }
}
