use std::net::Ipv4Addr;

use serde::Serialize;

pub(super) struct ReturnContext {
    pub ingress: u32,
    pub outputs: std::collections::BTreeSet<u32>,
    pub sources: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteObservationState {
    Resolved,
    NonUnicast,
    UnsupportedRoute,
    MissingDevice,
    DeviceDown,
    UnsupportedDevice,
    InvalidMtu,
    InvalidSourceMac,
    MissingNeighbor,
    UnusableNeighbor,
    InvalidDestinationMac,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TargetRouteObservation {
    pub target: Ipv4Addr,
    pub state: RouteObservationState,
    pub ifindex: Option<u32>,
    pub device: Option<String>,
    pub mtu: Option<u32>,
    pub next_hop: Option<Ipv4Addr>,
    pub source_mac: Option<[u8; 6]>,
    pub destination_mac: Option<[u8; 6]>,
    pub neighbor_confirmed: bool,
}
