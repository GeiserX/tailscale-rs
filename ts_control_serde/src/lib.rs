#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod client_version;
mod debug;
mod derp_map;
mod dial_plan;
mod dns;
mod env_type;
mod host_info;
mod id_token;
mod location;
mod net_info;
mod netmap;
mod node;
mod ping;
mod register;
mod service;
mod service_vip;
mod ssh_policy;
mod tka_info;
mod tpm;
mod user;
pub mod util;

pub use debug::Debug;
pub use derp_map::{
    DerpMap, DerpServer, IpUsage as DerpIpUsage, Region as DerpRegion, RegionId as DerpRegionId,
};
pub use dial_plan::{ControlDialPlan, ControlIpCandidate};
pub use dns::{
    Config as DnsConfig, Record as DnsRecord, Resolver as DnsResolver,
    ResolverAddr as DnsResolverAddr,
};
pub use host_info::HostInfo;
pub use id_token::{TokenRequest, TokenResponse};
pub use net_info::{DerpLatencyMap, LinkType, NetInfo};
pub use netmap::{Endpoint, EndpointType, MapRequest, MapResponse};
pub use node::{MarshaledSignature, Node, NodeId, StableNodeId};
pub use ping::{PingRequest, PingResponse, PingType};
pub use register::{RegisterAuth, RegisterRequest, RegisterResponse, SignatureType};
pub use service::{Service, ServiceProto};
pub use service_vip::{
    NODE_ATTR_SERVICE_HOST, ProtoPortRange, SERVICE_NAME_PREFIX, ServiceIpMappings, ServiceName,
    VipService,
};
pub use ssh_policy::{SSHAction, SSHPolicy, SSHPrincipal, SSHRecorderFailureAction, SSHRule};
pub use tka_info::TkaInfo;
pub use tpm::TpmInfo;
pub use user::{Login, LoginId, User, UserId, UserProfile};
