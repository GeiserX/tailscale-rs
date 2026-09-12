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
mod set_dns;
mod ssh_policy;
mod tka_bootstrap;
mod tka_info;
mod tka_mutation;
mod tka_sync;
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
pub use env_type::EnvType;
pub use host_info::HostInfo;
pub use id_token::{TokenRequest, TokenResponse};
pub use net_info::{DerpLatencyMap, LinkType, NetInfo};
pub use netmap::{
    DisplayMessage, DisplayMessageAction, Endpoint, EndpointType, MapRequest, MapResponse,
    PeerChange,
};
pub use node::{MarshaledSignature, Node, NodeId, StableNodeId};
pub use ping::{PingRequest, PingResponse, PingType};
pub use register::{RegisterAuth, RegisterRequest, RegisterResponse, SignatureType};
pub use service::{Service, ServiceProto};
pub use service_vip::{
    C2NVIPServicesResponse, NODE_ATTR_PREFIX_SERVICES, NODE_ATTR_SERVICE_HOST,
    NODE_ATTR_SUGGEST_EXIT_NODE, ProtoPortRange, SERVICE_ACTION_ATTRIBUTE_RESOURCE_NAME,
    SERVICE_ACTION_ATTRIBUTE_SKIP_USERNAME, SERVICE_ACTION_ATTRIBUTE_WEB_CLIENT_URL,
    SERVICE_ACTION_TYPE_AWS_S3, SERVICE_ACTION_TYPE_COCKROACH_DB,
    SERVICE_ACTION_TYPE_ELASTIC_SEARCH, SERVICE_ACTION_TYPE_HTTP, SERVICE_ACTION_TYPE_KUBERNETES,
    SERVICE_ACTION_TYPE_MONGO_DB, SERVICE_ACTION_TYPE_MSSQL, SERVICE_ACTION_TYPE_MYSQL,
    SERVICE_ACTION_TYPE_POSTGRESQL, SERVICE_ACTION_TYPE_RDP, SERVICE_ACTION_TYPE_SSH,
    SERVICE_ACTION_TYPE_TCP, SERVICE_ACTION_TYPE_VNC, SERVICE_ACTION_TYPES, SERVICE_NAME_PREFIX,
    ServiceAction, ServiceActionType, ServiceDetails, ServiceIpMappings, ServiceName, VipService,
    VipServiceOwned,
};
pub use set_dns::{SetDnsRequest, SetDnsResponse};
pub use ssh_policy::{SSHAction, SSHPolicy, SSHPrincipal, SSHRecorderFailureAction, SSHRule};
pub use tka_bootstrap::{TkaBootstrapRequest, TkaBootstrapResponse};
pub use tka_info::TkaInfo;
pub use tka_mutation::{
    TkaDisableRequest, TkaDisableResponse, TkaInitBeginRequest, TkaInitBeginResponse,
    TkaInitFinishRequest, TkaInitFinishResponse, TkaSignInfo, TkaSubmitSignatureRequest,
    TkaSubmitSignatureResponse,
};
pub use tka_sync::{
    TkaSyncOfferRequest, TkaSyncOfferResponse, TkaSyncSendRequest, TkaSyncSendResponse,
};
pub use tpm::TpmInfo;
pub use user::{Login, LoginId, User, UserId, UserProfile};
