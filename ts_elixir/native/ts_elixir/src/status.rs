//! Lane 1: `status`, `whois`, and a netmap snapshot accessor.
//!
//! Marshals the native [`tailscale::Status`] / [`tailscale::StatusNode`] / [`tailscale::WhoIs`]
//! types into Elixir structs (`Tailscale.Status`, `Tailscale.StatusNode`, `Tailscale.WhoIs`).
//! Per the native contract, `online`/`user`/`capabilities` are honestly surfaced as their
//! actual (empty/`None`) values in this fork — never fabricated.

use rustler::{Encoder, ResourceArc, Term};

use crate::{Device, NodeInfo, TOKIO_RUNTIME, atoms, ip_to_erl, sockaddr_from_erl};

#[derive(rustler::NifStruct)]
#[module = "Tailscale.StatusNode"]
struct StatusNode<'a> {
    stable_id: String,
    display_name: String,
    ipv4: Term<'a>,
    ipv6: Term<'a>,
    /// `true` / `false` / `nil` (always `nil` in this fork — see native contract).
    online: Option<bool>,
    /// Allowed routes as CIDR strings (e.g. `"100.64.0.1/32"`, `"0.0.0.0/0"`).
    allowed_routes: Vec<String>,
    is_exit_node: bool,
}

impl<'a> StatusNode<'a> {
    fn from_node(env: rustler::Env<'a>, value: tailscale::StatusNode) -> Self {
        Self {
            stable_id: value.stable_id.0,
            display_name: value.display_name,
            ipv4: ip_to_erl(env, value.ipv4),
            ipv6: ip_to_erl(env, value.ipv6),
            online: value.online,
            allowed_routes: value
                .allowed_routes
                .iter()
                .map(ToString::to_string)
                .collect(),
            is_exit_node: value.is_exit_node,
        }
    }
}

#[derive(rustler::NifStruct)]
#[module = "Tailscale.Status"]
struct Status<'a> {
    self_node: Option<StatusNode<'a>>,
    peers: Vec<StatusNode<'a>>,
}

impl<'a> Status<'a> {
    fn from_status(env: rustler::Env<'a>, value: tailscale::Status) -> Self {
        Self {
            self_node: value.self_node.map(|n| StatusNode::from_node(env, n)),
            peers: value
                .peers
                .into_iter()
                .map(|n| StatusNode::from_node(env, n))
                .collect(),
        }
    }
}

#[derive(rustler::NifStruct)]
#[module = "Tailscale.WhoIs"]
struct WhoIs<'a> {
    node: NodeInfo<'a>,
    /// Owning user login, if known (always `nil` in this fork — see native contract).
    user: Option<String>,
    /// Capability map as a list of `{capability, [args]}` tuples (always empty in this fork).
    capabilities: Vec<Term<'a>>,
}

impl<'a> WhoIs<'a> {
    fn from_whois(env: rustler::Env<'a>, value: tailscale::WhoIs) -> Self {
        Self {
            node: NodeInfo::from_node(env, value.node),
            user: value.user,
            capabilities: value
                .capabilities
                .into_iter()
                .map(|(cap, args)| (cap, args).encode(env))
                .collect(),
        }
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn status(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { dev.status().await }) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(status) => (atoms::ok(), Status::from_status(env, status)).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn whois(env: rustler::Env<'_>, dev: ResourceArc<Device>, addr: Term) -> impl Encoder {
    let dev = dev.inner.clone();
    let Some(sockaddr) = sockaddr_from_erl(addr) else {
        return env.error_tuple("invalid sockaddr");
    };

    match TOKIO_RUNTIME.block_on(async move { dev.whois(sockaddr).await }) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(None) => (atoms::ok(), Option::<()>::None).encode(env),
        Ok(Some(whois)) => (atoms::ok(), WhoIs::from_whois(env, whois)).encode(env),
    }
}

/// Snapshot the current netmap (the peer set the netmap watcher currently holds).
///
/// This is the in-process equivalent of reading the latest value from
/// [`tailscale::Device::watch_netmap`]: it returns the current set of peer [`StatusNode`]s
/// without subscribing to future updates (the BEAM has no idiomatic place to push a Rust
/// `watch::Receiver`, so we expose a pull-based snapshot).
#[rustler::nif(schedule = "DirtyIo")]
fn netmap(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move {
        let rx = dev.watch_netmap().await?;
        Ok::<_, tailscale::Error>(rx.borrow().clone())
    }) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(nodes) => (
            atoms::ok(),
            nodes
                .into_iter()
                .map(|n| StatusNode::from_node(env, n))
                .collect::<Vec<_>>(),
        )
            .encode(env),
    }
}
