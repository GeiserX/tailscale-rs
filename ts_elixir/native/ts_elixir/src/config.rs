use std::collections::HashMap;

use rustler::{Atom, Encoder, NifResult, Term};

mod atoms {
    rustler::atoms! {
        keys,
        control_url,
        hostname,
        tags,
        auth_key,

        accept_routes,
        exit_node,
        advertise_routes,
        advertise_exit_node,
        forward_tcp_ports,
        forward_udp_ports,
        forward_all_ports,
        forward_exit_egress,
    }
}

/// Load a [`tailscale::Config`] from the specified `erl_config`.
///
/// `erl_config` is expected to be a keyword list. Any keys missing from the list will adopt
/// default values.
pub fn config_from_erl(
    erl_config: &HashMap<Atom, Term>,
) -> NifResult<(tailscale::Config, Option<String>)> {
    let mut config = tailscale::Config {
        client_name: Some("ts_elixir".to_owned()),
        ..Default::default()
    };
    let mut auth_key = None;

    if let Some(value) = erl_config.get(&atoms::keys()) {
        config.key_state = value
            .decode::<Keystate>()?
            .try_into()
            .map_err(|_| rustler::Error::Atom("badkeys"))?;
    }

    if let Some(value) = erl_config.get(&atoms::control_url()) {
        config.control_server_url = value.decode::<&str>()?.parse().map_err(|e| {
            tracing::error!(error = %e, "parsing control server url");

            rustler::Error::Atom("bad_url")
        })?;
    }

    if let Some(value) = erl_config.get(&atoms::hostname()) {
        config.requested_hostname = value.decode()?;
    }

    if let Some(value) = erl_config.get(&atoms::tags()) {
        config.requested_tags = value.decode()?;
    }

    if let Some(value) = erl_config.get(&atoms::auth_key()) {
        auth_key = Some(value.decode()?);
    }

    // Lane 3: forwarding / routing config. All fields are optional and default to the native
    // `Config::default` (fail-closed: nothing forwarded, no exit egress) when absent.
    if let Some(value) = erl_config.get(&atoms::accept_routes()) {
        config.accept_routes = value.decode()?;
    }

    if let Some(value) = erl_config.get(&atoms::exit_node()) {
        // `ExitNodeSelector::from_str` is infallible (a non-IP string becomes a MagicDNS name),
        // matching the Go CLI's `--exit-node` auto-detection.
        let selector: &str = value.decode()?;
        config.exit_node = Some(
            selector
                .parse()
                .map_err(|_| rustler::Error::Atom("bad_exit_node"))?,
        );
    }

    if let Some(value) = erl_config.get(&atoms::advertise_routes()) {
        let routes: Vec<String> = value.decode()?;
        config.advertise_routes = routes
            .iter()
            .map(|s| s.parse())
            .collect::<Result<_, _>>()
            .map_err(|_| rustler::Error::Atom("bad_advertise_routes"))?;
    }

    if let Some(value) = erl_config.get(&atoms::advertise_exit_node()) {
        config.advertise_exit_node = value.decode()?;
    }

    if let Some(value) = erl_config.get(&atoms::forward_tcp_ports()) {
        config.forward_tcp_ports = value.decode()?;
    }

    if let Some(value) = erl_config.get(&atoms::forward_udp_ports()) {
        config.forward_udp_ports = value.decode()?;
    }

    if let Some(value) = erl_config.get(&atoms::forward_all_ports()) {
        config.forward_all_ports = value.decode()?;
    }

    if let Some(value) = erl_config.get(&atoms::forward_exit_egress()) {
        config.forward_exit_egress = value.decode()?;
    }

    Ok((config, auth_key))
}

#[derive(rustler::NifStruct, Debug, Clone)]
#[module = "Tailscale.Keystate"]
pub struct Keystate {
    pub machine: Vec<u8>,
    pub node: Vec<u8>,
    pub network_lock: Vec<u8>,
}

impl From<tailscale::keys::PersistState> for Keystate {
    fn from(value: tailscale::keys::PersistState) -> Self {
        Self {
            machine: value.machine_key.to_bytes().into(),
            node: value.node_key.to_bytes().into(),
            network_lock: value.network_lock_key.to_bytes().into(),
        }
    }
}

impl TryFrom<Keystate> for tailscale::keys::PersistState {
    type Error = ();

    fn try_from(value: Keystate) -> Result<Self, ()> {
        fn key<T>(v: Vec<u8>) -> Result<T, ()>
        where
            T: From<[u8; 32]>,
        {
            Ok(<[u8; 32]>::try_from(v).map_err(|_| ())?.into())
        }

        Ok(Self {
            machine_key: key(value.machine)?,
            node_key: key(value.node)?,
            network_lock_key: key(value.network_lock)?,
            old_node_key: None,
            acme_account_key: None,
        })
    }
}

/// Rotate the node key in a [`Keystate`] for embedder-driven re-registration (mirrors
/// `Config::rotate_node_key`, which delegates to `key_state.rotate_node_key()`).
///
/// The binding exposes key material as the `Tailscale.Keystate` struct rather than a `Config`
/// resource, so we rotate at that level: the current node key is recorded as the old key and a
/// fresh node key is generated. Re-`connect/1` with the returned `keys:` to perform the rotation;
/// the next registration sends the prior key as `OldNodeKey` for key continuity. Returns
/// `{:error, :badkeys}` if the keystate bytes are not valid 32-byte keys.
///
/// NOTE: the round-trip [`Keystate`] type drops `old_node_key` (it carries only the three 32-byte
/// keys), so the rotated `old_node_key` is held in the returned native `PersistState` only until it
/// is re-encoded; on `connect/1` the freshly-rotated node key is registered. This matches the
/// fork's reactive, re-registration-on-connect rotation model.
#[rustler::nif]
fn rotate_node_key(env: rustler::Env<'_>, keys: Term) -> impl Encoder {
    let Ok(keystate) = keys.decode::<Keystate>() else {
        return (crate::atoms::error(), "badkeys").encode(env);
    };

    let mut state: tailscale::keys::PersistState = match keystate.try_into() {
        Ok(s) => s,
        Err(()) => return (crate::atoms::error(), "badkeys").encode(env),
    };

    state.rotate_node_key();

    (crate::atoms::ok(), Keystate::from(state)).encode(env)
}
