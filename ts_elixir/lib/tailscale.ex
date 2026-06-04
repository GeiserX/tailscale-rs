defmodule Tailscale do
  @moduledoc """
  Elixir bindings for the Tailscale Rust client.

  ## Nomenclature (devices, peers, nodes, etc.)

  In our parlance, anything that shows up on console.tailscale.com
  and gets a tailnet IP is known canonically as a "device", though these are also variously been
  referred to as "nodes" or "peers". Conventionally, each of these would be a device running
  `tailscaled`, but with the advent of `tsnet` and now `tailscale-rs` and its derivative
  cross-language clients, a single computer can have many Tailscale connections simultaneously,
  possibly to many different tailnets. As an attempt to capture the whole ontology of "things that
  have a persistent identity and tailnet IP", we try to refer to them uniformly by the umbrella term
  "device".
  """

  @typedoc """
  An IPv4 address.
    
  `tailscale` is capable of interpreting either the `m::inet` format or a `String`.
  """
  @type ip4_addr() :: :inet.ip4_address() | String.t()

  @typedoc """
  An IPv6 address.
    
  `tailscale` is capable of interpreting either the `m::inet` format or a `String`.
  """
  @type ip6_addr() :: :inet.ip6_address() | String.t()

  @typedoc """
  An IP address (v4 or v6).
    
  `tailscale` is capable of interpreting either the `m::inet` format or a `String`.
  """
  @type ip_addr() :: ip4_addr() | ip6_addr()

  @typedoc """
  Handle to a tailscale "device", i.e. a unique tailnet-connected identity with a network address.
  See the note in `connect/2` about nomenclature for more details.
  """
  @opaque t() :: Tailscale.Native.device()

  @typedoc """
  Options for connecting to Tailscale:

  - `auth_key`: the auth key to use to authorize this device. You only need to supply this if the
    device's keys aren't authorized.
  - `keys`: the `m:Tailscale.Keystate` to use to connect. This defines the device identity.
  - `hostname`: the hostname this device will request. If omitted, uses the hostname the OS reports.
  - `tags`: tags the device will request.
  - `control_url`: the url of the control server to use.

  ## Forwarding / routing options (Lane 3)

  All default to a fail-closed value (nothing forwarded, no exit egress) when omitted.

  - `accept_routes`: whether to accept (and route traffic to) subnet routes advertised by peers.
  - `exit_node`: the peer to route internet-bound traffic through, as a tailnet IP or MagicDNS
    name string (auto-detected like the Go CLI's `--exit-node`).
  - `advertise_routes`: subnet routes to advertise as a subnet router, a list of CIDR strings.
  - `advertise_exit_node`: whether to advertise this node as an exit node.
  - `forward_tcp_ports`: TCP ports the inbound forwarder splices to real OS sockets.
  - `forward_udp_ports`: UDP ports the inbound forwarder splices to real OS sockets.
  - `forward_all_ports`: forward all TCP/UDP ports on every advertised route.
  - `forward_exit_egress`: whether exit-node flows actually egress via this host's real IP
    (anti-leak opt-in, separate from `advertise_exit_node`).
  """
  @type options :: [
          auth_key: String.t(),
          keys: Tailscale.Keystate.t(),
          control_url: String.t(),
          hostname: String.t(),
          tags: [String.t()],
          accept_routes: boolean(),
          exit_node: String.t(),
          advertise_routes: [String.t()],
          advertise_exit_node: boolean(),
          forward_tcp_ports: [:inet.port_number()],
          forward_udp_ports: [:inet.port_number()],
          forward_all_ports: boolean(),
          forward_exit_egress: boolean()
        ]

  @spec connect(String.t(), options()) :: {:ok, t()} | {:error, any()}
  @doc """
  Open a connection to tailscale, creating a device connected to a tailnet. Loads key state from
  the given path, creating it if it doesn't exist.

  See `t:options/0` for details on available options.
  """
  def connect(key_file_path, options) when is_binary(key_file_path) do
    case Tailscale.Native.load_key_file(key_file_path) do
      {:ok, keys} ->
        Keyword.put(options, :keys, keys) |> connect()

      err ->
        err
    end
  end

  @spec connect(options() | String.t()) :: {:ok, t()} | {:error, any()}
  @doc """
  Open a connection to Tailscale, creating a device connected to a tailnet. If the argument is a
  `m:String`, this is equivalent to `connect/2` with an empty option list.

  See `t:options/0` for details on available options. You may want to call `connect/2` for an easier
  way to load key state from a file.
  """
  def connect(options \\ [])

  def connect(options) when is_list(options),
    do: :proplists.to_map(options) |> Tailscale.Native.connect()

  def connect(key_file_path) when is_binary(key_file_path), do: connect(key_file_path, [])

  @spec ipv4_addr(t()) :: {:ok, :inet.ip4_address()} | {:error, any()}
  @doc """
  Get the current IPv4 address of this Tailscale node.
    
  Blocks until the address is available.
  """
  def ipv4_addr(dev), do: Tailscale.Native.ipv4_addr(dev)

  @spec ipv6_addr(t()) :: {:ok, :inet.ip6_address()} | {:error, any()}
  @doc """
  Get the current IPv6 address of this Tailscale node.
    
  Blocks until the address is available.

  Note that this address is in `t::inet.ip6_address/0` format (16-bit segments), which may be
  difficult to read. See `:inet.ntoa/1` to format to a string.
  """
  def ipv6_addr(dev), do: Tailscale.Native.ipv6_addr(dev)

  @spec self_node(t()) :: {:ok, Tailscale.NodeInfo.t()} | {:error, any()}
  @doc """
  Get this node's `m:Tailscale.NodeInfo`.
  """
  defdelegate self_node(dev), to: Tailscale.Native

  @spec peer_by_name(t(), String.t()) :: {:ok, Tailscale.NodeInfo.t() | nil} | {:error, any()}
  @doc """
  Look up a peer by name.

  Returns `{:ok, nil}` if there was no such peer, and `{:error, reason}` if the lookup encountered
  an error.
  """
  def peer_by_name(dev, name), do: Tailscale.Native.peer_by_name(dev, name)

  @spec peer_by_tailnet_ip(t(), Tailscale.ip_addr()) ::
          {:ok, Tailscale.NodeInfo.t() | nil} | {:error, any()}
  @doc """
  Look up the peer with the given tailnet IP address.

  Returns `{:ok, nil}` if there was no such peer. `:error` if the lookup encountered an error.
  """
  defdelegate peer_by_tailnet_ip(dev, ip), to: Tailscale.Native

  @spec peers_with_route(t(), Tailscale.ip_addr()) ::
          {:ok, [Tailscale.NodeInfo.t()]} | {:error, any()}
  @doc """
  Retrieve the most narrow set of peers that accept packets for the specified IP.
  """
  defdelegate peers_with_route(dev, ip), to: Tailscale.Native

  @spec status(t()) :: {:ok, Tailscale.Status.t()} | {:error, any()}
  @doc """
  Snapshot this device and its tailnet peers (like `tailscale status`).
  """
  defdelegate status(dev), to: Tailscale.Native

  @spec whois(t(), {Tailscale.ip_addr(), :inet.port_number()}) ::
          {:ok, Tailscale.WhoIs.t() | nil} | {:error, any()}
  @doc """
  Map a tailnet source `{ip, port}` to the node that owns its IP (like `tsnet`'s `WhoIs`).

  Only the IP is used; the port is ignored. Returns `{:ok, nil}` if no tailnet node owns the
  address.
  """
  defdelegate whois(dev, sockaddr), to: Tailscale.Native

  @spec netmap(t()) :: {:ok, [Tailscale.StatusNode.t()]} | {:error, any()}
  @doc """
  Snapshot the current netmap: the current set of peer `t:Tailscale.StatusNode.t/0`s.
  """
  defdelegate netmap(dev), to: Tailscale.Native

  @spec resolve(t(), String.t()) :: {:ok, :inet.ip4_address() | nil} | {:error, any()}
  @doc """
  Resolve a tailnet peer (or this node) by MagicDNS name to its tailnet IPv4 address.

  Returns `{:ok, ip}` on a match, `{:ok, nil}` if no tailnet node has that name.
  """
  defdelegate resolve(dev, name), to: Tailscale.Native

  @spec ping(t(), Tailscale.ip_addr(), non_neg_integer()) :: {:ok, float()} | {:error, any()}
  @doc """
  Ping a tailnet peer over the overlay (like `tailscale ping`), returning the round-trip time in
  milliseconds.
  """
  defdelegate ping(dev, addr, timeout_ms), to: Tailscale.Native

  @spec get_certificate(t(), String.t()) :: {:ok, :ok} | {:error, any()}
  @doc """
  Obtain a TLS certificate for a node's MagicDNS `name` (like `tsnet`'s `GetCertificate`).

  Fail-closed: this fork has no client-side ACME engine, so this currently always returns
  `{:error, reason}`. It never self-signs and never returns a placeholder certificate.
  """
  defdelegate get_certificate(dev, name), to: Tailscale.Native

  @spec listen_tls(t(), {String.t(), :inet.port_number(), :accept | {:proxy, String.t()}}) ::
          {:ok, :ok} | {:error, any()}
  @doc """
  Build a TLS acceptor terminating TLS for a serve config (like `tsnet`'s `ListenTLS`).

  The serve config is a `{name, port, target}` tuple where `target` is `:accept` or
  `{:proxy, "host:port"}`.

  Fail-closed: delegates to `get_certificate/2`, so it currently always returns `{:error, reason}`
  rather than ever serving a self-signed cert or downgrading to plaintext.
  """
  defdelegate listen_tls(dev, config), to: Tailscale.Native
end
