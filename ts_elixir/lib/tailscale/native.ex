defmodule Tailscale.Native do
  use Rustler,
    otp_app: :tailscale,
    crate: :ts_elixir

  @moduledoc false

  # The Elixir side of the Rustler bindings to `tailscale-rs`.
  #
  # The rest of this package adapts these bindings to a more Elixir-friendly module layout -- this is
  # where Rustler actually connects the Rust nifs to their Elixir names, so it's a flat module.
  #
  # Consider this module an internal implementation detail: we may break its API at our convenience
  # without a semver bump.

  @typedoc """
  A handle to a unique tailscale "identity" on a given tailnet.
  """
  @opaque device :: reference()

  @typedoc """
  A handle to a UDP socket.
  """
  @opaque udp_socket :: reference()

  @typedoc """
  A handle to a TCP listener.
  """
  @opaque tcp_listener :: reference()
  @typedoc """
  A handle to a TCP stream (connected socket).
  """
  @opaque tcp_stream :: reference()

  defp err, do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Open a new tailnet connection.

  See `t:Tailscale.options/0` for details on what options are supported.
  """
  @spec connect(%{}) :: {:ok, device()} | {:error, any()}
  def connect(_opts), do: err()

  @doc """
  Bind a new udp socket.

  ## Parameters

  - `dev`: the `m:Tailscale` device on which to create the socket.
  - `port`: the port to which the socket should bind.
  """
  @spec udp_bind(device(), Tailscale.ip_addr() | :ip4 | :ip6, :inet.port_number()) ::
          {:ok, udp_socket()} | {:error, any()}
  def udp_bind(_dev, _addr, _port), do: err()

  @doc """
  Send a packet to an address from a udp socket.

  ## Parameters

  - `sock`: the socket to send the packet from.
  - `ip`: the IP address to send the packet to.
  - `port`: the port to send the packet to.
  - `msg`: the packet to send.
  """
  @spec udp_send(udp_socket(), Tailscale.ip_addr(), :inet.port_number(), binary()) ::
          :ok | {:error, any()}
  def udp_send(_sock, _ip, _port, _msg), do: err()

  @doc """
  Receive an incoming UDP packet on the given socket.
  """
  @spec udp_recv(udp_socket()) ::
          {:ok, :inet.ip_address(), :inet.port_number(), binary()} | {:error, any()}
  def udp_recv(_sock), do: err()

  @doc """
  Get the local address to which the given UDP socket is bound.
  """
  @spec udp_local_addr(udp_socket()) :: {:inet.ip_address(), :inet.port_number()}
  def udp_local_addr(_sock), do: err()

  @doc """
  Start the Rust-side tracing machinery. This prints to stdout, so may conflict with erlang's
  logging setup.
  """
  @spec start_tracing() :: :ok
  def start_tracing(), do: err()

  @doc """
  Start a TCP listener on the given device, address, and port.
  """
  @spec tcp_listen(device(), Tailscale.ip_addr() | :ip4 | :ip6, :inet.port_number()) ::
          {:ok, tcp_listener()} | {:error, any()}
  def tcp_listen(_dev, _addr, _port), do: err()

  @doc """
  Get the local address to which the given TCP listener is bound.
  """
  @spec tcp_listen_local_addr(tcp_listener()) :: {:inet.ip_address(), :inet.port_number()}
  def tcp_listen_local_addr(_listener), do: err()

  @doc """
  Connect to the given TCP endpoint using the given device.
  """
  @spec tcp_connect(device(), Tailscale.ip_addr(), :inet.port_number()) ::
          {:ok, tcp_stream()} | {:error, any()}
  def tcp_connect(_dev, _addr, _port), do: err()

  @doc """
  Accept an incoming TCP connection. Blocks until one is available.
  """
  @spec tcp_accept(tcp_listener()) :: {:ok, tcp_stream()} | {:error, any()}
  def tcp_accept(_listener), do: err()

  @doc """
  Send a message to the remote peer on the given tcp socket, blocking until at least one byte can be
  sent.

  Returns the number of bytes actually written to the remote.
  """
  @spec tcp_send(tcp_stream(), binary()) :: {:ok, integer()} | {:error, any()}
  def tcp_send(_stream, _msg), do: err()

  @doc """
  Receive incoming data from the tcp socket, blocking until at least one byte can be received.
  """
  @spec tcp_recv(tcp_stream()) :: {:ok, binary()} | {:error, any()}
  def tcp_recv(_stream), do: err()

  @doc """
  Get the local address to which the given TCP stream is bound.
  """
  @spec tcp_local_addr(tcp_stream()) :: {:inet.ip_address(), :inet.port_number()}
  def tcp_local_addr(_stream), do: err()

  @doc """
  Get the remote address to which the given TCP stream is connected.
  """
  @spec tcp_remote_addr(tcp_stream()) :: {:inet.ip_address(), :inet.port_number()}
  def tcp_remote_addr(_stream), do: err()

  @doc """
  Retrieve the IPv4 address for the given tailscale device.

  Blocks until the device is connected and gets its address from control.
  """
  @spec ipv4_addr(device()) :: {:ok, :inet.ip4_address()} | {:error, any()}
  def ipv4_addr(_dev), do: err()

  @doc """
  Retrieve the IPv6 address for the given tailscale device.

  Blocks until the device is connected and gets its address from control.
  """
  @spec ipv6_addr(device()) :: {:ok, :inet.ip6_address()} | {:error, any()}
  def ipv6_addr(_dev), do: err()

  @doc """
  Retrieve a peer by name.
  """
  @spec peer_by_name(device(), String.t()) :: {:ok, %{} | nil} | {:error, any()}
  def peer_by_name(_dev, _name), do: err()

  @doc """
  Retrieve this node's info
  """
  @spec self_node(device()) :: {:ok, %{}} | {:error, any()}
  def self_node(_dev), do: err()

  @doc """
  Retrieve a peer by its tailnet IP.
  """
  @spec peer_by_tailnet_ip(device(), Tailscale.ip_addr()) :: {:ok, %{} | nil} | {:error, any()}
  def peer_by_tailnet_ip(_dev, _ip), do: err()

  @doc """
  Retrieve the most narrow set of peers that accept packets for the specified IP.
  """
  @spec peers_with_route(device(), Tailscale.ip_addr()) :: {:ok, [%{}]} | {:error, any()}
  def peers_with_route(_dev, _ip), do: err()

  @doc """
  Load key state from the specified path, generating a new state if the file doesn't exist.
  """
  @spec load_key_file(String.t()) :: {:ok, Tailscale.Keystate.t()} | {:error, any()}
  def load_key_file(_path), do: err()

  @doc """
  Snapshot this device and its tailnet peers (like `tailscale status`).
  """
  @spec status(device()) :: {:ok, Tailscale.Status.t()} | {:error, any()}
  def status(_dev), do: err()

  @doc """
  Map a tailnet source `{ip, port}` to the node that owns its IP (like `tsnet`'s `WhoIs`).
  Only the IP is used; the port is ignored.
  """
  @spec whois(device(), {Tailscale.ip_addr(), :inet.port_number()}) ::
          {:ok, Tailscale.WhoIs.t() | nil} | {:error, any()}
  def whois(_dev, _sockaddr), do: err()

  @doc """
  Snapshot the current netmap: the current set of peer `t:Tailscale.StatusNode.t/0`s.
  """
  @spec netmap(device()) :: {:ok, [Tailscale.StatusNode.t()]} | {:error, any()}
  def netmap(_dev), do: err()

  @doc """
  Resolve a tailnet peer (or this node) by MagicDNS name to its tailnet IPv4 address.

  Returns `{:ok, ip}` on a match, `{:ok, nil}` if no tailnet node has that name.
  """
  @spec resolve(device(), String.t()) ::
          {:ok, :inet.ip4_address() | nil} | {:error, any()}
  def resolve(_dev, _name), do: err()

  @doc """
  Connect to a tailnet peer by MagicDNS name and port over TCP.
  """
  @spec tcp_connect_by_name(device(), String.t(), :inet.port_number()) ::
          {:ok, tcp_stream()} | {:error, any()}
  def tcp_connect_by_name(_dev, _name, _port), do: err()

  @doc """
  Ping a tailnet peer over the overlay, returning the round-trip time in milliseconds.
  """
  @spec ping(device(), Tailscale.ip_addr(), non_neg_integer()) ::
          {:ok, float()} | {:error, any()}
  def ping(_dev, _addr, _timeout_ms), do: err()

  @doc """
  Obtain a TLS certificate for a node's MagicDNS `name` (fail-closed until ACME lands).
  """
  @spec get_certificate(device(), String.t()) :: {:ok, :ok} | {:error, any()}
  def get_certificate(_dev, _name), do: err()

  @doc """
  Build a TLS acceptor terminating TLS for a serve config (fail-closed until ACME lands).

  The config is a `{name, port, target}` tuple where `target` is `:accept` or `{:proxy, "host:port"}`.
  """
  @spec listen_tls(device(), {String.t(), :inet.port_number(), :accept | {:proxy, String.t()}}) ::
          {:ok, :ok} | {:error, any()}
  def listen_tls(_dev, _config), do: err()
end
