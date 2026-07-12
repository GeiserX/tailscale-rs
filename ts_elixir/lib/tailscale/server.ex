defmodule Tailscale.Server do
  @moduledoc """
  A `tsnet.Server`-shaped embedded Tailscale node, exposing the two surfaces the plain
  `Tailscale.connect/1` device does not: the **dual-credential loopback** and the **LocalClient**.

  Construct with `new/1` (Go-`tsnet.Server`-parity options); the wrapped node is built lazily on the
  first `loopback/1` / `local_client/1` call. Fork config supersets beyond Go `tsnet` parity (exit
  nodes, forwarding) remain on `Tailscale.connect/1`; this is the Go-parity `Server` surface. Cleanup
  happens on garbage collection — the loopback listeners and node shut down when the handle drops.
  """

  @typedoc "An opaque handle to a `tsnet.Server`-shaped node."
  @opaque t() :: Tailscale.Native.server()

  @typedoc """
  Options for a `tsnet.Server` (all optional):

  - `hostname`: the hostname this node requests.
  - `auth_key`: the auth key to authorize this node.
  - `control_url`: the control server URL.
  - `ephemeral`: register as an ephemeral node (default `false`, matching Go).
  - `dir`: a state directory persisting this node's identity keys across runs. Omit for a fresh
    ephemeral in-memory identity.
  - `tags`: ACL tags to advertise.
  """
  @type options :: [
          hostname: String.t(),
          auth_key: String.t(),
          control_url: String.t(),
          ephemeral: boolean(),
          dir: String.t(),
          tags: [String.t()]
        ]

  @doc """
  Build a new server. See `t:options/0`. No network I/O happens here — the node is built on first
  use.
  """
  @spec new(options()) :: {:ok, t()} | {:error, any()}
  def new(options \\ []) when is_list(options),
    do: :proplists.to_map(options) |> Tailscale.Native.server_new()

  @doc """
  Start (once) the loopback surface (Go `Loopback() (addr, proxyCred, localAPICred, err)`),
  returning `{:ok, {socks_addr, proxy_cred, localapi_addr, localapi_cred}}`.

  `socks_addr` is the SOCKS5 proxy's bound `{ip, port}` (password `proxy_cred`, username `tsnet`);
  `localapi_addr` is the in-process LocalAPI HTTP server's bound `{ip, port}` (HTTP Basic-auth
  password `localapi_cred`). Both listeners live for the server's lifetime, so repeated calls return
  the same addresses and credentials.
  """
  @spec loopback(t()) ::
          {:ok,
           {{:inet.ip_address(), :inet.port_number()}, String.t(),
            {:inet.ip_address(), :inet.port_number()}, String.t()}}
          | {:error, any()}
  defdelegate loopback(server), to: Tailscale.Native, as: :server_loopback

  @doc """
  Obtain a `Tailscale.LocalClient` for this node's in-process LocalAPI HTTP server (Go
  `tsnet.Server.LocalClient()`), starting the loopback surface if needed.
  """
  @spec local_client(t()) :: {:ok, Tailscale.LocalClient.t()} | {:error, any()}
  defdelegate local_client(server), to: Tailscale.Native, as: :server_local_client
end
