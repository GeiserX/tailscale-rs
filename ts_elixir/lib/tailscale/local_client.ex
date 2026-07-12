defmodule Tailscale.LocalClient do
  @moduledoc """
  A client for a node's in-process LocalAPI HTTP server (Go `tsnet.Server.LocalClient()` →
  `*local.Client`), obtained from `Tailscale.Server.local_client/1`.

  It authenticates every request with the loopback's LocalAPI credential and speaks plain HTTP to
  `127.0.0.1`. LocalAPI responses are JSON/text, decoded here as UTF-8 strings.
  """

  @typedoc "An opaque handle to a node's LocalAPI HTTP client."
  @opaque t() :: Tailscale.Native.local_client()

  @doc """
  `GET /localapi/v0/status` — the node + peer status as a JSON string (Go `LocalClient().Status`,
  over the loopback). Returns `{:error, _}` if the server answers non-`200`.
  """
  @spec status(t()) :: {:ok, String.t()} | {:error, any()}
  defdelegate status(client), to: Tailscale.Native, as: :local_client_status

  @doc """
  Perform an authenticated `GET` against an arbitrary LocalAPI `path` (e.g.
  `"/localapi/v0/status"`), returning `{:ok, {http_status_code, body}}` where `body` is the response
  decoded as a UTF-8 string.
  """
  @spec get(t(), String.t()) :: {:ok, {non_neg_integer(), String.t()}} | {:error, any()}
  defdelegate get(client, path), to: Tailscale.Native, as: :local_client_get

  @doc "The `{ip, port}` address of the LocalAPI HTTP server this client talks to."
  @spec address(t()) :: {:inet.ip_address(), :inet.port_number()}
  defdelegate address(client), to: Tailscale.Native, as: :local_client_address

  @doc "The LocalAPI credential (HTTP Basic-auth password) this client sends."
  @spec credential(t()) :: String.t()
  defdelegate credential(client), to: Tailscale.Native, as: :local_client_credential
end
