defmodule Tailscale.WhoIs do
  @moduledoc """
  The result of a `Tailscale.whois/2` lookup: the node that owns a tailnet source address,
  plus its user and capabilities (like `tsnet`'s `WhoIs`).

  The actual struct is produced on the Rust side.

  `user` is always `nil` and `capabilities` is always empty in this fork: the domain node model
  does not retain the wire-level user/login mapping or capability map.
  """

  @type t :: %__MODULE__{}

  defstruct [
    :node,
    :user,
    # List of `{capability, [args]}` tuples (always empty in this fork).
    capabilities: []
  ]
end
