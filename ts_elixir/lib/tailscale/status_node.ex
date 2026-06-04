defmodule Tailscale.StatusNode do
  @moduledoc """
  A single node entry in a `t:Tailscale.Status.t/0` snapshot (like `tailscale status`).

  The actual struct is produced on the Rust side.
  """

  @type t :: %__MODULE__{}

  defstruct [
    :stable_id,
    :display_name,
    :ipv4,
    :ipv6,
    # Always `nil` in this fork: the domain node model does not retain the wire-level
    # `online` field.
    :online,
    is_exit_node: false,
    # Allowed routes as CIDR strings (e.g. `"100.64.0.1/32"`, `"0.0.0.0/0"`).
    allowed_routes: []
  ]
end
