defmodule Tailscale.Status do
  @moduledoc """
  A snapshot of the local netmap: this node plus every known peer (like `tailscale status`).

  The actual struct is produced on the Rust side.
  """

  @type t :: %__MODULE__{}

  defstruct self_node: nil,
            peers: []
end
