defmodule Tailscale.WhoIs do
  @moduledoc """
  The result of a `Tailscale.whois/2` lookup: the node that owns a tailnet source address,
  plus its user and capabilities (like `tsnet`'s `WhoIs`).

  The actual struct is produced on the Rust side.

  `user` is the owning user's login (or display name), and `groups` is the group membership the
  coordination server reported for that user — SCIM groups such as `engineering@example.com`, or
  policy-document names such as `group:eng`. Both come from the netmap's user-profile table, so
  `user` is `nil` and `groups` is empty when control sent no profile for the owner (a tagged node,
  for instance). An empty `groups` also just means control reported none, so authorise on a
  membership you find, never on one you fail to find.
  """

  @type t :: %__MODULE__{}

  defstruct [
    :node,
    :user,
    # Group names reported for the owning user (empty when control reported none).
    groups: [],
    # List of `{capability, [args]}` tuples.
    capabilities: []
  ]
end
