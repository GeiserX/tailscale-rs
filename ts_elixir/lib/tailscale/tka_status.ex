defmodule Tailscale.TkaStatus do
  @moduledoc """
  The control-pushed Tailnet Lock (TKA) status.
  """

  @typedoc """
  Tailnet Lock status: the base32 authority head and the disablement signal.
  """
  @type t() :: %__MODULE__{
          head: String.t(),
          disabled: boolean()
        }

  defstruct [
    :head,
    :disabled
  ]
end
