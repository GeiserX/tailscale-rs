defmodule Tailscale.WaitingFile do
  @moduledoc """
  A Taildrop file that has been fully received and not yet consumed.
  """

  @typedoc """
  A waiting (fully-received) Taildrop file.
  """
  @type t() :: %__MODULE__{
          name: String.t(),
          size: non_neg_integer()
        }

  defstruct [
    :name,
    :size
  ]
end
