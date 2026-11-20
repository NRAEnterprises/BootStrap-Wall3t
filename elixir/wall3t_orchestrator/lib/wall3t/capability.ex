defmodule Wall3t.Capability do
  @moduledoc """
  A scoped, expiring capability granted to an agent.

  The token is an opaque handle. It never contains key material and it cannot
  authorize signing by itself: the Rust wallet core still evaluates policy and
  quarantine state. This struct only limits what the management plane will
  bother to submit.

  Scope shape:

      %{chains: [1], operations: [:swap, :transfer], venues: ["uniswap-v3"]}

  An empty list means "nothing allowed", never "everything allowed".
  """

  @enforce_keys [:token, :scopes, :expires_at_ms]
  defstruct [:token, :scopes, :expires_at_ms]

  @type operation :: atom()
  @type scope :: %{
          optional(:chains) => [integer()],
          optional(:operations) => [operation()],
          optional(:venues) => [String.t()]
        }
  @type t :: %__MODULE__{token: String.t(), scopes: scope(), expires_at_ms: integer()}

  @spec grant(scope(), keyword()) :: t()
  def grant(scope, opts \\ []) when is_map(scope) do
    ttl_ms = Keyword.get(opts, :ttl_ms, 3_600_000)
    issued_at_ms = Keyword.get(opts, :issued_at_ms, now_ms())
    token = Keyword.get_lazy(opts, :token, fn -> "cap_" <> Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false) end)

    %__MODULE__{
      token: token,
      scopes: normalize(scope),
      expires_at_ms: issued_at_ms + ttl_ms
    }
  end

  @spec authorizes?(t(), operation(), keyword()) :: boolean()
  def authorizes?(%__MODULE__{} = capability, operation, opts \\ []) do
    now = Keyword.get(opts, :now_ms, now_ms())
    chain = Keyword.get(opts, :chain_id)
    venue = Keyword.get(opts, :venue)

    capability.expires_at_ms > now and
      operation in Map.get(capability.scopes, :operations, []) and
      chain_allowed?(capability.scopes, chain) and
      venue_allowed?(capability.scopes, venue)
  end

  @spec expired?(t(), integer()) :: boolean()
  def expired?(%__MODULE__{expires_at_ms: expires_at_ms}, now_ms \\ now_ms()) do
    expires_at_ms <= now_ms
  end

  defp chain_allowed?(_scopes, nil), do: true
  defp chain_allowed?(scopes, chain_id), do: chain_id in Map.get(scopes, :chains, [])

  defp venue_allowed?(_scopes, nil), do: true
  defp venue_allowed?(scopes, venue), do: venue in Map.get(scopes, :venues, [])

  defp normalize(scope) do
    %{
      chains: Map.get(scope, :chains, []),
      operations: Map.get(scope, :operations, []),
      venues: Map.get(scope, :venues, [])
    }
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
