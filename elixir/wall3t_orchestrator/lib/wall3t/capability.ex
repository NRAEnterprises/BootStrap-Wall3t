defmodule Wall3t.Capability do
  @moduledoc """
  A scoped, expiring capability granted to an agent.

  Authorization requires a fully populated `Wall3t.ActionContext`. Missing
  action context is never treated as an unconstrained wildcard.
  """

  alias Wall3t.ActionContext

  @enforce_keys [:token, :scopes, :expires_at_ms]
  defstruct [:token, :scopes, :expires_at_ms]

  @type operation :: atom()
  @type scope :: %{
          required(:chains) => [pos_integer()],
          required(:operations) => [operation()],
          required(:venues) => [String.t()],
          required(:assets) => [String.t()],
          required(:destinations) => [String.t()],
          required(:max_amount) => non_neg_integer(),
          required(:max_fee) => non_neg_integer(),
          required(:max_slippage_bps) => non_neg_integer()
        }
  @type t :: %__MODULE__{token: String.t(), scopes: scope(), expires_at_ms: integer()}

  @spec grant(scope(), keyword()) :: t()
  def grant(scope, opts \\ []) when is_map(scope) do
    normalized = normalize!(scope)
    ttl_ms = Keyword.get(opts, :ttl_ms, 3_600_000)
    issued_at_ms = Keyword.get(opts, :issued_at_ms, now_ms())
    token = Keyword.get_lazy(opts, :token, fn -> "cap_" <> Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false) end)

    %__MODULE__{
      token: token,
      scopes: normalized,
      expires_at_ms: issued_at_ms + ttl_ms
    }
  end

  @spec authorizes?(t(), ActionContext.t(), keyword()) :: boolean()
  def authorizes?(%__MODULE__{} = capability, %ActionContext{} = context, opts \\ []) do
    now = Keyword.get(opts, :now_ms, now_ms())
    scopes = capability.scopes

    capability.expires_at_ms > now and
      context.operation in scopes.operations and
      context.chain_id in scopes.chains and
      context.venue in scopes.venues and
      Enum.all?(context.assets, &(&1 in scopes.assets)) and
      context.destination in scopes.destinations and
      context.amount <= scopes.max_amount and
      context.fee_limit <= scopes.max_fee and
      context.slippage_bps <= scopes.max_slippage_bps
  end

  def authorizes?(_capability, _context, _opts), do: false

  @spec expired?(t(), integer()) :: boolean()
  def expired?(%__MODULE__{expires_at_ms: expires_at_ms}, now_ms \\ now_ms()) do
    expires_at_ms <= now_ms
  end

  defp normalize!(scope) do
    required = [:chains, :operations, :venues, :assets, :destinations, :max_amount, :max_fee, :max_slippage_bps]

    unless Enum.all?(required, &Map.has_key?(scope, &1)) do
      raise ArgumentError, "capability scope is incomplete"
    end

    normalized = Map.take(scope, required)

    unless is_list(normalized.chains) and
             is_list(normalized.operations) and
             is_list(normalized.venues) and
             is_list(normalized.assets) and
             is_list(normalized.destinations) and
             is_integer(normalized.max_amount) and normalized.max_amount >= 0 and
             is_integer(normalized.max_fee) and normalized.max_fee >= 0 and
             is_integer(normalized.max_slippage_bps) and normalized.max_slippage_bps >= 0 do
      raise ArgumentError, "capability scope contains invalid values"
    end

    normalized
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
