defmodule Wall3t.ActionContext do
  @moduledoc """
  Canonical, fully populated context for one proposed operation.

  This is an authorization input, not a transaction payload. Missing
  security-relevant fields are rejected rather than treated as unconstrained.
  Rust wallet-core remains authoritative for decoding the final transaction
  and deriving the complete execution footprint.
  """

  @enforce_keys [
    :operation,
    :chain_id,
    :venue,
    :assets,
    :destination,
    :amount,
    :fee_limit,
    :slippage_bps,
    :footprint
  ]
  defstruct [
    :operation,
    :chain_id,
    :venue,
    :assets,
    :destination,
    :amount,
    :fee_limit,
    :slippage_bps,
    :footprint
  ]

  @type t :: %__MODULE__{
          operation: atom(),
          chain_id: pos_integer(),
          venue: String.t(),
          assets: [String.t()],
          destination: String.t(),
          amount: non_neg_integer(),
          fee_limit: non_neg_integer(),
          slippage_bps: non_neg_integer(),
          footprint: [String.t()]
        }

  @spec new(map()) :: {:ok, t()} | {:error, atom()}
  def new(attrs) when is_map(attrs) do
    required = [
      :operation,
      :chain_id,
      :venue,
      :assets,
      :destination,
      :amount,
      :fee_limit,
      :slippage_bps,
      :footprint
    ]

    with :ok <- require_fields(attrs, required),
         :ok <- validate_operation(Map.get(attrs, :operation)),
         :ok <- validate_positive_integer(Map.get(attrs, :chain_id), :invalid_chain_id),
         :ok <- validate_non_empty_binary(Map.get(attrs, :venue), :invalid_venue),
         :ok <- validate_string_list(Map.get(attrs, :assets), :invalid_assets, false),
         :ok <- validate_non_empty_binary(Map.get(attrs, :destination), :invalid_destination),
         :ok <- validate_non_negative_integer(Map.get(attrs, :amount), :invalid_amount),
         :ok <- validate_non_negative_integer(Map.get(attrs, :fee_limit), :invalid_fee_limit),
         :ok <- validate_non_negative_integer(Map.get(attrs, :slippage_bps), :invalid_slippage),
         :ok <- validate_string_list(Map.get(attrs, :footprint), :invalid_footprint, false) do
      {:ok,
       %__MODULE__{
         operation: attrs.operation,
         chain_id: attrs.chain_id,
         venue: attrs.venue,
         assets: Enum.uniq(attrs.assets),
         destination: attrs.destination,
         amount: attrs.amount,
         fee_limit: attrs.fee_limit,
         slippage_bps: attrs.slippage_bps,
         footprint: Enum.uniq(attrs.footprint)
       }}
    end
  end

  def new(_), do: {:error, :invalid_action_context}

  @spec canonical(t()) :: tuple()
  def canonical(%__MODULE__{} = context) do
    {
      context.operation,
      context.chain_id,
      context.venue,
      Enum.sort(context.assets),
      context.destination,
      context.amount,
      context.fee_limit,
      context.slippage_bps,
      Enum.sort(context.footprint)
    }
  end

  defp require_fields(attrs, fields) do
    if Enum.all?(fields, &Map.has_key?(attrs, &1)), do: :ok, else: {:error, :incomplete_action_context}
  end

  defp validate_operation(value) when is_atom(value), do: :ok
  defp validate_operation(_), do: {:error, :invalid_operation}

  defp validate_positive_integer(value, _error) when is_integer(value) and value > 0, do: :ok
  defp validate_positive_integer(_, error), do: {:error, error}

  defp validate_non_negative_integer(value, _error) when is_integer(value) and value >= 0, do: :ok
  defp validate_non_negative_integer(_, error), do: {:error, error}

  defp validate_non_empty_binary(value, _error) when is_binary(value) and byte_size(value) > 0, do: :ok
  defp validate_non_empty_binary(_, error), do: {:error, error}

  defp validate_string_list(value, error, allow_empty?) when is_list(value) do
    cond do
      value == [] and not allow_empty? -> {:error, error}
      Enum.all?(value, &(is_binary(&1) and byte_size(&1) > 0)) -> :ok
      true -> {:error, error}
    end
  end

  defp validate_string_list(_, error, _allow_empty?), do: {:error, error}
end
