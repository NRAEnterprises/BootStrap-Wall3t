defmodule Wall3t.Automation.Flow do
  @moduledoc """
  An immutable automation flow definition.

  A flow is configuration, not authority. It describes steps, each of which
  becomes a typed intent for the Rust wallet core. The flow carries a content
  hash so a policy activation can pin the exact version the user approved.

  Steps use canonical string footprints, for example:

      %{operation: :swap, footprint: ["token:1:0xaaa", "router:1:0xbbb"], cost: 1}
  """

  @enforce_keys [:id, :version, :trigger, :steps]
  defstruct [:id, :version, :trigger, :steps, :content_hash, :scope]

  @type step :: %{required(:operation) => atom(), required(:footprint) => [String.t()], optional(:cost) => pos_integer()}
  @type trigger :: %{kind: :manual | :interval | :event, every_ms: pos_integer() | nil, at_ms: integer() | nil}
  @type t :: %__MODULE__{
          id: String.t(),
          version: String.t(),
          trigger: trigger(),
          steps: [step()],
          content_hash: String.t() | nil,
          scope: map() | nil
        }

  @spec new(map()) :: {:ok, t()} | {:error, atom()}
  def new(attrs) when is_map(attrs) do
    flow = struct(__MODULE__, attrs)

    with :ok <- validate_id(flow.id),
         :ok <- validate_version(flow.version),
         :ok <- validate_trigger(flow.trigger),
         :ok <- validate_steps(flow.steps) do
      {:ok, %{flow | content_hash: content_hash(flow)}}
    end
  end

  @doc """
  Recomputes the hash from id, version, trigger, and steps.

  `scope` is intentionally excluded so the same flow can be attached to
  different wallets without changing its identity.
  """
  @spec content_hash(t()) :: String.t()
  def content_hash(%__MODULE__{} = flow) do
    canonical = {flow.id, flow.version, normalize_trigger(flow.trigger), normalize_steps(flow.steps)}

    :crypto.hash(:sha256, :erlang.term_to_binary(canonical))
    |> Base.encode16(case: :lower)
  end

  @spec hash_matches?(t()) :: boolean()
  def hash_matches?(%__MODULE__{content_hash: nil}), do: false

  def hash_matches?(%__MODULE__{} = flow) do
    content_hash(flow) == flow.content_hash
  end

  @doc "Every distinct entity across all steps, used for the pre-flight deny check."
  @spec footprint(t()) :: [String.t()]
  def footprint(%__MODULE__{steps: steps}) do
    steps
    |> Enum.flat_map(&Map.get(&1, :footprint, []))
    |> Enum.uniq()
  end

  @spec total_cost(t()) :: non_neg_integer()
  def total_cost(%__MODULE__{steps: steps}) do
    Enum.reduce(steps, 0, fn step, acc -> acc + Map.get(step, :cost, 1) end)
  end

  defp validate_id(id) when is_binary(id) and byte_size(id) > 0, do: :ok
  defp validate_id(_), do: {:error, :invalid_flow_id}

  defp validate_version(version) when is_binary(version) and byte_size(version) > 0, do: :ok
  defp validate_version(_), do: {:error, :invalid_flow_version}

  defp validate_trigger(%{kind: kind} = trigger) when kind in [:manual, :interval, :event] do
    cond do
      kind == :interval and not is_integer(Map.get(trigger, :every_ms)) -> {:error, :invalid_trigger}
      kind == :interval and Map.get(trigger, :every_ms) <= 0 -> {:error, :invalid_trigger}
      true -> :ok
    end
  end

  defp validate_trigger(_), do: {:error, :invalid_trigger}

  defp validate_steps(steps) when is_list(steps) and steps != [] do
    if Enum.all?(steps, &valid_step?/1), do: :ok, else: {:error, :invalid_step}
  end

  defp validate_steps(_), do: {:error, :invalid_step}

  defp valid_step?(%{operation: operation, footprint: footprint})
       when is_atom(operation) and is_list(footprint) do
    Enum.all?(footprint, &is_binary/1)
  end

  defp valid_step?(_), do: false

  defp normalize_trigger(trigger) do
    {Map.get(trigger, :kind), Map.get(trigger, :every_ms), Map.get(trigger, :at_ms)}
  end

  defp normalize_steps(steps) do
    Enum.map(steps, fn step ->
      {Map.get(step, :operation), Enum.sort(Map.get(step, :footprint, [])), Map.get(step, :cost, 1)}
    end)
  end
end
