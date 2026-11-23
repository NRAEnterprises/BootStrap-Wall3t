defmodule Wall3t.Automation.Flow do
  @moduledoc """
  An immutable automation flow definition.

  A flow is configuration, not authority. Each step must contain a validated
  `Wall3t.ActionContext`; model or external-content maps must be normalized
  before they can enter a flow.
  """

  alias Wall3t.ActionContext

  @enforce_keys [:id, :version, :trigger, :steps]
  defstruct [:id, :version, :trigger, :steps, :content_hash, :scope]

  @type step :: %{required(:action_context) => ActionContext.t(), optional(:cost) => pos_integer()}
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

  @doc "Recomputes the hash from identity, trigger, and canonical action contexts."
  @spec content_hash(t()) :: String.t()
  def content_hash(%__MODULE__{} = flow) do
    canonical = {flow.id, flow.version, normalize_trigger(flow.trigger), normalize_steps(flow.steps)}

    :crypto.hash(:sha256, :erlang.term_to_binary(canonical))
    |> Base.encode16(case: :lower)
  end

  @spec hash_matches?(t()) :: boolean()
  def hash_matches?(%__MODULE__{content_hash: nil}), do: false
  def hash_matches?(%__MODULE__{} = flow), do: content_hash(flow) == flow.content_hash

  @doc "Every distinct entity across all typed action contexts."
  @spec footprint(t()) :: [String.t()]
  def footprint(%__MODULE__{steps: steps}) do
    steps
    |> Enum.flat_map(& &1.action_context.footprint)
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

  defp valid_step?(%{action_context: %ActionContext{} = context} = step) do
    context.operation != nil and context.footprint != [] and
      (not Map.has_key?(step, :cost) or (is_integer(step.cost) and step.cost > 0))
  end

  defp valid_step?(_), do: false

  defp normalize_trigger(trigger) do
    {Map.get(trigger, :kind), Map.get(trigger, :every_ms), Map.get(trigger, :at_ms)}
  end

  defp normalize_steps(steps) do
    Enum.map(steps, fn step ->
      {ActionContext.canonical(step.action_context), Map.get(step, :cost, 1)}
    end)
  end
end
