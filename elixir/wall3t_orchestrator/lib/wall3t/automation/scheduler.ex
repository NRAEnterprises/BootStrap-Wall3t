defmodule Wall3t.Automation.Scheduler do
  @moduledoc """
  Pure scheduling logic for automation flows.

  Keeping selection pure makes replay deterministic: given the same flows and
  clock, the runtime selects the same work. Actual execution is delegated to
  `Wall3t.Automation.Runner`, which performs the pre-flight gates.
  """

  alias Wall3t.Automation.Flow

  @doc """
  Returns the flows due at `now_ms`.

  - `:manual` flows are never auto-selected.
  - `:interval` flows are due when `now_ms >= last_run_ms + every_ms`.
  - `:event` flows are due when their `at_ms` has passed and they have not run.
  """
  @spec due_flows([Flow.t()], map(), integer()) :: [Flow.t()]
  def due_flows(flows, last_run_by_flow, now_ms)
      when is_list(flows) and is_map(last_run_by_flow) and is_integer(now_ms) do
    flows
    |> Enum.filter(&due?(&1, Map.get(last_run_by_flow, &1.id), now_ms))
    |> Enum.sort_by(& &1.id)
  end

  @spec due?(Flow.t(), integer() | nil, integer()) :: boolean()
  def due?(%Flow{trigger: %{kind: :manual}}, _last_run_ms, _now_ms), do: false

  def due?(%Flow{trigger: %{kind: :interval, every_ms: every_ms}}, last_run_ms, now_ms)
      when is_integer(every_ms) and every_ms > 0 do
    case last_run_ms do
      nil -> true
      last when is_integer(last) -> now_ms >= last + every_ms
      _ -> true
    end
  end

  def due?(%Flow{trigger: %{kind: :event, at_ms: at_ms}}, last_run_ms, now_ms) do
    is_integer(at_ms) and is_nil(last_run_ms) and now_ms >= at_ms
  end

  def due?(_flow, _last_run_ms, _now_ms), do: false
end
