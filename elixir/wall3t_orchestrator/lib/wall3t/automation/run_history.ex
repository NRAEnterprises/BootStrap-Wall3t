defmodule Wall3t.Automation.RunHistory do
  @moduledoc """
  Append-only run-history contract and local reference implementation.

  A run has a caller-supplied idempotency key. Repeating the same key returns
  the original record instead of executing a duplicate run. The production
  implementation should use a durable database/event log with a unique key
  constraint and an append-only audit projection.
  """

  use GenServer

  @type run :: %{
          idempotency_key: String.t(),
          agent_id: String.t(),
          flow_id: String.t(),
          status: :started | :succeeded | :failed | :paused,
          attempt: pos_integer(),
          started_at_ms: integer(),
          finished_at_ms: integer() | nil,
          result: term()
        }

  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, %{runs: %{}}, name: __MODULE__)
  end

  @spec begin(String.t(), String.t(), String.t(), keyword()) :: {:ok, run()} | {:duplicate, run()}
  def begin(agent_id, flow_id, idempotency_key, opts \\ []) do
    GenServer.call(__MODULE__, {:begin, agent_id, flow_id, idempotency_key, opts})
  end

  @spec finish(String.t(), :succeeded | :failed | :paused, term()) :: {:ok, run()} | {:error, :not_found}
  def finish(idempotency_key, status, result) when status in [:succeeded, :failed, :paused] do
    GenServer.call(__MODULE__, {:finish, idempotency_key, status, result})
  end

  @spec get(String.t()) :: {:ok, run()} | {:error, :not_found}
  def get(key), do: GenServer.call(__MODULE__, {:get, key})

  @spec all() :: [run()]
  def all, do: GenServer.call(__MODULE__, :all)

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_call({:begin, agent_id, flow_id, key, opts}, _from, state) do
    case Map.fetch(state.runs, key) do
      {:ok, existing} -> {:reply, {:duplicate, existing}, state}
      :error ->
        run = %{
          idempotency_key: key,
          agent_id: agent_id,
          flow_id: flow_id,
          status: :started,
          attempt: Keyword.get(opts, :attempt, 1),
          started_at_ms: Keyword.get(opts, :now_ms, System.monotonic_time(:millisecond)),
          finished_at_ms: nil,
          result: nil
        }

        Wall3t.Audit.Log.record(%{type: :run_started, subject: agent_id, at_ms: run.started_at_ms, flow_id: flow_id, idempotency_key: key})
        {:reply, {:ok, run}, %{state | runs: Map.put(state.runs, key, run)}}
    end
  end

  def handle_call({:finish, key, status, result}, _from, state) do
    case Map.fetch(state.runs, key) do
      :error -> {:reply, {:error, :not_found}, state}
      {:ok, run} ->
        updated = %{run | status: status, result: result, finished_at_ms: System.monotonic_time(:millisecond)}
        Wall3t.Audit.Log.record(%{type: :run_finished, subject: run.agent_id, at_ms: updated.finished_at_ms, flow_id: run.flow_id, idempotency_key: key, status: status})
        {:reply, {:ok, updated}, %{state | runs: Map.put(state.runs, key, updated)}}
    end
  end

  def handle_call({:get, key}, _from, state) do
    {:reply, Map.fetch(state.runs, key) |> normalize_fetch(), state}
  end

  def handle_call(:all, _from, state), do: {:reply, Map.values(state.runs), state}

  defp normalize_fetch({:ok, run}), do: {:ok, run}
  defp normalize_fetch(:error), do: {:error, :not_found}
end
