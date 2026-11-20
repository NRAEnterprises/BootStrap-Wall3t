defmodule Wall3t.Agent.Server do
  @moduledoc """
  Supervised lifecycle process for one opaque agent wallet assignment.

  The process owns orchestration state only: agent id, wallet id, capabilities,
  budget, policy references, and lifecycle status. It never receives a seed,
  private key, mnemonic, or signer handle. `:revoked` and `:killed` are
  terminal states until a new supervised process is created.
  """

  use GenServer

  @statuses [:running, :paused, :revoked, :killed]

  @type state :: %{
          id: String.t(),
          wallet_id: String.t(),
          status: atom(),
          capabilities: map(),
          budget: %{limit: non_neg_integer(), spent: non_neg_integer()},
          metadata: map(),
          runs: [map()]
        }

  def start_link(attrs) when is_map(attrs) do
    GenServer.start_link(__MODULE__, attrs, name: via(attrs.id))
  end

  @spec via(String.t()) :: {:via, Registry, {atom(), String.t()}}
  def via(id), do: {:via, Registry, {Wall3t.AgentRegistry, id}}

  @spec status(String.t()) :: {:ok, atom()} | {:error, :not_found}
  def status(id), do: call(id, :status)

  @spec pause(String.t(), String.t()) :: :ok | {:error, term()}
  def pause(id, reason), do: call(id, {:transition, :paused, reason})

  @spec resume(String.t()) :: :ok | {:error, term()}
  def resume(id), do: call(id, {:transition, :running, "resumed"})

  @spec revoke(String.t(), String.t()) :: :ok | {:error, term()}
  def revoke(id, reason), do: call(id, {:transition, :revoked, reason})

  @spec kill(String.t(), String.t()) :: :ok | {:error, term()}
  def kill(id, reason), do: call(id, {:transition, :killed, reason})

  @spec append_run(String.t(), map()) :: :ok | {:error, term()}
  def append_run(id, run), do: call(id, {:append_run, run})

  @spec snapshot(String.t()) :: {:ok, state()} | {:error, :not_found}
  def snapshot(id), do: call(id, :snapshot)

  @impl true
  def init(attrs) do
    id = Map.fetch!(attrs, :id)
    wallet_id = Map.fetch!(attrs, :wallet_id)
    capabilities = Map.get(attrs, :capabilities, %{})
    limit = Map.get(attrs, :budget_limit, 0)

    {:ok,
     %{
       id: id,
       wallet_id: wallet_id,
       status: :running,
       capabilities: capabilities,
       budget: %{limit: limit, spent: 0},
       metadata: Map.get(attrs, :metadata, %{}),
       runs: []
     }}
  end

  @impl true
  def handle_call(:status, _from, state), do: {:reply, {:ok, state.status}, state}
  def handle_call(:snapshot, _from, state), do: {:reply, {:ok, state}, state}

  def handle_call({:transition, target, reason}, _from, state) when target in @statuses do
    cond do
      state.status in [:revoked, :killed] ->
        {:reply, {:error, :terminal_state}, state}

      target == :running and state.status != :paused ->
        {:reply, {:error, :not_paused}, state}

      true ->
        Wall3t.Audit.Log.record(%{
          type: :agent_status_changed,
          subject: state.id,
          at_ms: System.monotonic_time(:millisecond),
          from: state.status,
          to: target,
          reason: reason
        })

        {:reply, :ok, %{state | status: target}}
    end
  end

  def handle_call({:append_run, run}, _from, %{status: :running} = state) when is_map(run) do
    {:reply, :ok, %{state | runs: [run | state.runs]}}
  end

  def handle_call({:append_run, _run}, _from, state), do: {:reply, {:error, :agent_not_running}, state}

  defp call(id, message) do
    try do
      GenServer.call(via(id), message)
    catch
      :exit, {:noproc, _} -> {:error, :not_found}
    end
  end
end
