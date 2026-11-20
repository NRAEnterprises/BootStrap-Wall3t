defmodule Wall3t.Quarantine.Store do
  @moduledoc """
  Local projection of the authoritative quarantine registry.

  This process is a *cache*, not an authority. It exists so the management
  plane can fail fast and invalidate strategy/quote caches when a checkpoint
  arrives. The Rust wallet core still performs the authoritative check before
  simulation, signing, and broadcast.

  Freshness is explicit: a checkpoint carries `fresh_until_ms`, and every
  barrier call compares it against the current monotonic clock. A stale or
  missing checkpoint returns an error, never a permissive default.
  """

  use GenServer

  @default_ttl_ms 30_000

  @type entity :: String.t()
  @type snapshot :: %{
          version: non_neg_integer(),
          state_root: String.t(),
          fresh_until_ms: integer() | nil
        }

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec snapshot() :: snapshot()
  def snapshot, do: GenServer.call(__MODULE__, :snapshot)

  @doc """
  Returns `{:ok, snapshot}` only when the projection has a checkpoint whose
  freshness window covers now and whose version is at least `min_version`.
  """
  @spec barrier(non_neg_integer()) :: {:ok, snapshot()} | {:error, :stale | :unavailable}
  def barrier(min_version \\ 0) when is_integer(min_version) and min_version >= 0 do
    GenServer.call(__MODULE__, {:barrier, min_version})
  end

  @spec denied?(entity()) :: boolean()
  def denied?(entity) when is_binary(entity) do
    GenServer.call(__MODULE__, {:denied?, entity})
  end

  @spec denied_any?([entity()]) :: {:error, entity()} | :ok
  def denied_any?(entities) when is_list(entities) do
    case Enum.find(entities, &denied?/1) do
      nil -> :ok
      entity -> {:error, entity}
    end
  end

  @doc """
  Applies a signed checkpoint projection.

  `attrs` must contain `:version` and `:state_root`. `:denied` is the active
  deny set and `:fresh_until_ms` is an absolute monotonic deadline.
  """
  @spec apply_checkpoint(map()) :: :ok
  def apply_checkpoint(attrs) when is_map(attrs) do
    GenServer.call(__MODULE__, {:apply_checkpoint, attrs})
  end

  @spec reset() :: :ok
  def reset, do: GenServer.call(__MODULE__, :reset)

  @spec default_ttl_ms() :: pos_integer()
  def default_ttl_ms, do: @default_ttl_ms

  @impl true
  def init(opts) do
    {:ok,
     %{
       version: 0,
       state_root: "genesis",
       denied: MapSet.new(),
       fresh_until_ms: nil,
       ttl_ms: Keyword.get(opts, :ttl_ms, @default_ttl_ms)
     }}
  end

  @impl true
  def handle_call(:snapshot, _from, state) do
    {:reply, %{version: state.version, state_root: state.state_root, fresh_until_ms: state.fresh_until_ms}, state}
  end

  def handle_call({:barrier, min_version}, _from, state) do
    cond do
      is_nil(state.fresh_until_ms) ->
        {:reply, {:error, :unavailable}, state}

      now_ms() > state.fresh_until_ms ->
        {:reply, {:error, :stale}, state}

      state.version < min_version ->
        {:reply, {:error, :stale}, state}

      true ->
        {:reply, {:ok, %{version: state.version, state_root: state.state_root, fresh_until_ms: state.fresh_until_ms}}, state}
    end
  end

  def handle_call({:denied?, entity}, _from, state) do
    {:reply, MapSet.member?(state.denied, entity), state}
  end

  def handle_call({:apply_checkpoint, attrs}, _from, state) do
    version = Map.fetch!(attrs, :version)
    state_root = Map.fetch!(attrs, :state_root)
    denied = attrs |> Map.get(:denied, []) |> MapSet.new()
    fresh_until_ms = Map.get(attrs, :fresh_until_ms, now_ms() + state.ttl_ms)

    if version < state.version do
      # Never regress to an older checkpoint; that would be a rollback attack.
      {:reply, :ok, state}
    else
      Wall3t.Audit.Log.record(%{
        type: :checkpoint_applied,
        subject: "registry",
        at_ms: now_ms(),
        version: version,
        previous_version: state.version,
        state_root: state_root
      })

      {:reply, :ok,
       %{state | version: version, state_root: state_root, denied: denied, fresh_until_ms: fresh_until_ms}}
    end
  end

  def handle_call(:reset, _from, _state) do
    {:reply, :ok,
     %{version: 0, state_root: "genesis", denied: MapSet.new(), fresh_until_ms: nil, ttl_ms: @default_ttl_ms}}
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
