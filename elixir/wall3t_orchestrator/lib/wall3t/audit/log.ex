defmodule Wall3t.Audit.Log do
  @moduledoc """
  Append-only in-memory audit stream for management-plane events.

  Production replaces this with a durable, tamper-evident sink. The contract is
  append-only: entries are never mutated or removed except by an explicit test
  reset, and every entry carries the registry version observed at the time.
  """

  use GenServer

  @type event :: %{
          required(:type) => atom(),
          required(:subject) => String.t(),
          required(:at_ms) => integer(),
          optional(atom()) => term()
        }

  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, %{entries: []}, name: __MODULE__)
  end

  @spec record(event()) :: :ok
  def record(event) when is_map(event) do
    GenServer.cast(__MODULE__, {:record, event})
  end

  @spec entries() :: [event()]
  def entries do
    GenServer.call(__MODULE__, :entries)
  end

  @spec count(atom()) :: non_neg_integer()
  def count(type) when is_atom(type) do
    Enum.count(entries(), &(&1.type == type))
  end

  @spec reset() :: :ok
  def reset do
    GenServer.call(__MODULE__, :reset)
  end

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_cast({:record, event}, state) do
    {:noreply, %{state | entries: [event | state.entries]}}
  end

  @impl true
  def handle_call(:entries, _from, state), do: {:reply, Enum.reverse(state.entries), state}
  def handle_call(:reset, _from, state), do: {:reply, :ok, %{state | entries: []}}
end
