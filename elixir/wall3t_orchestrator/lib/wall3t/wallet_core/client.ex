defmodule Wall3t.WalletCore.Client do
  @moduledoc """
  Boundary between the management plane and the Rust wallet core.

  The management plane may only request work. It cannot sign, broadcast, or
  bypass policy. Production uses an authenticated adapter and opaque tickets.
  """

  alias Wall3t.ActionContext

  @type intent :: %{
          required(:agent_id) => String.t(),
          required(:wallet_id) => String.t(),
          required(:operation) => atom(),
          required(:action_context) => ActionContext.t(),
          required(:context_hash) => String.t(),
          required(:flow_id) => String.t(),
          required(:flow_hash) => String.t(),
          optional(:metadata) => map()
        }

  @type ticket :: %{ticket_id: String.t(), registry_version: non_neg_integer()}

  @callback simulate(intent()) :: {:ok, ticket()} | {:error, term()}
  @callback sign(ticket()) :: {:ok, map()} | {:error, term()}
  @callback broadcast(map()) :: {:ok, map()} | {:error, term()}
end

defmodule Wall3t.WalletCore.Stub do
  @moduledoc """
  Recording stub for tests and local development.

  It is not a signing implementation and must never be deployed as one.
  """

  use GenServer
  @behaviour Wall3t.WalletCore.Client

  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, %{intents: []}, name: __MODULE__)
  end

  @impl Wall3t.WalletCore.Client
  def simulate(intent) do
    GenServer.call(__MODULE__, {:simulate, intent})
  end

  @impl Wall3t.WalletCore.Client
  def sign(ticket), do: {:ok, Map.put(ticket, :signed, true)}

  @impl Wall3t.WalletCore.Client
  def broadcast(signed), do: {:ok, %{transaction_id: "stub:" <> to_string(signed.ticket_id), registry_version: signed.registry_version}}

  @spec intents() :: [map()]
  def intents, do: GenServer.call(__MODULE__, :intents)

  @spec reset() :: :ok
  def reset, do: GenServer.call(__MODULE__, :reset)

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_call({:simulate, intent}, _from, state) do
    with {:ok, snapshot} <- Wall3t.Quarantine.Store.barrier(),
         :ok <- Wall3t.Quarantine.Store.denied_any?(intent.action_context.footprint) do
      ticket = %{
        ticket_id: "tkt_" <> Integer.to_string(length(state.intents) + 1),
        registry_version: snapshot.version,
        state_root: snapshot.state_root
      }

      {:reply, {:ok, ticket}, %{state | intents: [intent | state.intents]}}
    else
      {:error, :stale} -> {:reply, {:error, :stale_registry}, state}
      {:error, :unavailable} -> {:reply, {:error, :registry_unavailable}, state}
      {:error, entity} -> {:reply, {:error, {:quarantined, entity}}, state}
    end
  end

  def handle_call(:intents, _from, state), do: {:reply, Enum.reverse(state.intents), state}
  def handle_call(:reset, _from, state), do: {:reply, :ok, %{state | intents: []}}
end
