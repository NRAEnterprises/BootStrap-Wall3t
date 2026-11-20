defmodule Wall3t.Automation.Runner do
  @moduledoc """
  Turns an approved flow into typed intents for the Rust wallet core.

  Ordering matters:

    1. capability must authorize the operation and scope;
    2. budget must cover the flow's declared cost;
    3. the local quarantine projection must be fresh;
    4. no entity in the flow footprint may be denied;
    5. only then are intents submitted.

  Steps 3 and 4 are a *pre-flight* check to fail fast and to avoid pointless
  work. They are not the enforcement point. The Rust core re-checks policy and
  quarantine authoritatively at simulation, signing, and broadcast, and a stale
  ticket is rejected there even if this layer allowed the attempt.
  """

  alias Wall3t.Automation.Flow
  alias Wall3t.Capability
  alias Wall3t.Quarantine.Store

  @type agent :: %{
          required(:id) => String.t(),
          required(:wallet_id) => String.t(),
          required(:capability) => Capability.t(),
          required(:budget) => %{limit: non_neg_integer(), spent: non_neg_integer()}
        }

  @type result :: {:ok, [map()]} | {:error, atom() | tuple()}

  @spec run(agent(), Flow.t(), module(), keyword()) :: result()
  def run(agent, %Flow{} = flow, client \\ Wall3t.WalletCore.Stub, opts \\ []) do
    now_ms = Keyword.get(opts, :now_ms)

    with :ok <- verify_flow(flow),
         :ok <- verify_capability(agent, flow, now_ms),
         :ok <- verify_budget(agent, flow),
         :ok <- verify_quarantine(flow) do
      submit(agent, flow, client)
    end
  end

  @spec verify_flow(Flow.t()) :: :ok | {:error, atom()}
  def verify_flow(%Flow{} = flow) do
    if Flow.hash_matches?(flow), do: :ok, else: {:error, :flow_hash_mismatch}
  end

  @spec verify_capability(agent(), Flow.t(), integer() | nil) :: :ok | {:error, atom()}
  def verify_capability(agent, %Flow{} = flow, now_ms \\ nil) do
    opts = if now_ms, do: [now_ms: now_ms], else: []

    authorized? =
      Enum.all?(flow.steps, fn step ->
        Capability.authorizes?(agent.capability, step.operation, opts)
      end)

    cond do
      Capability.expired?(agent.capability, now_ms || System.monotonic_time(:millisecond)) ->
        {:error, :capability_expired}

      authorized? ->
        :ok

      true ->
        {:error, :capability_denied}
    end
  end

  @spec verify_budget(agent(), Flow.t()) :: :ok | {:error, atom()}
  def verify_budget(agent, %Flow{} = flow) do
    if agent.budget.spent + Flow.total_cost(flow) <= agent.budget.limit do
      :ok
    else
      {:error, :budget_exhausted}
    end
  end

  @spec verify_quarantine(Flow.t()) :: :ok | {:error, atom() | tuple()}
  def verify_quarantine(%Flow{} = flow) do
    with {:ok, _snapshot} <- Store.barrier(),
         :ok <- Store.denied_any?(Flow.footprint(flow)) do
      :ok
    else
      {:error, :stale} -> {:error, :stale_registry}
      {:error, :unavailable} -> {:error, :registry_unavailable}
      {:error, entity} -> {:error, {:quarantined, entity}}
    end
  end

  defp submit(agent, %Flow{} = flow, client) do
    flow.steps
    |> Enum.reduce_while({:ok, []}, fn step, {:ok, acc} ->
      intent = %{
        agent_id: agent.id,
        wallet_id: agent.wallet_id,
        operation: step.operation,
        footprint: step.footprint,
        flow_id: flow.id,
        flow_hash: flow.content_hash
      }

      case client.simulate(intent) do
        {:ok, ticket} ->
          Wall3t.Audit.Log.record(%{
            type: :intent_submitted,
            subject: agent.id,
            at_ms: System.monotonic_time(:millisecond),
            flow_id: flow.id,
            flow_hash: flow.content_hash,
            operation: step.operation,
            ticket_id: ticket.ticket_id,
            registry_version: ticket.registry_version
          })

          {:cont, {:ok, [Map.put(intent, :ticket, ticket) | acc]}}

        {:error, reason} ->
          Wall3t.Audit.Log.record(%{
            type: :intent_rejected,
            subject: agent.id,
            at_ms: System.monotonic_time(:millisecond),
            flow_id: flow.id,
            operation: step.operation,
            reason: reason
          })

          {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, intents} -> {:ok, Enum.reverse(intents)}
      {:error, reason} -> {:error, reason}
    end
  end
end
