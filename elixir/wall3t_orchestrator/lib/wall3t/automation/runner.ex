defmodule Wall3t.Automation.Runner do
  @moduledoc """
  Turns an approved flow into typed intents for the Rust wallet core.

  The management plane only performs early checks. Rust wallet-core must still
  re-derive the final footprint and re-check policy, quarantine, and freshness
  at simulation, signing, and broadcast.
  """

  alias Wall3t.ActionContext
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
    effective_now = now_ms || System.monotonic_time(:millisecond)

    cond do
      Capability.expired?(agent.capability, effective_now) ->
        {:error, :capability_expired}

      Enum.all?(flow.steps, fn
        %{action_context: %ActionContext{} = context} ->
          Capability.authorizes?(agent.capability, context, opts)

        _ ->
          false
      end) ->
        :ok

      true ->
        {:error, :capability_denied}
    end
  end

  def verify_capability(_agent, _flow, _now_ms), do: {:error, :incomplete_action_context}

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
    |> Enum.reduce_while({:ok, []}, fn %{action_context: %ActionContext{} = context} = step, {:ok, acc} ->
      context_hash = context_hash(context)

      intent = %{
        agent_id: agent.id,
        wallet_id: agent.wallet_id,
        operation: context.operation,
        action_context: context,
        context_hash: context_hash,
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
            operation: context.operation,
            context_hash: context_hash,
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
            operation: context.operation,
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

  defp context_hash(context) do
    :crypto.hash(:sha256, :erlang.term_to_binary(ActionContext.canonical(context)))
    |> Base.encode16(case: :lower)
  end
end
