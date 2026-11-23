defmodule Wall3t.QuarantineAndRunnerTest do
  use ExUnit.Case

  alias Wall3t.ActionContext
  alias Wall3t.Automation.Flow
  alias Wall3t.Automation.Runner
  alias Wall3t.Capability

  setup do
    Wall3t.Quarantine.Store.reset()
    Wall3t.WalletCore.Stub.reset()
    Wall3t.Audit.Log.reset()
    :ok
  end

  defp action_context(overrides \\ %{}) do
    attrs = Map.merge(%{
      operation: :swap,
      chain_id: 1,
      venue: "registered:test-venue",
      assets: ["asset:1:good"],
      destination: "contract:1:good",
      amount: 1_000,
      fee_limit: 10,
      slippage_bps: 50,
      footprint: ["token:1:bad", "router:1:good"]
    }, overrides)

    {:ok, context} = ActionContext.new(attrs)
    context
  end

  defp flow do
    {:ok, flow} = Flow.new(%{
      id: "swap-flow",
      version: "v1",
      trigger: %{kind: :manual},
      steps: [%{action_context: action_context()}]
    })

    flow
  end

  defp agent do
    context = action_context()

    capability = Capability.grant(%{
      chains: [context.chain_id],
      operations: [context.operation],
      venues: [context.venue],
      assets: context.assets,
      destinations: [context.destination],
      max_amount: context.amount,
      max_fee: context.fee_limit,
      max_slippage_bps: context.slippage_bps
    }, ttl_ms: 10_000)

    %{id: "agent-1", wallet_id: "wallet-1", capability: capability, budget: %{limit: 10, spent: 0}}
  end

  test "runner fails closed until a fresh checkpoint exists" do
    assert {:error, :registry_unavailable} = Runner.run(agent(), flow())
  end

  test "runner blocks an entity from the global deny projection" do
    now = System.monotonic_time(:millisecond)
    assert :ok = Wall3t.Quarantine.Store.apply_checkpoint(%{version: 1, state_root: "root-1", denied: ["token:1:bad"], fresh_until_ms: now + 10_000})
    assert {:error, {:quarantined, "token:1:bad"}} = Runner.run(agent(), flow())
  end

  test "runner submits typed intent only after pre-flight gates" do
    now = System.monotonic_time(:millisecond)
    assert :ok = Wall3t.Quarantine.Store.apply_checkpoint(%{version: 1, state_root: "root-1", denied: [], fresh_until_ms: now + 10_000})
    assert {:ok, [intent]} = Runner.run(agent(), flow())
    assert intent.agent_id == "agent-1"
    assert intent.wallet_id == "wallet-1"
    assert intent.action_context.chain_id == 1
    assert is_binary(intent.context_hash)
    assert intent.ticket.registry_version == 1
    refute Map.has_key?(intent, :mnemonic)
    assert length(Wall3t.WalletCore.Stub.intents()) == 1
  end

  test "runner rejects an action outside the agent capability" do
    now = System.monotonic_time(:millisecond)
    assert :ok = Wall3t.Quarantine.Store.apply_checkpoint(%{version: 1, state_root: "root-1", denied: [], fresh_until_ms: now + 10_000})
    assert {:ok, out_of_scope_flow} = Flow.new(%{
      id: "out-of-scope",
      version: "v1",
      trigger: %{kind: :manual},
      steps: [%{action_context: action_context(%{destination: "contract:1:other"})}]
    })

    assert {:error, :capability_denied} = Runner.run(agent(), out_of_scope_flow)
  end
end
