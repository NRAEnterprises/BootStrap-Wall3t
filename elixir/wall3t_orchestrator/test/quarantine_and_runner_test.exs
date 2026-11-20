defmodule Wall3t.QuarantineAndRunnerTest do
  use ExUnit.Case

  alias Wall3t.Automation.Flow
  alias Wall3t.Automation.Runner
  alias Wall3t.Capability

  setup do
    Wall3t.Quarantine.Store.reset()
    Wall3t.WalletCore.Stub.reset()
    Wall3t.Audit.Log.reset()
    :ok
  end

  defp flow do
    {:ok, flow} = Flow.new(%{
      id: "swap-flow",
      version: "v1",
      trigger: %{kind: :manual},
      steps: [%{operation: :swap, footprint: ["token:1:bad", "router:1:good"]}]
    })

    flow
  end

  defp agent do
    %{id: "agent-1", wallet_id: "wallet-1", capability: Capability.grant(%{operations: [:swap]}, ttl_ms: 10_000), budget: %{limit: 10, spent: 0}}
  end

  test "runner fails closed until a fresh checkpoint exists" do
    assert {:error, :registry_unavailable} = Runner.run(agent(), flow())
  end

  test "runner blocks an entity from the global deny projection" do
    now = System.monotonic_time(:millisecond)
    assert :ok = Wall3t.Quarantine.Store.apply_checkpoint(%{version: 1, state_root: "root-1", denied: ["token:1:bad"], fresh_until_ms: now + 10_000})
    assert {:error, {:quarantined, "token:1:bad"}} = Runner.run(agent(), flow())
  end

  test "runner submits opaque intent only after pre-flight gates" do
    now = System.monotonic_time(:millisecond)
    assert :ok = Wall3t.Quarantine.Store.apply_checkpoint(%{version: 1, state_root: "root-1", denied: [], fresh_until_ms: now + 10_000})
    assert {:ok, [intent]} = Runner.run(agent(), flow())
    assert intent.agent_id == "agent-1"
    assert intent.wallet_id == "wallet-1"
    assert intent.ticket.registry_version == 1
    refute Map.has_key?(intent, :mnemonic)
    assert length(Wall3t.WalletCore.Stub.intents()) == 1
  end
end
