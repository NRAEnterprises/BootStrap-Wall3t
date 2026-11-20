defmodule Wall3t.FlowAndCapabilityTest do
  use ExUnit.Case, async: true

  alias Wall3t.Automation.Flow
  alias Wall3t.Automation.Scheduler
  alias Wall3t.Capability

  test "capability requires an explicit operation and expires" do
    capability = Capability.grant(%{chains: [1], operations: [:swap], venues: ["venue"]}, token: "test", issued_at_ms: 0, ttl_ms: 100)

    assert Capability.authorizes?(capability, :swap, chain_id: 1, venue: "venue", now_ms: 1)
    refute Capability.authorizes?(capability, :transfer, chain_id: 1, venue: "venue", now_ms: 1)
    refute Capability.authorizes?(capability, :swap, chain_id: 5, venue: "venue", now_ms: 1)
    refute Capability.authorizes?(capability, :swap, chain_id: 1, venue: "venue", now_ms: 101)
  end

  test "flow hash is stable and footprint is deduplicated" do
    assert {:ok, flow} = Flow.new(%{
             id: "flow-1",
             version: "v1",
             trigger: %{kind: :manual},
             steps: [
               %{operation: :swap, footprint: ["token:1:a", "router:1:r"], cost: 2},
               %{operation: :transfer, footprint: ["token:1:a"], cost: 1}
             ]
           })

    assert Flow.hash_matches?(flow)
    assert Flow.footprint(flow) == ["token:1:a", "router:1:r"]
    assert Flow.total_cost(flow) == 3
  end

  test "scheduler selects only due autonomous flows in deterministic order" do
    attrs = fn id, trigger ->
      {:ok, flow} = Flow.new(%{id: id, version: "v1", trigger: trigger, steps: [%{operation: :swap, footprint: ["x"]}]})
      flow
    end

    flows = [
      attrs.("manual", %{kind: :manual}),
      attrs.("later", %{kind: :interval, every_ms: 1000}),
      attrs.("ready", %{kind: :interval, every_ms: 1000})
    ]

    assert Enum.map(Scheduler.due_flows(flows, %{"ready" => 1_000, "later" => 2_000}, 2_100), & &1.id) == ["ready"]
  end
end
