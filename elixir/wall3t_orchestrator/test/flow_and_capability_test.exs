defmodule Wall3t.FlowAndCapabilityTest do
  use ExUnit.Case, async: true

  alias Wall3t.ActionContext
  alias Wall3t.Automation.Flow
  alias Wall3t.Automation.Scheduler
  alias Wall3t.Capability

  defp context(overrides \\ %{}) do
    attrs = %{
      operation: :swap,
      chain_id: 42161,
      venue: "registered:uniswap-v3",
      assets: ["asset:arbitrum:0xinput", "asset:arbitrum:0xoutput"],
      destination: "contract:arbitrum:0xrouter",
      amount: 10_000,
      fee_limit: 100,
      slippage_bps: 25,
      footprint: ["token:42161:0xinput", "router:42161:0xrouter"]
    }

    {:ok, context} = ActionContext.new(Map.merge(attrs, overrides))
    context
  end

  defp capability(context, overrides \\ %{}) do
    scope = Map.merge(%{
      chains: [context.chain_id],
      operations: [context.operation],
      venues: [context.venue],
      assets: context.assets,
      destinations: [context.destination],
      max_amount: context.amount,
      max_fee: context.fee_limit,
      max_slippage_bps: context.slippage_bps
    }, overrides)

    Capability.grant(scope, token: "test", issued_at_ms: 0, ttl_ms: 100)
  end

  test "capability requires a complete matching action context and expires" do
    action = context()
    granted = capability(action)

    assert Capability.authorizes?(granted, action, now_ms: 1)
    refute Capability.authorizes?(granted, context(%{operation: :transfer}), now_ms: 1)
    refute Capability.authorizes?(granted, context(%{chain_id: 1}), now_ms: 1)
    refute Capability.authorizes?(granted, action, now_ms: 101)
  end

  test "legacy operation-only authorization is rejected" do
    action = context()
    granted = capability(action)

    refute Capability.authorizes?(granted, :swap, chain_id: action.chain_id, venue: action.venue, now_ms: 1)
  end

  test "incomplete action context is rejected" do
    assert {:error, :incomplete_action_context} = ActionContext.new(%{operation: :swap})
  end

  test "out-of-scope destination and amount are denied" do
    action = context()
    granted = capability(action, %{max_amount: 9_999})

    refute Capability.authorizes?(granted, action, now_ms: 1)
    refute Capability.authorizes?(capability(action, %{destinations: ["contract:arbitrum:0xother"]}), action, now_ms: 1)
  end

  test "flow hash is stable and footprint is deduplicated" do
    assert {:ok, flow} = Flow.new(%{
             id: "flow-1",
             version: "v1",
             trigger: %{kind: :manual},
             steps: [
               %{action_context: context(), cost: 2},
               %{action_context: context(%{operation: :transfer, footprint: ["token:42161:0xinput"]}), cost: 1}
             ]
           })

    assert Flow.hash_matches?(flow)
    assert Flow.footprint(flow) == ["token:42161:0xinput", "router:42161:0xrouter"]
    assert Flow.total_cost(flow) == 3
  end

  test "legacy free-form flow steps are rejected" do
    assert {:error, :invalid_step} = Flow.new(%{
             id: "legacy",
             version: "v1",
             trigger: %{kind: :manual},
             steps: [%{operation: :swap, footprint: ["token:1:a"]}]
           })
  end

  test "scheduler selects only due autonomous flows in deterministic order" do
    attrs = fn id, trigger ->
      {:ok, flow} = Flow.new(%{id: id, version: "v1", trigger: trigger, steps: [%{action_context: context()}]})
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
