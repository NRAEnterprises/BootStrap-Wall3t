defmodule Wall3t.LifecycleTest do
  use ExUnit.Case

  alias Wall3t.Agent.Manager
  alias Wall3t.Automation.RunHistory
  alias Wall3t.Automation.Retry
  alias Wall3t.WalletCore.RustService

  setup do
    id = "test-agent-#{System.unique_integer([:positive])}"
    assert {:ok, _pid} = Manager.start_agent(%{id: id, wallet_id: "wallet-1", budget_limit: 10})
    %{id: id}
  end

  test "agent can pause and resume, then revoke permanently", %{id: id} do
    assert {:ok, :running} = Wall3t.Agent.Server.status(id)
    assert :ok = Manager.pause(id, "quarantine")
    assert {:ok, :paused} = Wall3t.Agent.Server.status(id)
    assert :ok = Manager.resume(id)
    assert :ok = Manager.revoke(id, "user_revocation")
    assert {:ok, :revoked} = Wall3t.Agent.Server.status(id)
    assert {:error, :terminal_state} = Manager.resume(id)
  end

  test "run history deduplicates idempotency keys", %{id: id} do
    key = "run-#{System.unique_integer([:positive])}"
    assert {:ok, first} = RunHistory.begin(id, "flow-1", key, now_ms: 10)
    assert {:duplicate, ^first} = RunHistory.begin(id, "flow-1", key, now_ms: 11)
    assert {:ok, finished} = RunHistory.finish(key, :succeeded, %{ticket: "t1"})
    assert finished.status == :succeeded
  end

  test "retry backoff is capped and bounded", _ctx do
    assert Retry.delay_ms(1, base_ms: 100, max_ms: 500) == 100
    assert Retry.delay_ms(4, base_ms: 100, max_ms: 500) == 500
    assert Retry.retry?(1, 3)
    refute Retry.retry?(3, 3)
  end

  test "supervisor restarts the Rust service after an abnormal exit", _ctx do
    name = String.to_atom("rust-service-test-#{System.unique_integer([:positive])}")

    marker =
      Path.join(System.tmp_dir!(), "wall3t-rust-service-#{System.unique_integer([:positive])}")

    script = "if [ -e #{marker} ]; then exec sleep 2; else : > #{marker}; exit 17; fi"

    on_exit(fn -> File.rm(marker) end)

    assert is_pid(
             start_supervised!(
               {RustService,
                command: System.find_executable("sh"), args: ["-c", script], name: name}
             )
           )

    assert wait_until(fn -> File.exists?(marker) and RustService.status(name) == :running end)
  end

  defp wait_until(predicate, attempts \\ 50)
  defp wait_until(_predicate, 0), do: false

  defp wait_until(predicate, attempts) do
    if predicate.() do
      true
    else
      Process.sleep(20)
      wait_until(predicate, attempts - 1)
    end
  end
end
