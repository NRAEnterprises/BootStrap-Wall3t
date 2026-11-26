defmodule Wall3t.Application do
  @moduledoc """
  Supervision tree for the BootStrap Wall3t management plane.

  This layer supervises agents, capabilities, budgets, flow scheduling, and
  audit emission. It holds no key material and cannot sign or broadcast.
  Every value-moving action becomes an intent submitted to the Rust wallet
  core, which performs the authoritative policy and quarantine checks.
  """

  use Application

  @impl true
  def start(_type, _args) do
    Wall3t.WalletCore.Readiness.ensure_ready()

    children =
      [
        {Registry, keys: :unique, name: Wall3t.AgentRegistry},
        {DynamicSupervisor, strategy: :one_for_one, name: Wall3t.AgentSupervisor},
        Wall3t.Automation.RunHistory,
        Wall3t.Quarantine.Store,
        Wall3t.Audit.Log,
        Wall3t.WalletCore.Stub
      ] ++ rust_service_children()

    Supervisor.start_link(children,
      strategy: :one_for_one,
      max_restarts: 3,
      max_seconds: 5,
      name: Wall3t.Supervisor
    )
  end

  defp rust_service_children do
    case System.get_env("WALL3T_RUST_SERVICE_AUTOSTART") do
      "1" -> [Wall3t.WalletCore.RustService.from_env()]
      _ -> []
    end
  end
end
