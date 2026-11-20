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
    children = [
      {Registry, keys: :unique, name: Wall3t.AgentRegistry},
      {DynamicSupervisor, strategy: :one_for_one, name: Wall3t.AgentSupervisor},
      Wall3t.Automation.RunHistory,
      Wall3t.Quarantine.Store,
      Wall3t.Audit.Log,
      Wall3t.WalletCore.Stub
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Wall3t.Supervisor)
  end
end
