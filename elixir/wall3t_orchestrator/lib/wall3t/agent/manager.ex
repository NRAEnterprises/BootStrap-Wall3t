defmodule Wall3t.Agent.Manager do
  @moduledoc "Public API for creating and controlling supervised agents."

  alias Wall3t.Agent.Server

  @spec start_agent(map()) :: {:ok, pid()} | {:error, term()}
  def start_agent(attrs) when is_map(attrs) do
    DynamicSupervisor.start_child(Wall3t.AgentSupervisor, {Server, attrs})
  end

  @spec pause(String.t(), String.t()) :: :ok | {:error, term()}
  def pause(id, reason \\ "operator_pause"), do: Server.pause(id, reason)

  @spec resume(String.t()) :: :ok | {:error, term()}
  def resume(id), do: Server.resume(id)

  @spec revoke(String.t(), String.t()) :: :ok | {:error, term()}
  def revoke(id, reason \\ "capability_revoked"), do: Server.revoke(id, reason)

  @spec kill(String.t(), String.t()) :: :ok | {:error, term()}
  def kill(id, reason \\ "emergency_kill"), do: Server.kill(id, reason)

  @spec list() :: [String.t()]
  def list do
    Registry.select(Wall3t.AgentRegistry, [{{:"$1", :"$2", :"$3"}, [], [{{:"$1", :"$2"}}]}])
    |> Enum.map(fn {id, _pid} -> id end)
    |> Enum.sort()
  end
end
