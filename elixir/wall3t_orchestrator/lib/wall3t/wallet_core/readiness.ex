defmodule Wall3t.WalletCore.Readiness do
  @moduledoc """
  Startup gate for the systemd-managed wallet-core endpoint.

  In external lifecycle mode, the orchestrator does not start a Rust child and
  does not report ready until the authenticated, non-consuming health exchange
  succeeds. Development and test applications keep the gate disabled unless
  explicitly enabled through the deployment environment.
  """

  alias Wall3t.WalletCore.UnixSocketClient

  @default_timeout 5_000

  @spec ensure_ready() :: :ok
  def ensure_ready do
    case System.get_env("WALL3T_RUST_SERVICE_EXTERNAL") do
      "1" ->
        socket_path =
          System.get_env("WALL3T_SOCKET_PATH") || raise "WALL3T_SOCKET_PATH is required"

        timeout = readiness_timeout()

        case UnixSocketClient.health(socket_path, timeout) do
          {:ok, %{state_flags: 0x1F, protocol_epoch: epoch}} when epoch >= 1 ->
            :ok

          {:ok, response} ->
            raise "wallet-core readiness returned unusable state: #{inspect(response)}"

          {:error, reason} ->
            raise "wallet-core authenticated readiness failed: #{inspect(reason)}"
        end

      _ ->
        :ok
    end
  end

  defp readiness_timeout do
    case System.get_env("WALL3T_READINESS_TIMEOUT_MS") do
      nil -> @default_timeout
      value -> parse_timeout(value)
    end
  end

  defp parse_timeout(value) do
    case Integer.parse(value) do
      {timeout, ""} when timeout > 0 -> timeout
      _ -> raise "WALL3T_READINESS_TIMEOUT_MS must be a positive integer"
    end
  end
end
