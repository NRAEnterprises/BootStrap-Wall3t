defmodule Wall3t.WalletCore.RustService do
  @moduledoc """
  Supervised lifecycle wrapper for the Rust wallet-core socket service.

  The process is started only from explicit deployment configuration. Any
  unexpected Rust exit stops this child so the supervisor can restart it under
  bounded intensity; repeated failures terminate the application rather than
  leaving the management plane attached to an unavailable signer boundary.
  """

  use GenServer

  @type option :: {:command, Path.t()} | {:args, [binary()]} | {:name, atom() | nil}

  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(options) do
    name = Keyword.get(options, :name, __MODULE__)
    GenServer.start_link(__MODULE__, options, name: name)
  end

  @spec child_spec([option()]) :: Supervisor.child_spec()
  def child_spec(options) do
    %{
      id: Keyword.get(options, :name, __MODULE__),
      start: {__MODULE__, :start_link, [options]},
      restart: :permanent,
      shutdown: 5_000,
      type: :worker
    }
  end

  @spec from_env() :: Supervisor.child_spec()
  def from_env do
    command = System.get_env("WALL3T_RUST_SERVICE_COMMAND")
    args = System.get_env("WALL3T_RUST_SERVICE_ARGS")

    if is_binary(command) and command != "" and is_binary(args) do
      child_spec(command: command, args: parse_args(args))
    else
      raise "WALL3T_RUST_SERVICE_COMMAND and WALL3T_RUST_SERVICE_ARGS are required when autostart is enabled"
    end
  end

  @spec status(GenServer.server()) :: :running | {:stopping, term()}
  def status(server \\ __MODULE__), do: GenServer.call(server, :status)

  @impl true
  def init(options) do
    Process.flag(:trap_exit, true)
    command = Keyword.fetch!(options, :command)
    args = Keyword.get(options, :args, [])

    with :ok <- validate_command(command),
         :ok <- validate_args(args),
         {:ok, port} <- open_port(command, args) do
      {:ok, %{command: command, args: args, port: port, status: :running}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:status, _from, state), do: {:reply, state.status, state}

  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    {:stop, {:rust_service_exit, status}, %{state | status: {:stopping, status}}}
  end

  def handle_info({:EXIT, port, reason}, %{port: port} = state) do
    {:stop, {:rust_service_exit, reason}, %{state | status: {:stopping, reason}}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{port: port}) do
    if is_port(port) do
      try do
        Port.close(port)
      catch
        :error, :badarg -> :ok
      end
    end

    :ok
  end

  defp validate_command(command) when is_binary(command) and command != "", do: :ok
  defp validate_command(_), do: {:error, :invalid_rust_service_command}

  defp validate_args(args) when is_list(args) do
    if Enum.all?(args, &(is_binary(&1) and byte_size(&1) <= 4096)) do
      :ok
    else
      {:error, :invalid_rust_service_arguments}
    end
  end

  defp validate_args(_), do: {:error, :invalid_rust_service_arguments}

  defp open_port(command, args) do
    try do
      {:ok, Port.open({:spawn_executable, command}, [:binary, :exit_status, {:args, args}])}
    rescue
      ArgumentError -> {:error, :rust_service_spawn_failed}
    end
  end

  # The unit-separator delimiter avoids shell parsing and keeps argument
  # boundaries explicit. Deployment manifests must provide, for example,
  # "/run/wall3t.sock\u001faccept\u001fkey-id".
  defp parse_args(value), do: String.split(value, <<31>>, trim: true)
end
