defmodule Wall3t.WalletCore.UnixSocketClient do
  @moduledoc """
  Authenticated Unix-domain client for the Rust wallet-core socket endpoint.

  The client transports already-authenticated BWAU bytes only. It cannot sign,
  broadcast, unlock keys, or construct private-key material.
  """

  @max_frame 8 * 1024 * 1024
  @max_response 16 * 1024

  @spec submit(Path.t(), binary(), timeout()) :: {:ok, map()} | {:error, atom() | binary()}
  def submit(socket_path, envelope, timeout \\ 5_000)
  def submit(socket_path, envelope, timeout)
      when is_binary(socket_path) and is_binary(envelope) and is_integer(timeout) and timeout > 0 do
    if byte_size(envelope) == 0 or byte_size(envelope) > @max_frame do
      {:error, :invalid_request_size}
    else
      with {:ok, socket} <- connect(socket_path, timeout),
           :ok <- send_frame(socket, envelope),
           {:ok, response} <- recv_frame(socket, timeout),
           result <- parse_response(response),
           :ok <- :gen_tcp.close(socket) do
        result
      else
        {:error, reason} -> {:error, reason}
      end
    end
  end

  def submit(_, _, _), do: {:error, :invalid_arguments}

  defp connect(path, timeout) do
    case :gen_tcp.connect({:local, String.to_charlist(path)}, 0, [:binary, active: false], timeout) do
      {:ok, socket} -> {:ok, socket}
      {:error, :econnrefused} -> {:error, :service_unavailable}
      {:error, :enoent} -> {:error, :service_unavailable}
      {:error, reason} -> {:error, reason}
    end
  end

  defp send_frame(socket, payload) do
    :gen_tcp.send(socket, <<byte_size(payload)::unsigned-big-integer-size(32), payload::binary>>)
  end

  defp recv_frame(socket, timeout) do
    with {:ok, <<length::unsigned-big-integer-size(32)>>} <- :gen_tcp.recv(socket, 4, timeout),
         true <- length > 0 and length <= @max_response,
         {:ok, response} <- :gen_tcp.recv(socket, length, timeout) do
      {:ok, response}
    else
      false -> {:error, :invalid_response_size}
      {:error, :closed} -> {:error, :service_closed}
      {:error, :timeout} -> {:error, :service_timeout}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_response_frame}
    end
  end

  defp parse_response(<<"OK ", metadata::binary>>) do
    case Regex.run(~r/^kind=(\d+) payload_bytes=(\d+) registry_version=(\d+)\n$/, metadata, capture: :all_but_first) do
      [kind, payload_bytes, registry_version] ->
        {:ok,
         %{
           kind: String.to_integer(kind),
           payload_bytes: String.to_integer(payload_bytes),
           registry_version: String.to_integer(registry_version)
         }}

      _ -> {:error, :invalid_success_response}
    end
  end

  defp parse_response(<<"ERR ", reason::binary>>) do
    if byte_size(reason) > 0 and byte_size(reason) <= 512 and String.valid?(reason) do
      {:error, String.trim_trailing(reason, "\n")}
    else
      {:error, :invalid_error_response}
    end
  end

  defp parse_response(_), do: {:error, :invalid_response}
end
