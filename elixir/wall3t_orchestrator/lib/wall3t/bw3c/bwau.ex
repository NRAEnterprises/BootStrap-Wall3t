defmodule Wall3t.BW3C.Bwau do
  @moduledoc """
  Strict BWAU v1 decoder for the Elixir management-plane transport boundary.

  This module verifies public authenticated envelopes and returns opaque
  transport data. It never accepts private keys and cannot sign or broadcast.
  """

  @magic "BWAU"
  @version 1
  @domain "BOOTSTRAP-WALL3T/AUTHENTICATED-WIRE/V1\0"
  @max_payload 8 * 1024 * 1024
  @max_text 512
  @nonce_size 16

  @type envelope :: %{
          kind: 1..7,
          signer: binary(),
          key_id: binary(),
          subject: binary(),
          registry_version: non_neg_integer(),
          expires_at_unix: non_neg_integer(),
          nonce: <<_::128>>,
          payload: binary(),
          payload_hash: <<_::256>>,
          signature: binary()
        }

  @spec decode_and_verify(binary(), binary(), non_neg_integer()) :: {:ok, envelope()} | {:error, atom()}
  def decode_and_verify(encoded, public_key, now_unix)
      when is_binary(encoded) and is_binary(public_key) and is_integer(now_unix) and now_unix >= 0 do
    with {:ok, envelope} <- decode(encoded),
         :ok <- verify_key(public_key),
         :ok <- verify_context(envelope, now_unix),
         :ok <- verify_signature(envelope, public_key) do
      {:ok, envelope}
    end
  end

  def decode_and_verify(_, _, _), do: {:error, :invalid_arguments}

  @spec decode(binary()) :: {:ok, envelope()} | {:error, atom()}
  def decode(encoded) when is_binary(encoded) do
    with {:ok, <<@magic, @version::unsigned-big-integer-size(16), kind, rest::binary>>} <- {:ok, encoded},
         true <- kind in 1..7,
         {:ok, signer, rest} <- take_text(rest),
         {:ok, key_id, rest} <- take_text(rest),
         {:ok, subject, rest} <- take_text(rest),
         {:ok, registry_version, rest} <- take_u64(rest),
         {:ok, expires_at_unix, rest} <- take_u64(rest),
         {:ok, nonce, rest} <- take_exact(rest, @nonce_size),
         {:ok, payload, rest} <- take_bytes(rest, @max_payload),
         {:ok, payload_hash, rest} <- take_exact(rest, 32),
         {:ok, signature, rest} <- take_bytes(rest, 16 * 1024),
         true <- signature != <<>>,
         true <- rest == <<>>,
         true <- payload_hash == payload_hash(kind, payload) do
      {:ok,
       %{
         kind: kind,
         signer: signer,
         key_id: key_id,
         subject: subject,
         registry_version: registry_version,
         expires_at_unix: expires_at_unix,
         nonce: nonce,
         payload: payload,
         payload_hash: payload_hash,
         signature: signature
       }}
    else
      false -> {:error, :invalid_envelope}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_envelope}
    end
  end

  def decode(_), do: {:error, :invalid_envelope}

  defp verify_key(<<_::binary-size(32)>>), do: :ok
  defp verify_key(_), do: {:error, :invalid_public_key}

  defp verify_context(%{registry_version: 0}, _), do: {:error, :invalid_context}
  defp verify_context(%{nonce: <<0::128>>}, _), do: {:error, :invalid_context}
  defp verify_context(%{expires_at_unix: expiry}, now) when expiry <= now, do: {:error, :expired}
  defp verify_context(_, _), do: :ok

  defp verify_signature(envelope, public_key) do
    message =
      IO.iodata_to_binary([
        @domain,
        <<@version::unsigned-big-integer-size(16), envelope.kind>>,
        text(envelope.signer),
        text(envelope.key_id),
        text(envelope.subject),
        <<envelope.registry_version::unsigned-big-integer-size(64),
          envelope.expires_at_unix::unsigned-big-integer-size(64)>>,
        envelope.nonce,
        envelope.payload_hash
      ])

    if :crypto.verify(:eddsa, :none, message, envelope.signature, [public_key, :ed25519]) do
      :ok
    else
      {:error, :signature_rejected}
    end
  end

  defp payload_hash(kind, payload) do
    :crypto.hash(:sha256, [@domain, <<@version::unsigned-big-integer-size(16), kind>>, bytes(payload)])
  end

  defp text(value), do: bytes(value)
  defp bytes(value), do: <<byte_size(value)::unsigned-big-integer-size(32), value::binary>>

  defp take_text(data) do
    with {:ok, value, rest} <- take_bytes(data, @max_text),
         true <- value != <<>>,
         true <- String.valid?(value),
         true <- Enum.all?(:binary.bin_to_list(value), &(&1 >= 32 and &1 != 127)) do
      {:ok, value, rest}
    else
      false -> {:error, :invalid_text}
      {:error, reason} -> {:error, reason}
    end
  end

  defp take_bytes(<<length::unsigned-big-integer-size(32), rest::binary>>, maximum)
       when length <= maximum and byte_size(rest) >= length do
    <<value::binary-size(length), tail::binary>> = rest
    {:ok, value, tail}
  end

  defp take_bytes(_, _), do: {:error, :truncated}

  defp take_u64(<<value::unsigned-big-integer-size(64), rest::binary>>), do: {:ok, value, rest}
  defp take_u64(_), do: {:error, :truncated}

  defp take_exact(data, size) when byte_size(data) >= size do
    <<value::binary-size(size), rest::binary>> = data
    {:ok, value, rest}
  end

  defp take_exact(_, _), do: {:error, :truncated}
end
