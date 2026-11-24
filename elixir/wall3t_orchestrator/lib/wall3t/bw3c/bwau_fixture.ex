defmodule Wall3t.BW3C.BwauFixture do
  @moduledoc "Secret-free BWAU authenticated-ticket interoperability vector."

  @fixture_path Path.expand("../../../../../fixtures/bwau/evm_simulation_ticket_v1.json", __DIR__)

  def verify do
    json = File.read!(@fixture_path)
    payload = extract!(json, "canonical_payload_hex") |> Base.decode16!(case: :lower)
    public_key = extract!(json, "public_key_hex") |> Base.decode16!(case: :lower)
    envelope_signature = extract!(json, "envelope_hex") |> envelope_signature()
    signed_message = extract!(json, "signed_message_hex") |> Base.decode16!(case: :lower)
    ticket_message = extract!(json, "ticket_context_message_hex") |> Base.decode16!(case: :lower)
    ticket_signature = extract!(json, "ticket_signature_hex") |> Base.decode16!(case: :lower)

    payload_hash =
      :crypto.hash(:sha256, <<"BOOTSTRAP-WALL3T/AUTHENTICATED-WIRE/V1\0"::binary, 1::unsigned-big-integer-size(16),
        7, byte_size(payload)::unsigned-big-integer-size(32), payload::binary>>)

    %{
      payload_hash: Base.encode16(payload_hash, case: :lower),
      envelope_signature_valid?: :crypto.verify(:eddsa, :none, signed_message, envelope_signature, [public_key, :ed25519]),
      ticket_signature_valid?: :crypto.verify(:eddsa, :none, ticket_message, ticket_signature, [public_key, :ed25519])
    }
  end

  defp extract!(json, key) do
    case Regex.run(~r/"#{Regex.escape(key)}"\s*:\s*"([0-9a-f]+)"/, json, capture: :all_but_first) do
      [value] -> value
      _ -> raise "missing BWAU fixture field: #{key}"
    end
  end

  defp envelope_signature(envelope_hex) do
    envelope = Base.decode16!(envelope_hex, case: :lower)
    <<_prefix::binary-size(byte_size(envelope) - 68), length::unsigned-big-integer-size(32), signature::binary-size(length)>> = envelope
    signature
  end
end
