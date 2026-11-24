defmodule Wall3t.BW3CBwauTest do
  use ExUnit.Case

  alias Wall3t.BW3C.Bwau

  @fixture Path.expand("../../../fixtures/bwau/evm_simulation_ticket_v1.json", __DIR__)

  test "decodes and verifies the authenticated envelope fixture" do
    json = File.read!(@fixture)
    envelope = extract_hex!(json, "envelope_hex")
    public_key = extract_hex!(json, "public_key_hex")

    assert {:ok, decoded} = Bwau.decode_and_verify(envelope, public_key, 1_700_000_000)
    assert decoded.kind == 7
    assert decoded.signer == extract_text!(json, "signer")
    assert decoded.key_id == extract_text!(json, "signer_key_id")
    assert decoded.payload_hash == extract_hex!(json, "payload_hash_sha256")
  end

  test "rejects a valid envelope with trailing bytes" do
    json = File.read!(@fixture)
    envelope = extract_hex!(json, "envelope_hex") <> <<0>>
    public_key = extract_hex!(json, "public_key_hex")

    assert {:error, :invalid_envelope} = Bwau.decode_and_verify(envelope, public_key, 1_700_000_000)
  end

  test "rejects expiry before attempting signature acceptance" do
    json = File.read!(@fixture)
    envelope = extract_hex!(json, "envelope_hex")
    public_key = extract_hex!(json, "public_key_hex")
    expiry = extract_number!(json, "expires_at_unix")

    assert {:error, :expired} = Bwau.decode_and_verify(envelope, public_key, expiry)
  end

  test "rejects a payload hash mutation" do
    json = File.read!(@fixture)
    envelope = extract_hex!(json, "envelope_hex")
    public_key = extract_hex!(json, "public_key_hex")
    <<prefix::binary-size(byte_size(envelope) - 100), hash::binary-size(32),
      length::unsigned-big-integer-size(32), signature::binary-size(64)>> = envelope
    mutated =
      prefix <> :crypto.exor(hash, :binary.copy(<<1>>, 32)) <>
        <<length::unsigned-big-integer-size(32), signature::binary>>

    assert {:error, :invalid_envelope} = Bwau.decode_and_verify(mutated, public_key, 1_700_000_000)
  end

  defp extract_hex!(json, key) do
    json |> extract_text!(key) |> Base.decode16!(case: :lower)
  end

  defp extract_number!(json, key) do
    [value] = Regex.run(~r/"#{key}"\s*:\s*(\d+)/, json, capture: :all_but_first)
    String.to_integer(value)
  end

  defp extract_text!(json, key) do
    [value] = Regex.run(~r/"#{key}"\s*:\s*"([^"]+)"/, json, capture: :all_but_first)
    value
  end
end
