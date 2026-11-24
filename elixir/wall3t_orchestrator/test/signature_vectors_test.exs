defmodule Wall3t.SignatureVectorsTest do
  use ExUnit.Case

  @vectors Path.expand("../../../vectors/phase2_ed25519_vectors.tsv", __DIR__)

  test "shared Phase 2 Ed25519 vectors match expected outcomes" do
    @vectors
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.reject(&String.starts_with?(&1, "#"))
    |> Enum.each(fn line ->
      [id, "ed25519", _signer, _key_id, public_key, message, signature, expected] =
        String.split(line, "|")

      valid =
        :crypto.verify(
          :eddsa,
          :none,
          Base.decode16!(message, case: :lower),
          Base.decode16!(signature, case: :lower),
          [Base.decode16!(public_key, case: :lower), :ed25519]
        )

      assert valid == (expected == "valid"), "vector #{id}"
    end)
  end
end
