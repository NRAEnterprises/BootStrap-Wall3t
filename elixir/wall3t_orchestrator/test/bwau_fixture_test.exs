defmodule Wall3t.BW3CBwauFixtureTest do
  use ExUnit.Case

  test "OTP verifies the BWAU envelope and complete ticket transcript" do
    result = Wall3t.BW3C.BwauFixture.verify()

    assert result.payload_hash ==
             "471a229ca02b31554bb9ff0a36ddc89f14211c90bf0a1df15d2266d94d292796"

    assert result.envelope_signature_valid?
    assert result.ticket_signature_valid?
  end
end
