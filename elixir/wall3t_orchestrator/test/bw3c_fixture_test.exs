defmodule Wall3t.BW3CFixtureTest do
  use ExUnit.Case, async: true

  alias Wall3t.BW3C.EvmFixture

  test "Elixir reproduces the Rust BW3C kind-7 fixture exactly" do
    bytes = EvmFixture.encode()
    assert Base.encode16(bytes, case: :lower) == EvmFixture.expected_hex()
    assert Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) == EvmFixture.expected_digest()
  end
end
