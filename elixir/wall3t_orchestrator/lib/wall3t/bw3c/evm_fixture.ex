defmodule Wall3t.BW3C.EvmFixture do
  @moduledoc "Independent BW3C kind-7 fixture encoder for cross-language compatibility."

  @fixture_hex "4257334300010700000010666978747572652d696e74656e742d310000001077616c6c65742d666978747572652d31020000000f6167656e742d666978747572652d3102000000000000000111111111111111111111111111111111111111110122222222222222222222222222222222222222220000000000000007000000000000000000000000000000000000000000000000000000000000000900000000000186a0020000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000003aabbcc0000000010706f6c6963792d666978747572652d310000000d6361702d666978747572652d310000000d646f632d666978747572652d310000000302000000000000000100000028323232323232323232323232323232323232323232323232323232323232323232323232323232320500000000000000010800000000000000010000002831313131313131313131313131313131313131313131313131313131313131313131313131313131000000006553f100000000006553f358"
  @digest "74bdcab9ad7743ff37567874bceb8b0333aa8d8bc6b425c93bd65e1b1f3a3708"

  def expected_hex, do: @fixture_hex
  def expected_digest, do: @digest

  def encode do
    i = fn value -> <<value::unsigned-big-integer-size(256)>> end
    s = fn value -> <<byte_size(value)::unsigned-big-integer-size(32), value::binary>> end
    b = fn value -> <<byte_size(value)::unsigned-big-integer-size(32), value::binary>> end
    entity = fn
      {:contract, chain, address} -> <<2, chain::unsigned-big-integer-size(64), s.(address)::binary>>
      {:chain, chain} -> <<5, chain::unsigned-big-integer-size(64)>>
      {:wallet, chain, address} -> <<8, chain::unsigned-big-integer-size(64), s.(address)::binary>>
    end

    footprint = [
      {:contract, 1, "2222222222222222222222222222222222222222"},
      {:chain, 1},
      {:wallet, 1, "1111111111111111111111111111111111111111"}
    ]

    <<"BW3C", 1::unsigned-big-integer-size(16), 7,
      s.("fixture-intent-1")::binary,
      s.("wallet-fixture-1")::binary,
      2, s.("agent-fixture-1")::binary,
      2,
      1::unsigned-big-integer-size(64),
      0x1111111111111111111111111111111111111111::unsigned-big-integer-size(160),
      1,
      0x2222222222222222222222222222222222222222::unsigned-big-integer-size(160),
      7::unsigned-big-integer-size(64), i.(9)::binary,
      100_000::unsigned-big-integer-size(64),
      2, i.(2)::binary, i.(1)::binary,
      b.(<<0xAA, 0xBB, 0xCC>>)::binary,
      0,
      s.("policy-fixture-1")::binary,
      s.("cap-fixture-1")::binary,
      s.("doc-fixture-1")::binary,
      length(footprint)::unsigned-big-integer-size(32),
      (for item <- footprint, into: <<>>, do: entity.(item))::binary,
      1_700_000_000::unsigned-big-integer-size(64),
      1_700_000_600::unsigned-big-integer-size(64)>>
  end
end
