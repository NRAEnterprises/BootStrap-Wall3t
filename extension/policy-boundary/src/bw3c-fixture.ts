const EXPECTED_HEX = "4257334300010700000010666978747572652d696e74656e742d310000001077616c6c65742d666978747572652d31020000000f6167656e742d666978747572652d3102000000000000000111111111111111111111111111111111111111110122222222222222222222222222222222222222220000000000000007000000000000000000000000000000000000000000000000000000000000000900000000000186a0020000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000003aabbcc0000000010706f6c6963792d666978747572652d310000000d6361702d666978747572652d310000000d646f632d666978747572652d310000000302000000000000000100000028323232323232323232323232323232323232323232323232323232323232323232323232323232320500000000000000010800000000000000010000002831313131313131313131313131313131313131313131313131313131313131313131313131313131000000006553f100000000006553f358";
const EXPECTED_DIGEST = "74bdcab9ad7743ff37567874bceb8b0333aa8d8bc6b425c93bd65e1b1f3a3708";

function u64(value: bigint): Uint8Array {
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, value, false);
  return output;
}
function u32(value: number): Uint8Array {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}
function u16(value: number): Uint8Array {
  const output = new Uint8Array(2);
  new DataView(output.buffer).setUint16(0, value, false);
  return output;
}
function u256(value: bigint): Uint8Array {
  const output = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error("uint256 overflow");
  return output;
}
function hexBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error("odd hex length");
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return output;
}
function text(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  return concat(u32(bytes.length), bytes);
}
function blob(value: Uint8Array): Uint8Array { return concat(u32(value.length), value); }
function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}
function hex(value: Uint8Array): string { return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join(""); }

export function encodeEvmFixture(): Uint8Array {
  const entity = concat(
    new Uint8Array([2]), u64(1n), text("2222222222222222222222222222222222222222"),
    new Uint8Array([5]), u64(1n),
    new Uint8Array([8]), u64(1n), text("1111111111111111111111111111111111111111"),
  );
  return concat(
    new TextEncoder().encode("BW3C"), u16(1), new Uint8Array([7]),
    text("fixture-intent-1"), text("wallet-fixture-1"), new Uint8Array([2]), text("agent-fixture-1"),
    new Uint8Array([2]), u64(1n), hexBytes("1111111111111111111111111111111111111111"),
    new Uint8Array([1]), hexBytes("2222222222222222222222222222222222222222"),
    u64(7n), u256(9n), u64(100000n), new Uint8Array([2]), u256(2n), u256(1n),
    blob(hexBytes("aabbcc")), new Uint8Array([0]),
    text("policy-fixture-1"), text("cap-fixture-1"), text("doc-fixture-1"), u32(3), entity,
    u64(1700000000n), u64(1700000600n),
  );
}

export async function verifyEvmFixture(): Promise<boolean> {
  const bytes = encodeEvmFixture();
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer);
  return hex(bytes) === EXPECTED_HEX && hex(new Uint8Array(digest)) === EXPECTED_DIGEST;
}

export const bw3cFixtureExpected = { canonicalBytesHex: EXPECTED_HEX, intentDigestSha256: EXPECTED_DIGEST } as const;
