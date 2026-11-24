import { canonicalizePolicyIntent } from "../src/index.js";
import { verifyEvmFixture } from "../src/bw3c-fixture.js";

const actual = canonicalizePolicyIntent({ chain: "ethereum", operation: "simulate", subject: "agent-1" });
if (actual !== '{"chain":"ethereum","operation":"simulate","subject":"agent-1"}') {
  throw new Error(`unexpected canonical value: ${actual}`);
}
let rejected = false;
try {
  canonicalizePolicyIntent({ chain: "bitcoin", operation: "discover", subject: "" });
} catch {
  rejected = true;
}
if (!rejected) throw new Error("empty subject was accepted");
void verifyEvmFixture().then((valid) => {
  if (!valid) throw new Error("TypeScript BW3C EVM fixture mismatch");
  console.log("TypeScript policy and BW3C boundaries: PASS");
});
