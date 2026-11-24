import { verifyBwauFixture } from "../src/bwau-fixture.js";

if (!(await verifyBwauFixture())) {
  throw new Error("TypeScript BWAU authenticated fixture mismatch");
}

console.log("TypeScript BWAU authenticated fixture: PASS");
