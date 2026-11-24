export type ChainId = "ethereum" | "bitcoin" | "solana";

export interface PolicyIntent {
  readonly chain: ChainId;
  readonly operation: "discover" | "simulate" | "execute";
  readonly subject: string;
}

/**
 * Canonical, secret-free transport representation for the policy plane.
 * This boundary cannot carry seeds, private keys, or signing handles.
 */
export function canonicalizePolicyIntent(intent: PolicyIntent): string {
  if (!intent.subject || intent.subject.length > 128) {
    throw new Error("subject must be non-empty and at most 128 characters");
  }
  return JSON.stringify({
    chain: intent.chain,
    operation: intent.operation,
    subject: intent.subject,
  });
}
