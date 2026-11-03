/**
 * MOVED to `src/agent/sim.ts` — the attestation producer now SHIPS, as the separate
 * `@humanos-ai/via-sdk/agent/sim` entry point, so the agent SDK can mint a real
 * COSE_Sign1 against a dev root instead of a mock quote no validator accepts.
 * Shim kept so the existing test imports stay put.
 */
export * from "../../src/agent/sim.js";
