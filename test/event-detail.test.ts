/**
 * Detail slots survive `buildChainedEvent` — the pass-through contract.
 *
 * `buildChainedEvent` re-lists every field it hands to `buildEvent`, and the caller's input is
 * assembled with spreads, which TypeScript does NOT excess-property-check. So a slot declared on
 * `BuildEventInput` but forgotten on `BuildChainedEventInput` compiles at every call site and is
 * silently dropped at build time. That is exactly what happened to `stepUp`: v0.3 §2.2 makes it a
 * MUST on a `VERIFICATION_APPROVED` that rested on a step-up, the platform was already forwarding
 * it (`credential.handler.ts`), and it reached none of the signed events.
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  generateEd25519Key,
  buildChainedEvent,
  verifyEvent,
  type BuildEventInput,
  type BuildChainedEventInput,
  type Ed25519KeyPair,
} from "../src/index.js";

/**
 * Compile-time half: every `BuildEventInput` field must have a home on `BuildChainedEventInput`.
 * `previousEvent` is the one deliberate difference — the chained builder takes the prior SIGNED
 * event (`previous`) and computes the link itself.
 */
type Dropped = Exclude<keyof BuildEventInput, keyof BuildChainedEventInput | "previousEvent">;
const _everySlotHasAHome: Dropped extends never ? true : Dropped = true;

const ACTOR = "did:web:humanos.tech:u:alice";
const VM = "did:web:humanos.tech#key-1";
const URN = "urn:via:credential:0199a0d0-0000-7000-8000-000000000001";

let platform: Ed25519KeyPair;
beforeAll(() => {
  platform = generateEd25519Key();
});

/** One value per detail slot, each distinguishable in the output. */
const DETAILS = {
  reason: "step_up_satisfied",
  evaluations: [{ rule: "amount_limit", passed: true }],
  executionParams: { tool: "slack_send_message" },
  targetVerifier: "did:web:verifier.example",
  role: "grantor",
  agent: { rung: "R2" },
  operator: { org: "did:web:acme.com", relation: "employee" },
  accreditation: { level: "verified" },
  stepUp: {
    id: "urn:via:stepup:0199a0d0-0000-7000-8000-000000000002",
    method: "webauthn",
    termsDigest: "sha384-abc",
    tool: "slack_send_message",
  },
  enforcement: "semantic",
  review: { id: "reys", version: "2026-09-14", verdict: "entailed" },
} satisfies Partial<BuildChainedEventInput>;

describe("buildChainedEvent detail pass-through", () => {
  it("carries every detail slot into credentialSubject", () => {
    const signed = buildChainedEvent({
      subject: URN,
      event: "VERIFICATION_APPROVED",
      actor: ACTOR,
      previous: null,
      ...DETAILS,
      signer: { privateKey: platform.privateKey, verificationMethod: VM },
    });
    for (const [key, value] of Object.entries(DETAILS)) {
      expect(signed.credentialSubject[key as keyof typeof signed.credentialSubject]).toEqual(value);
    }
  });

  it("§2.2: the step-up reference is inside the signature, not beside it", async () => {
    const signed = buildChainedEvent({
      subject: URN,
      event: "VERIFICATION_APPROVED",
      actor: ACTOR,
      previous: null,
      stepUp: DETAILS.stepUp,
      signer: { privateKey: platform.privateKey, verificationMethod: VM },
    });
    expect(signed.credentialSubject.stepUp).toEqual(DETAILS.stepUp);
    expect((await verifyEvent(signed, () => platform.publicKey)).valid).toBe(true);

    // Tampering with the reference breaks the proof — the audit claim §2.2 rests on.
    const forged = {
      ...signed,
      credentialSubject: { ...signed.credentialSubject, stepUp: { ...DETAILS.stepUp, method: "otp" } },
    };
    expect((await verifyEvent(forged, () => platform.publicKey)).valid).toBe(false);
  });

  it("omits a slot that was not given (absence stays absence)", () => {
    const signed = buildChainedEvent({
      subject: URN,
      event: "ISSUE",
      actor: ACTOR,
      previous: null,
      signer: { privateKey: platform.privateKey, verificationMethod: VM },
    });
    for (const key of Object.keys(DETAILS)) {
      expect(signed.credentialSubject).not.toHaveProperty(key);
    }
  });
});
