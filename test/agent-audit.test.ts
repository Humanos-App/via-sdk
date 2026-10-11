import { describe, it, expect, beforeAll } from "vitest";
import {
  generateEd25519Key,
  buildVerificationEvent,
  buildOutcomeEvent,
  verifyEvent,
  walkEventChain,
  computeSRI,
  canonicalizeRFC8785,
  type Ed25519KeyPair,
  type AgentEnv,
} from "../src/index.js";

const VM = "did:web:humanos.tech#key-1";
let humanos: Ed25519KeyPair;
const resolve = async (vm: string) => {
  if (vm !== VM) throw new Error("unknown key");
  return humanos.publicKey;
};

beforeAll(async () => {
  humanos = generateEd25519Key();
});

const signer = () => ({ privateKey: humanos.privateKey, verificationMethod: VM });
const env: AgentEnv = { assurance: "hardware", binding: "attested", root: "aws-nitro", verifiedAt: Date.parse("2026-07-20T10:00:00.000Z") };

const VERIFIER = "did:web:acme-bank.example";
/** A decision's event — `null` only for a rechallenge, which no test here builds unless it says so. */
const decide = (input: Omit<Parameters<typeof buildVerificationEvent>[0], "issuer" | "agent">) => {
  const ev = buildVerificationEvent({ issuer: VERIFIER, agent: env, ...input }, signer());
  if (!ev) throw new Error("no event");
  return ev;
};

describe("§16.9 signed agent audit events (M6)", () => {
  // v0.3 §2.0: the rung evidence is the event's own fields — no `agent` wrapper, no `actor`.
  it("VERIFICATION_APPROVED carries the evaluated rung evidence as its own fields, signed by the verifier", async () => {
    const ev = decide({ mandateId: "urn:via:credential:9c1e", decision: "allow", popNonceRef: "n-1", targetVerifier: "acme-bank.example" });
    expect(ev.credentialSubject.event).toBe("VERIFICATION_APPROVED");
    expect(ev.issuer).toBe(VERIFIER);
    expect(ev.credentialSubject).toMatchObject({
      assuranceEvaluated: "hardware",
      bindingEvaluated: "attested",
      rootUsed: "aws-nitro",
      popNonceRef: "n-1",
      attestationFreshnessAt: "2026-07-20T10:00:00.000Z",
    });
    expect(ev.credentialSubject).not.toHaveProperty("agent");
    expect(ev.credentialSubject).not.toHaveProperty("actor");
    expect((await verifyEvent(ev, resolve)).valid).toBe(true);
  });

  it("a denial maps to VERIFICATION_DENIED with the reason, and may name why an accreditation was withdrawn", async () => {
    const ev = decide({ mandateId: "m1", decision: "deny", popNonceRef: "n-2", reason: "accreditation_revoked", revocationReason: "struck_off", enforcement: "rules" });
    expect(ev.credentialSubject).toMatchObject({ event: "VERIFICATION_DENIED", reason: "accreditation_revoked", revocationReason: "struck_off", enforcement: "rules" });
  });

  // @invariant v0.3 §2.2: a rechallenge is pending and records nothing.
  it("records no event for a rechallenge", () => {
    expect(buildVerificationEvent({ mandateId: "m1", decision: "rechallenge", issuer: VERIFIER, agent: env, popNonceRef: "n-3" }, signer())).toBeNull();
  });

  it("the verification stream forms a verifiable previousEvent chain", async () => {
    const e1 = decide({ mandateId: "m1", decision: "deny", popNonceRef: "n-0", reason: "attestation_stale" });
    const e2 = decide({ mandateId: "m1", decision: "allow", popNonceRef: "n-1", previousEvent: computeSRI(canonicalizeRFC8785(e1)) });
    expect((await walkEventChain([e1, e2])).ok).toBe(true);
    expect((await verifyEvent(e1, resolve)).valid && (await verifyEvent(e2, resolve)).valid).toBe(true);
  });

  it("tampering with the rung evidence invalidates the signature", async () => {
    const ev = decide({ mandateId: "m1", decision: "allow", popNonceRef: "n-1" });
    const tampered = { ...ev, credentialSubject: { ...ev.credentialSubject, assuranceEvaluated: "pop" } };
    expect((await verifyEvent(tampered, resolve)).valid).toBe(false);
  });

  // v0.3 §2.1, §2.0: an outcome names the decision it closes in `decision`; the deciding verifier signs it.
  it("an outcome names the decision it closes, and carries the agent's error on a failure", async () => {
    const approved = decide({ mandateId: "m1", decision: "allow", popNonceRef: "n-4" });
    const done = buildOutcomeEvent({ mandateId: "m1", outcome: "completed", decision: approved.id, issuer: VERIFIER, previousEvent: computeSRI(canonicalizeRFC8785(approved)) }, signer());
    const failed = buildOutcomeEvent({ mandateId: "m1", outcome: "failed", decision: approved.id, issuer: VERIFIER, reason: "upstream_timeout" }, signer());
    expect(done.credentialSubject).toMatchObject({ event: "ACTION_COMPLETED", decision: approved.id });
    expect(failed.credentialSubject).toMatchObject({ event: "ACTION_FAILED", decision: approved.id, reason: "upstream_timeout" });
    expect(done.issuer).toBe(VERIFIER);
    expect((await verifyEvent(done, resolve)).valid).toBe(true);
  });
});
