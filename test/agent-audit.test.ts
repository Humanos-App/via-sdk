import { describe, it, expect, beforeAll } from "vitest";
import {
  generateEd25519Key,
  buildVerificationEvent,
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

describe("§16.9 signed agent audit events (M6)", () => {
  it("VERIFICATION_APPROVED carries the evaluated rung evidence and verifies", async () => {
    const ev = buildVerificationEvent(
      { mandateId: "urn:via:credential:9c1e", decision: "allow", actor: "did:web:acme-bank.example", agent: env, popNonceRef: "n-1", targetVerifier: "acme-bank.example" },
      signer(),
    );
    expect(ev.credentialSubject.event).toBe("VERIFICATION_APPROVED");
    expect(ev.credentialSubject.agent).toMatchObject({
      assuranceEvaluated: "hardware",
      bindingEvaluated: "attested",
      rootUsed: "aws-nitro",
      popNonceRef: "n-1",
      attestationFreshnessAt: "2026-07-20T10:00:00.000Z",
    });
    expect((await verifyEvent(ev, resolve)).valid).toBe(true);
  });

  it("a denial maps to VERIFICATION_DENIED with the reason", async () => {
    const ev = buildVerificationEvent(
      { mandateId: "m1", decision: "deny", actor: "did:web:acme-bank.example", agent: env, popNonceRef: "n-2", reason: "agent_binding_insufficient" },
      signer(),
    );
    expect(ev.credentialSubject.event).toBe("VERIFICATION_DENIED");
    expect(ev.credentialSubject.reason).toBe("agent_binding_insufficient");
  });

  it("the verification stream forms a verifiable previousEvent chain", async () => {
    const e1 = buildVerificationEvent(
      { mandateId: "m1", decision: "deny", actor: "did:web:acme-bank.example", agent: env, popNonceRef: "n-0", reason: "attestation_stale" },
      signer(),
    );
    const e2 = buildVerificationEvent(
      { mandateId: "m1", decision: "allow", actor: "did:web:acme-bank.example", agent: env, popNonceRef: "n-1", previousEvent: computeSRI(canonicalizeRFC8785(e1)) },
      signer(),
    );
    expect((await walkEventChain([e1, e2])).ok).toBe(true);
    expect((await verifyEvent(e1, resolve)).valid && (await verifyEvent(e2, resolve)).valid).toBe(true);
  });

  it("tampering with the rung evidence invalidates the signature", async () => {
    const ev = buildVerificationEvent({ mandateId: "m1", decision: "allow", actor: "did:web:acme-bank.example", agent: env, popNonceRef: "n-1" }, signer());
    const tampered = { ...ev, credentialSubject: { ...ev.credentialSubject, agent: { ...ev.credentialSubject.agent, assuranceEvaluated: "pop" } } };
    expect((await verifyEvent(tampered, resolve)).valid).toBe(false);
  });
});
