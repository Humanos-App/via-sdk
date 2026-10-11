import { describe, it, expect } from "vitest";
import {
  buildChainedEvent,
  generateEd25519Key,
  signEvent,
  verifyAffiliation,
  verifyEvent,
  type ViaEvent,
} from "../src/index.js";

/**
 * `type` is part of what a verifier checks, not decoration (v0.3 §3.1: a VIAEvent's `type` carries
 * `VIAEvent`; the signed VIAActor and its `type` check are v0.4's). A correctly signed
 * artifact of another kind must not pass as one of these — the signature alone says who signed,
 * not what was signed.
 */
const VM = "did:web:humanos.tech#key-1";
const key = generateEd25519Key();
const signer = { privateKey: key.privateKey, verificationMethod: VM };
const resolve = () => key.publicKey;

const event = () =>
  buildChainedEvent({
    subject: "did:web:humanos.tech:agent:a1",
    event: "ACTOR_REGISTERED",
    previous: null,
    actorType: "agent",
    signer: { ...signer, created: "2026-09-28T00:00:00.000Z" },
  });

describe("verifiers check `type`", () => {
  it("verifyEvent refuses a correctly signed artifact that is not a VIAEvent", async () => {
    const e = event();
    const { proof: _proof, ...unsigned } = e as ViaEvent & { proof?: unknown };
    const mistyped = signEvent({ ...unsigned, type: ["VerifiableCredential", "VIAMandate"] } as ViaEvent, {
      ...signer,
      created: "2026-09-28T00:00:00.000Z",
    } as never);
    await expect(verifyEvent(e, resolve)).resolves.toEqual({ valid: true });
    await expect(verifyEvent(mistyped, resolve)).resolves.toMatchObject({ valid: false, reason: "type_invalid" });
  });

});

describe("verifyAffiliation reads the org where the spec puts it, and where history put it", () => {
  const acme = { privateKey: key.privateKey, verificationMethod: "did:web:acme.example#key-1", created: "2026-09-28T00:00:00.000Z" };
  const affiliation = (detail: Record<string, unknown>): ViaEvent => {
    if (!("agent" in detail)) {
      return buildChainedEvent({ subject: "did:web:humanos.tech:agent:a1", event: "ACTOR_AFFILIATED", previous: null, ...detail, signer: acme });
    }
    // Written before the fix, under the old name, with the org in the `agent` wrapper and an `actor`.
    const e = buildChainedEvent({ subject: "did:web:humanos.tech:agent:a1", event: "ACTOR_AFFILIATED", previous: null, signer: acme });
    const { proof: _p, ...unsigned } = e;
    return signEvent(
      { ...unsigned, credentialSubject: { ...unsigned.credentialSubject, event: "AFFILIATION", actor: "did:web:acme.example", ...detail } } as ViaEvent,
      acme,
    );
  };

  it.each([
    ["operator", { operator: { org: "did:web:acme.example", relation: "operates" } }],
    ["agent (written before the fix)", { agent: { org: "did:web:acme.example", relation: "operates" } }],
  ])("accepts an affiliation whose org is in %s", async (_where, detail) => {
    await expect(
      verifyAffiliation(affiliation(detail), resolve, { subject: "did:web:humanos.tech:agent:a1", org: "did:web:acme.example" }),
    ).resolves.toMatchObject({ valid: true });
  });
});
