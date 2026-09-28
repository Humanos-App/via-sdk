import { describe, it, expect } from "vitest";
import {
  buildChainedEvent,
  generateEd25519Key,
  issueActorCredential,
  signEvent,
  verifyActorStamp,
  verifyAffiliation,
  verifyEvent,
  type ViaEvent,
} from "../src/index.js";

/**
 * `type` is part of what a verifier checks, not decoration (v0.3 §3.1: a VIAActor's `type` MUST be
 * `["VerifiableCredential","VIAActor"]`; a VIAEvent's carries `VIAEvent`). A correctly signed
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
    actor: "did:web:humanos.tech",
    previous: null,
    agent: { actorType: "agent" },
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

  it("verifyActorStamp refuses a stamped artifact that is not a VIAActor", async () => {
    const snapshot = {
      specVersion: "0.3",
      subject: { id: "did:web:humanos.tech:agent:a1", actorType: "agent", status: "active", keys: [], assurance: "pop", binding: "self", bootstrapAnchor: "manual", verifiedAt: "2026-09-28T00:00:00.000Z" },
      chain: { genesisEvent: "sha256-g", headEvent: "sha256-g", sequence: 1 },
      supersedes: null,
      validFrom: "2026-09-28T00:00:00.000Z",
    };
    const good = issueActorCredential(snapshot as never, { ...signer, created: "2026-09-28T00:00:00.000Z" });
    await expect(verifyActorStamp(good, resolve)).resolves.toEqual({ valid: true });
    const retyped = issueActorCredential(snapshot as never, { ...signer, created: "2026-09-28T00:00:00.000Z" });
    (retyped as { type: string[] }).type = ["VerifiableCredential", "VIAEvent"];
    await expect(verifyActorStamp(retyped, resolve)).resolves.toMatchObject({ valid: false, reason: "type_invalid" });
  });
});

describe("verifyAffiliation reads the org where the spec puts it, and where history put it", () => {
  const affiliation = (detail: Record<string, unknown>) =>
    buildChainedEvent({
      subject: "did:web:humanos.tech:agent:a1",
      event: "AFFILIATION",
      actor: "did:web:acme.example",
      issuer: "did:web:acme.example",
      previous: null,
      ...detail,
      signer: { privateKey: key.privateKey, verificationMethod: "did:web:acme.example#key-1", created: "2026-09-28T00:00:00.000Z" },
    } as never);

  it.each([
    ["operator", { operator: { org: "did:web:acme.example", relation: "operates" } }],
    ["agent (written before the fix)", { agent: { org: "did:web:acme.example", relation: "operates" } }],
  ])("accepts an affiliation whose org is in %s", async (_where, detail) => {
    await expect(
      verifyAffiliation(affiliation(detail), resolve, { subject: "did:web:humanos.tech:agent:a1", org: "did:web:acme.example" }),
    ).resolves.toMatchObject({ valid: true });
  });
});
