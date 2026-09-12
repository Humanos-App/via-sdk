/**
 * v0.3 §3.1 — the VIAActor envelope.
 *
 * The fold produces a body; the protocol publishes a Verifiable Credential with a STAMP over it.
 * These tests pin the three things a consumer depends on: the envelope is what §3.1 says, the
 * signature covers the whole artifact, and the body survives the round trip so §5's
 * `fold(chain) == credentialSubject` is still checkable — including for snapshots issued before
 * the envelope existed.
 */
import { describe, expect, it } from "vitest";
import {
  auditActorArtifact,
  buildActorCredential,
  buildChainedEvent,
  foldActorChain,
  generateEd25519Key,
  issueActorCredential,
  issueSnapshot,
  isActorCredential,
  unwrapActorCredential,
  verifyActorStamp,
  type ViaEvent,
} from "../src/index.js";

const KEY = { kty: "EC", crv: "P-256", x: "aJ43Tc6rRHX1b0Z2vnLsMavRyHzBaOFGXq6VwWKIDzI", y: "FIN9450Oewbsj3nhr5gKkYKHQlipraEyU-FgbuDymEo" } as const;
const DID = "did:web:humanos.tech:agent:test-envelope";
const AT = "2026-09-12T10:00:00.000Z";

function genesis(signer: { privateKey: Uint8Array; verificationMethod: string }): ViaEvent {
  return buildChainedEvent({
    subject: DID,
    event: "ACTOR_REGISTERED",
    actor: "did:web:humanos.tech",
    issuer: "did:web:humanos.tech",
    previous: null,
    validFrom: AT,
    agent: {
      actorType: "agent",
      keyId: `${DID}#key-1`,
      jwk: KEY,
      assurance: "pop",
      binding: "custodial",
      bootstrapAnchor: "manual",
      verifiedAt: AT,
      custody: "platform",
      existedSince: AT,
    },
    signer: { privateKey: signer.privateKey, verificationMethod: signer.verificationMethod, created: AT },
  });
}

describe("the VIAActor credential (v0.3 §3.1)", () => {
  const platform = generateEd25519Key();
  const signer = { privateKey: platform.privateKey, verificationMethod: "did:web:humanos.tech#key-1" };
  const events = [genesis(signer)];
  const snapshot = (() => {
    const r = issueSnapshot(events, { validFrom: AT });
    if (!r.ok) throw new Error(r.reason);
    return r.snapshot;
  })();

  it("wraps the fold in the envelope the spec fixes", () => {
    const c = buildActorCredential(snapshot);
    expect(c.type).toEqual(["VerifiableCredential", "VIAActor"]);
    expect(c.issuer).toBe("did:web:humanos.tech");
    expect(c["@context"][0]).toBe("https://www.w3.org/ns/credentials/v2");
    expect(c.id).toMatch(/^urn:via:actor:[0-9a-f-]{36}$/);
    expect(c.specVersion).toBe("0.3");
    // The actor is named by its DID, as credentialSubject.id — the URN names this copy.
    expect(c.credentialSubject.id).toBe(DID);
    expect(c.credentialSubject.chain.sequence).toBe(1);
    expect(c.credentialSubject.supersedes).toBeNull();
  });

  it("publishes key material as publicKeyJwk, while the chain keeps saying jwk", () => {
    const c = buildActorCredential(snapshot);
    expect(c.credentialSubject.keys[0]!.publicKeyJwk).toEqual(KEY);
    expect(c.credentialSubject.keys[0]).not.toHaveProperty("jwk");
    // The signed event is untouched: renaming it would invalidate history.
    expect((events[0]!.credentialSubject as unknown as { agent?: Record<string, unknown> }).agent).toHaveProperty("jwk");
  });

  it("stamps the whole artifact, and the stamp fails on any edit", async () => {
    const c = issueActorCredential(snapshot, signer);
    expect(c.proof?.event).toBe("STAMP");
    await expect(verifyActorStamp(c, () => platform.publicKey)).resolves.toEqual({ valid: true });

    const tampered = { ...c, credentialSubject: { ...c.credentialSubject, status: "suspended" as const } };
    await expect(verifyActorStamp(tampered, () => platform.publicKey)).resolves.toMatchObject({ valid: false });

    const unstamped = buildActorCredential(snapshot);
    await expect(verifyActorStamp(unstamped, () => platform.publicKey)).resolves.toMatchObject({ valid: false });
  });

  it("round-trips to the body the fold produced", () => {
    const c = issueActorCredential(snapshot, signer);
    expect(unwrapActorCredential(c)).toEqual(snapshot);
    const folded = foldActorChain(events);
    expect(folded.ok && folded.subject).toEqual(unwrapActorCredential(c).subject);
  });

  it("audits either shape — a credential, or a body stored before the envelope existed", () => {
    expect(auditActorArtifact(issueActorCredential(snapshot, signer), events)).toEqual({ ok: true });
    expect(auditActorArtifact(snapshot, events)).toEqual({ ok: true });
    expect(isActorCredential(snapshot)).toBe(false);
  });

  it("catches a credential whose subject disagrees with the chain", () => {
    const c = issueActorCredential(snapshot, signer);
    const lying = { ...c, credentialSubject: { ...c.credentialSubject, assurance: "hardware" as const } };
    expect(auditActorArtifact(lying, events)).toEqual({ ok: false, reason: "snapshot_subject_mismatch" });
  });
});
