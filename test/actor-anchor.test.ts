/**
 * v0.3 §3.1 / §16.14 — `bootstrapAnchor: "person"` and the `anchoredBy` record.
 *
 * A member connecting a host over OAuth is neither "the organization's own key" (`api_key`) nor
 * "nobody vouched" (`manual`). The token says which of the three happened; `anchoredBy` says who,
 * how they authenticated, and when — and it is written at genesis only, because writing it later
 * would be a claim about the past.
 */
import { describe, expect, it } from "vitest";
import {
  buildChainedEvent,
  foldActorChain,
  foldActorRecord,
  generateEd25519Key,
  projectAgentContext,
  type ViaEvent,
} from "../src/index.js";

const PLATFORM = generateEd25519Key();
const signer = { privateKey: PLATFORM.privateKey, verificationMethod: "did:web:humanos.tech#key-1", created: "2026-09-12T10:00:00.000Z" };
const DID = "did:web:humanos.tech:agent:connected-by-a-person";
const PERSON = "did:web:humanos.tech:user:3c222fa0-ac7f-479b-941d-6f4b5fc02c58";
const AT = "2026-09-12T10:00:00.000Z";

const ANCHORED_BY = {
  actor: PERSON,
  method: "session" as const,
  host: "Cursor",
  at: "2026-09-12T09:59:58.720Z",
};

function genesis(fields: Record<string, unknown>): ViaEvent {
  return buildChainedEvent({
    subject: DID,
    event: "ACTOR_REGISTERED",
    issuer: "did:web:humanos.tech",
    previous: null,
    validFrom: AT,
    actorType: "agent", keyId: `${DID}#key-1`, publicKeyJwk: { kty: "EC", crv: "P-256", x: "aJ43", y: "FIN9" }, assurance: "pop", binding: "custodial", verifiedAt: AT,
    ...fields,
    signer,
  });
}

describe("bootstrapAnchor: person (v0.3 §3.1/§16.14)", () => {
  it("folds the token and the anchoredBy record", () => {
    const folded = foldActorChain([genesis({ bootstrapAnchor: "person", anchoredBy: ANCHORED_BY })]);
    expect(folded.ok).toBe(true);
    if (!folded.ok) return;
    expect(folded.subject.bootstrapAnchor).toBe("person");
    expect(folded.subject.anchoredBy).toEqual(ANCHORED_BY);
  });

  it("carries anchoredBy on the record, beside the token", () => {
    const r = foldActorRecord([genesis({ bootstrapAnchor: "person", anchoredBy: ANCHORED_BY })]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.record.bootstrapAnchor).toBe("person");
    expect(r.record.anchoredBy).toMatchObject({ actor: PERSON, method: "session", host: "Cursor" });
  });

  it("an absent `event` is the grading, not an omission — a session leaves no signed fact", () => {
    const folded = foldActorChain([genesis({ bootstrapAnchor: "person", anchoredBy: ANCHORED_BY })]);
    if (!folded.ok) throw new Error(folded.reason);
    expect(folded.subject.anchoredBy).not.toHaveProperty("event");

    // With a passkey the method is stronger AND points at the KEY_ADDED that proves it.
    const withPasskey = foldActorChain([
      genesis({ bootstrapAnchor: "person", anchoredBy: { ...ANCHORED_BY, method: "passkey", event: "sha256-KeyAdded" } }),
    ]);
    if (!withPasskey.ok) throw new Error(withPasskey.reason);
    expect(withPasskey.subject.anchoredBy).toMatchObject({ method: "passkey", event: "sha256-KeyAdded" });
  });

  // v0.3 removed the signed snapshot (parked in v0.4); a genesis written before it still names one.
  it("leaves out of the record the actorSnapshot reference a genesis signed before v0.3 carries", () => {
    const g = genesis({ bootstrapAnchor: "person", anchoredBy: { ...ANCHORED_BY, actorSnapshot: "urn:via:snapshot:1" } });
    const folded = foldActorChain([g]);
    if (!folded.ok) throw new Error(folded.reason);
    expect(folded.subject.anchoredBy).toEqual(ANCHORED_BY);
    expect((g.credentialSubject as { anchoredBy: object }).anchoredBy).toHaveProperty("actorSnapshot");
  });

  it("stays out of the rule environment — policy compares the TOKEN (§9.2)", () => {
    const folded = foldActorChain([genesis({ bootstrapAnchor: "person", anchoredBy: ANCHORED_BY })]);
    if (!folded.ok) throw new Error(folded.reason);
    const env = projectAgentContext(folded.subject);
    expect(env.bootstrapAnchor).toBe("person");
    expect(env).not.toHaveProperty("anchoredBy");
  });

  it("is immutable after genesis, like the anchor itself", () => {
    const g = genesis({ bootstrapAnchor: "person", anchoredBy: ANCHORED_BY });
    const later = buildChainedEvent({
      subject: DID,
      event: "ASSURANCE_UPDATED",
      issuer: "did:web:humanos.tech",
      previous: g,
      validFrom: "2026-09-12T11:00:00.000Z",
      // Re-anchoring to the organization's own key after the fact is exactly the rewrite §9.5 bars.
      assurance: "pop", binding: "custodial", bootstrapAnchor: "api_key",
      signer: { ...signer, created: "2026-09-12T11:00:00.000Z" },
    });
    const folded = foldActorChain([g, later]);
    expect(folded).toMatchObject({ ok: false, reason: "anchor_immutable" });
  });
});
