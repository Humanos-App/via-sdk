/**
 * The actor chain (v0.3 §3.4/§4/§5/§7) — fold, key resolution, snapshots, audit.
 *
 * The fold is a state machine over a hash-linked chain, and its whole value is that it is
 * FAIL-CLOSED: a broken link, an illegal transition or an unknown event must reject rather than
 * silently produce a subject. So most of what follows asserts refusals, and each one names the
 * reason code — a fold that rejects for the wrong reason is a fold that will accept the wrong chain
 * later.
 *
 * Signatures are deliberately out of scope here (that is `auditEventChain`); these tests exercise
 * linkage and transition semantics only, which is the split the module documents.
 */
import { evaluateRules } from "../src/cel/evaluate.js";
import { describe, it, expect } from "vitest";
import {
  chooseSurvivor,
  resolvePinnedKeysAcrossMerge,
  partyStatus,
  resolveSuccession,
  foldActorChain,
  projectAgentContext,
  type ViaActorSubject,
  resolvePinnedKeys,
  snapshotDigest,
  issueSnapshot,
  auditActorSnapshot,
  ACTOR_EVENT_TYPES,
  EVENT_SCOPE,
  type ActorSnapshot,
} from "../src/actor/model.js";
import { EVENT_TYPES } from "../src/crypto/proof.js";
import { eventChainLink } from "../src/event/build.js";
import type { ViaEvent } from "../src/types.js";

const ACTOR = "did:web:humanos.tech:agent:a1";
const JWK = { kty: "EC", crv: "P-256", x: "x", y: "y" } as const;

/**
 * Build one actor-scoped event, linked to `prev`. Hand-assembled rather than routed through
 * `buildChainedEvent` because these tests need to produce chains the builder would refuse —
 * a missing `previousEvent`, a mismatched subject — which is exactly what the fold must catch.
 */
let seq = 0;
function ev(
  event: string,
  detail: Record<string, unknown> = {},
  opts: { prev?: ViaEvent | null | undefined; id?: string; at?: string } = {},
): ViaEvent {
  const previousEvent =
    opts.prev === undefined ? undefined : opts.prev === null ? null : eventChainLink(opts.prev);
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://via.humanos.tech/ns/v1"],
    id: `urn:via:event:${++seq}`,
    type: ["VerifiableCredential", "VIAEvent"],
    specVersion: "0.3",
    issuer: "did:web:humanos.tech",
    validFrom: opts.at ?? "2026-09-01T00:00:00.000Z",
    credentialSubject: {
      id: opts.id ?? ACTOR,
      event,
      actor: ACTOR,
      ...(previousEvent !== undefined ? { previousEvent } : {}),
      agent: detail,
    },
  } as unknown as ViaEvent;
}

const genesis = (detail: Record<string, unknown> = {}) =>
  ev(
    "ACTOR_REGISTERED",
    {
      keyId: "k1",
      jwk: JWK,
      actorType: "agent",
      assurance: "hardware",
      binding: "attested",
      bootstrapAnchor: "api_key",
      verifiedAt: "2026-09-01T00:00:00.000Z",
      ...detail,
    },
    { prev: null },
  );

/** Link a list of builders into a chain, each pointing at the one before. */
function chain(...steps: ((prev: ViaEvent) => ViaEvent)[]): ViaEvent[] {
  const g = genesis();
  const out = [g];
  for (const step of steps) out.push(step(out[out.length - 1]!));
  return out;
}

// ── genesis ──────────────────────────────────────────────────────────────────

describe("foldActorChain — genesis", () => {
  it("refuses an empty chain", () => {
    expect(foldActorChain([])).toEqual({ ok: false, reason: "empty_chain" });
  });

  it("refuses a chain that does not open with ACTOR_REGISTERED", () => {
    const r = foldActorChain([ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: null })]);
    expect(r).toMatchObject({ ok: false, reason: "genesis_missing", at: 0 });
  });

  it("refuses an event with no previousEvent at all — the link is not optional", () => {
    // `undefined` is distinct from `null`: null is "I am the root", undefined is "I forgot".
    const r = foldActorChain([ev("ACTOR_REGISTERED", { keyId: "k1", jwk: JWK }, {})]);
    expect(r).toMatchObject({ ok: false, reason: "previous_event_missing", at: 0 });
  });

  it("refuses a genesis that claims a predecessor", () => {
    const g = genesis();
    const bad = ev("ACTOR_REGISTERED", { keyId: "k1", jwk: JWK }, { prev: g });
    expect(foldActorChain([bad])).toMatchObject({ ok: false, reason: "chain_link_broken", at: 0 });
  });

  it("builds the subject from the founding event", () => {
    const r = foldActorChain([genesis()]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.subject).toMatchObject({
      id: ACTOR,
      actorType: "agent",
      status: "active",
      assurance: "hardware",
      binding: "attested",
      bootstrapAnchor: "api_key",
    });
    expect(r.subject.keys).toHaveLength(1);
    expect(r.subject.keys[0]).toMatchObject({ id: "k1", status: "active" });
  });

  it("points the founding key's attestation at the founding event itself", () => {
    // An event cannot carry its own SRI, so the fold computes it — the self-link pattern.
    const g = genesis({ attestationKind: "attestation-eat" });
    const r = foldActorChain([g]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.keys[0]!.attestation).toEqual({
      event: eventChainLink(g),
      kind: "attestation-eat",
    });
  });

  it("refuses a second genesis", () => {
    const c = chain((p) => ev("ACTOR_REGISTERED", { keyId: "k9", jwk: JWK }, { prev: p }));
    expect(foldActorChain(c)).toMatchObject({ ok: false, reason: "duplicate_genesis", at: 1 });
  });

  it("refuses an event kind outside the actor taxonomy", () => {
    const c = chain((p) => ev("VERIFICATION_APPROVED", {}, { prev: p }));
    expect(foldActorChain(c)).toMatchObject({ ok: false, reason: "unknown_event_type", at: 1 });
  });

  it("refuses an event about a different subject", () => {
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p, id: "did:web:x:agent:other" }));
    expect(foldActorChain(c)).toMatchObject({ ok: false, reason: "subject_mismatch", at: 1 });
  });
});

// ── linkage ──────────────────────────────────────────────────────────────────

describe("foldActorChain — chain linkage", () => {
  it("refuses a broken link and names the index", () => {
    const g = genesis();
    const a = ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: g });
    const orphan = ev("KEY_ADDED", { keyId: "k3", jwk: JWK }, { prev: g }); // links to g, not a
    expect(foldActorChain([g, a, orphan])).toMatchObject({ ok: false, reason: "chain_link_broken", at: 2 });
  });

  it("order is linkage, not timestamps", () => {
    // validFrom runs BACKWARDS here; a correct fold does not care.
    const g = genesis();
    const a = ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: g, at: "2020-01-01T00:00:00.000Z" });
    const r = foldActorChain([g, a]);
    expect(r.ok).toBe(true);
  });
});

// ── keys ─────────────────────────────────────────────────────────────────────

describe("foldActorChain — key lifecycle", () => {
  it("KEY_ADDED appends, and refuses a duplicate id", () => {
    const ok = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const r = foldActorChain(ok);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.keys.map((k) => k.id)).toEqual(["k1", "k2"]);

    const dupe = chain((p) => ev("KEY_ADDED", { keyId: "k1", jwk: JWK }, { prev: p }));
    expect(foldActorChain(dupe)).toMatchObject({ ok: false, reason: "duplicate_key", at: 1 });
  });

  it("KEY_ROTATED labels the predecessor and records the succession pointer", () => {
    const c = chain((p) => ev("KEY_ROTATED", { predecessorId: "k1", keyId: "k2", jwk: JWK }, { prev: p }));
    const r = foldActorChain(c);
    if (!r.ok) throw new Error(r.reason);
    const [k1, k2] = r.subject.keys;
    // `rotated` is a LABEL, not a disablement — only KEY_REVOKED disables.
    expect(k1).toMatchObject({ id: "k1", status: "rotated", rotatedTo: "k2" });
    expect(k2).toMatchObject({ id: "k2", status: "active" });
  });

  it("KEY_ROTATED refuses an unknown predecessor, a revoked one, or a colliding successor", () => {
    const unknown = chain((p) => ev("KEY_ROTATED", { predecessorId: "nope", keyId: "k2", jwk: JWK }, { prev: p }));
    expect(foldActorChain(unknown)).toMatchObject({ ok: false, reason: "unknown_key" });

    const revoked = chain(
      (p) => ev("KEY_REVOKED", { keyId: "k1" }, { prev: p }),
      (p) => ev("KEY_ROTATED", { predecessorId: "k1", keyId: "k2", jwk: JWK }, { prev: p }),
    );
    expect(foldActorChain(revoked)).toMatchObject({ ok: false, reason: "key_already_revoked", at: 2 });

    const collide = chain(
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }),
      (p) => ev("KEY_ROTATED", { predecessorId: "k1", keyId: "k2", jwk: JWK }, { prev: p }),
    );
    expect(foldActorChain(collide)).toMatchObject({ ok: false, reason: "duplicate_key", at: 2 });
  });

  it("KEY_REVOKED flips only that key, and never the actor", () => {
    const c = chain(
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }),
      (p) => ev("KEY_REVOKED", { keyId: "k1" }, { prev: p }),
    );
    const r = foldActorChain(c);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.status).toBe("active");
    expect(r.subject.keys.find((k) => k.id === "k1")!.status).toBe("revoked");
    expect(r.subject.keys.find((k) => k.id === "k2")!.status).toBe("active");
  });

  it("KEY_REVOKED refuses an unknown key and a double revoke", () => {
    const unknown = chain((p) => ev("KEY_REVOKED", { keyId: "nope" }, { prev: p }));
    expect(foldActorChain(unknown)).toMatchObject({ ok: false, reason: "unknown_key" });

    const twice = chain(
      (p) => ev("KEY_REVOKED", { keyId: "k1" }, { prev: p }),
      (p) => ev("KEY_REVOKED", { keyId: "k1" }, { prev: p }),
    );
    expect(foldActorChain(twice)).toMatchObject({ ok: false, reason: "key_already_revoked", at: 2 });
  });
});

// ── attestation & assurance ──────────────────────────────────────────────────

describe("foldActorChain — attestation and assurance", () => {
  it("ATTESTATION_RENEWED repoints the key at the renewal event and moves verifiedAt", () => {
    const g = genesis();
    const renew = ev(
      "ATTESTATION_RENEWED",
      { keyId: "k1", attestationKind: "attestation-eat", verifiedAt: "2026-10-01T00:00:00.000Z" },
      { prev: g },
    );
    const r = foldActorChain([g, renew]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.keys[0]!.attestation).toEqual({
      event: eventChainLink(renew),
      kind: "attestation-eat",
    });
    expect(r.subject.verifiedAt).toBe("2026-10-01T00:00:00.000Z");
  });

  it("the summary is DERIVED — the floor across usable keys — and ASSURANCE_UPDATED without keyId only audits it (§9.1bis rules 5–6)", () => {
    const g = genesis({ root: "aws-nitro" }); // one key: hardware/attested, root aws-nitro
    // Asserting a summary the keys do not support is refused: there is one writer, the keys.
    const lie = ev("ASSURANCE_UPDATED", { assurance: "pop", binding: "self" }, { prev: g });
    expect(foldActorChain([g, lie])).toMatchObject({ ok: false, reason: expect.stringContaining("summary_mismatch") });

    // Lower the KEY (the §9.1bis downgrade path); the summary follows without being asserted…
    const regrade = ev("ASSURANCE_UPDATED", { keyId: "k1", assurance: "pop", binding: "self" }, { prev: g });
    const r = foldActorChain([g, regrade]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject).toMatchObject({ assurance: "pop", binding: "self", bootstrapAnchor: "api_key" });
    // …and a root no usable key carries is gone from the summary — a stale root would claim
    // hardware backing the actor no longer has.
    expect(r.subject.root).toBeUndefined();
    // …and the audit event that states the new floor is accepted.
    const audit = ev("ASSURANCE_UPDATED", { assurance: "pop", binding: "self" }, { prev: regrade });
    expect(foldActorChain([g, regrade, audit]).ok).toBe(true);

    // The anchor is history (§9.5): restating it is fine, changing it fails the fold.
    const same = ev("ASSURANCE_UPDATED", { assurance: "hardware", binding: "attested", bootstrapAnchor: "api_key" }, { prev: g });
    expect(foldActorChain([g, same]).ok).toBe(true);
    const rewrite = ev("ASSURANCE_UPDATED", { assurance: "hardware", binding: "attested", bootstrapAnchor: "manual" }, { prev: g });
    expect(foldActorChain([g, rewrite])).toMatchObject({ ok: false, reason: expect.stringContaining("anchor_immutable") });
  });

  it("a weak key added lowers the floor; revoking it raises the floor back — nobody asserts either", () => {
    const g = genesis({ root: "aws-nitro" });
    const weak = ev("KEY_ADDED", { keyId: "k2", jwk: JWK, assurance: "pop", binding: "self" }, { prev: g });
    const lowered = foldActorChain([g, weak]);
    if (!lowered.ok) throw new Error(lowered.reason);
    expect(lowered.subject).toMatchObject({ assurance: "pop", binding: "self" });
    expect(lowered.subject.root).toBeUndefined(); // not every usable key shares aws-nitro
    const kill = ev("KEY_REVOKED", { keyId: "k2" }, { prev: weak });
    const raised = foldActorChain([g, weak, kill]);
    if (!raised.ok) throw new Error(raised.reason);
    expect(raised.subject).toMatchObject({ assurance: "hardware", binding: "attested", root: "aws-nitro" });
  });

  it("an unknown assurance or binding token fails the fold — an unranked rung would fail OPEN", () => {
    const g = genesis({ root: "aws-nitro" });
    // `software` was never a rung (§16.3: pop < device < hardware). Ranked, it is NaN, and every
    // floor comparison against NaN is false — so a token typo would have passed every check.
    const bogus = ev("ASSURANCE_UPDATED", { assurance: "software", binding: "self", bootstrapAnchor: "manual" }, { prev: g });
    expect(foldActorChain([g, bogus])).toMatchObject({ ok: false, reason: expect.stringContaining("invalid_assurance") });
    const bogusBinding = ev("ASSURANCE_UPDATED", { assurance: "pop", binding: "floating", bootstrapAnchor: "manual" }, { prev: g });
    expect(foldActorChain([g, bogusBinding])).toMatchObject({ ok: false, reason: expect.stringContaining("invalid_binding") });
  });

  it("ASSURANCE_UPDATED with keyId re-grades THAT key, and the summary follows as the floor (§9.1bis downgrade path)", () => {
    const g = genesis({ root: "aws-nitro" });
    const before = foldActorChain([g]);
    if (!before.ok) throw new Error(before.reason);
    const keyId = before.subject.keys[0]!.id;

    // The root the key was graded under is distrusted: the KEY drops, the actor summary stays.
    const downgrade = ev(
      "ASSURANCE_UPDATED",
      { keyId, assurance: "pop", binding: "self", verifiedAt: "2026-10-02T00:00:00.000Z" },
      { prev: g },
    );
    const r = foldActorChain([g, downgrade]);
    if (!r.ok) throw new Error(r.reason);
    const k = r.subject.keys.find((x) => x.id === keyId)!;
    expect(k).toMatchObject({ assurance: "pop", binding: "self", verifiedAt: "2026-10-02T00:00:00.000Z" });
    expect(k.root).toBeUndefined();
    expect(r.subject.assurance).toBe("pop"); // the floor follows the re-graded key (rule 5)
    expect(r.subject.root).toBeUndefined(); // no usable key carries the root any more

    // A keyId the actor never had fails the fold, like every other key-addressed event.
    const bad = ev("ASSURANCE_UPDATED", { keyId: "did:web:x#key-9", assurance: "pop" }, { prev: g });
    expect(foldActorChain([g, bad])).toMatchObject({ ok: false, reason: expect.stringContaining("unknown_key") });
  });
});

// ── status (§4 transition table) ─────────────────────────────────────────────

describe("foldActorChain — status transitions", () => {
  it("suspends from active and resumes from suspended", () => {
    const c = chain(
      (p) => ev("SUSPENDED", {}, { prev: p }),
      (p) => ev("RESUMED", {}, { prev: p }),
    );
    const mid = foldActorChain(c.slice(0, 2));
    if (!mid.ok) throw new Error(mid.reason);
    expect(mid.subject.status).toBe("suspended");
    const end = foldActorChain(c);
    if (!end.ok) throw new Error(end.reason);
    expect(end.subject.status).toBe("active");
  });

  it("refuses a double suspend and a resume that was never suspended", () => {
    const twice = chain(
      (p) => ev("SUSPENDED", {}, { prev: p }),
      (p) => ev("SUSPENDED", {}, { prev: p }),
    );
    expect(foldActorChain(twice)).toMatchObject({ ok: false, reason: "illegal_transition", at: 2 });

    const bogus = chain((p) => ev("RESUMED", {}, { prev: p }));
    expect(foldActorChain(bogus)).toMatchObject({ ok: false, reason: "illegal_transition", at: 1 });
  });

  it("retires from active and from suspended", () => {
    const fromActive = chain((p) => ev("RETIRED", {}, { prev: p }));
    const a = foldActorChain(fromActive);
    if (!a.ok) throw new Error(a.reason);
    expect(a.subject.status).toBe("retired");

    const fromSuspended = chain(
      (p) => ev("SUSPENDED", {}, { prev: p }),
      (p) => ev("RETIRED", {}, { prev: p }),
    );
    const s = foldActorChain(fromSuspended);
    if (!s.ok) throw new Error(s.reason);
    expect(s.subject.status).toBe("retired");
  });

  it("retired is absorbing — nothing may follow it", () => {
    const c = chain(
      (p) => ev("RETIRED", {}, { prev: p }),
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }),
    );
    expect(foldActorChain(c)).toMatchObject({ ok: false, reason: "event_after_retired", at: 2 });
  });

  it("content events stay legal while suspended — the audit trail does not pause", () => {
    const c = chain(
      (p) => ev("SUSPENDED", {}, { prev: p }),
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }),
    );
    const r = foldActorChain(c);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.status).toBe("suspended");
    expect(r.subject.keys.map((k) => k.id)).toEqual(["k1", "k2"]);
  });
});

// ── state-neutral events ─────────────────────────────────────────────────────

describe("foldActorChain — pointer and evidence events", () => {
  it("FORK_EVIDENCE, DELEGATED and SNAPSHOT_ISSUED change no state", () => {
    const before = foldActorChain([genesis()]);
    const c = chain(
      (p) => ev("FORK_EVIDENCE", {}, { prev: p }),
      (p) => ev("DELEGATED", {}, { prev: p }),
      (p) => ev("SNAPSHOT_ISSUED", {}, { prev: p }),
    );
    const after = foldActorChain(c);
    if (!before.ok || !after.ok) throw new Error("fold failed");
    // They POINT; any state change arrives via the events they trigger.
    expect(after.subject).toEqual(before.subject);
  });

  it("AFFILIATION sets an operator POINTER, never an inline claim", () => {
    const g = genesis();
    const aff = ev("AFFILIATION", { org: "did:web:acme.example" }, { prev: g });
    const r = foldActorChain([g, aff]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.operator).toEqual({
      org: "did:web:acme.example",
      affiliationEvent: eventChainLink(aff),
    });
  });
});

// ── checkpointed fold ────────────────────────────────────────────────────────

describe("foldActorChain — folding from a checkpoint", () => {
  it("resumes from a seed and requires the tail to link to its head", () => {
    const g = genesis();
    const add = ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: g });
    const full = foldActorChain([g, add]);
    if (!full.ok) throw new Error(full.reason);

    const tail = ev("KEY_REVOKED", { keyId: "k1" }, { prev: add });
    const seeded = foldActorChain([tail], { subject: full.subject, headEvent: eventChainLink(add) });
    if (!seeded.ok) throw new Error(seeded.reason);
    expect(seeded.subject.keys.find((k) => k.id === "k1")!.status).toBe("revoked");

    const wrongSeed = foldActorChain([tail], { subject: full.subject, headEvent: eventChainLink(g) });
    expect(wrongSeed).toMatchObject({ ok: false, reason: "chain_link_broken", at: 0 });
  });

  it("does not mutate the seed subject", () => {
    const g = genesis();
    const full = foldActorChain([g]);
    if (!full.ok) throw new Error(full.reason);
    const snapshotOfSeed = JSON.stringify(full.subject);
    const tail = ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: g });
    foldActorChain([tail], { subject: full.subject, headEvent: eventChainLink(g) });
    expect(JSON.stringify(full.subject)).toBe(snapshotOfSeed);
  });
});

// ── D7 key resolution (§7) ───────────────────────────────────────────────────

describe("resolvePinnedKeys", () => {
  const rotatedChain = () =>
    chain(
      (p) => ev("KEY_ROTATED", { predecessorId: "k1", keyId: "k2", jwk: JWK }, { prev: p }),
      (p) => ev("KEY_ROTATED", { predecessorId: "k2", keyId: "k3", jwk: JWK }, { prev: p }),
    );

  it("follows the succession from the pinned id", () => {
    const r = foldActorChain(rotatedChain());
    if (!r.ok) throw new Error(r.reason);
    expect(resolvePinnedKeys(r.subject, "k1").map((k) => k.id)).toEqual(["k1", "k2", "k3"]);
    expect(resolvePinnedKeys(r.subject, "k2").map((k) => k.id)).toEqual(["k2", "k3"]);
  });

  it("drops a revoked key from the set WITHOUT breaking the walk", () => {
    // The scheduled predecessor-revocation at a rotation window's end must not kill a
    // rotated-forward mandate, or rotation tolerance is defeated.
    const c = [...rotatedChain()];
    c.push(ev("KEY_REVOKED", { keyId: "k1" }, { prev: c[c.length - 1] }));
    const r = foldActorChain(c);
    if (!r.ok) throw new Error(r.reason);
    expect(resolvePinnedKeys(r.subject, "k1").map((k) => k.id)).toEqual(["k2", "k3"]);
  });

  it("returns nothing for an unknown pin, so the verifier fails closed", () => {
    const r = foldActorChain([genesis()]);
    if (!r.ok) throw new Error(r.reason);
    expect(resolvePinnedKeys(r.subject, "nope")).toEqual([]);
  });

  it("terminates on a succession cycle", () => {
    const r = foldActorChain([genesis()]);
    if (!r.ok) throw new Error(r.reason);
    // Not reachable through the fold; guards the walk itself.
    r.subject.keys = [
      { id: "a", jwk: JWK as never, status: "rotated", rotatedTo: "b" },
      { id: "b", jwk: JWK as never, status: "rotated", rotatedTo: "a" },
    ];
    expect(resolvePinnedKeys(r.subject, "a").map((k) => k.id)).toEqual(["a", "b"]);
  });
});

// ── snapshots ────────────────────────────────────────────────────────────────

describe("issueSnapshot / snapshotDigest", () => {
  it("binds the chain's genesis, head and a sequence starting at 1", () => {
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const s = issueSnapshot(c);
    if (!s.ok) throw new Error(s.reason);
    expect(s.snapshot.chain).toEqual({
      genesisEvent: eventChainLink(c[0]!),
      headEvent: eventChainLink(c[1]!),
      sequence: 1,
    });
    expect(s.snapshot.supersedes).toBeNull();
    // A snapshot is an artifact a verifier routes on, so it carries the marker (§13).
    expect(s.snapshot.specVersion).toBe("0.3");
  });

  it("supersedes the previous snapshot by digest, and increments the sequence", () => {
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const first = issueSnapshot(c);
    if (!first.ok) throw new Error(first.reason);
    const second = issueSnapshot(c, { previous: first.snapshot });
    if (!second.ok) throw new Error(second.reason);
    expect(second.snapshot.chain.sequence).toBe(2);
    expect(second.snapshot.supersedes).toBe(snapshotDigest(first.snapshot));
  });

  it("digest is stable across key order and changes with content", () => {
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const s = issueSnapshot(c);
    if (!s.ok) throw new Error(s.reason);
    // RFC-8785 sorts keys, so the same content in a different insertion order is the same bytes.
    // (Rebuild rather than JSON.stringify's replacer array — that FILTERS keys, it does not reorder,
    // and it silently strips nested properties.)
    const reorder = (v: unknown): unknown =>
      Array.isArray(v)
        ? v.map(reorder)
        : v && typeof v === "object"
          ? Object.fromEntries(Object.entries(v as object).reverse().map(([k, x]) => [k, reorder(x)]))
          : v;
    const reordered = reorder(s.snapshot) as ActorSnapshot;
    expect(Object.keys(reordered)).not.toEqual(Object.keys(s.snapshot)); // genuinely reordered
    expect(snapshotDigest(reordered)).toBe(snapshotDigest(s.snapshot));
    expect(snapshotDigest({ ...s.snapshot, validFrom: "2030-01-01T00:00:00.000Z" })).not.toBe(
      snapshotDigest(s.snapshot),
    );
  });

  it("propagates a fold failure instead of issuing a snapshot of nothing", () => {
    expect(issueSnapshot([])).toEqual({ ok: false, reason: "empty_chain" });
  });
});

// ── audit ────────────────────────────────────────────────────────────────────

describe("auditActorSnapshot", () => {
  const built = () => {
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const s = issueSnapshot(c);
    if (!s.ok) throw new Error(s.reason);
    return { c, snapshot: s.snapshot };
  };

  it("accepts a snapshot that matches its chain", () => {
    const { c, snapshot } = built();
    expect(auditActorSnapshot(snapshot, c)).toEqual({ ok: true });
  });

  it("a snapshot binds a PREFIX — later events supersede it without invalidating it", () => {
    const { c, snapshot } = built();
    const extended = [...c, ev("KEY_REVOKED", { keyId: "k1" }, { prev: c[c.length - 1] })];
    expect(auditActorSnapshot(snapshot, extended)).toEqual({ ok: true });
  });

  it("rejects a snapshot bound to a different genesis", () => {
    const { snapshot } = built();
    const other = chain((p) => ev("KEY_ADDED", { keyId: "kX", jwk: JWK }, { prev: p }));
    expect(auditActorSnapshot(snapshot, other)).toMatchObject({ reason: "chain_binding_mismatch" });
    expect(auditActorSnapshot(snapshot, [])).toMatchObject({ reason: "chain_binding_mismatch" });
  });

  it("rejects a snapshot whose head is not in the chain", () => {
    const { c, snapshot } = built();
    expect(auditActorSnapshot({ ...snapshot, chain: { ...snapshot.chain, headEvent: "sha256-nope" } }, c))
      .toMatchObject({ reason: "chain_binding_mismatch" });
  });

  it("rejects a tampered subject — the chain is authoritative", () => {
    const { c, snapshot } = built();
    const lying = { ...snapshot, subject: { ...snapshot.subject, assurance: "hardware" as never, status: "active" as never, id: "did:web:humanos.tech:agent:someone-else" } };
    expect(auditActorSnapshot(lying, c)).toMatchObject({ reason: "snapshot_subject_mismatch" });

    // A snapshot issued before the fold learned a field is OUTDATED, not a lie: every value it
    // carries still matches. The platform re-issues it; a verifier never authorizes from it anyway.
    const older = structuredClone(snapshot);
    delete (older.subject as unknown as Record<string, unknown>).genesisAt;
    expect(auditActorSnapshot(older, c)).toMatchObject({ reason: "snapshot_outdated" });
    // Missing a field AND lying about another is a mismatch — the missing field does not launder it.
    const olderAndLying = structuredClone(older);
    olderAndLying.subject.id = "did:web:humanos.tech:agent:someone-else";
    expect(auditActorSnapshot(olderAndLying, c)).toMatchObject({ reason: "snapshot_subject_mismatch" });
  });

  it("surfaces a fold failure with its reason attached", () => {
    const { snapshot } = built();
    // A chain whose genesis matches but which breaks further along.
    const g = genesis();
    const orphan = ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: g });
    const broken = [g, orphan, ev("KEY_ADDED", { keyId: "k3", jwk: JWK }, { prev: g })];
    const bound: ActorSnapshot = {
      ...snapshot,
      chain: { ...snapshot.chain, genesisEvent: eventChainLink(g), headEvent: eventChainLink(broken[2]!) },
    };
    expect(auditActorSnapshot(bound, broken).reason).toMatch(/^fold_failed:/);
  });
});

describe("EVENT_SCOPE / ACTOR_EVENT_TYPES", () => {
  it("classifies every EventType exactly once, and derives the actor set from it", () => {
    // The compiler already refuses an unclassified kind (`satisfies Record<EventType, …>`);
    // this guards the derivation itself.
    expect(Object.keys(EVENT_SCOPE).sort()).toEqual([...EVENT_TYPES].sort());
    const actor = Object.entries(EVENT_SCOPE).filter(([, v]) => v === "actor").map(([k]) => k);
    expect([...ACTOR_EVENT_TYPES].sort()).toEqual(actor.sort());
  });

  it("every credential-scoped kind is refused by the actor fold", () => {
    for (const [kind, scope] of Object.entries(EVENT_SCOPE)) {
      if (scope !== "credential") continue;
      const c = chain((p) => ev(kind, {}, { prev: p }));
      expect(foldActorChain(c)).toMatchObject({ ok: false, reason: "unknown_event_type" });
    }
  });
});

describe("ACTOR_EVENT_TYPES", () => {
  it("is the §3.4 actor-scoped set, and every member is folded", () => {
    expect(ACTOR_EVENT_TYPES).toContain("ACTOR_REGISTERED");
    expect(ACTOR_EVENT_TYPES).not.toContain("VERIFICATION_APPROVED");
    // Every listed kind must be reachable in the fold's switch, or it would be
    // accepted as valid and then silently ignored.
    for (const kind of ACTOR_EVENT_TYPES) {
      if (kind === "ACTOR_REGISTERED") continue;
      const c = chain((p) => ev(kind, { keyId: "k1", predecessorId: "k1", jwk: JWK, attestationKind: "x" }, { prev: p }));
      const r = foldActorChain(c);
      // It may reject for a semantic reason, but never as "unknown_event_type".
      if (!r.ok) expect(r.reason).not.toBe("unknown_event_type");
    }
  });
});

describe("projectAgentContext (§9 / KYA A.3) — the agent.* CEL namespace", () => {
  const subject = (over: Partial<ViaActorSubject> = {}): ViaActorSubject =>
    ({
      id: "did:web:humanos.tech:agent:abc",
      actorType: "agent",
      status: "active",
      keys: [{ id: "did:web:humanos.tech:agent:abc#key-1", jwk: {} as never, status: "active" }],
      assurance: "hardware",
      binding: "attested",
      bootstrapAnchor: "api_key",
      verifiedAt: "2026-08-01T00:00:00.000Z",
      ...over,
    }) as ViaActorSubject;

  it("projects the v0.3 fields flat, and never keys[]", () => {
    const ctx = projectAgentContext(subject());
    expect(ctx).toMatchObject({
      assurance: "hardware",
      binding: "attested",
      bootstrapAnchor: "api_key",
      status: "active",
      verifiedAt: "2026-08-01T00:00:00.000Z",
    });
    // Pinned-key resolution is §7's job, not a rule's — a rule reaching into keys would be
    // writing its own D7, badly.
    expect(ctx).not.toHaveProperty("keys");
  });

  it("operator and lineage project PRESENCE + DID, never the event", () => {
    const ctx = projectAgentContext(
      subject({
        operator: { org: "did:web:humanos.tech:org:acme", affiliationEvent: "sha256-xyz" },
        lineage: { parent: "did:web:humanos.tech:agent:parent", event: "sha256-abc" },
      }),
    );
    expect(ctx.operator).toEqual({ org: "did:web:humanos.tech:org:acme" });
    expect(ctx.lineage).toEqual({ parent: "did:web:humanos.tech:agent:parent" });
    // Reading the claim is the verifier's job, through the pointer — not a rule's.
    expect(JSON.stringify(ctx)).not.toContain("affiliationEvent");
    expect(JSON.stringify(ctx)).not.toContain("sha256-");
  });

  it("absent optionals are ABSENT, so `has(agent.operator)` is meaningful", () => {
    const ctx = projectAgentContext(subject());
    expect(ctx).not.toHaveProperty("operator");
    expect(ctx).not.toHaveProperty("lineage");
    expect(ctx).not.toHaveProperty("root");
  });

  it("makes a freshness rule EVALUABLE — the v0.3 attestation-age bound", () => {
    // §16's `maxAttestationStaleness` bounds a raw-pinned BoundKey. On the actor path the rung is
    // resolved THROUGH the actor, so the bound belongs to the mandate that cares. This is the
    // projection that lets it be written at all.
    const rule = [
      { name: "fresh", description: "attestation too old", expression: 'agent.verifiedAt >= "2026-07-15T00:00:00.000Z"' },
    ];
    const fresh = evaluateRules(rule, { userParams: {}, executionParams: {}, agent: projectAgentContext(subject()) });
    expect(fresh.decision).toBe("allow");

    const stale = evaluateRules(rule, {
      userParams: {},
      executionParams: {},
      agent: projectAgentContext(subject({ verifiedAt: "2026-01-01T00:00:00.000Z" })),
    });
    expect(stale.decision).toBe("deny");
  });

  it("a suspended actor is visible to a rule", () => {
    const rule = [{ name: "active", description: "actor not active", expression: 'agent.status == "active"' }];
    expect(
      evaluateRules(rule, { userParams: {}, executionParams: {}, agent: projectAgentContext(subject({ status: "suspended" })) }).decision,
    ).toBe("deny");
  });

  it("a key carries ITS OWN rung — the weakest key no longer inherits the strongest", () => {
    // The hole per-key rungs exist to close: an actor holds one flat rung but many keys, and a
    // mandate pins a key ID. Reading the actor's rung for a software key evaluated an attacker who
    // stole it at `hardware`.
    const c = chain((p) =>
      ev("KEY_ADDED", { keyId: "k2", jwk: JWK, assurance: "pop", binding: "self" }, { prev: p }),
    );
    const folded = foldActorChain(c);
    expect(folded.ok).toBe(true);
    if (!folded.ok) return;

    const [k1, k2] = folded.subject.keys;
    expect([k1!.assurance, k1!.binding]).toEqual(["hardware", "attested"]);
    expect([k2!.assurance, k2!.binding]).toEqual(["pop", "self"]);

    // Authorization reads the PRESENTING key…
    expect(projectAgentContext(folded.subject, k2).assurance).toBe("pop");
    expect(projectAgentContext(folded.subject, k1).assurance).toBe("hardware");
    // …and with no key supplied it reports the actor summary — the FLOOR across usable keys
    // (§9.1bis rule 5), which the weak key just lowered. Reporting never overstates.
    expect(projectAgentContext(folded.subject).assurance).toBe("pop");
    expect(projectAgentContext(folded.subject, k2).actorType).toBe("agent");
  });

  it("renewing ONE key does not refresh a sibling's freshness claim", () => {
    // The sharper bug. `ATTESTATION_RENEWED` moved only `subject.verifiedAt`, so a mandate pinned
    // to a key last attested a year ago passed a 30-day bound because a sibling was renewed
    // yesterday.
    const OLD = "2026-09-01T00:00:00.000Z"; // genesis default
    const NEW = "2026-12-01T00:00:00.000Z";
    const c = chain(
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK, assurance: "hardware", binding: "attested", verifiedAt: OLD }, { prev: p }),
      (p) => ev("ATTESTATION_RENEWED", { keyId: "k1", verifiedAt: NEW, attestationKind: "attestation-eat" }, { prev: p }),
    );
    const folded = foldActorChain(c);
    expect(folded.ok).toBe(true);
    if (!folded.ok) return;

    const k1 = folded.subject.keys.find((k) => k.id === "k1")!;
    const k2 = folded.subject.keys.find((k) => k.id === "k2")!;
    expect(k1.verifiedAt).toBe(NEW);
    expect(k2.verifiedAt).toBe(OLD); // untouched — it was not re-attested

    const bound = [{ name: "fresh", description: "too old", expression: 'agent.verifiedAt >= "2026-10-01T00:00:00.000Z"' }];
    const ctx = (k: typeof k1) => ({ userParams: {}, executionParams: {}, agent: projectAgentContext(folded.subject, k) });
    expect(evaluateRules(bound, ctx(k1)).decision).toBe("allow");
    expect(evaluateRules(bound, ctx(k2)).decision).toBe("deny");
  });

  it("a chain written before per-key rungs falls back to the actor summary", () => {
    // Historical KEY_ADDED events carry no assurance. Inheriting the summary is what they meant;
    // inventing a rung for them would be worse.
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const folded = foldActorChain(c);
    expect(folded.ok).toBe(true);
    if (!folded.ok) return;
    expect(folded.subject.keys[1]!.assurance).toBe("hardware");
  });
});

// ── the runtime axis (v0.3 §9.4ter) ──────────────────────────────────────────

describe("RUNTIME_ATTESTED — the runtime axis", () => {
  it("latest wins, and it moves nothing else", () => {
    const before = foldActorChain([genesis()]);
    const c = chain(
      (p) => ev("RUNTIME_ATTESTED", { runtime: { class: "tee", at: "2026-09-03T10:00:00.000Z", measurementId: "rel-1" } }, { prev: p }),
      (p) => ev("RUNTIME_ATTESTED", { runtime: { class: "host", at: "2026-09-03T11:00:00.000Z" } }, { prev: p }),
    );
    const after = foldActorChain(c);
    if (!before.ok || !after.ok) throw new Error("fold failed");
    expect(after.subject.runtime?.class).toBe("host");
    expect(after.subject.runtime?.at).toBe("2026-09-03T11:00:00.000Z");
    // the key axes are untouched — runtime describes the environment, not the key
    expect([after.subject.assurance, after.subject.binding]).toEqual([before.subject.assurance, before.subject.binding]);
    expect(after.subject.status).toBe(before.subject.status);
  });

  it("rejects a class outside the four", () => {
    const c = chain((p) => ev("RUNTIME_ATTESTED", { runtime: { class: "enclave-ish" } }, { prev: p }));
    const r = foldActorChain(c);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("runtime_attestation_invalid");
  });

  it("projects as the literal \"none\" when never attested, so a rule can require one", () => {
    const r = foldActorChain([genesis()]);
    if (!r.ok) throw new Error("fold failed");
    expect(projectAgentContext(r.subject).runtime).toBe("none");
  });

  it("projects the class, and carries when it was established", () => {
    const c = chain((p) => ev("RUNTIME_ATTESTED", { runtime: { class: "tee", at: "2026-09-03T10:00:00.000Z" } }, { prev: p }));
    const r = foldActorChain(c);
    if (!r.ok) throw new Error("fold failed");
    const ctx = projectAgentContext(r.subject);
    expect(ctx.runtime).toBe("tee");
    expect(ctx.runtimeAt).toBe("2026-09-03T10:00:00.000Z");
  });
});

// ── §3.6 — one actor one DID, addresses, and merge succession ────────────────
//
// These pin the cases that are easy to state in prose and easy to get wrong in code. Case 2 below
// is the one that matters most: it is the only one where a bug is a security hole rather than a
// wrong answer, and it is the case the first draft of §3.6 missed entirely.

describe("§3.6 aliases and succession", () => {
  const alias = (did: string, reason = "channel") =>
    (p: ViaEvent) => ev("ALIAS_ADDED", { alias: did, aliasReason: reason }, { prev: p });

  it("ALIAS_ADDED records the identifier and moves nothing else", () => {
    const before = foldActorChain([genesis()]);
    const r = foldActorChain(chain(alias("did:web:humanos.tech:user:old-email")));
    if (!before.ok || !r.ok) throw new Error("fold failed");
    expect(r.subject.aliases).toEqual([{ did: "did:web:humanos.tech:user:old-email", reason: "channel" }]);
    // the party is still exactly what its own chain says
    expect([r.subject.status, r.subject.assurance, r.subject.binding]).toEqual([
      before.subject.status, before.subject.assurance, before.subject.binding,
    ]);
    expect(r.subject.keys).toEqual(before.subject.keys);
  });

  it("re-adding the same alias is a NO-OP — a migration must be safe to re-run", () => {
    const r = foldActorChain(chain(alias("did:x"), alias("did:x"), alias("did:x")));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.subject.aliases).toHaveLength(1);
  });

  it("an actor cannot alias itself", () => {
    const c = chain((p) => ev("ALIAS_ADDED", { alias: "did:web:humanos.tech:agent:a1" }, { prev: p }));
    const r = foldActorChain(c);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("alias_invalid");
  });

  it("an alias is never INFERRED — sharing a key or a name creates none", () => {
    // Two actors folded from chains that share key material still know nothing about each other.
    const a = foldActorChain([genesis()]);
    const b = foldActorChain([genesis()]);
    if (!a.ok || !b.ok) throw new Error("fold failed");
    expect(a.subject.aliases).toBeUndefined();
    expect(b.subject.aliases).toBeUndefined();
  });

  it("RETIRED carries succeededBy on a merge, and nothing when a party simply stops", () => {
    const merged = foldActorChain(chain((p) => ev("RETIRED", { succeededBy: "did:survivor" }, { prev: p })));
    const stopped = foldActorChain(chain((p) => ev("RETIRED", {}, { prev: p })));
    expect(merged.ok && merged.subject.succeededBy).toBe("did:survivor");
    expect(stopped.ok && stopped.subject.succeededBy).toBeUndefined();
    // absorbing either way
    expect(merged.ok && merged.subject.status).toBe("retired");
  });

  it("an absorbed actor accepts NO further events", () => {
    const c = chain(
      (p) => ev("RETIRED", { succeededBy: "did:survivor" }, { prev: p }),
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: {} }, { prev: p }),
    );
    const r = foldActorChain(c);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("event_after_retired");
  });
});

describe("§3.6 partyStatus — restrictions survive a merge", () => {
  const subj = (id: string, status: "active" | "suspended" | "retired") =>
    ({ id, actorType: "user", status, keys: [], assurance: "pop", binding: "self",
       bootstrapAnchor: "manual", verifiedAt: "2026-01-01T00:00:00.000Z" }) as never;

  it("CASE 2 — a suspension on the absorbed party binds the survivor", () => {
    // The laundering case: get suspended, register again through another channel, have the two
    // recognised as one person. The survivor's own chain says `active` and must not be believed.
    expect(partyStatus(subj("did:survivor", "active"), [subj("did:absorbed", "suspended")])).toBe("suspended");
  });

  it("a retirement is more restrictive than a suspension", () => {
    expect(partyStatus(subj("s", "suspended"), [subj("a", "retired")])).toBe("retired");
  });

  it("a clean merge leaves the survivor active", () => {
    expect(partyStatus(subj("s", "active"), [subj("a", "active")])).toBe("active");
  });

  it("the survivor's OWN restriction is not erased by a clean absorbed party", () => {
    expect(partyStatus(subj("s", "suspended"), [subj("a", "active")])).toBe("suspended");
  });

  it("no absorbed parties is just the survivor", () => {
    expect(partyStatus(subj("s", "active"))).toBe("active");
  });
});

describe("§3.6 resolveSuccession — follow the pointer, or fail closed", () => {
  const node = (id: string, succeededBy?: string) =>
    ({ id, actorType: "user", status: succeededBy ? "retired" : "active", keys: [], assurance: "pop",
       binding: "self", bootstrapAnchor: "manual", verifiedAt: "2026-01-01T00:00:00.000Z",
       ...(succeededBy ? { succeededBy } : {}) }) as never;

  it("walks a chain of merges to the party that survives", () => {
    const world = new Map([["b", node("b", "c")], ["c", node("c")]]);
    const r = resolveSuccession(node("a", "b"), (d) => world.get(d));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.path).toEqual(["a", "b", "c"]);
      expect(r.survivor.id).toBe("c");
    }
  });

  it("CASE 5 — terminates on a cycle instead of hanging", () => {
    const world = new Map([["b", node("b", "a")]]);
    const r = resolveSuccession(node("a", "b"), (d) => world.get(d));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("succession_cycle");
  });

  it("fails closed when the survivor cannot be loaded", () => {
    const r = resolveSuccession(node("a", "gone"), () => undefined);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("succession_unresolved");
  });

  it("an actor that succeeds nobody resolves to itself", () => {
    const r = resolveSuccession(node("a"), () => undefined);
    expect(r.ok && r.survivor.id).toBe("a");
  });
});

describe("§3.6c chooseSurvivor — the older actor survives", () => {
  const at = (id: string, genesisAt?: string) =>
    ({ id, actorType: "user", status: "active", keys: [], assurance: "pop", binding: "self",
       bootstrapAnchor: "manual", verifiedAt: "2026-01-01T00:00:00.000Z",
       ...(genesisAt ? { genesisAt } : {}) }) as never;

  it("CASE 9 — the older actor survives, whichever order it is offered in", () => {
    const old = at("did:old", "2026-01-01T00:00:00.000Z");
    const recent = at("did:new", "2026-06-01T00:00:00.000Z");
    // Order-independence is the whole point: the KYC path and the contact path pass their
    // arguments in opposite orders, and both must reach the same answer.
    expect(chooseSurvivor(old, recent).survivor.id).toBe("did:old");
    expect(chooseSurvivor(recent, old).survivor.id).toBe("did:old");
    expect(chooseSurvivor(recent, old).absorbed.id).toBe("did:new");
  });

  it("is INDEPENDENT of standing and of activity — the properties that move", () => {
    // The younger party is the verified, busy one. It still loses: standing travels by its own
    // signature and restrictions by partyStatus, so neither needs to win the identifier.
    const old = at("did:old", "2026-01-01T00:00:00.000Z");
    const strong = { ...(at("did:new", "2026-06-01T00:00:00.000Z") as object), assurance: "hardware", keys: [{}, {}] } as never;
    expect(chooseSurvivor(old, strong).survivor.id).toBe("did:old");
  });

  it("ties break deterministically on the DID, so the rule is TOTAL", () => {
    const a = at("did:aaa", "2026-01-01T00:00:00.000Z");
    const b = at("did:bbb", "2026-01-01T00:00:00.000Z");
    expect(chooseSurvivor(a, b).survivor.id).toBe("did:aaa");
    expect(chooseSurvivor(b, a).survivor.id).toBe("did:aaa");
  });

  it("a missing genesisAt sorts YOUNGER — never win on absent data", () => {
    const known = at("did:known", "2026-06-01T00:00:00.000Z");
    const unknown = at("did:unknown");
    expect(chooseSurvivor(unknown, known).survivor.id).toBe("did:known");
  });

  it("genesisAt comes from the chain and does not move as evidence is re-checked", () => {
    const r = foldActorChain(chain((p) => ev("ATTESTATION_RENEWED", { keyId: "k1", verifiedAt: "2027-01-01T00:00:00.000Z" }, { prev: p })));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.subject.verifiedAt).toBe("2027-01-01T00:00:00.000Z"); // moves
      expect(r.subject.genesisAt).not.toBe("2027-01-01T00:00:00.000Z"); // does not
      expect(r.subject.genesisAt).toBeTruthy();
    }
  });
});

describe("§3.6c keySuccession — a mandate survives the merge, or fails closed", () => {
  const actor = (id: string, keys: string[], succ?: { to: string; map: Record<string, string> }) =>
    ({ id, actorType: "user", status: succ ? "retired" : "active",
       keys: keys.map((k) => ({ id: k, status: "active" })),
       assurance: "pop", binding: "self", bootstrapAnchor: "manual",
       verifiedAt: "2026-01-01T00:00:00.000Z", genesisAt: "2026-01-01T00:00:00.000Z",
       ...(succ ? { succeededBy: succ.to, keySuccession: succ.map } : {}) }) as never;

  it("THE GAP — following the actor pointer alone finds nothing", () => {
    // Without translation this is what happens: correct actor, wrong key id, empty set, mandate
    // dead. The plain §7 resolver cannot see across a merge at all.
    const survivor = actor("did:A", ["did:A#key-3"]);
    expect(resolvePinnedKeys(survivor, "did:B#key-2")).toEqual([]);
  });

  it("translates the pinned id through the merge and resolves", () => {
    const survivor = actor("did:A", ["did:A#key-3"]);
    const absorbed = actor("did:B", ["did:B#key-2"], { to: "did:A", map: { "did:B#key-2": "did:A#key-3" } });
    const keys = resolvePinnedKeysAcrossMerge(absorbed, "did:B#key-2", (d) => (d === "did:A" ? survivor : undefined));
    expect(keys.map((k) => k.id)).toEqual(["did:A#key-3"]);
  });

  it("a key with NO entry did not survive — and is not matched by material", () => {
    const survivor = actor("did:A", ["did:A#key-3"]);
    const absorbed = actor("did:B", ["did:B#key-9"], { to: "did:A", map: { "did:B#key-2": "did:A#key-3" } });
    expect(resolvePinnedKeysAcrossMerge(absorbed, "did:B#key-9", () => survivor)).toEqual([]);
  });

  it("walks two merges", () => {
    const c = actor("did:C", ["did:C#key-1"]);
    const b = actor("did:B", ["did:B#key-1"], { to: "did:C", map: { "did:B#key-1": "did:C#key-1" } });
    const a = actor("did:A", ["did:A#key-1"], { to: "did:B", map: { "did:A#key-1": "did:B#key-1" } });
    const world: Record<string, never> = { "did:B": b, "did:C": c };
    expect(resolvePinnedKeysAcrossMerge(a, "did:A#key-1", (d) => world[d]).map((k) => k.id)).toEqual(["did:C#key-1"]);
  });

  it("fails closed when the survivor cannot be loaded", () => {
    const absorbed = actor("did:B", ["did:B#key-2"], { to: "did:A", map: { "did:B#key-2": "did:A#key-3" } });
    expect(resolvePinnedKeysAcrossMerge(absorbed, "did:B#key-2", () => undefined)).toEqual([]);
  });

  it("terminates on a succession cycle", () => {
    const a = actor("did:A", ["did:A#key-1"], { to: "did:B", map: { "did:A#key-1": "did:B#key-1" } });
    const b = actor("did:B", ["did:B#key-1"], { to: "did:A", map: { "did:B#key-1": "did:A#key-1" } });
    const world: Record<string, never> = { "did:A": a, "did:B": b };
    expect(resolvePinnedKeysAcrossMerge(a, "did:A#key-1", (d) => world[d])).toEqual([]);
  });

  it("an un-merged actor behaves exactly as §7 alone", () => {
    const plain = actor("did:A", ["did:A#key-1"]);
    expect(resolvePinnedKeysAcrossMerge(plain, "did:A#key-1", () => undefined).map((k) => k.id)).toEqual(["did:A#key-1"]);
  });
});

describe("§18 ACCREDITED — a registrar's claim, on the actor's own chain", () => {
  const accredited = (over: Record<string, unknown> = {}) =>
    (p: ViaEvent) => ev("ACCREDITED", { accreditation: { level: "verified", method: "kyb-registry", registrar: "humanos", verifiedAt: "2026-07-08T11:00:00.000Z", ...over } }, { prev: p });

  /** `chain()` always starts from an AGENT genesis, and an agent may not be accredited — so these
   *  build their own chain from an organization. */
  const orgChain = (...steps: ((p: ViaEvent) => ViaEvent)[]) => {
    const out = [genesis({ actorType: "organization" })];
    for (const step of steps) out.push(step(out[out.length - 1]!));
    return out;
  };

  it("folds onto the actor and leaves CONFINEMENT untouched — two axes, not one", () => {
    const before = foldActorChain([genesis({ actorType: "organization" })]);
    const r = foldActorChain(orgChain(accredited()));
    if (!before.ok || !r.ok) throw new Error("fold failed");
    expect(r.subject.accreditation?.level).toBe("verified");
    expect(r.subject.accreditation?.method).toBe("kyb-registry");
    // a KYB-verified company whose key sits in our KMS is BOTH verified and pop
    expect(r.subject.assurance).toBe(before.subject.assurance);
    expect(r.subject.binding).toBe(before.subject.binding);
  });

  it("REPLACES wholesale — an accreditation is one coherent statement", () => {
    const r = foldActorChain(orgChain(
      accredited({ level: "domain", method: "dns-challenge" }),
      accredited({ level: "verified", method: "kyb-registry" }),
    ));
    if (!r.ok) throw new Error("fold failed");
    expect(r.subject.accreditation?.level).toBe("verified");
    // not merged: the earlier method is gone, not carried alongside
    expect(r.subject.accreditation?.method).toBe("kyb-registry");
  });

  it("REFUSES an agent — an agent inherits standing, it is never accredited (§18.4)", () => {
    // Accepting one would let an agent hold standing no registrar granted it: the forgery the
    // affiliation conjunction exists to prevent, arriving by a different door.
    const r = foldActorChain(chain(accredited()));  // genesis() defaults to actorType agent
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("accreditation_on_agent");
  });

  it("refuses a level outside the ladder", () => {
    const r = foldActorChain(orgChain(accredited({ level: "super-verified" })));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("accreditation_invalid");
  });

  it("carries a pointer to an EXTERNAL credential rather than re-typing it", () => {
    const r = foldActorChain(orgChain(accredited({
      method: "eidas-high", registrar: "some-qtsp",
      credential: { id: "urn:eidas:…", digestSRI: "sha256-…", location: "https://qtsp.example/…" },
    })));
    if (!r.ok) throw new Error("fold failed");
    expect(r.subject.accreditation?.credential?.id).toBe("urn:eidas:…");
  });
});
