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
  foldActorChain,
  projectAgentContext,
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

  it("ASSURANCE_UPDATED replaces the fields wholesale, and drops root when the update omits it", () => {
    const g = genesis({ root: "aws-nitro" });
    const downgrade = ev(
      "ASSURANCE_UPDATED",
      { assurance: "software", binding: "self", bootstrapAnchor: "manual", verifiedAt: "2026-10-02T00:00:00.000Z" },
      { prev: g },
    );
    const r = foldActorChain([g, downgrade]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject).toMatchObject({ assurance: "software", binding: "self", bootstrapAnchor: "manual" });
    // A stale root would claim hardware backing the actor no longer has.
    expect(r.subject.root).toBeUndefined();
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
    expect(auditActorSnapshot(lying, c)).toMatchObject({ reason: "subject_mismatch" });
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
      { id: "fresh", expression: 'agent.verifiedAt >= "2026-07-15T00:00:00.000Z"', message: "attestation too old" },
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
    const rule = [{ id: "active", expression: 'agent.status == "active"', message: "actor not active" }];
    expect(
      evaluateRules(rule, { userParams: {}, executionParams: {}, agent: projectAgentContext(subject({ status: "suspended" })) }).decision,
    ).toBe("deny");
  });
});
