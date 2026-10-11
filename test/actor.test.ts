/**
 * The actor chain (v0.3 §3.4/§4/§5/§7) — fold, key resolution, the record, audit.
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
  resolveSuccession,
  foldActorChain,
  projectAgentContext,
  type ViaActorSubject,
  resolvePinnedKeys,
  buildMergeClaim,
  checkMergeClaim,
  foldActorRecord,
  auditActorRecord,
  ACTOR_EVENT_TYPES,
  EVENT_SCOPE,
  type ViaActorRecord,
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
    // v0.3 §2.0: the kind's own fields directly in credentialSubject — no `agent` wrapper, no `actor`.
    credentialSubject: {
      id: opts.id ?? ACTOR,
      event,
      ...(previousEvent !== undefined ? { previousEvent } : {}),
      ...detail,
    },
  } as unknown as ViaEvent;
}

/**
 * An event as written before 2026-10-11 (and every "0.2" actor event): its fields under `agent`, an
 * `actor` beside `issuer`, and — when given — the kind's old name (v0.3 §2.0, §3.4). Read as written.
 */
function evOld(
  event: string,
  detail: Record<string, unknown> = {},
  opts: { prev?: ViaEvent | null | undefined; id?: string; at?: string } = {},
): ViaEvent {
  const e = ev(event, {}, opts);
  return {
    ...e,
    credentialSubject: { ...(e.credentialSubject as object), actor: "did:web:humanos.tech", agent: detail },
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
  // `lineage` left the v0.3 record with delegation (v0.4 §8): a genesis that carries one, written
  // by an implementation that delegates, still folds — without it.
  it("a genesis carrying lineage folds without it", () => {
    const r = foldActorChain([genesis({ lineage: { parent: "did:web:humanos.tech:agent:parent", event: "sha256-Del" } })]);
    expect(r.ok).toBe(true);
    expect(r.ok && r.subject).not.toHaveProperty("lineage");
  });

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

  // @invariant §9.1bis rule 2: a renewal re-grades the key from the evidence it presented, the whole
  // rung — weaker evidence drops the root the stronger one earned, and a renewal with no quote does
  // not claim one.
  it("a weaker renewal drops the root and records no quote", () => {
    const g = genesis({ root: "aws-nitro" });
    const before = foldActorChain([g]);
    if (!before.ok) throw new Error(before.reason);
    const keyId = before.subject.keys[0]!.id;
    const weak = ev("ATTESTATION_RENEWED", { keyId, assurance: "pop", binding: "self", verifiedAt: "2026-10-01T00:00:00.000Z" }, { prev: g });
    const r = foldActorChain([g, weak]);
    if (!r.ok) throw new Error(r.reason);
    const k = r.subject.keys[0]!;
    expect(k).toMatchObject({ assurance: "pop", binding: "self" });
    expect(k.root).toBeUndefined();
    expect(k.attestation?.kind).toBe("none");
  });

  // @invariant §9.3/§9.4ter: runtime is per key. A software key added beside an enclave key does not
  // inherit `tee` — the hole §9.1bis closed for the rung, closed here for the runtime.
  it("a key added beside an attested one does not inherit its runtime", () => {
    const TEE = { class: "tee", mechanism: "nitro" };
    const c = chain(
      (p) => ev("RUNTIME_ATTESTED", { keyId: "k1", runtime: TEE }, { prev: p, at: "2026-09-02T00:00:00.000Z" }),
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK, assurance: "pop", binding: "self" }, { prev: p }),
    );
    const r = foldActorChain(c);
    if (!r.ok) throw new Error(r.reason);
    const [k1, k2] = r.subject.keys;
    expect(projectAgentContext(r.subject, k1).runtime).toBe("tee");
    expect(projectAgentContext(r.subject, k2).runtime).toBe("none");
    expect(r.subject.runtime).toBeUndefined(); // the keys do not share a class: no summary
  });

  it("a RUNTIME_ATTESTED with no keyId attests the genesis key", () => {
    const c = chain((p) => ev("RUNTIME_ATTESTED", { runtime: { class: "tee" } }, { prev: p }));
    const r = foldActorChain(c);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.keys[0]!.runtime?.class).toBe("tee");
    expect(r.subject.runtime?.class).toBe("tee"); // its only key: the summary is that class
  });

  it("refuses a RUNTIME_ATTESTED naming a key the actor never had", () => {
    const c = chain((p) => ev("RUNTIME_ATTESTED", { keyId: "k9", runtime: { class: "tee" } }, { prev: p }));
    expect(foldActorChain(c)).toMatchObject({ ok: false, reason: "unknown_key" });
  });

  // @invariant §5: a key is rotated once. A second rotation of the same predecessor would overwrite
  // `rotatedTo` and strand the first successor — still active — outside the walk.
  it("refuses a second rotation of the same key — rotate the head of the chain", () => {
    const c = chain(
      (p) => ev("KEY_ROTATED", { predecessorId: "k1", keyId: "k2", jwk: JWK }, { prev: p }),
      (p) => ev("KEY_ROTATED", { predecessorId: "k1", keyId: "k3", jwk: JWK }, { prev: p }),
    );
    expect(foldActorChain(c)).toMatchObject({ ok: false, reason: "key_already_rotated", at: 2 });
    const head = chain(
      (p) => ev("KEY_ROTATED", { predecessorId: "k1", keyId: "k2", jwk: JWK }, { prev: p }),
      (p) => ev("KEY_ROTATED", { predecessorId: "k2", keyId: "k3", jwk: JWK }, { prev: p }),
    );
    expect(foldActorChain(head).ok).toBe(true);
  });

  // @invariant §9.1bis rule 5: the summary is the floor across USABLE keys. With none left there is
  // no floor — the actor reports no rung, not the one its revoked key earned.
  it("an actor whose every key is revoked has no rung — not its last", () => {
    const c = chain((p) => ev("KEY_REVOKED", { keyId: "k1" }, { prev: p }));
    const r = foldActorChain(c);
    if (!r.ok) throw new Error(r.reason);
    for (const f of ["assurance", "binding", "verifiedAt", "root"] as const) expect(r.subject[f]).toBeUndefined();
    expect(r.subject.bootstrapAnchor).toBe("api_key"); // history, not the summary
  });

  it("a new key gives an actor with no usable key its rung back, from that key", () => {
    const c = chain(
      (p) => ev("KEY_REVOKED", { keyId: "k1" }, { prev: p }),
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK, assurance: "pop", binding: "self", verifiedAt: "2026-09-02T00:00:00.000Z" }, { prev: p }),
    );
    const r = foldActorChain(c);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject).toMatchObject({ assurance: "pop", binding: "self", verifiedAt: "2026-09-02T00:00:00.000Z" });
  });

  // @invariant §9.1bis rule 6: a summary event without keyId, in a chain written before it was
  // retired, is still checked but writes nothing — with no usable key it cannot give a rung back.
  it("a summary event without keyId sets no rung on an actor with no usable key", () => {
    const c = chain(
      (p) => ev("KEY_REVOKED", { keyId: "k1" }, { prev: p }),
      (p) => ev("ASSURANCE_UPDATED", { assurance: "hardware", binding: "attested" }, { prev: p }),
    );
    const r = foldActorChain(c);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.assurance).toBeUndefined();
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

  // @invariant §5: a keyed regrade carries no evidence, so it lowers or keeps every rung field and
  // never names a root — "downgrade-only" on assurance alone let it raise the binding and set a root.
  it("refuses a keyed ASSURANCE_UPDATED that raises any rung field", () => {
    const g = genesis({ assurance: "pop", binding: "self" });
    const before = foldActorChain([g]);
    if (!before.ok) throw new Error(before.reason);
    const keyId = before.subject.keys[0]!.id;
    for (const raise of [
      { assurance: "hardware", binding: "self" },
      { assurance: "pop", binding: "attested" },
      { assurance: "pop", binding: "self", root: "aws-nitro" },
    ]) {
      const up = ev("ASSURANCE_UPDATED", { keyId, ...raise }, { prev: g });
      expect(foldActorChain([g, up])).toMatchObject({ ok: false, reason: expect.stringContaining("regrade_raises") });
    }
  });
});

// ── status (§4 transition table) ─────────────────────────────────────────────

describe("foldActorChain — status transitions", () => {
  it("suspends from active and resumes from suspended", () => {
    const c = chain(
      (p) => ev("ACTOR_SUSPENDED", {}, { prev: p }),
      (p) => ev("ACTOR_RESUMED", {}, { prev: p }),
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
      (p) => ev("ACTOR_SUSPENDED", {}, { prev: p }),
      (p) => ev("ACTOR_SUSPENDED", {}, { prev: p }),
    );
    expect(foldActorChain(twice)).toMatchObject({ ok: false, reason: "illegal_transition", at: 2 });

    const bogus = chain((p) => ev("ACTOR_RESUMED", {}, { prev: p }));
    expect(foldActorChain(bogus)).toMatchObject({ ok: false, reason: "illegal_transition", at: 1 });
  });

  it("retires from active and from suspended", () => {
    const fromActive = chain((p) => ev("ACTOR_RETIRED", {}, { prev: p }));
    const a = foldActorChain(fromActive);
    if (!a.ok) throw new Error(a.reason);
    expect(a.subject.status).toBe("retired");

    const fromSuspended = chain(
      (p) => ev("ACTOR_SUSPENDED", {}, { prev: p }),
      (p) => ev("ACTOR_RETIRED", {}, { prev: p }),
    );
    const s = foldActorChain(fromSuspended);
    if (!s.ok) throw new Error(s.reason);
    expect(s.subject.status).toBe("retired");
  });

  it("retired is absorbing — nothing may follow it", () => {
    const c = chain(
      (p) => ev("ACTOR_RETIRED", {}, { prev: p }),
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }),
    );
    expect(foldActorChain(c)).toMatchObject({ ok: false, reason: "event_after_retired", at: 2 });
  });

  it("content events stay legal while suspended — the audit trail does not pause", () => {
    const c = chain(
      (p) => ev("ACTOR_SUSPENDED", {}, { prev: p }),
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
      (p) => ev("FORK_DETECTED", {}, { prev: p }),
      (p) => ev("DELEGATED", {}, { prev: p }),
      (p) => ev("SNAPSHOT_ISSUED", {}, { prev: p }),
    );
    const after = foldActorChain(c);
    if (!before.ok || !after.ok) throw new Error("fold failed");
    // They POINT; any state change arrives via the events they trigger.
    expect(after.subject).toEqual(before.subject);
  });

  // Delegation is parked in v0.4 §8 (2026-10-11): `DELEGATED` stays a reserved kind, so a chain
  // written by an implementation that delegates still folds here — and nothing of it is folded.
  it("DELEGATED is reserved: a parent's grant is accepted and folds nothing", () => {
    const before = foldActorChain([genesis()]);
    const after = foldActorChain(
      chain((p) => ev("DELEGATED", { child: "did:web:humanos.tech:agent:child", tools: ["search"], depth: 1 }, { prev: p })),
    );
    if (!before.ok || !after.ok) throw new Error("fold failed");
    expect(after.subject).toEqual(before.subject);
  });

  it("AFFILIATION sets an operator POINTER, never an inline claim", () => {
    const g = genesis();
    const aff = ev("ACTOR_AFFILIATED", { org: "did:web:acme.example" }, { prev: g });
    const r = foldActorChain([g, aff]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.operator).toEqual({
      org: "did:web:acme.example",
      affiliationEvent: eventChainLink(aff),
    });
  });
});

// ── one detail field per event kind ─────────────────────────────────────────

/** An event whose detail sits in a NAMED field (`operator`, `accreditation`), not in `agent`. */
function evNamed(event: string, named: Record<string, unknown>, prev: ViaEvent, issuer = "did:web:humanos.tech"): ViaEvent {
  const e = ev(event, {}, { prev });
  const cs = e.credentialSubject as unknown as Record<string, unknown>;
  delete cs.agent;
  Object.assign(cs, named);
  return { ...e, issuer } as ViaEvent;
}

describe("detail fields — each event kind reads the field the spec names", () => {
  // §18: the org-signed AFFILIATION carries its claim in `credentialSubject.operator`.
  it("AFFILIATION reads the org and relation from `operator`", () => {
    const g = genesis();
    const aff = evNamed("ACTOR_AFFILIATED", { operator: { org: "did:web:acme.example", relation: "operates" } }, g, "did:web:other.example");
    const r = foldActorChain([g, aff]);
    if (!r.ok) throw new Error(r.reason);
    // The org the EVENT names, not whoever the envelope says issued it.
    expect(r.subject.operator).toEqual({ org: "did:web:acme.example", relation: "operates", affiliationEvent: eventChainLink(aff) });
  });

  // Signed history cannot be rewritten: events written with the org in `agent` must keep folding.
  it("an AFFILIATION written with its org in `agent` still folds", () => {
    const g = genesis();
    const aff = ev("ACTOR_AFFILIATED", { org: "did:web:acme.example", relation: "sandbox_of" }, { prev: g });
    const r = foldActorChain([g, aff]);
    expect(r.ok && r.subject.operator).toEqual({ org: "did:web:acme.example", relation: "sandbox_of", affiliationEvent: eventChainLink(aff) });
  });

  // §18.4, §3.1: the record restates the affiliation's lapse — no event marks the moment it passes.
  it("AFFILIATION records the claim's lapse as `operator.validUntil`", () => {
    const g = genesis();
    const until = "2026-12-31T23:59:59.000Z";
    const aff = evNamed("ACTOR_AFFILIATED", { operator: { org: "did:web:acme.example", relation: "operates", validUntil: until } }, g, "did:web:acme.example");
    const r = foldActorChain([g, aff]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.operator).toEqual({
      org: "did:web:acme.example",
      relation: "operates",
      validUntil: until,
      affiliationEvent: eventChainLink(aff),
    });
  });

  // Signed history is read as written: an affiliation signed before 2026-10-07 names its lapse `expiresAt`.
  it("reads an AFFILIATION's `expiresAt` as `validUntil`", () => {
    const g = genesis();
    const until = "2026-12-31T23:59:59.000Z";
    const aff = evNamed("ACTOR_AFFILIATED", { operator: { org: "did:web:acme.example", relation: "operates", expiresAt: until } }, g, "did:web:acme.example");
    const r = foldActorChain([g, aff]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.operator?.validUntil).toBe(until);
    expect(r.subject.operator).not.toHaveProperty("expiresAt");
  });

  it("records no lapse when the AFFILIATION states none", () => {
    const g = genesis();
    const aff = evNamed("ACTOR_AFFILIATED", { operator: { org: "did:web:acme.example", relation: "operates" } }, g, "did:web:acme.example");
    const r = foldActorChain([g, aff]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.operator).not.toHaveProperty("validUntil");
  });

  // A renewal is a new claim: its lapse replaces the old one, and a renewal with none clears it.
  it("a later AFFILIATION from the operator replaces the lapse", () => {
    const g = genesis();
    const first = evNamed("ACTOR_AFFILIATED", { operator: { org: "did:web:acme.example", relation: "operates", validUntil: "2026-12-31T23:59:59.000Z" } }, g, "did:web:acme.example");
    const renewed = evNamed("ACTOR_AFFILIATED", { operator: { org: "did:web:acme.example", relation: "operates", validUntil: "2027-06-30T23:59:59.000Z" } }, first, "did:web:acme.example");
    const open = evNamed("ACTOR_AFFILIATED", { operator: { org: "did:web:acme.example", relation: "operates" } }, renewed, "did:web:acme.example");
    const r1 = foldActorChain([g, first, renewed]);
    if (!r1.ok) throw new Error(r1.reason);
    expect(r1.subject.operator?.validUntil).toBe("2027-06-30T23:59:59.000Z");
    const r2 = foldActorChain([g, first, renewed, open]);
    if (!r2.ok) throw new Error(r2.reason);
    expect(r2.subject.operator).not.toHaveProperty("validUntil");
  });

  it("ACCREDITED reads the accreditation from its own `accreditation` field", () => {
    const g = genesis({ actorType: "organization" });
    const acc = evNamed("ACTOR_ACCREDITED", { accreditation: { level: "verified", method: "kyb-registry", registrar: "humanos" } }, g);
    const r = foldActorChain([g, acc]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.accreditation).toMatchObject({ level: "verified", method: "kyb-registry" });
  });

  // @invariant No silent default: an organization or person genesis missing its type would
  // otherwise fold as an AGENT, with an agent's rules applied to a party that is not one.
  it("a genesis without actorType does not fold", () => {
    const g = genesis({ actorType: undefined });
    const r = foldActorChain([g]);
    expect(r).toMatchObject({ ok: false, reason: "genesis_actor_type_missing" });
  });

  // §9.4ter: the runtime axis says where an AGENT's key-holding process runs. An organization or a
  // person has no such process to attest; accepting one would put a claim on their record that
  // means nothing — the mirror of `accreditation_on_agent`.
  it.each(["organization", "user"])("RUNTIME_ATTESTED on %s does not fold", (actorType) => {
    const g = genesis({ actorType });
    const rt = ev("RUNTIME_ATTESTED", { runtime: { class: "tee" } }, { prev: g });
    expect(foldActorChain([g, rt])).toMatchObject({ ok: false, reason: "runtime_on_non_agent" });
  });

  // §3.4: "REGULATORY — a regulator's own claim about this actor … Actor-scoped, like AFFILIATION".
  it("REGULATORY is actor-scoped and state-neutral on the chain", () => {
    expect(EVENT_SCOPE.ACTOR_REGULATED).toBe("actor");
    const g = genesis({ actorType: "organization" });
    const reg = ev("ACTOR_REGULATED", { licence: "PT-INS-1234" }, { prev: g });
    const r = foldActorChain([g, reg]);
    expect(r.ok && r.subject.status).toBe("active");
  });
});

// ── an agent key's JWK: one name in the record (v0.3 §3.1, 2026-10-11) ─────────

describe("an agent key's JWK — `publicKeyJwk` in the record, read from either name", () => {
  const recordKey = (events: ViaEvent[], id: string) => {
    const r = foldActorChain(events);
    if (!r.ok) throw new Error(r.reason);
    return r.subject.keys.find((k) => k.id === id)!;
  };

  it.each<[string, string]>([
    ["an event written from 2026-10-11", "publicKeyJwk"],
    ["an event signed before, as written", "jwk"],
  ])("ACTOR_REGISTERED, KEY_ADDED and KEY_ROTATED from %s fold to `publicKeyJwk`", (_case, name) => {
    const key = (n: number) => ({ [name]: { ...JWK, x: `x${n}` } });
    const g = ev("ACTOR_REGISTERED", { keyId: "k1", ...key(1), actorType: "agent", assurance: "hardware", binding: "attested", bootstrapAnchor: "api_key" }, { prev: null });
    const add = ev("KEY_ADDED", { keyId: "k2", ...key(2) }, { prev: g });
    const rot = ev("KEY_ROTATED", { predecessorId: "k2", keyId: "k3", ...key(3) }, { prev: add });
    for (const [id, n] of [["k1", 1], ["k2", 2], ["k3", 3]] as const) {
      const k = recordKey([g, add, rot], id);
      expect(k.publicKeyJwk).toEqual({ ...JWK, x: `x${n}` });
      expect(k).not.toHaveProperty("jwk");
    }
  });

  it.each(["publicKeyJwk", "jwk"])("a MERGED key written with `%s` folds to `publicKeyJwk`", (name) => {
    const g = genesis();
    const m = ev("ACTOR_MERGED", {}, { prev: g });
    (m.credentialSubject as unknown as { merge: unknown }).merge = {
      absorbed: "did:web:humanos.tech:agent:b2",
      keys: [{ keyId: "did:web:humanos.tech:agent:b2#key-1", [name]: { ...JWK, x: "xb" }, status: "active" }],
    };
    const k = recordKey([g, m], "did:web:humanos.tech:agent:b2#key-1");
    expect(k.publicKeyJwk).toEqual({ ...JWK, x: "xb" });
    expect(k).not.toHaveProperty("jwk");
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
      { id: "a", publicKeyJwk: JWK as never, status: "rotated", rotatedTo: "b" },
      { id: "b", publicKeyJwk: JWK as never, status: "rotated", rotatedTo: "a" },
    ];
    expect(resolvePinnedKeys(r.subject, "a").map((k) => k.id)).toEqual(["a", "b"]);
  });
});

// ── the record ───────────────────────────────────────────────────────────────

describe("foldActorRecord", () => {
  it("binds the chain's genesis, head, and how many events were folded", () => {
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const r = foldActorRecord(c);
    if (!r.ok) throw new Error(r.reason);
    expect(r.record.chain).toEqual({
      genesisEvent: eventChainLink(c[0]!),
      headEvent: eventChainLink(c[1]!),
      sequence: 2,
    });
  });

  it("is the fold's state plus its chain position — nothing a signed copy would add", () => {
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const r = foldActorRecord(c);
    const f = foldActorChain(c);
    if (!r.ok || !f.ok) throw new Error("fold");
    const { chain: _position, ...state } = r.record;
    expect(state).toEqual(f.subject);
    for (const field of ["supersedes", "validFrom", "validUntil", "specVersion", "proof"]) {
      expect(r.record).not.toHaveProperty(field);
    }
  });

  it("propagates a fold failure instead of producing a record of nothing", () => {
    expect(foldActorRecord([])).toMatchObject({ ok: false, reason: "empty_chain" });
  });
});

// ── audit ────────────────────────────────────────────────────────────────────

describe("auditActorRecord", () => {
  const built = () => {
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const r = foldActorRecord(c);
    if (!r.ok) throw new Error(r.reason);
    return { c, record: r.record };
  };

  it("accepts a record that matches its chain", () => {
    const { c, record } = built();
    expect(auditActorRecord(record, c)).toEqual({ ok: true });
  });

  it("a record names a PREFIX — later events make it stale without making it wrong", () => {
    const { c, record } = built();
    const extended = [...c, ev("KEY_REVOKED", { keyId: "k1" }, { prev: c[c.length - 1] })];
    expect(auditActorRecord(record, extended)).toEqual({ ok: true });
  });

  it("rejects a record bound to a different genesis", () => {
    const { record } = built();
    const other = chain((p) => ev("KEY_ADDED", { keyId: "kX", jwk: JWK }, { prev: p }));
    expect(auditActorRecord(record, other)).toMatchObject({ reason: "chain_binding_mismatch" });
    expect(auditActorRecord(record, [])).toMatchObject({ reason: "chain_binding_mismatch" });
  });

  it("rejects a record whose head is not in the chain, or whose sequence is not the head's position", () => {
    const { c, record } = built();
    expect(auditActorRecord({ ...record, chain: { ...record.chain, headEvent: "sha256-nope" } }, c))
      .toMatchObject({ reason: "chain_binding_mismatch" });
    expect(auditActorRecord({ ...record, chain: { ...record.chain, sequence: 7 } }, c))
      .toMatchObject({ reason: "chain_binding_mismatch" });
  });

  it("rejects a tampered state — the chain is authoritative", () => {
    const { c, record } = built();
    const lying = { ...record, assurance: "hardware" as never, id: "did:web:humanos.tech:agent:someone-else" };
    expect(auditActorRecord(lying, c)).toMatchObject({ reason: "record_mismatch" });

    // A record computed before the fold learned a field is OUTDATED, not a lie: every value it
    // carries still matches. Recompute it; a verifier never authorizes from a stale one anyway.
    const older = structuredClone(record);
    delete (older as unknown as Record<string, unknown>).existedSince;
    expect(auditActorRecord(older, c)).toMatchObject({ reason: "record_outdated" });
    // Missing a field AND lying about another is a mismatch — the missing field does not launder it.
    const olderAndLying = structuredClone(older);
    olderAndLying.id = "did:web:humanos.tech:agent:someone-else";
    expect(auditActorRecord(olderAndLying, c)).toMatchObject({ reason: "record_mismatch" });
  });

  it("surfaces a fold failure with its reason attached", () => {
    const { record } = built();
    // A chain whose genesis matches but which breaks further along.
    const g = genesis();
    const orphan = ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: g });
    const broken = [g, orphan, ev("KEY_ADDED", { keyId: "k3", jwk: JWK }, { prev: g })];
    const bound: ViaActorRecord = {
      ...record,
      chain: { genesisEvent: eventChainLink(g), headEvent: eventChainLink(broken[2]!), sequence: 3 },
    };
    expect(auditActorRecord(bound, broken).reason).toMatch(/^fold_failed:/);
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
      keys: [{ id: "did:web:humanos.tech:agent:abc#key-1", publicKeyJwk: {} as never, status: "active" }],
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

  it("operator projects PRESENCE + DID, never the event", () => {
    const ctx = projectAgentContext(
      subject({
        operator: { org: "did:web:humanos.tech:org:acme", affiliationEvent: "sha256-xyz" },
      }),
    );
    expect(ctx.operator).toEqual({ org: "did:web:humanos.tech:org:acme" });
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

  // @invariant §9.1bis rule 4: a key with no rung of its own is possession only — it never inherits
  // the hardware grade of the actor or the key beside it.
  it("a key added with no rung of its own is pop/self, never the actor's grade", () => {
    const c = chain((p) => ev("KEY_ADDED", { keyId: "k2", jwk: JWK }, { prev: p }));
    const folded = foldActorChain(c);
    if (!folded.ok) throw new Error(folded.reason);
    expect(folded.subject.keys[1]).toMatchObject({ assurance: "pop", binding: "self" });
    expect(folded.subject.keys[1]!.root).toBeUndefined();
    expect(folded.subject.assurance).toBe("pop"); // the floor follows the weakest usable key
  });

  // @invariant §5: once an actor has an operator, only that operator writes a later AFFILIATION.
  it("refuses an AFFILIATION from an organization other than the current operator", () => {
    const g = genesis();
    const first = { ...ev("ACTOR_AFFILIATED", {}, { prev: g }), issuer: "did:web:acme.example" } as ViaEvent;
    (first.credentialSubject as Record<string, unknown>).operator = { org: "did:web:acme.example", relation: "operates" };
    const hijack = { ...ev("ACTOR_AFFILIATED", {}, { prev: first }), issuer: "did:web:evil.example" } as ViaEvent;
    (hijack.credentialSubject as Record<string, unknown>).operator = { org: "did:web:evil.example", relation: "operates" };
    expect(foldActorChain([g, first, hijack])).toMatchObject({ ok: false, reason: "affiliation_invalid" });

    const renewal = { ...ev("ACTOR_AFFILIATED", {}, { prev: first }), issuer: "did:web:acme.example" } as ViaEvent;
    (renewal.credentialSubject as Record<string, unknown>).operator = { org: "did:web:acme.example", relation: "vouches" };
    const r = foldActorChain([g, first, renewal]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.operator).toMatchObject({ org: "did:web:acme.example", relation: "vouches" });
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
    const merged = foldActorChain(chain((p) => ev("ACTOR_RETIRED", { succeededBy: "did:survivor" }, { prev: p })));
    const stopped = foldActorChain(chain((p) => ev("ACTOR_RETIRED", {}, { prev: p })));
    expect(merged.ok && merged.subject.succeededBy).toBe("did:survivor");
    expect(stopped.ok && stopped.subject.succeededBy).toBeUndefined();
    // absorbing either way
    expect(merged.ok && merged.subject.status).toBe("retired");
  });

  it("an absorbed actor accepts NO further events", () => {
    const c = chain(
      (p) => ev("ACTOR_RETIRED", { succeededBy: "did:survivor" }, { prev: p }),
      (p) => ev("KEY_ADDED", { keyId: "k2", jwk: {} }, { prev: p }),
    );
    const r = foldActorChain(c);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("event_after_retired");
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
  const at = (id: string, existedSince?: string) =>
    ({ id, actorType: "user", status: "active", keys: [], assurance: "pop", binding: "self",
       bootstrapAnchor: "manual", verifiedAt: "2026-01-01T00:00:00.000Z",
       ...(existedSince ? { existedSince } : {}) }) as never;

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
    // signature and restrictions by the merge's own SUSPENDED event (rule 7), so neither needs to win the identifier.
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

  it("a missing existedSince sorts YOUNGER — never win on absent data", () => {
    const known = at("did:known", "2026-06-01T00:00:00.000Z");
    const unknown = at("did:unknown");
    expect(chooseSurvivor(unknown, known).survivor.id).toBe("did:known");
  });

  it("existedSince comes from the chain and does not move as evidence is re-checked", () => {
    const r = foldActorChain(chain((p) => ev("ATTESTATION_RENEWED", { keyId: "k1", verifiedAt: "2027-01-01T00:00:00.000Z" }, { prev: p })));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.subject.verifiedAt).toBe("2027-01-01T00:00:00.000Z"); // moves
      expect(r.subject.existedSince).toBe("2026-09-01T00:00:00.000Z"); // does not
    }
  });

  // §3.1: one age. A genesis that states none is as old as its own signing — the fallback the
  // merge rule used to make (`genesisAt`) is the fold's now, so the field is always present.
  it("a genesis that states no existedSince is as old as its own validFrom", () => {
    const r = foldActorChain([ev("ACTOR_REGISTERED", { keyId: "k1", jwk: JWK, actorType: "agent", assurance: "pop", binding: "self" }, { prev: null, at: "2026-07-04T00:00:00.000Z" })]);
    expect(r.ok && r.subject.existedSince).toBe("2026-07-04T00:00:00.000Z");
    expect(r.ok && r.subject).not.toHaveProperty("genesisAt");
  });

  // §3.6c ranks age by `existedSince` alone. A backfill registers every actor at the moment it
  // runs, so ranking on when each chain began would make a 2024 organization registered in 2026
  // younger than a person who signed up natively last month — the exact population §3.5 backfills.
  it("genesis folds `existedSince` into the actor — the party's age, not its chain's", () => {
    const r = foldActorChain([genesis({ existedSince: "2024-03-01T00:00:00.000Z" })]);
    expect(r.ok && r.subject.existedSince).toBe("2024-03-01T00:00:00.000Z");
  });

  it("ranks by existedSince — a backfilled old party beats a newer native one", () => {
    const backfilled = at("did:backfilled", "2024-03-01T00:00:00.000Z");
    const native = at("did:native", "2026-08-01T00:00:00.000Z");
    expect(chooseSurvivor(native, backfilled).survivor.id).toBe("did:backfilled");
    expect(chooseSurvivor(backfilled, native).survivor.id).toBe("did:backfilled");
  });
});

describe("§3.6c keySuccession — a mandate survives the merge, or fails closed", () => {
  const actor = (id: string, keys: string[], succ?: { to: string; map: Record<string, string> }) =>
    ({ id, actorType: "user", status: succ ? "retired" : "active",
       keys: keys.map((k) => ({ id: k, status: "active" })),
       assurance: "pop", binding: "self", bootstrapAnchor: "manual",
       verifiedAt: "2026-01-01T00:00:00.000Z", existedSince: "2026-01-01T00:00:00.000Z",
       ...(succ ? { succeededBy: succ.to, keySuccession: succ.map } : {}) }) as never;

  it("THE GAP — following the actor pointer alone finds nothing", () => {
    // Without translation this is what happens: correct actor, wrong key id, empty set, mandate
    // dead. The plain §7 resolver cannot see across a merge at all.
    const survivor = actor("did:A", ["did:A#key-3"]);
    expect(resolvePinnedKeys(survivor, "did:B#key-2")).toEqual([]);
  });

  // A key keeps its id since 2026-10-11 (§3.6c); a chain written when it could be renumbered still reads.
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

describe("§3.6c MERGED — the survivor's half of a merge, in one event", () => {
  const B = "did:web:humanos.tech:agent:b2";
  const K = (n: number) => `${B}#key-${n}`;
  /** `MERGED` on the survivor (ACTOR): its claim rides in `credentialSubject.merge`. */
  const merged = (merge: Record<string, unknown>) => (p: ViaEvent) => {
    const e = ev("ACTOR_MERGED", {}, { prev: p });
    (e.credentialSubject as unknown as { merge: unknown }).merge = merge;
    return e;
  };
  const active = (n: number, over: Record<string, unknown> = {}) => ({
    keyId: K(n), jwk: { ...JWK, x: `x${n}` }, status: "active", assurance: "pop", binding: "self",
    verifiedAt: "2026-03-01T00:00:00.000Z", ...over,
  });

  // @invariant The absorbed actor's name, its aliases and its surviving keys reach the survivor in
  // ONE event — and a carried key arrives with the state it had, not as a freshly enrolled one.
  it("adds the absorbed identifier, its aliases and its keys, each key with its own state", () => {
    const r = foldActorChain(chain(merged({
      absorbed: B,
      aliases: ["did:web:humanos.tech:agent:b2-old"],
      keys: [
        active(1, { status: "rotated", rotatedTo: K(2) }),
        active(2, { assurance: "hardware", binding: "attested", root: "aws-nitro",
          attestation: { event: "sha256-att", kind: "attestation-eat" } }),
      ],
    })));
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.aliases).toEqual([
      { did: B, reason: "merge" },
      { did: "did:web:humanos.tech:agent:b2-old", reason: "inherited" },
    ]);
    const k1 = r.subject.keys.find((k) => k.id === K(1))!;
    const k2 = r.subject.keys.find((k) => k.id === K(2))!;
    expect(k1).toMatchObject({ status: "rotated", rotatedTo: K(2), assurance: "pop", binding: "self", verifiedAt: "2026-03-01T00:00:00.000Z" });
    expect(k2).toMatchObject({ status: "active", assurance: "hardware", root: "aws-nitro", attestation: { event: "sha256-att", kind: "attestation-eat" } });
    // …and a pin on the rotated key still walks to its successor, on the survivor (§7).
    expect(resolvePinnedKeys(r.subject, K(1)).map((k) => k.id)).toEqual([K(1), K(2)]);
    expect(r.subject.status).toBe("active"); // state-neutral for the status (§4)
  });

  it("the summary follows: a weak key carried in lowers the survivor's floor", () => {
    const before = foldActorChain([genesis()]);
    const r = foldActorChain(chain(merged({ absorbed: B, keys: [active(1)] })));
    if (!before.ok || !r.ok) throw new Error("fold failed");
    expect(before.subject.assurance).toBe("hardware");
    expect(r.subject).toMatchObject({ assurance: "pop", binding: "self" });
  });

  // @invariant §3.6 rule 10: accreditation does not transfer — a `MERGED` carries none and moves none.
  it("moves no accreditation and no status", () => {
    const r = foldActorChain(chain(merged({ absorbed: B, keys: [active(1)], accreditation: { level: "verified", method: "kyc-doc" } })));
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.accreditation).toBeUndefined();
  });

  it.each<[string, Record<string, unknown>, string]>([
    ["names no absorbed actor", { keys: [] }, "merge_invalid"],
    ["names the survivor itself", { absorbed: ACTOR }, "merge_invalid"],
    ["lists the survivor among the aliases", { absorbed: B, aliases: [ACTOR] }, "merge_invalid"],
    // §3.6c rule 2: a revoked key does not survive a merge.
    ["carries a revoked key", { absorbed: B, keys: [active(1, { status: "revoked" })] }, "merge_invalid"],
    ["carries a key with no material", { absorbed: B, keys: [{ keyId: K(1), status: "active" }] }, "merge_invalid"],
    ["points a rotated key at a key it does not carry", { absorbed: B, keys: [active(1, { status: "rotated", rotatedTo: K(9) })] }, "merge_invalid"],
    ["gives an active key a successor", { absorbed: B, keys: [active(1, { rotatedTo: K(2) }), active(2)] }, "merge_invalid"],
    ["carries a key id the survivor already holds", { absorbed: B, keys: [{ ...active(1), keyId: "k1" }] }, "duplicate_key"],
    ["carries one key id twice", { absorbed: B, keys: [active(1), active(1)] }, "duplicate_key"],
    ["carries an unknown rung", { absorbed: B, keys: [active(1, { assurance: "platinum" })] }, "invalid_assurance"],
  ])("refuses a MERGED that %s", (_case, merge, reason) => {
    expect(foldActorChain(chain(merged(merge)))).toMatchObject({ ok: false, reason: expect.stringContaining(reason) });
  });

  it("is refused on a retired actor, like every event (§4)", () => {
    const r = foldActorChain(chain((p) => ev("ACTOR_RETIRED", {}, { prev: p }), merged({ absorbed: B })));
    expect(r).toMatchObject({ ok: false, reason: expect.stringContaining("event_after_retired") });
  });

  it("a rotated key whose successor was revoked is carried without a pointer", () => {
    const r = foldActorChain(chain(merged({ absorbed: B, keys: [active(1, { status: "rotated" })] })));
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.keys.find((k) => k.id === K(1))).toMatchObject({ status: "rotated" });
    expect(r.subject.keys.find((k) => k.id === K(1))!.rotatedTo).toBeUndefined();
  });

  describe("the whole merge, across both chains", () => {
    // The absorbed actor B: key-1 rotated to key-2, key-3 revoked, one alias.
    const bEv = (event: string, detail: Record<string, unknown>, prev: ViaEvent | null) => ev(event, detail, { prev, id: B });
    const absorbedChain = () => {
      const g = bEv("ACTOR_REGISTERED", { keyId: K(1), jwk: { ...JWK, x: "x1" }, actorType: "agent", assurance: "pop", binding: "self", bootstrapAnchor: "api_key", verifiedAt: "2026-03-01T00:00:00.000Z" }, null);
      const rot = bEv("KEY_ROTATED", { keyId: K(2), jwk: { ...JWK, x: "x2" }, predecessorId: K(1), assurance: "hardware", binding: "attested", root: "aws-nitro", verifiedAt: "2026-04-01T00:00:00.000Z" }, g);
      const add = bEv("KEY_ADDED", { keyId: K(3), jwk: { ...JWK, x: "x3" }, verifiedAt: "2026-04-02T00:00:00.000Z" }, rot);
      const rev = bEv("KEY_REVOKED", { keyId: K(3) }, add);
      const alias = bEv("ALIAS_ADDED", { alias: "did:web:humanos.tech:agent:b2-old", aliasReason: "channel" }, rev);
      return [g, rot, add, rev, alias];
    };
    const fold = (events: ViaEvent[]) => {
      const r = foldActorChain(events);
      if (!r.ok) throw new Error(r.reason);
      return r.subject;
    };

    // @invariant `buildMergeClaim` states exactly what the absorbed actor holds: live keys with
    // their state, never the revoked one — and the two halves it returns agree with each other.
    it("builds both halves from the absorbed actor, folds them, and a pinned mandate survives", () => {
      const live = absorbedChain();
      const { merge, keySuccession } = buildMergeClaim(fold(live));
      expect(merge.keys.map((k) => [k.keyId, k.status, k.rotatedTo])).toEqual([[K(1), "rotated", K(2)], [K(2), "active", undefined]]);
      expect(keySuccession).toEqual({ [K(1)]: K(1), [K(2)]: K(2) });
      expect(merge.aliases).toEqual(["did:web:humanos.tech:agent:b2-old"]);

      const retired = fold([...live, bEv("ACTOR_RETIRED", { succeededBy: ACTOR, keySuccession }, live.at(-1)!)]);
      const survivor = fold(chain(merged(merge as never)));
      expect(checkMergeClaim(merge, survivor, retired)).toEqual({ ok: true });

      // A mandate pinned to the absorbed actor's ROTATED key resolves on the survivor, through
      // the succession the merge carried — and the revoked key resolves to nothing.
      const usable = resolvePinnedKeysAcrossMerge(retired, K(1), (d) => (d === ACTOR ? survivor : undefined));
      expect(usable.map((k) => k.id)).toEqual([K(1), K(2)]);
      expect(resolvePinnedKeysAcrossMerge(retired, K(3), () => survivor)).toEqual([]);
      // The rung read at authorization is the carried key's own (§9.1bis rule 1).
      expect(usable[1]).toMatchObject({ assurance: "hardware", binding: "attested", root: "aws-nitro" });
    });

    // @invariant v0.3 §3.6c (2026-10-11): a carried key keeps the id its own DID gave it — never
    // renumbered under the survivor's DID — so `keySuccession` maps every surviving key to itself.
    it("keeps every key's id, and leaves out a key the survivor already holds", () => {
      const absorbed = fold(absorbedChain());
      const kept = buildMergeClaim(absorbed);
      expect(kept.keySuccession).toEqual({ [K(1)]: K(1), [K(2)]: K(2) });
      expect(kept.merge.keys.map((k) => [k.keyId, k.rotatedTo])).toEqual([[K(1), K(2)], [K(2), undefined]]);
      const held = buildMergeClaim(absorbed, { held: new Set([K(2)]) });
      // key-2 is mapped but not carried again; key-1's pointer to it is not carried either.
      expect(held.keySuccession[K(2)]).toBe(K(2));
      expect(held.merge.keys.map((k) => [k.keyId, k.rotatedTo])).toEqual([[K(1), undefined]]);
    });

    // @invariant §5.2: `MERGED` puts keys on an actor with no evidence of its own, so it carries
    // only what the absorbed actor's chain holds. Anything else is refused at append.
    it.each<[string, (m: ReturnType<typeof buildMergeClaim>["merge"]) => void]>([
      ["smuggles a key the absorbed actor never had", (m) => m.keys.push({ keyId: `${B}#key-9`, publicKeyJwk: { ...JWK, x: "evil" } as never, status: "active" })],
      ["carries the revoked key", (m) => m.keys.push({ keyId: K(3), publicKeyJwk: { ...JWK, x: "x3" } as never, status: "active", assurance: "pop", binding: "self", verifiedAt: "2026-04-02T00:00:00.000Z" })],
      ["swaps a key's material", (m) => { m.keys[0]!.publicKeyJwk = { ...JWK, x: "evil" } as never; }],
      ["raises a key's rung", (m) => { m.keys[0]!.assurance = "hardware"; }],
      ["un-rotates a rotated key", (m) => { m.keys[0]!.status = "active"; delete m.keys[0]!.rotatedTo; }],
      ["drops a rotated key's pointer to the successor it carries", (m) => { delete m.keys[0]!.rotatedTo; }],
      ["points a rotated key at another carried key", (m) => { m.keys.push({ keyId: `${B}#key-9`, publicKeyJwk: { ...JWK, x: "x9" } as never, status: "active" }); m.keys[0]!.rotatedTo = `${B}#key-9`; }],
      ["names an alias the absorbed actor never had", (m) => m.aliases.push("did:web:humanos.tech:agent:stranger")],
    ])("checkMergeClaim refuses a claim that %s", (_case, tamper) => {
      const live = absorbedChain();
      const { merge, keySuccession } = buildMergeClaim(fold(live));
      const retired = fold([...live, bEv("ACTOR_RETIRED", { succeededBy: ACTOR, keySuccession }, live.at(-1)!)]);
      tamper(merge);
      expect(checkMergeClaim(merge, { id: ACTOR, actorType: "agent" }, retired)).toEqual({ ok: false, reason: "merge_target_invalid" });
    });

    // v0.3 §3.1 (2026-10-11): a claim is written with `publicKeyJwk`; one signed before says `jwk`,
    // and is checked the same way — the material must still be the absorbed key's own.
    it("writes `publicKeyJwk` in the claim, and checks a claim that says `jwk` the same way", () => {
      const live = absorbedChain();
      const { merge, keySuccession } = buildMergeClaim(fold(live));
      expect(merge.keys[0]).toHaveProperty("publicKeyJwk", { ...JWK, x: "x1" });
      expect(merge.keys[0]).not.toHaveProperty("jwk");
      const retired = fold([...live, bEv("ACTOR_RETIRED", { succeededBy: ACTOR, keySuccession }, live.at(-1)!)]);
      const asWritten = (x1: string) => ({
        ...merge,
        keys: merge.keys.map(({ publicKeyJwk, ...k }) => ({ ...k, jwk: k.keyId === K(1) ? { ...JWK, x: x1 } : publicKeyJwk })),
      }) as never;
      const survivor = fold(chain(merged(asWritten("x1"))));
      expect(survivor.keys.find((k) => k.id === K(1))).toHaveProperty("publicKeyJwk", { ...JWK, x: "x1" });
      expect(checkMergeClaim(asWritten("x1"), survivor, retired)).toEqual({ ok: true });
      expect(checkMergeClaim(asWritten("evil"), survivor, retired)).toEqual({ ok: false, reason: "merge_target_invalid" });
    });

    it("checkMergeClaim refuses an actor that is not retired into this one, or of another type", () => {
      const live = absorbedChain();
      const { merge, keySuccession } = buildMergeClaim(fold(live));
      expect(checkMergeClaim(merge, { id: ACTOR, actorType: "agent" }, fold(live))).toMatchObject({ ok: false, reason: "merge_target_invalid" });
      const elsewhere = fold([...live, bEv("ACTOR_RETIRED", { succeededBy: "did:web:humanos.tech:agent:other", keySuccession }, live.at(-1)!)]);
      expect(checkMergeClaim(merge, { id: ACTOR, actorType: "agent" }, elsewhere)).toMatchObject({ ok: false, reason: "merge_target_invalid" });
      const retired = fold([...live, bEv("ACTOR_RETIRED", { succeededBy: ACTOR, keySuccession }, live.at(-1)!)]);
      expect(checkMergeClaim(merge, { id: ACTOR, actorType: "user" }, retired)).toMatchObject({ ok: false, reason: "merge_target_invalid" });
    });
  });
});

describe("§18 ACCREDITED — a registrar's claim, on the actor's own chain", () => {
  const accredited = (over: Record<string, unknown> = {}) =>
    (p: ViaEvent) => ev("ACTOR_ACCREDITED", { accreditation: { level: "verified", method: "kyb-registry", registrar: "humanos", verifiedAt: "2026-07-08T11:00:00.000Z", ...over } }, { prev: p });

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

  // @invariant The record has ONE name for when a claim lapses. A claim signed before 2026-10-07
  // says `expiresAt`; the fold records it as `validUntil` and the instant survives the rename.
  it("records when the claim lapses as `validUntil`, whichever name the event used", () => {
    const now = foldActorChain(orgChain(accredited({ validUntil: "2027-07-08T11:00:00.000Z" })));
    const before = foldActorChain(orgChain(accredited({ expiresAt: "2027-07-08T11:00:00.000Z" })));
    if (!now.ok || !before.ok) throw new Error("fold failed");
    expect(now.subject.accreditation).toMatchObject({ validUntil: "2027-07-08T11:00:00.000Z" });
    expect(before.subject.accreditation).toEqual(now.subject.accreditation);
    expect(before.subject.accreditation).not.toHaveProperty("expiresAt");
    // No lapse stated: none recorded.
    const open = foldActorChain(orgChain(accredited()));
    if (!open.ok) throw new Error("fold failed");
    expect(open.subject.accreditation).not.toHaveProperty("validUntil");
  });

  // @invariant v0.3 §18.2: the registrar is who SIGNED the event — its issuer — never a name the
  // claim states about itself. A claim signed before 2026-10-08 may carry one; it is not read.
  it("records the event's signer as the registrar, whatever the claim names", () => {
    const stated = foldActorChain(orgChain(accredited({ registrar: "some-other-registrar" })));
    const silent = foldActorChain(orgChain((p: ViaEvent) => ev("ACTOR_ACCREDITED", { accreditation: { level: "domain", method: "dns-challenge" } }, { prev: p })));
    if (!stated.ok || !silent.ok) throw new Error("fold failed");
    const signer = orgChain()[0]!.issuer;
    expect(stated.subject.accreditation?.registrar).toBe(signer);
    expect(silent.subject.accreditation?.registrar).toBe(signer);
  });

  // v0.3 §3.1, §3.2: actor status lists are parked in v0.4 (2026-10-11) — a published `status` entry
  // on the claim is read without it, and the record carries none.
  it("does not fold a published `status` entry onto the record", () => {
    const r = foldActorChain(orgChain(accredited({ status: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: "42", statusListCredential: "https://status.humanos.tech/operator/list/1" } })));
    if (!r.ok) throw new Error("fold failed");
    expect(r.subject.accreditation).toBeDefined();
    expect(r.subject.accreditation).not.toHaveProperty("status");
  });

  // v0.3 §18.2: a withdrawal for cause is a bottom-rung claim with a reason; a re-verification replaces it.
  it("records a withdrawal for cause, and a re-verification replaces it", () => {
    const withdraw = (p: ViaEvent) => ev("ACTOR_ACCREDITED", { accreditation: { level: "unverified", withdrawn: { reason: "sanctions" } } }, { prev: p });
    const out = foldActorChain(orgChain(accredited(), withdraw));
    if (!out.ok) throw new Error(out.reason);
    expect(out.subject.accreditation).toMatchObject({ level: "unverified", withdrawn: { reason: "sanctions" } });
    const back = foldActorChain(orgChain(accredited(), withdraw, accredited()));
    if (!back.ok) throw new Error(back.reason);
    expect(back.subject.accreditation?.level).toBe("verified");
    expect(back.subject.accreditation).not.toHaveProperty("withdrawn");
  });

  it("refuses a withdrawal above the bottom rung, or with a reason off the list", () => {
    const above = foldActorChain(orgChain(accredited({ withdrawn: { reason: "fraud" } })));
    const odd = foldActorChain(orgChain((p: ViaEvent) => ev("ACTOR_ACCREDITED", { accreditation: { level: "unverified", withdrawn: { reason: "bored" } } }, { prev: p })));
    expect(above.ok).toBe(false);
    if (!above.ok) expect(above.reason).toBe("accreditation_invalid");
    expect(odd.ok).toBe(false);
    if (!odd.ok) expect(odd.reason).toBe("accreditation_invalid");
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

// ── v0.3 §2.0 / §3.4: one structure for every event, and signed history read as written ──────────

describe("the event's own fields, and events written before 2026-10-11", () => {
  // §2.0: the kind's fields sit directly in credentialSubject.
  it("folds a key event whose fields sit directly in credentialSubject", () => {
    const g = genesis();
    const add = ev("KEY_ADDED", { keyId: "k2", publicKeyJwk: JWK, assurance: "device", binding: "self" }, { prev: g });
    const r = foldActorChain([g, add]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.keys.find((k) => k.id === "k2")).toMatchObject({ publicKeyJwk: JWK, assurance: "device", binding: "self" });
  });

  // §2.0: an event written before 2026-10-11 carries its fields under `agent`, and an `actor`.
  it("folds the same chain written in the old `agent` shape to the same record", () => {
    const flat = (() => {
      const g = genesis();
      return [g, ev("KEY_ADDED", { keyId: "k2", publicKeyJwk: JWK, assurance: "device", binding: "self" }, { prev: g })];
    })();
    const old = (() => {
      const g = evOld("ACTOR_REGISTERED", { keyId: "k1", jwk: JWK, actorType: "agent", assurance: "hardware", binding: "attested", bootstrapAnchor: "api_key", verifiedAt: "2026-09-01T00:00:00.000Z" }, { prev: null });
      return [g, evOld("KEY_ADDED", { keyId: "k2", jwk: JWK, assurance: "device", binding: "self" }, { prev: g })];
    })();
    const a = foldActorChain(flat);
    const b = foldActorChain(old);
    if (!a.ok || !b.ok) throw new Error("fold failed");
    const { chain: _a, ...ra } = a.subject as unknown as Record<string, unknown>;
    const { chain: _b, ...rb } = b.subject as unknown as Record<string, unknown>;
    expect(rb).toEqual(ra);
  });

  // A field the event carries directly wins over the same field under `agent` (§2.0).
  it("reads a field from `agent` only when the event does not carry it directly", () => {
    const g = genesis();
    const mixed = { ...ev("KEY_ADDED", { keyId: "k2", publicKeyJwk: JWK, assurance: "device" }, { prev: g }) } as unknown as ViaEvent;
    (mixed.credentialSubject as Record<string, unknown>).agent = { assurance: "pop", binding: "self" };
    const r = foldActorChain([g, mixed]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.keys.find((k) => k.id === "k2")).toMatchObject({ assurance: "device", binding: "self" });
  });

  // §3.4: the eight old names are read as today's.
  it.each([
    ["SUSPENDED", "suspended"],
    ["RETIRED", "retired"],
  ])("folds a %s written under its old name as the renamed kind", (oldName, status) => {
    const g = genesis();
    const r = foldActorChain([g, evOld(oldName, {}, { prev: g })]);
    expect(r.ok && r.subject.status).toBe(status);
  });

  it("folds an old AFFILIATION and FORK_EVIDENCE as ACTOR_AFFILIATED and FORK_DETECTED", () => {
    const g = genesis();
    const aff = evOld("AFFILIATION", { org: "did:web:acme.example", relation: "operates" }, { prev: g });
    const fork = evOld("FORK_EVIDENCE", { keyId: "k1", evidence: { ref: "https://e" } }, { prev: aff });
    const r = foldActorChain([g, aff, fork]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.operator?.org).toBe("did:web:acme.example");
  });

  // §2.0: ALIAS_ADDED says why it aliases in `aliasReason` — `reason` is the event's general one.
  it("reads an alias's reason from `aliasReason`, beside a general `reason`", () => {
    const g = genesis();
    const alias = ev("ALIAS_ADDED", { alias: "did:web:humanos.tech:user:old", aliasReason: "merge", reason: "consolidation" }, { prev: g });
    const r = foldActorChain([g, alias]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.subject.aliases).toEqual([{ did: "did:web:humanos.tech:user:old", reason: "merge" }]);
  });

  // §2.0 binds the WRITER: an event written before a field became required still folds with the
  // defaults the fold always applied — `existedSince` from the event's `validFrom`, `bootstrapAnchor`
  // `manual` (e.g. an API-key agent registered before 2026-10-11 with no `existedSince`).
  it.each([["the flat shape", ev], ["the old `agent` shape", evOld]])(
    "folds an ACTOR_REGISTERED with neither existedSince nor bootstrapAnchor, in %s, with the defaults",
    (_shape, build) => {
      const g = (build as typeof ev)("ACTOR_REGISTERED", { keyId: "k1", publicKeyJwk: JWK, actorType: "agent" }, { prev: null, at: "2026-09-03T00:00:00.000Z" });
      const r = foldActorChain([g]);
      if (!r.ok) throw new Error(r.reason);
      expect(r.subject).toMatchObject({ existedSince: "2026-09-03T00:00:00.000Z", bootstrapAnchor: "manual" });
    },
  );
});
