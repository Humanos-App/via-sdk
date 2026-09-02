// v0.3 §3–§5 — the VIAActor: the actor-generic artifact + its lifecycle chain.
//
// The actor is the second SUBJECT CLASS of the unified `VIAEvent` (v0.3 §2):
// `credentialSubject.id` is an actor DID instead of a credential URN, the event
// kind is one of the ACTOR TAXONOMY (§3.4), and detail rides the §16.9 `agent`
// field. The chain is LIFECYCLE-ONLY — per-action and per-boot facts stay off it.
//
// Model: the snapshot is a SIGNED CACHE of the chain fold ("what is true now");
// the chain is AUTHORITATIVE ("how it got here"). If they disagree, the chain
// wins; the audit primitive is exactly re-fold-and-diff (§5).
//
// The fold IS the state machine (§4): the transition table below and the fold
// rules are two views of the same transitions — a fold that accepts an illegal
// transition is a bug. Fail-closed: unknown event kinds and illegal orderings
// REJECT the chain, never repair it.
//
// Build-found refinements vs the v0.3 draft text (fold back into the spec):
//  - KEY_ROTATED marks the predecessor `rotated` — a LABEL, not a kill: rotated
//    keys still verify; only `revoked` blocks. ("MUST NOT touch" = must not
//    disable; the per-key sub-state set {active, rotated, revoked} needs the
//    label to be reachable.)
//  - FORK_EVIDENCE is state-neutral in the fold: the evidence pointer is
//    CHAIN-resident (the event itself), not a subject field — the kill arrives
//    via the KEY_REVOKED / SUSPENDED events it triggers.
//  - DELEGATED on the PARENT chain is state-neutral (it records the grant);
//    the CHILD's lineage pointer is set at its own ACTOR_REGISTERED genesis.
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import { eventChainLink } from "../event/build.js";
import { EVENT_TYPES, type EventType } from "../crypto/proof.js";
import type { ViaEvent, SpecVersion } from "../types.js";
import { VIA_SPEC_VERSION } from "../types.js";
import type { Assurance, Binding } from "../agent/types.js";
import type { Jwk } from "../crypto/p256.js";

// ── Types (v0.3 §3.1 — assurance fields FLAT, §16 tokens verbatim) ───────────

export type ActorType = "agent" | "organization" | "user";
export type ActorStatus = "active" | "suspended" | "retired";
export type ActorKeyStatus = "active" | "rotated" | "revoked";
/**
 * How this actor got in — recorded at genesis, permanent, and part of the KYA picture.
 *
 * It answers a question the assurance rung does not: the rung says how well the KEY is held, this
 * says who let the actor through the door. A `hardware`-rung agent nobody vouched for is a different
 * risk from a `hardware`-rung agent an organization registered under its own API key, and a verifier
 * can tell them apart without asking us.
 *
 * - `api_key` — registered through an organization's API key. The org is accountable, and an
 *   `AFFILIATION` event signed by that org accompanies genesis.
 * - `manual`  — created by a Humanos operator (support, migration, admin). No org vouched for it,
 *   so it carries the weakest provenance and is the fold's default when genesis omits the field.
 *
 * A self-service path for actors with no organization would add a third value here. It is
 * deliberately absent: `"wit"` previously sat in this union with no definition and no writer, which
 * is the same drift that produced `VP_DENIED`. Add the token when the path that emits it exists.
 */
export type BootstrapAnchor = "api_key" | "manual";

/** By-reference pointer to a signed attestation event (v0.3 §9.4 — never inline). */
export interface AttestationRef {
  /** SRI chain-link of the attestation-carrying event. */
  event: string;
  /** §16.5 evidence kind that produced it (e.g. `attestation-eat`, `custody`). */
  kind: string;
}

export interface ActorKeyState {
  /** Key id (`<did>#key-N`) — what a v0.3 mandate pins (D7). */
  id: string;
  /** Public JWK (P-256) — resolved through the actor at verify time. */
  jwk: Jwk;
  status: ActorKeyStatus;
  attestation?: AttestationRef;
  /**
   * THE RUNG THIS KEY EARNED, and the freshness of the evidence behind it.
   *
   * Authorization reads these, not the actor's. An actor holds ONE flat rung but MANY keys, and a
   * mandate pins a key *id* — so reading the actor's rung for a key meant the weakest key inherited
   * the strongest rung, and an attacker who took the software key was evaluated at `hardware`.
   *
   * `verifiedAt` is per-key for the same reason, and it fixes a sharper bug: renewing ONE key used
   * to move the actor's `verifiedAt`, which refreshed the freshness claim for EVERY key. A mandate
   * pinned to a key last attested a year ago passed a 30-day bound because a sibling was renewed
   * yesterday.
   *
   * OPTIONAL for chains written before this existed. Absent means "fall back to the actor summary",
   * which is what those chains meant when they were written.
   */
  assurance?: Assurance;
  binding?: Binding;
  verifiedAt?: string;
  root?: string;
  /**
   * Rotation SUCCESSION pointer (set on the predecessor by KEY_ROTATED). D7
   * resolution follows it: a mandate pinned to `#key-1` stays satisfiable by the
   * rotation successor(s) — rotation-tolerant; only `revoked` kills usability.
   */
  rotatedTo?: string;
}

/** The `credentialSubject` of a VIAActor snapshot (v0.3 §3.1). */
export interface ViaActorSubject {
  /** The actor DID. */
  id: string;
  actorType: ActorType;
  status: ActorStatus;
  keys: ActorKeyState[];
  // the assurance fields — flat, §16's names (v0.3 §3.1 / §9.1)
  assurance: Assurance;
  binding: Binding;
  bootstrapAnchor: BootstrapAnchor;
  verifiedAt: string;
  root?: string;
  /** Pointer to the org-signed AFFILIATION event — never an inline claim. */
  operator?: { org: string; affiliationEvent: string };
  /** Pointer to the parent-signed DELEGATED event — set at genesis (delegated actors). */
  lineage?: { parent: string; event: string };
}

/** The snapshot body: subject + chain binding + supersession (v0.3 §3.1/§5). */
export interface ActorSnapshot {
  /**
   * The spec version this snapshot conforms to (§13).
   *
   * A snapshot is an artifact a verifier consumes and whose digest is chained into the next one
   * via `supersedes`, so it needs the same routing marker every other VIA artifact carries —
   * otherwise a consumer has to infer the shape, which is what the marker exists to prevent.
   */
  specVersion: SpecVersion;
  subject: ViaActorSubject;
  chain: { genesisEvent: string; headEvent: string; sequence: number };
  /** SRI of the prior snapshot, `null` at genesis. */
  supersedes: string | null;
  validFrom: string;
  /** Staleness backstop for routine (bit-less) supersessions (v0.3 §8). */
  validUntil?: string;
}

/**
 * Which subject an event kind is ABOUT — the one place scope is decided.
 *
 * `credential` events carry a credential URN in `credentialSubject.id`; `actor` events carry an
 * actor DID (v0.3 §3.4). The platform reads this to know whether a row is keyed by credential or by
 * actor, and the fold reads it to know what it may consume.
 *
 * `satisfies Record<EventType, …>` is the point of the shape: add a kind to EVENT_TYPES without
 * classifying it here and the build fails. Previously the actor list was a second hand-written
 * literal, so a missed entry surfaced as the fold rejecting a perfectly good chain with
 * `unknown_event_type` — a bug that reads as bad data.
 */
export const EVENT_SCOPE = {
  // credential-scoped — about a mandate
  ISSUE: "credential",
  ACCEPT: "credential",
  REJECT: "credential",
  STAMP: "credential",
  REVOKE: "credential",
  CANCEL: "credential",
  EXPIRE: "credential",
  EXHAUST: "credential",
  VP_CREATED: "credential",
  VERIFICATION_APPROVED: "credential",
  VERIFICATION_DENIED: "credential",
  ACTION_COMPLETED: "credential",
  ACTION_FAILED: "credential",
  AGENT_REGISTERED: "credential",
  REGULATORY: "credential",
  // actor-scoped — about the actor itself
  ACTOR_REGISTERED: "actor",
  KEY_ADDED: "actor",
  KEY_ROTATED: "actor",
  KEY_REVOKED: "actor",
  ATTESTATION_RENEWED: "actor",
  ASSURANCE_UPDATED: "actor",
  FORK_EVIDENCE: "actor",
  AFFILIATION: "actor",
  DELEGATED: "actor",
  SUSPENDED: "actor",
  RESUMED: "actor",
  RETIRED: "actor",
  SNAPSHOT_ISSUED: "actor",
} as const satisfies Record<EventType, "credential" | "actor">;

export type EventScope = (typeof EVENT_SCOPE)[EventType];

/** The actor-scoped event kinds (v0.3 §3.4) — DERIVED, never a second list. */
export const ACTOR_EVENT_TYPES = EVENT_TYPES.filter(
  (t): t is ActorEventType => EVENT_SCOPE[t] === "actor",
);

export type ActorEventType = {
  [K in EventType]: (typeof EVENT_SCOPE)[K] extends "actor" ? K : never;
}[EventType];

export type ActorFoldResult =
  | { ok: true; subject: ViaActorSubject }
  | { ok: false; reason: string; at?: number };

// ── The fold (v0.3 §5) — deterministic, fail-closed ──────────────────────────

interface FoldSeed {
  /** Fold from a verified checkpoint instead of genesis (§5 checkpointing). */
  subject: ViaActorSubject;
  /** The checkpoint's `chain.headEvent` — the first tail event must link to it. */
  headEvent: string;
}

const fail = (reason: string, at?: number): ActorFoldResult => ({ ok: false, reason, at });

/** Event detail rides the §16.9 `agent` field of the actor-scoped VIAEvent. */
const detailOf = (e: ViaEvent): Record<string, unknown> =>
  (e.credentialSubject.agent as Record<string, unknown> | undefined) ?? {};

/**
 * Fold an actor chain into its current subject (v0.3 §5). Chain order is
 * `previousEvent` linkage — timestamps are metadata, never the sort key. The
 * §4 transition table is enforced: illegal transitions REJECT the fold.
 * Signatures are NOT verified here (that is `auditEventChain`'s job); the fold
 * checks linkage + transition semantics, so a full audit = signatures + fold +
 * snapshot diff.
 */
/**
 * The rung to record ON A KEY, from the event that introduced it.
 *
 * Falls back to the actor summary when the event carries none — chains written before per-key rungs
 * existed meant exactly that, and inventing a rung for them would be worse than inheriting one.
 */
function keyRung(
  detail: Record<string, unknown>,
  fallback: { assurance?: unknown; binding?: unknown; root?: unknown },
  at: string,
): Pick<ActorKeyState, "assurance" | "binding" | "verifiedAt" | "root"> {
  const assurance = (detail.assurance ?? fallback.assurance) as Assurance | undefined;
  const binding = (detail.binding ?? fallback.binding) as Binding | undefined;
  const root = (detail.root ?? fallback.root) as string | undefined;
  return {
    ...(assurance ? { assurance } : {}),
    ...(binding ? { binding } : {}),
    ...(root ? { root } : {}),
    verifiedAt: (detail.verifiedAt as string) ?? at,
  };
}

export function foldActorChain(events: ViaEvent[], seed?: FoldSeed): ActorFoldResult {
  if (events.length === 0 && !seed) return fail("empty_chain");

  let subject: ViaActorSubject | null = seed ? structuredClone(seed.subject) : null;
  let prevLink: string | null = seed ? seed.headEvent : null;

  for (let i = 0; i < events.length; i++) {
    const e = events[i]!;
    const cs = e.credentialSubject;
    const kind = cs.event as ActorEventType;
    const detail = detailOf(e);

    // chain-link discipline: genesis previousEvent === null, else link to prior
    if (cs.previousEvent === undefined) return fail("previous_event_missing", i);
    if (cs.previousEvent !== prevLink) return fail("chain_link_broken", i);
    prevLink = eventChainLink(e);

    if (!(ACTOR_EVENT_TYPES as readonly string[]).includes(kind)) return fail("unknown_event_type", i);

    // ── genesis ──
    if (subject === null) {
      if (kind !== "ACTOR_REGISTERED") return fail("genesis_missing", i);
      subject = {
        id: cs.id,
        actorType: (detail.actorType as ActorType) ?? "agent",
        status: "active",
        keys: [
          {
            id: String(detail.keyId),
            jwk: detail.jwk as Jwk,
            status: "active",
            // by-reference pointer to the FOUNDING event itself — computed by the
            // fold (an event cannot carry its own SRI), same pattern as AFFILIATION
            ...(detail.attestationKind
              ? { attestation: { event: prevLink, kind: String(detail.attestationKind) } }
              : {}),
            // Genesis grades the actor and its first key in one act, so they start equal. They
            // diverge the moment a second key is added on different evidence.
            ...keyRung(detail, detail as Record<string, unknown>, e.validFrom),
          },
        ],
        assurance: detail.assurance as Assurance,
        binding: detail.binding as Binding,
        bootstrapAnchor: (detail.bootstrapAnchor as BootstrapAnchor) ?? "manual",
        verifiedAt: (detail.verifiedAt as string) ?? e.validFrom,
        ...(detail.root ? { root: String(detail.root) } : {}),
        ...(detail.lineage ? { lineage: detail.lineage as ViaActorSubject["lineage"] } : {}),
      };
      continue;
    }

    if (cs.id !== subject.id) return fail("subject_mismatch", i);
    if (kind === "ACTOR_REGISTERED") return fail("duplicate_genesis", i);
    if (subject.status === "retired") return fail("event_after_retired", i); // absorbing (§4)

    const key = (id: unknown): ActorKeyState | undefined => subject!.keys.find((k) => k.id === id);

    switch (kind) {
      // content self-loops — legal in `active` AND `suspended` (recording
      // continues while gated; the audit trail never pauses — §4)
      case "KEY_ADDED": {
        if (key(detail.keyId)) return fail("duplicate_key", i);
        subject.keys.push({
          id: String(detail.keyId),
          jwk: detail.jwk as Jwk,
          status: "active",
          ...(detail.attestationKind
            ? { attestation: { event: prevLink, kind: String(detail.attestationKind) } }
            : {}),
          ...keyRung(detail, subject, e.validFrom),
        });
        break;
      }
      case "KEY_ROTATED": {
        // successor active; predecessor gets the `rotated` LABEL (still usable —
        // only KEY_REVOKED disables; see the refinement note in the header)
        const pred = key(detail.predecessorId);
        if (!pred) return fail("unknown_key", i);
        if (pred.status === "revoked") return fail("key_already_revoked", i);
        if (key(detail.keyId)) return fail("duplicate_key", i);
        pred.status = "rotated";
        pred.rotatedTo = String(detail.keyId); // succession pointer — D7 follows it
        subject.keys.push({
          id: String(detail.keyId),
          jwk: detail.jwk as Jwk,
          status: "active",
          ...(detail.attestationKind
            ? { attestation: { event: prevLink, kind: String(detail.attestationKind) } }
            : {}),
          ...keyRung(detail, subject, e.validFrom),
        });
        break;
      }
      case "KEY_REVOKED": {
        const k = key(detail.keyId);
        if (!k) return fail("unknown_key", i);
        if (k.status === "revoked") return fail("key_already_revoked", i);
        k.status = "revoked"; // flips ONLY that key — the actor is unaffected
        break;
      }
      case "ATTESTATION_RENEWED": {
        const k = key(detail.keyId);
        if (!k) return fail("unknown_key", i);
        // pointer to THIS renewal event — computed by the fold (self-link pattern)
        k.attestation = { event: prevLink, kind: String(detail.attestationKind ?? "attestation-eat") };
        const at = (detail.verifiedAt as string) ?? e.validFrom;
        // PER-KEY, and that is the whole point. This used to move only `subject.verifiedAt`, so
        // renewing one key refreshed the freshness claim for EVERY key — a mandate pinned to a key
        // last attested a year ago passed a 30-day bound because a sibling was renewed yesterday.
        k.verifiedAt = at;
        if (detail.assurance) k.assurance = detail.assurance as Assurance;
        if (detail.binding) k.binding = detail.binding as Binding;
        // The actor summary still moves: it answers "when was this actor last verified at all",
        // which a renewal genuinely advances. Authorization reads the KEY.
        subject.verifiedAt = at;
        break;
      }
      case "ASSURANCE_UPDATED": {
        // replaces the assurance FIELDS wholesale — exactly these five (§5)
        subject.assurance = detail.assurance as Assurance;
        subject.binding = detail.binding as Binding;
        subject.bootstrapAnchor = detail.bootstrapAnchor as BootstrapAnchor;
        subject.verifiedAt = (detail.verifiedAt as string) ?? e.validFrom;
        if (detail.root) subject.root = String(detail.root);
        else delete subject.root;
        break;
      }
      case "FORK_EVIDENCE":
      case "DELEGATED":
      case "SNAPSHOT_ISSUED":
        // state-neutral: evidence/grant/audit events POINT (they live on the
        // chain); any state change arrives via the events they trigger
        break;
      case "AFFILIATION": {
        // set the operator POINTER to this org-signed event — never inline
        subject.operator = { org: String(detail.org ?? e.issuer), affiliationEvent: eventChainLink(e) };
        break;
      }
      // ── status transitions (§4 table; illegal → reject) ──
      case "SUSPENDED": {
        if (subject.status !== "active") return fail("illegal_transition", i);
        subject.status = "suspended"; // preserves everything else
        break;
      }
      case "RESUMED": {
        if (subject.status !== "suspended") return fail("illegal_transition", i);
        subject.status = "active"; // pure un-flip
        break;
      }
      case "RETIRED": {
        subject.status = "retired"; // from active OR suspended; terminal
        break;
      }
    }
  }

  return subject ? { ok: true, subject } : fail("empty_chain");
}

// ── D7 key resolution (v0.3 §7) — pin an ID, follow the succession ───────────

/**
 * Resolve a mandate's pinned key id through the actor (v0.3 §7). The walk
 * follows `rotatedTo` succession from the pinned id and returns every key in
 * the succession that is NOT revoked — the set a PoP may verify against.
 * A revoked link does not break the walk (only drops out of the usable set):
 * the §3.4 scheduled predecessor-revocation at window end must NOT kill a
 * rotated-forward mandate, or rotation tolerance would be defeated.
 * Empty result ⇒ nothing usable ⇒ the verifier fails closed.
 */
export function resolvePinnedKeys(subject: ViaActorSubject, pinnedKeyId: string): ActorKeyState[] {
  const usable: ActorKeyState[] = [];
  const seen = new Set<string>();
  let id: string | undefined = pinnedKeyId;
  while (id && !seen.has(id)) {
    seen.add(id);
    const k = subject.keys.find((x) => x.id === id);
    if (!k) break;
    if (k.status !== "revoked") usable.push(k);
    id = k.rotatedTo;
  }
  return usable;
}

// ── Snapshots (v0.3 §5) — signed cache + supersession linkage ────────────────

/** SRI of the canonicalized snapshot — the value `supersedes` links to. */
export function snapshotDigest(snapshot: ActorSnapshot): string {
  return computeSRI(canonicalizeRFC8785(snapshot as unknown as Record<string, unknown>));
}

export type SnapshotResult =
  | { ok: true; snapshot: ActorSnapshot }
  | { ok: false; reason: string };

/**
 * Fold the chain and bind the result into a snapshot: `chain.{genesisEvent,
 * headEvent, sequence}` + `supersedes` (SRI of the prior snapshot, null at
 * genesis). Higher `sequence` is an AUDIT tie-break — a stateless verifier
 * never compares it (v0.3 §8); freshness rides the snapshot revocation bit
 * and `validUntil`.
 */
export function issueSnapshot(
  events: ViaEvent[],
  opts: { previous?: ActorSnapshot | null; validFrom?: string; validUntil?: string } = {},
): SnapshotResult {
  const folded = foldActorChain(events);
  if (!folded.ok) return { ok: false, reason: folded.reason };
  const previous = opts.previous ?? null;
  return {
    ok: true,
    snapshot: {
      specVersion: VIA_SPEC_VERSION as SpecVersion,
      subject: folded.subject,
      chain: {
        genesisEvent: eventChainLink(events[0]!),
        headEvent: eventChainLink(events[events.length - 1]!),
        sequence: previous ? previous.chain.sequence + 1 : 1,
      },
      supersedes: previous ? snapshotDigest(previous) : null,
      validFrom: opts.validFrom ?? new Date().toISOString(),
      ...(opts.validUntil ? { validUntil: opts.validUntil } : {}),
    },
  };
}

/**
 * Project a folded actor into the CEL `agent.*` namespace (v0.3 §9 / KYA A.3).
 *
 * There is no `actor.*` namespace: the artifact is actor-generic, projections are role-specific.
 * §16 ships `agent.assurance` / `agent.binding`; this extends the same namespace with the fields
 * v0.3 added, so a rule can say `agent.status == "active"` or `agent.bootstrapAnchor != "api_key"`.
 *
 * FLAT, and deliberately WITHOUT `keys[]`: pinned-key resolution is §7's job (`resolvePinnedKeys`),
 * not a rule's. A rule that could reach into keys would be writing its own D7, badly.
 *
 * `operator` and `lineage` project PRESENCE plus the DID, never the event — a rule may ask "is this
 * agent affiliated, and to whom", never "what did the affiliation say". Reading the claim is the
 * verifier's job, through the pointer.
 *
 * FRESHNESS. This is what makes `agent.verifiedAt >= now - duration("720h")` evaluable, which is
 * how v0.3 bounds attestation age. With a `presentingKey` the bound applies to THAT key, so
 * renewing one key does not refresh a sibling's claim. §16's `maxAttestationStaleness` bounds a raw-pinned BoundKey's
 * re-attest window; on the actor path the rung is resolved THROUGH the actor, so the bound belongs
 * to the mandate that cares — per-mandate rather than global, and curable by `ATTESTATION_RENEWED`
 * or `ASSURANCE_UPDATED` moving `verifiedAt` forward.
 */
export function projectAgentContext(
  subject: ViaActorSubject,
  /**
   * The key actually presenting — the one whose PoP the verifier just checked.
   *
   * SUPPLY IT WHENEVER AUTHORIZING. `agent.assurance` then means the rung of the key doing the
   * signing, which is the only rung that answers "what did an attacker have to defeat to produce
   * this request". Omit it only for reporting, where the actor summary is the honest answer to a
   * different question ("what is this agent, overall").
   *
   * A key with no rung of its own falls back to the summary — chains written before per-key rungs
   * existed meant exactly that.
   */
  presentingKey?: Pick<ActorKeyState, "assurance" | "binding" | "verifiedAt" | "root">,
): Record<string, unknown> {
  const assurance = presentingKey?.assurance ?? subject.assurance;
  const binding = presentingKey?.binding ?? subject.binding;
  const verifiedAt = presentingKey?.verifiedAt ?? subject.verifiedAt;
  const root = presentingKey?.root ?? subject.root;
  return {
    assurance,
    binding,
    bootstrapAnchor: subject.bootstrapAnchor,
    verifiedAt,
    status: subject.status,
    ...(root ? { root } : {}),
    ...(subject.operator ? { operator: { org: subject.operator.org } } : {}),
    ...(subject.lineage ? { lineage: { parent: subject.lineage.parent } } : {}),
  };
}

export interface ActorAudit {
  ok: boolean;
  /** `fold_failed:<reason>` | `chain_binding_mismatch` | `subject_mismatch` */
  reason?: string;
}

/**
 * The audit primitive (v0.3 §5): RE-FOLD AND DIFF. A snapshot binds a PREFIX of
 * the chain — `chain[0..headEvent]` — so events appended after it (including the
 * `SNAPSHOT_ISSUED` that audits it) SUPERSEDE the snapshot without invalidating
 * it. Valid iff the bound head exists in the chain and
 * `fold(chain[0..headEvent]) == credentialSubject`. The chain is authoritative —
 * on any disagreement the snapshot is the invalid artifact.
 */
export function auditActorSnapshot(snapshot: ActorSnapshot, events: ViaEvent[]): ActorAudit {
  if (events.length === 0 || snapshot.chain.genesisEvent !== eventChainLink(events[0]!)) {
    return { ok: false, reason: "chain_binding_mismatch" };
  }
  const head = events.findIndex((e) => eventChainLink(e) === snapshot.chain.headEvent);
  if (head < 0) return { ok: false, reason: "chain_binding_mismatch" };
  const folded = foldActorChain(events.slice(0, head + 1));
  if (!folded.ok) return { ok: false, reason: `fold_failed:${folded.reason}` };
  const same =
    canonicalizeRFC8785(folded.subject as unknown as Record<string, unknown>) ===
    canonicalizeRFC8785(snapshot.subject as unknown as Record<string, unknown>);
  return same ? { ok: true } : { ok: false, reason: "subject_mismatch" };
}
