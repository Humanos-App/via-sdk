// v0.3 §3–§5 — the VIAActor: the actor-generic artifact + its lifecycle chain.
//
// The actor is the second SUBJECT CLASS of the unified `VIAEvent` (v0.3 §2):
// `credentialSubject.id` is an actor DID instead of a credential URN, the event
// kind is one of the ACTOR TAXONOMY (v0.3 §3.4), and detail rides the §16.9 `agent`
// field. The chain is LIFECYCLE-ONLY — per-action and per-boot facts stay off it.
//
// Model: the snapshot is a SIGNED CACHE of the chain fold ("what is true now");
// the chain is AUTHORITATIVE ("how it got here"). If they disagree, the chain
// wins; the audit primitive is exactly re-fold-and-diff (v0.3 §5).
//
// The fold IS the state machine (v0.3 §4): the transition table below and the fold
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
import type { Assurance, Binding, RuntimeAttestation } from "../agent/types.js";
import { assuranceRank, isAssurance, isBinding } from "../agent/types.js";
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
  /**
   * The key's published form, and there are TWO because v0.2-new §16.2 says so deliberately:
   * Humanos-issued keys (organizations, people) are Ed25519 published as `Multikey` +
   * `publicKeyMultibase`; agent keys are P-256 published as `JsonWebKey` + `publicKeyJwk`. Ed25519
   * has no hardware-attestation ecosystem, which is the whole reason agent keys are P-256.
   *
   * EXACTLY ONE is present, matching how that key is published. Carrying only `jwk` excluded every
   * organization and person from the actor model — found while writing the §3.5 genesis backfill,
   * which had no way to name the key it was binding.
   */
  jwk?: Jwk;
  publicKeyMultibase?: string;
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
  /**
   * The RUNTIME axis (v0.3 §9.4ter) — the latest attestation, NOT a folded value.
   *
   * `assurance` is locked at registration and only moves by an explicit event; runtime is a fact
   * about a process that restarts and redeploys. So the fold keeps the most recent
   * `RUNTIME_ATTESTED` verbatim and lets the verifier decide whether it is fresh enough. Absent
   * evaluates as `none` — no evidence is not a weak claim, it is no claim.
   */
  runtime?: RuntimeAttestation;
  /**
   * Prior identifiers that resolve to this actor (v0.3 §3.6) — a per-channel DID, or a party
   * absorbed by a merge. UNORDERED: the first entry is not "primary", and reading it that way would
   * invent a precedence the protocol does not define.
   */
  /**
   * This actor's own accreditation — the IDENTITY axis (§18), set by `ACCREDITED`.
   *
   * Orthogonal to `assurance`, which grades KEY CONFINEMENT. A KYB-verified company whose key sits
   * in the platform's KMS is `accreditation.level: verified` AND `assurance: pop`: both true,
   * neither implying the other.
   *
   * ORGANIZATIONS and PEOPLE carry this. **An agent never does** — it has no legal identity to
   * verify and inherits its operator's through `operator` + `AFFILIATION` (§18.4). The presence of
   * this field is therefore a fact about what KIND of actor this is.
   */
  accreditation?: {
    level: "unverified" | "domain" | "verified";
    method: string;
    registrar: string;
    verifiedAt: string;
    expiresAt?: string;
    /**
     * Evidence BY REFERENCE, when the accreditation came from outside — an eIDAS attestation, a
     * company registry. A foreign registrar issues in its own format and will not write an event on
     * our chain, so the event points at their credential rather than re-typing it as ours.
     */
    credential?: { id: string; digestSRI?: string; location?: string };
    /** Published revocation entry (O3) — checkable offline, no live registrar call. */
    status?: Record<string, unknown>;
  };
  aliases?: { did: string; reason: "channel" | "merge" }[];
  /**
   * Set by `RETIRED` when this actor was absorbed into another (§3.6c) — the surviving actor's DID.
   * `rotatedTo` at actor scope: the old identifier is a label, not a dead end, and a verifier
   * meeting it MUST follow the pointer rather than treat the party as gone.
   */
  succeededBy?: string;
  /**
   * Where each of this actor's key ids went on the survivor (§3.6c), set by the same `RETIRED` that
   * sets `succeededBy`. Key ids are DID-scoped, so following the actor pointer alone lands a pinned
   * mandate on an actor that has no key of that id — correct and useless.
   *
   * A key with NO entry did not survive the merge. It is deliberately not matched by comparing
   * public key material: absence is a decision, not a gap to fill by inference.
   */
  keySuccession?: Record<string, string>;
  /**
   * When this actor came into existence — the `validFrom` of its `ACTOR_REGISTERED` (§3.5).
   *
   * Distinct from `verifiedAt`, which moves whenever evidence is re-checked. This never moves, and
   * that is why the merge survivor rule (§3.6c) is built on it: a property that cannot change is
   * the only kind that makes the outcome independent of when you look.
   */
  genesisAt?: string;
}

/** The snapshot body: subject + chain binding + supersession (v0.3 §3.1/§5). */
export interface ActorSnapshot {
  /**
   * The spec version this snapshot conforms to (v0.2-new §13).
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
  STEP_UP_APPROVED: "credential",
  STEP_UP_DECLINED: "credential",
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
  ACCREDITED: "actor",
  ALIAS_ADDED: "actor",
  RUNTIME_ATTESTED: "actor",
  SNAPSHOT_ISSUED: "actor",
} as const satisfies Record<EventType, "credential" | "actor">;

export type EventScope = (typeof EVENT_SCOPE)[EventType];

/** The actor-scoped event kinds (v0.3 §3.4) — DERIVED, never a second list. */
/**
 * Read whichever published form the event carries (§3.1, v0.2-new §16.2). Neither is invented: an
 * event that names no key material yields none, and the fold's own validation is what rejects it.
 */
function keyMaterial(detail: Record<string, unknown>): { jwk?: Jwk; publicKeyMultibase?: string } {
  if (typeof detail.publicKeyMultibase === "string") return { publicKeyMultibase: detail.publicKeyMultibase };
  return detail.jwk ? { jwk: detail.jwk as Jwk } : {};
}

/** The four runtime classes (v0.3 §9.4ter). Categorical — deliberately a Set, not an array with
 * an index, so nothing can accidentally derive an order from it. */
export const RUNTIME_CLASSES: ReadonlySet<string> = new Set(["none", "app", "host", "tee"]);

/** §18's identity ladder. Ordinal — `accreditationRank` compares it; `method` beside it is categorical. */
export const ACCREDITATION_LEVELS: ReadonlySet<string> = new Set(["unverified", "domain", "verified"]);
/** Which methods can earn which level (v0.3 §18.2). `unverified` carries no method. */
export const ACCREDITATION_METHODS_BY_LEVEL = {
  unverified: new Set<string>(),
  domain: new Set<string>(["dns-challenge"]),
  verified: new Set<string>(["kyc-doc", "kyb-registry", "eidas-substantial", "eidas-high"]),
} as const;

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
  /** Fold from a verified checkpoint instead of genesis (v0.3 §5 checkpointing). */
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
 * v0.3 §4 transition table is enforced: illegal transitions REJECT the fold.
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
  // A key with NO rung of its own falls back to the actor summary as a whole (v0.3 §9.1bis
  // rule 4). A key that carries a rung carries the whole rung: a key graded `pop` without a root
  // does not inherit a sibling's `aws-nitro` field by field.
  const own = detail.assurance !== undefined || detail.binding !== undefined;
  const assurance = (own ? detail.assurance : fallback.assurance) as Assurance | undefined;
  const binding = (own ? detail.binding : fallback.binding) as Binding | undefined;
  const root = (own ? detail.root : fallback.root) as string | undefined;
  return {
    ...(assurance ? { assurance } : {}),
    ...(binding ? { binding } : {}),
    ...(root ? { root } : {}),
    verifiedAt: (detail.verifiedAt as string) ?? at,
  };
}

/** How confined a binding is. Only the ORDER matters (v0.3 §9.1bis rule 5). */
const BINDING_RANK: Record<Binding, number> = { self: 0, custodial: 1, attested: 2 };

/**
 * The actor summary is DERIVED (v0.3 §9.1bis rule 5): the floor across usable keys — the weakest
 * an attacker can choose. `assurance` the lowest rung, `binding` the weakest by
 * self < custodial < attested, `root` only when every usable key shares one, `verifiedAt` the
 * oldest. Keys with no rung of their own (chains written before per-key rungs) do not vote; when
 * no usable key carries a rung the summary is whatever was asserted, and `null` says so.
 */
export function actorSummaryFloor(
  keys: ActorKeyState[],
): Pick<ViaActorSubject, "assurance" | "binding" | "verifiedAt" | "root"> | null {
  const voting = keys.filter((k) => k.status !== "revoked" && k.assurance && k.binding);
  if (voting.length === 0) return null;
  let assurance = voting[0]!.assurance!;
  let binding = voting[0]!.binding!;
  let verifiedAt = voting[0]!.verifiedAt ?? "";
  for (const k of voting) {
    if (assuranceRank(k.assurance!) < assuranceRank(assurance)) assurance = k.assurance!;
    if (BINDING_RANK[k.binding!] < BINDING_RANK[binding]) binding = k.binding!;
    if (k.verifiedAt && (!verifiedAt || k.verifiedAt < verifiedAt)) verifiedAt = k.verifiedAt;
  }
  const roots = new Set(voting.map((k) => k.root ?? ""));
  const root = roots.size === 1 && voting[0]!.root ? voting[0]!.root : undefined;
  return { assurance, binding, verifiedAt, ...(root ? { root } : {}) };
}

/** Apply the derived floor to the subject; a no-op when no usable key carries a rung. */
function deriveSummary(subject: ViaActorSubject): void {
  const floor = actorSummaryFloor(subject.keys);
  if (!floor) return;
  subject.assurance = floor.assurance;
  subject.binding = floor.binding;
  subject.verifiedAt = floor.verifiedAt;
  if (floor.root) subject.root = floor.root;
  else delete subject.root;
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

    // §16.3 tokens only, checked once for every writer. An unknown rung ranks as NaN and every
    // floor comparison against NaN is false — which is fail-OPEN, so a token typo must not fold.
    if (detail.assurance !== undefined && !isAssurance(detail.assurance)) return fail("invalid_assurance", i);
    if (detail.binding !== undefined && !isBinding(detail.binding)) return fail("invalid_binding", i);

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
            ...keyMaterial(detail),
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
        genesisAt: e.validFrom,
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
    if (subject.status === "retired") return fail("event_after_retired", i); // absorbing (v0.3 §4)

    const key = (id: unknown): ActorKeyState | undefined => subject!.keys.find((k) => k.id === id);

    switch (kind) {
      // content self-loops — legal in `active` AND `suspended` (recording
      // continues while gated; the audit trail never pauses — v0.3 §4)
      case "KEY_ADDED": {
        if (key(detail.keyId)) return fail("duplicate_key", i);
        subject.keys.push({
          id: String(detail.keyId),
          ...keyMaterial(detail),
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
          ...keyMaterial(detail),
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
        // With `keyId` (v0.3 §5 / §9.1bis): re-grade THAT key's own rung and leave the summary
        // alone. This is the per-key downgrade path — a root that becomes distrusted lowers the
        // key graded under it, and authorization reads the key, not the summary.
        if (detail.keyId) {
          const k = key(detail.keyId);
          if (!k) return fail("unknown_key", i);
          if (detail.assurance) k.assurance = detail.assurance as Assurance;
          if (detail.binding) k.binding = detail.binding as Binding;
          if (detail.root) k.root = String(detail.root);
          else delete k.root;
          k.verifiedAt = (detail.verifiedAt as string) ?? e.validFrom;
          deriveSummary(subject); // the floor follows the re-graded key (§9.1bis rule 5)
          break;
        }
        // Without `keyId` (v0.3 §9.1bis rule 6): an AUDIT of the summary, not a second writer. The
        // summary is the floor across usable keys, derived below after every key event; this event
        // exists so a floor MOVE is a signed, visible fact. Its values must be that floor. The anchor
        // is history, who let the actor in (§9.5): naming a different one is refused, not applied.
        if (detail.bootstrapAnchor !== undefined && detail.bootstrapAnchor !== subject.bootstrapAnchor) return fail("anchor_immutable", i);
        const floor = actorSummaryFloor(subject.keys);
        if (floor) {
          if (detail.assurance !== floor.assurance || detail.binding !== floor.binding) return fail("summary_mismatch", i);
          deriveSummary(subject);
          break;
        }
        // No usable key carries a rung (a chain written before per-key rungs): the assertion stands.
        subject.assurance = detail.assurance as Assurance;
        subject.binding = detail.binding as Binding;
        subject.verifiedAt = (detail.verifiedAt as string) ?? e.validFrom;
        if (detail.root) subject.root = String(detail.root);
        else delete subject.root;
        break;
      }
      case "RUNTIME_ATTESTED": {
        // LATEST WINS, and nothing else moves. The runtime axis says where the process runs now;
        // it never touches `assurance` (the key), `status` (the actor) or any key's state. Writing
        // it is a claim about the environment and only that.
        const r = detail.runtime as RuntimeAttestation | undefined;
        if (!r || typeof r.class !== "string") return fail("runtime_attestation_invalid", i);
        if (!RUNTIME_CLASSES.has(r.class)) return fail("runtime_attestation_invalid", i);
        subject.runtime = { ...r, at: r.at ?? e.validFrom };
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
      // ── status transitions (v0.3 §4 table; illegal → reject) ──
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
        // §3.6c — a merge retires the absorbed actor and points it at the survivor. Optional: an
        // ordinary retirement succeeds nobody, and inventing a pointer would claim a party
        // continued somewhere when it simply stopped.
        if (typeof detail.succeededBy === "string" && detail.succeededBy.length > 0) {
          subject.succeededBy = detail.succeededBy;
          const ks = detail.keySuccession;
          if (ks && typeof ks === "object" && !Array.isArray(ks)) {
            const map: Record<string, string> = {};
            for (const [from, to] of Object.entries(ks as Record<string, unknown>)) {
              if (typeof to === "string" && to.length > 0) map[from] = to;
            }
            if (Object.keys(map).length > 0) subject.keySuccession = map;
          }
        }
        break;
      }
      case "ACCREDITED": {
        // §18 — a registrar's claim about THIS actor. Replaces wholesale, like ASSURANCE_UPDATED:
        // an accreditation is a single coherent statement (level earned BY a method FROM a
        // registrar), and merging fields across two of them would invent a claim nobody made.
        const a = detail.accreditation as ViaActorSubject["accreditation"] | undefined;
        if (!a || typeof a.level !== "string" || !ACCREDITATION_LEVELS.has(a.level)) {
          return fail("accreditation_invalid", i);
        }
        // `level` and `method` cohere (v0.3 §18.2): a registrar cannot claim `verified` by DNS.
        const allowed = ACCREDITATION_METHODS_BY_LEVEL[a.level as keyof typeof ACCREDITATION_METHODS_BY_LEVEL];
        if (a.level === "unverified" ? a.method !== undefined : !a.method || !allowed.has(a.method)) {
          return fail("accreditation_invalid", i);
        }
        // An AGENT has no legal identity to verify and inherits its operator's (§18.4). Accepting
        // one here would let an agent hold standing no registrar granted it — the forgery the
        // affiliation conjunction exists to prevent, arriving by a different door.
        if (subject.actorType === "agent") return fail("accreditation_on_agent", i);
        subject.accreditation = { ...a, verifiedAt: a.verifiedAt ?? e.validFrom };
        break;
      }
      case "ALIAS_ADDED": {
        // §3.6b — add the named identifier and NOTHING else: no rung, no key, no status. An alias
        // says two names denote one party; what that party IS stays the fold of its own chain.
        const did = typeof detail.alias === "string" ? detail.alias : undefined;
        const reason = detail.aliasReason === "merge" ? "merge" : "channel";
        if (!did) return fail("alias_invalid", i);
        if (did === subject.id) return fail("alias_invalid", i); // an actor is not its own alias
        subject.aliases ??= [];
        // Idempotent by design: a migration that cannot be safely re-run is one nobody dares
        // finish. A repeat is a no-op, not a duplicate error.
        if (!subject.aliases.some((a) => a.did === did)) subject.aliases.push({ did, reason });
        break;
      }
    }
    // The summary follows the keys (v0.3 §9.1bis rule 5). Derived here, after the event, so a
    // revoked weak key raises the floor and an added weak key lowers it without anyone asserting.
    if (KEY_EVENTS.has(kind)) deriveSummary(subject);
  }

  return subject ? { ok: true, subject } : fail("empty_chain");
}

/** The events after which the summary is re-derived. `ASSURANCE_UPDATED` derives inside its case. */
const KEY_EVENTS: ReadonlySet<string> = new Set(["KEY_ADDED", "KEY_ROTATED", "KEY_REVOKED", "ATTESTATION_RENEWED"]);

// ── Party resolution across a merge (v0.3 §3.6) ─────────────────────────────

/** How restrictive a status is. Only the ORDER matters; the numbers are private to this file. */
const STATUS_SEVERITY: Record<ActorStatus, number> = { active: 0, suspended: 1, retired: 2 };

/**
 * The effective status of a PARTY whose identity spans a merge (§3.6, rules 6-8).
 *
 * A merge does not erase what an actor did under its previous name. If either the survivor or any
 * actor it absorbed is suspended or retired, the party is — **the most restrictive status wins**.
 *
 * WITHOUT THIS, MERGING IS A LAUNDERING PRIMITIVE: get suspended, register again through another
 * channel, have the two recognised as one person, and walk away clean. The survivor's own chain
 * says `active` and would be believed.
 *
 * Restrictions only. Standing does NOT combine here — two weakly-verified parties do not become
 * strongly verified (rule 8), and a grant reaches verifiers through the survivor's snapshot like
 * any other change rather than by a fast path (§6). This function answers "may this party act",
 * never "how well is it vouched for".
 *
 * `absorbed` is the folded subject of every actor the survivor aliases with `reason: "merge"`; the
 * caller loads them, because the fold is pure and does not do I/O.
 */
export function partyStatus(survivor: ViaActorSubject, absorbed: ViaActorSubject[] = []): ActorStatus {
  let worst = survivor.status;
  for (const a of absorbed) {
    if (STATUS_SEVERITY[a.status] > STATUS_SEVERITY[worst]) worst = a.status;
  }
  return worst;
}

/**
 * Resolve a pinned key id across a merge (§3.6c), then through the survivor's own succession (§7).
 *
 * §7 alone is not enough once actors merge. Key ids are DID-scoped, so a mandate pinned to
 * `did:B#key-2` follows `succeededBy` to the surviving actor and finds no key of that id there —
 * the usable set is empty and the verifier fails closed. The mandate dies at the merge, which is
 * §7's own failure mode one level up: succession that lands somewhere correct and useless.
 *
 * So each hop translates the id through the absorbed actor's `keySuccession` before matching. A key
 * with NO entry did not survive, and is deliberately NOT matched by comparing public key material:
 * absence is a decision the merge made, not a gap to fill by inference.
 *
 * Returns the usable keys on the surviving actor, empty when nothing resolves — the caller fails
 * closed on empty, exactly as with {@link resolvePinnedKeys}.
 */
export function resolvePinnedKeysAcrossMerge(
  subject: ViaActorSubject,
  pinnedKeyId: string,
  load: (did: string) => ViaActorSubject | undefined,
): ActorKeyState[] {
  let current = subject;
  let id = pinnedKeyId;
  const seen = new Set<string>([current.id]);

  while (current.succeededBy) {
    const next = current.keySuccession?.[id];
    if (!next) return []; // this key did not survive the merge — do not guess
    const survivor = load(current.succeededBy);
    if (!survivor) return []; // unresolvable successor: fail closed, never treat absorbed as current
    if (seen.has(survivor.id)) return []; // malformed succession must terminate
    seen.add(survivor.id);
    current = survivor;
    id = next;
  }
  return resolvePinnedKeys(current, id);
}

/**
 * Which of two actors for the same party SURVIVES a merge (§3.6c) — the older one.
 *
 * DECIDED 2026-09-05, and the reason is narrower than tidiness: **only age cannot change.** Picking
 * by standing or by activity means the same two identities merge differently depending on when you
 * look, or on which trigger noticed the duplicate — which is the defect the rule exists to remove.
 * The platform's two merge paths currently disagree (the KYC path keeps the party verified first,
 * the contact path keeps the current session's), so the outcome depends on how the duplicate was
 * discovered rather than on anything about the parties.
 *
 * Age also CONVERGES. Merge a third identity later and the oldest still wins, so successions all
 * point at one terminal DID instead of accumulating hops.
 *
 * Ties break on the DID string — arbitrary, but total and auditable, which "earliest wins" alone is
 * not. An actor with no `genesisAt` (a chain folded from a checkpoint that predates the field)
 * sorts as younger: never silently win on missing data.
 */
export function chooseSurvivor(
  a: ViaActorSubject,
  b: ViaActorSubject,
): { survivor: ViaActorSubject; absorbed: ViaActorSubject } {
  const age = (s: ViaActorSubject) => s.genesisAt ?? "\uffff"; // missing sorts last
  const aAge = age(a);
  const bAge = age(b);
  if (aAge !== bAge) return aAge < bAge ? { survivor: a, absorbed: b } : { survivor: b, absorbed: a };
  return a.id <= b.id ? { survivor: a, absorbed: b } : { survivor: b, absorbed: a };
}

/**
 * Follow `succeededBy` from an absorbed actor to the party that survives it (§3.6c).
 *
 * Returns the DID chain walked, ending at the survivor. Terminates on a repeated identifier rather
 * than looping: a malformed succession must fail, not hang. An unresolvable pointer yields
 * `{ ok: false }` so the caller fails closed instead of treating the absorbed actor as current.
 */
export function resolveSuccession(
  start: ViaActorSubject,
  load: (did: string) => ViaActorSubject | undefined,
): { ok: true; path: string[]; survivor: ViaActorSubject } | { ok: false; reason: string; path: string[] } {
  const path: string[] = [start.id];
  const seen = new Set<string>([start.id]);
  let current = start;
  while (current.succeededBy) {
    const next = current.succeededBy;
    if (seen.has(next)) return { ok: false, reason: "succession_cycle", path };
    const loaded = load(next);
    if (!loaded) return { ok: false, reason: "succession_unresolved", path: [...path, next] };
    seen.add(next);
    path.push(next);
    current = loaded;
  }
  return { ok: true, path, survivor: current };
}

// ── D7 key resolution (v0.3 §7) — pin an ID, follow the succession ───────────

/**
 * Resolve a mandate's pinned key id through the actor (v0.3 §7). The walk
 * follows `rotatedTo` succession from the pinned id and returns every key in
 * the succession that is NOT revoked — the set a PoP may verify against.
 * A revoked link does not break the walk (only drops out of the usable set):
 * the v0.3 §3.4 scheduled predecessor-revocation at window end must NOT kill a
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
 * FLAT, and deliberately WITHOUT `keys[]`: pinned-key resolution is v0.3 §7's job (`resolvePinnedKeys`),
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
    // The actor's own DID. §16.1 splits IDENTIFIER from AUTHENTICATOR: the DID is who the agent
    // IS, the key is what proves it — an actor holds several keys over its life and stays the same
    // actor, which is the whole point of the actor axis. Rules could already reach the OPERATOR's
    // DID and the PARENT's DID below while the subject's own was missing, so a policy could speak
    // about an agent's relations and not the agent.
    //
    // It does not weaken pinning and is not an alternative to it: which key signed is settled by
    // A2/A3 against `cnf` before any rule runs, and v0.3 §7 resolves an id-pinned mandate THROUGH
    // this actor. This is policy about identity, layered on a binding already proven.
    did: subject.id,
    // The projection is for the PRESENTING actor whatever its type (v0.3 §9.3): a person with a
    // passkey or an org under its own key lands here too, and this says which.
    actorType: subject.actorType,
    assurance,
    binding,
    bootstrapAnchor: subject.bootstrapAnchor,
    verifiedAt,
    status: subject.status,
    ...(root ? { root } : {}),
    ...(subject.operator ? { operator: { org: subject.operator.org } } : {}),
    ...(subject.lineage ? { lineage: { parent: subject.lineage.parent } } : {}),
    // The RUNTIME axis (v0.3 §9.4ter). CATEGORICAL — a mandate writes `agent.runtime in ["tee"]`,
    // never a rank comparison, and there is no helper that would let it. Absent evidence projects
    // as the literal string "none": a rule must be able to say "I require an attested environment"
    // and have that FAIL for an actor that has never presented one, which an undefined field
    // would not do reliably in CEL.
    runtime: subject.runtime?.class ?? "none",
    // When the class was established, so a mandate can bound freshness itself. Not compared here:
    // a projection that silently expired a claim would hide which rule rejected the request.
    ...(subject.runtime?.at ? { runtimeAt: subject.runtime.at } : {}),
  };
}

export interface ActorAudit {
  ok: boolean;
  /** `fold_failed:<reason>` | `chain_binding_mismatch` | `snapshot_outdated` (older than the fold: every stored value matches, newer derived fields are absent — re-issue) | `snapshot_subject_mismatch` (a stored value disagrees with the chain) */
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
  const fresh = folded.subject as unknown as Record<string, unknown>;
  const stored = snapshot.subject as unknown as Record<string, unknown>;
  if (canonicalizeRFC8785(fresh) === canonicalizeRFC8785(stored)) return { ok: true };
  // The fold learns to derive new fields over time (`genesisAt`, `existedSince`, `runtime`…). A
  // snapshot issued before such a field existed still says nothing FALSE — every value it carries
  // matches — it is merely older than the fold. That is `snapshot_outdated`: re-issue it. A stored
  // value that disagrees with the chain is the lie this audit exists to catch.
  const differing = [...new Set([...Object.keys(fresh), ...Object.keys(stored)])].filter(
    (k) => canonicalizeRFC8785({ v: fresh[k] }) !== canonicalizeRFC8785({ v: stored[k] }),
  );
  const onlyMissing = differing.every((k) => stored[k] === undefined && fresh[k] !== undefined);
  return { ok: false, reason: onlyMissing ? "snapshot_outdated" : "snapshot_subject_mismatch" };
}
