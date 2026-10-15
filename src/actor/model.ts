// v0.3 §3–§5 — the VIAActor: the actor-generic artifact + its lifecycle chain.
//
// The actor is the second SUBJECT CLASS of the unified `VIAEvent` (v0.3 §2):
// `credentialSubject.id` is an actor DID instead of a credential URN, the event
// kind is one of the ACTOR TAXONOMY (v0.3 §3.4), and detail rides the §16.9 `agent`
// field. The chain is LIFECYCLE-ONLY — per-action and per-boot facts stay off it.
//
// Model: the VIAActor RECORD is the chain fold ("what is true now") plus the chain
// position it was folded to; the chain is AUTHORITATIVE ("how it got here"). A stored
// record is a cache: if it and the chain disagree, the chain wins; the audit primitive
// is exactly re-fold-and-diff (v0.3 §5). A SIGNED copy of the record is not v0.3 — it
// is parked in v0.4 (sdk-v04).
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
//  - DELEGATED is reserved and state-neutral: delegation (and the child's
//    `lineage`) is parked in v0.4 §8 (2026-10-11); a v0.3 fold accepts a chain
//    that carries it and changes nothing.
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { eventChainLink } from "../event/build.js";
import { EVENT_TYPES, canonicalEventType, type EventType } from "../crypto/proof.js";
import type { ViaEvent } from "../types.js";
import type { Assurance, Binding, RuntimeAttestation } from "../agent/types.js";
import { BINDINGS, assuranceRank, isAssurance, isBinding } from "../agent/types.js";
import type { Jwk } from "../crypto/p256.js";
import { claimValidUntil, WITHDRAWAL_REASONS, type AccreditationRevocationReason } from "../operator/types.js";

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
export type BootstrapAnchor = "api_key" | "person" | "manual";

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
   * The key's published form, and there are TWO because §16.2 says so deliberately:
   * Humanos-issued keys (organizations, people) are Ed25519 published as `Multikey` +
   * `publicKeyMultibase`; agent keys are P-256 published as `JsonWebKey` + `publicKeyJwk`. Ed25519
   * has no hardware-attestation ecosystem, which is the whole reason agent keys are P-256.
   *
   * EXACTLY ONE is present, matching how that key is published. Carrying only a JWK excluded every
   * organization and person from the actor model — found while writing the §3.5 genesis backfill,
   * which had no way to name the key it was binding.
   *
   * One name for the JWK, `publicKeyJwk`, in the record, the DID document and new events (v0.3 §3.1,
   * 2026-10-11). Events signed before then carry it as `jwk`; the fold reads either.
   */
  publicKeyJwk?: Jwk;
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
  /**
   * The runtime attested for THIS key's process (v0.3 §9.4ter) — the latest `RUNTIME_ATTESTED`
   * naming the key. Absent is `none`: an attestation is over the process holding one key, so a
   * sibling never inherits it.
   */
  runtime?: RuntimeAttestation;
}

/** An actor's folded state — the VIAActor record's fields (v0.3 §3.1), less its `chain` position. */
export interface ViaActorSubject {
  /** The actor DID. */
  id: string;
  actorType: ActorType;
  status: ActorStatus;
  keys: ActorKeyState[];
  // the assurance fields — flat, §16's names (v0.3 §3.1 / §9.1). `assurance`, `binding`,
  // `verifiedAt` and `root` are the SUMMARY: the floor across usable keys (§9.1bis rule 5), absent
  // when no usable key carries a rung — an actor whose keys are all revoked has no rung, not its last.
  assurance?: Assurance;
  binding?: Binding;
  bootstrapAnchor: BootstrapAnchor;
  verifiedAt?: string;
  root?: string;
  /**
   * Pointer to the org-signed AFFILIATION event — never an inline claim. `relation` and `validUntil`
   * restate that event's own claim for readers of the record (v0.3 §3.1): `validUntil` is when the
   * affiliation lapses, absent when the event states none. Nothing is recorded when it passes, so the
   * pointer stays; a verifier compares the date with the time of the verification (§18.5 O2).
   */
  operator?: { org: string; relation?: string; validUntil?: string; affiliationEvent: string };
  /**
   * WHY this actor exists, when a PERSON is what let it through the door (v0.3 §3.1, §16.14).
   *
   * Present with `bootstrapAnchor: "person"`. `actor` is the person's DID — the ADDRESS they
   * authenticated at, not the party (§3.6), which is how `grantor` already behaves. `method` is
   * graded honestly: `session` is a browser session and the weakest of the three, and `event`
   * points at the signed fact behind the method only when one exists (a passkey's `KEY_ADDED`) —
   * its ABSENCE is the grading, not an omission.
   *
   * GENESIS ONLY. Writing it later would be a claim about the past, which is the one thing a chain
   * must not let anyone do. And no rule reads it: policy compares the anchor TOKEN (§9.2); this is
   * provenance for a person reading the record.
   */
  anchoredBy?: {
    actor: string;
    method: "passkey" | "otp" | "session";
    event?: string;
    host?: string;
    /** When the person authorized — an instant something happened, like `verifiedAt`; not a `validFrom`. */
    at: string;
  };
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
    /** How it was verified. Absent on `unverified`, which carries no method (v0.3 §18.2). */
    method?: string;
    /** Who made the claim: the DID that signed the `ACCREDITED` event (v0.3 §18.2). */
    registrar: string;
    verifiedAt: string;
    /** When the claim lapses (v0.3 §18.2). The record says `validUntil` whatever the event said. */
    validUntil?: string;
    /**
     * Evidence BY REFERENCE, when the accreditation came from outside — an eIDAS attestation, a
     * company registry. A foreign registrar issues in its own format and will not write an event on
     * our chain, so the event points at their credential rather than re-typing it as ours.
     */
    credential?: { id: string; digestSRI?: string; location?: string };
    // No `status`: a published revocation entry is parked in v0.4 §9.3 with the actors' status
    // lists (2026-10-11). A claim that carries one is read without it.
    /**
     * Withdrawn for cause (v0.3 §18.2) — struck off, fraud, sanctions. `level` is then `unverified`,
     * and O3 denies every mandate that reads `accreditation.*` with this reason, even one whose floor
     * is `unverified`, which a plain downgrade would pass.
     */
    withdrawn?: { reason: AccreditationRevocationReason };
  };
  /**
   * Prior identifiers that resolve to this actor (v0.3 §3.6). `merge` — an actor retired INTO this
   * one (its chain ends pointing here); `inherited` — an alias such an actor held, which came with
   * it; `channel` — a contact identifier that never had a chain of its own.
   */
  aliases?: { did: string; reason: "channel" | "merge" | "inherited" }[];
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
   * When the PARTY came to exist on the platform — an organization's creation, a contact's (v0.3
   * §3.1, §3.5). The `existedSince` its `ACTOR_REGISTERED` carries as content, or that event's own
   * `validFrom` when it states none, so it is always present on a registered actor. Equal to when the
   * chain began for a natively registered actor; earlier for a backfilled one, which today is
   * nearly every organization and person.
   *
   * The merge survivor rule ranks on it alone (§3.6c): a backfill registers everyone on the day it
   * runs, so the date a chain began would make a 2024 party younger than one that signed up last
   * month. It never moves — distinct from `verifiedAt`, which does — and a property that cannot
   * change is the only kind that makes the outcome independent of when you look. (Until 2026-10-11
   * the record also carried `genesisAt`, used only as this field's fallback; the fallback is now the
   * fold's.)
   */
  existedSince?: string;
}

/** Where on its chain a record was folded to (v0.3 §3.1 `chain`). */
export interface ActorChainPosition {
  /** The chain-link of the first event — the genesis. */
  genesisEvent: string;
  /** The chain-link of the LAST event folded. */
  headEvent: string;
  /** How many events were folded: the head's position, counting the genesis as 1. */
  sequence: number;
}

/**
 * The VIAActor record (v0.3 §3.1): the fold's state, and the chain position it is the fold of.
 * Unsigned — what makes it checkable is the chain it names (`auditActorRecord`).
 */
export type ViaActorRecord = ViaActorSubject & { chain: ActorChainPosition };

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
  ACTOR_REGULATED: "actor", // §3.4: a regulator's claim about THIS actor — reserved, parked in v0.4 §10
  // actor-scoped — about the actor itself
  ACTOR_REGISTERED: "actor",
  KEY_ADDED: "actor",
  KEY_ROTATED: "actor",
  KEY_REVOKED: "actor",
  ATTESTATION_RENEWED: "actor",
  ASSURANCE_UPDATED: "actor",
  FORK_DETECTED: "actor",
  ACTOR_AFFILIATED: "actor",
  DELEGATED: "actor",
  ACTOR_SUSPENDED: "actor",
  ACTOR_RESUMED: "actor",
  ACTOR_RETIRED: "actor",
  ACTOR_ACCREDITED: "actor",
  ALIAS_ADDED: "actor",
  ACTOR_MERGED: "actor",
  RUNTIME_ATTESTED: "actor",
  SNAPSHOT_ISSUED: "actor",
} as const satisfies Record<EventType, "credential" | "actor">;

export type EventScope = (typeof EVENT_SCOPE)[EventType];

/** The actor-scoped event kinds (v0.3 §3.4) — DERIVED, never a second list. */
/**
 * Read whichever published form the event carries (§3.1, §16.2). Neither is invented: an
 * event that names no key material yields none, and the fold's own validation is what rejects it.
 *
 * A JWK is `publicKeyJwk` in an event written from 2026-10-11 and `jwk` in one signed before
 * (v0.3 §3.1): signed history is read as written, never renamed, and the record says `publicKeyJwk`.
 */
function keyMaterial(detail: Record<string, unknown>): { publicKeyJwk?: Jwk; publicKeyMultibase?: string } {
  if (typeof detail.publicKeyMultibase === "string") return { publicKeyMultibase: detail.publicKeyMultibase };
  const jwk = eventJwk(detail);
  return jwk ? { publicKeyJwk: jwk } : {};
}

/** An event's JWK under either name — `publicKeyJwk` (2026-10-11 on) or `jwk` (signed before). */
function eventJwk(detail: Record<string, unknown>): Jwk | undefined {
  const jwk = detail.publicKeyJwk ?? detail.jwk;
  return jwk && typeof jwk === "object" ? (jwk as Jwk) : undefined;
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

/** The core fields of every event (v0.3 §2.0) — never part of a kind's own fields. */
const CORE_FIELDS: ReadonlySet<string> = new Set(["id", "event", "previousEvent", "credentialDigest", "actor", "agent"]);

/**
 * An event's own fields (v0.3 §2.0): directly in `credentialSubject`, falling back to the `agent`
 * wrapper actor events used before 2026-10-11 (and every `"0.2"` actor event) for a field the event
 * does not carry directly. Read as written: nothing is renamed, nothing invented.
 */
const detailOf = (e: ViaEvent): Record<string, unknown> => {
  const cs = e.credentialSubject as Record<string, unknown>;
  const own = Object.fromEntries(Object.entries(cs).filter(([k]) => !CORE_FIELDS.has(k)));
  return { ...((cs.agent as Record<string, unknown> | undefined) ?? {}), ...own };
};

/**
 * Fold an actor chain into its current subject (v0.3 §5). Chain order is
 * `previousEvent` linkage — timestamps are metadata, never the sort key. The
 * v0.3 §4 transition table is enforced: illegal transitions REJECT the fold.
 * Signatures are NOT verified here (that is `auditEventChain`'s job); the fold
 * checks linkage + transition semantics, so a full audit = signatures + fold +
 * record diff (`auditActorRecord`).
 */
/**
 * The rung to record ON A KEY, from the event that introduced it (v0.3 §9.1bis rule 4).
 *
 * A key that carries a rung carries the whole rung: a key graded `pop` without a root does not
 * inherit a sibling's `aws-nitro` field by field. A key with NO rung of its own — an older writer
 * graded only the actor — is `pop`/`self` with no root: possession is all that was proven when it
 * entered the chain. It never copies the actor's grade, which would let a key added with no evidence
 * count as the hardware key beside it.
 */
function keyRung(
  detail: Record<string, unknown>,
  at: string,
): Pick<ActorKeyState, "assurance" | "binding" | "verifiedAt" | "root"> {
  const own = detail.assurance !== undefined || detail.binding !== undefined;
  if (!own) return { assurance: "pop", binding: "self", verifiedAt: (detail.verifiedAt as string) ?? at };
  return {
    ...(detail.assurance ? { assurance: detail.assurance as Assurance } : {}),
    ...(detail.binding ? { binding: detail.binding as Binding } : {}),
    ...(detail.root ? { root: detail.root as string } : {}),
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

/**
 * The version of what the fold DERIVES. Bump it whenever the fold starts producing a field, or a
 * value, it did not before (2 = `existedSince` folded, `operator.relation` carried; 3 = no rung on an
 * actor with no usable key carrying one, instead of its last; 4 = a second rotation of one key
 * refused, `key_already_rotated`; 5 = runtime per key, the actor's a shared-class summary; 6 = a
 * rungless key is pop/self, and a later AFFILIATION only from the current operator; 7 = a renewal
 * states the key's whole rung, root included, and a keyed regrade never raises, `regrade_raises`;
 * 8 = `MERGED` folded — a merge's aliases and carried keys in one event; 9 = an accreditation's
 * `expiresAt` is recorded as `validUntil`; 10 = the aliases an absorbed actor held join the
 * survivor as `inherited`, not `channel`; 11 = an accreditation's `registrar` is the event's signer,
 * whatever the claim stated; 12 = an agent key's JWK is `publicKeyJwk` in the record, read from
 * `publicKeyJwk` or `jwk`, an affiliation's lapse is recorded as `operator.validUntil`, the record
 * has one age — `existedSince`, the genesis's `validFrom` when it states none — and no `genesisAt`,
 * `lineage` is no longer folded: delegation is parked in v0.4, and neither is an accreditation's
 * published `status`: actor status lists are parked in v0.4; an accreditation withdrawn for cause
 * carries `withdrawn`; 13 = a renewal or a keyed regrade naming a revoked key is refused,
 * `key_already_revoked`, and a regrade measures a field the key does not state at the bottom —
 * `pop`, `self` — so it cannot give a key half a rung no evidence earned; 14 = an AFFILIATION on a
 * person's chain folds nothing: a person's affiliation is parked in v0.4).
 *
 * A stored record (a checkpoint) is only as current as the fold that wrote it. Seeding a fold from
 * one written by an older version would silently omit whatever the newer fold adds, so a
 * checkpointed read MUST seed only from a record written by this version and replay the whole
 * chain otherwise.
 */
export const ACTOR_FOLD_VERSION = 14;

/**
 * §5 — a keyed `ASSURANCE_UPDATED` lowers or keeps every rung field; it never raises one or names a new root.
 * A field the key does not state is measured at the bottom — `pop`, `self` (§9.1bis rule 4: possession
 * is all that was proven) — so a regrade cannot hand a key a rung no evidence earned.
 */
function regradeLowers(k: ActorKeyState, detail: Record<string, unknown>): boolean {
  if (detail.assurance !== undefined && assuranceRank(detail.assurance as Assurance) > assuranceRank(k.assurance ?? "pop")) return false;
  if (detail.binding !== undefined && BINDINGS.indexOf(detail.binding as Binding) > BINDINGS.indexOf(k.binding ?? "self")) return false;
  if (detail.root && String(detail.root) !== k.root) return false;
  return true;
}

/**
 * The actor's runtime SUMMARY (v0.3 §3.1) — for reporting, never authorization: the class every
 * usable key shares, dated by the oldest of their attestations; absent when they do not share one or
 * any usable key has none. Categorical, like `root`: no class is ranked above another here.
 */
function deriveRuntimeSummary(subject: ViaActorSubject): void {
  const usable = subject.keys.filter((k) => k.status !== "revoked");
  const classes = new Set(usable.map((k) => k.runtime?.class ?? "none"));
  const [only] = [...classes];
  if (usable.length === 0 || classes.size !== 1 || only === "none") {
    delete subject.runtime;
    return;
  }
  const at = usable.map((k) => k.runtime!.at).sort()[0]!;
  subject.runtime = { class: only as RuntimeAttestation["class"], at };
}

/** Apply the derived floor to the subject; with no usable key carrying a rung, the subject has none. */
function deriveSummary(subject: ViaActorSubject): void {
  const floor = actorSummaryFloor(subject.keys);
  if (!floor) {
    // §9.1bis rule 5: no usable key carries a rung, so the actor has none. Keeping the last value
    // would report a grade no signed fact supports any more — the key that earned it was revoked.
    delete subject.assurance;
    delete subject.binding;
    delete subject.verifiedAt;
    delete subject.root;
    return;
  }
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
    // Old names are read as today's (v0.3 §3.4): an event signed before the rename is read as written.
    const kind = canonicalEventType(cs.event) as ActorEventType;
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
      // No silent default: an organization or person genesis without its type would otherwise fold
      // as an AGENT and be held to an agent's rules. Every writer states it.
      if (typeof detail.actorType !== "string") return fail("genesis_actor_type_missing", i);
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
            ...keyRung(detail, e.validFrom),
          },
        ],
        // §3.1: the party's age — what the genesis states (§3.5), else when the genesis was signed.
        existedSince: typeof detail.existedSince === "string" ? detail.existedSince : e.validFrom,
        assurance: detail.assurance as Assurance,
        binding: detail.binding as Binding,
        bootstrapAnchor: (detail.bootstrapAnchor as BootstrapAnchor) ?? "manual",
        verifiedAt: (detail.verifiedAt as string) ?? e.validFrom,
        ...(detail.root ? { root: String(detail.root) } : {}),
        ...(detail.anchoredBy ? { anchoredBy: detail.anchoredBy as ViaActorSubject["anchoredBy"] } : {}),
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
          ...keyRung(detail, e.validFrom),
        });
        break;
      }
      case "KEY_ROTATED": {
        // successor active; predecessor gets the `rotated` LABEL (still usable —
        // only KEY_REVOKED disables; see the refinement note in the header)
        const pred = key(detail.predecessorId);
        if (!pred) return fail("unknown_key", i);
        if (pred.status === "revoked") return fail("key_already_revoked", i);
        // §5: a key is rotated once — overwriting `rotatedTo` would strand the first successor.
        if (pred.rotatedTo) return fail("key_already_rotated", i);
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
          ...keyRung(detail, e.validFrom),
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
        // §5: revocation is terminal per key — a revoked key is never graded again.
        if (k.status === "revoked") return fail("key_already_revoked", i);
        // pointer to THIS renewal event — computed by the fold (self-link pattern). The kind is what the
        // renewal presented; one that names none presented no quote, and must not claim one.
        k.attestation = { event: prevLink, kind: String(detail.attestationKind ?? "none") };
        const at = (detail.verifiedAt as string) ?? e.validFrom;
        // PER-KEY, and that is the whole point. This used to move only `subject.verifiedAt`, so
        // renewing one key refreshed the freshness claim for EVERY key — a mandate pinned to a key
        // last attested a year ago passed a 30-day bound because a sibling was renewed yesterday.
        k.verifiedAt = at;
        // A renewal RE-GRADES the key from the evidence it just presented (§9.1bis rule 2), which the
        // writer MUST have checked proves THIS key (§5.2). It states the whole rung: a root it does not
        // name is gone — weaker evidence must not keep the anchor the stronger one earned.
        if (detail.assurance) k.assurance = detail.assurance as Assurance;
        if (detail.binding) k.binding = detail.binding as Binding;
        if (detail.assurance || detail.binding) {
          if (detail.root) k.root = String(detail.root);
          else delete k.root;
          deriveSummary(subject);
        }
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
          if (k.status === "revoked") return fail("key_already_revoked", i);
          // DOWN only, on every field (§5): a rung is earned by evidence, and this event carries
          // none. Lower or equal assurance and binding; the root kept or dropped, never named anew.
          if (!regradeLowers(k, detail)) return fail("regrade_raises", i);
          if (detail.assurance) k.assurance = detail.assurance as Assurance;
          if (detail.binding) k.binding = detail.binding as Binding;
          if (detail.root) k.root = String(detail.root);
          else delete k.root;
          k.verifiedAt = (detail.verifiedAt as string) ?? e.validFrom;
          deriveSummary(subject); // the floor follows the re-graded key (§9.1bis rule 5)
          break;
        }
        // Without `keyId` (v0.3 §9.1bis rule 6): a writer no longer emits it — the summary is derived
        // from the keys, and a signed restatement of that derivation proves nothing. Chains written
        // before carry it, and it is still checked: its values must be the floor (`summary_mismatch`),
        // and the anchor is history, who let the actor in (§9.5) — naming another is refused. It
        // changes nothing: with no usable key carrying a rung there is no floor, and no rung to set.
        if (detail.bootstrapAnchor !== undefined && detail.bootstrapAnchor !== subject.bootstrapAnchor) return fail("anchor_immutable", i);
        const floor = actorSummaryFloor(subject.keys);
        if (floor && (detail.assurance !== floor.assurance || detail.binding !== floor.binding)) return fail("summary_mismatch", i);
        deriveSummary(subject);
        break;
      }
      case "RUNTIME_ATTESTED": {
        // LATEST WINS, and nothing else moves. The runtime axis says where the process runs now;
        // it never touches `assurance` (the key), `status` (the actor) or any key's state. Writing
        // it is a claim about the environment and only that.
        // §9.4ter: the runtime axis describes an AGENT's key-holding process. An organization or a
        // person has none to attest — the mirror of `accreditation_on_agent`.
        if (subject.actorType !== "agent") return fail("runtime_on_non_agent", i);
        const r = detail.runtime as RuntimeAttestation | undefined;
        if (!r || typeof r.class !== "string") return fail("runtime_attestation_invalid", i);
        if (!RUNTIME_CLASSES.has(r.class)) return fail("runtime_attestation_invalid", i);
        // §5: the key it names; with no `keyId` (written before keys carried a runtime) the genesis
        // key — §9.4ter (d) requires the attestation to be over the registering key.
        const attested = detail.keyId ? key(detail.keyId) : subject.keys[0];
        if (!attested) return fail("unknown_key", i);
        if (attested.status === "revoked") return fail("key_already_revoked", i);
        attested.runtime = { ...r, at: r.at ?? e.validFrom };
        deriveRuntimeSummary(subject);
        break;
      }
      case "FORK_DETECTED":
      case "SNAPSHOT_ISSUED":
      case "ACTOR_REGULATED":
        // state-neutral: evidence/audit events POINT (they live on the
        // chain); any state change arrives via the events they trigger
        break;
      case "DELEGATED":
        // reserved; delegation is parked in v0.4 §8 — accepted, nothing folded
        break;
      case "ACTOR_AFFILIATED": {
        // §3.4: on a person's (`user`) chain it is reserved — a person's affiliation is parked in
        // v0.4 §12 — and folds nothing. An `operator` here would make §18.5 project the org's
        // accreditation as the person's own.
        if (subject.actorType === "user") break;
        // set the operator POINTER to this org-signed event — never inline. §18 names the claim's
        // field, `credentialSubject.operator`; events written before that was honoured carry it in
        // `agent`, and signed history is read as it was written.
        const op = (cs.operator ?? {}) as { org?: unknown; relation?: unknown };
        const org = op.org ?? detail.org ?? e.issuer;
        const relation = op.relation ?? detail.relation;
        // §18.4: the lapse, `validUntil` (`expiresAt` on an affiliation signed before 2026-10-07).
        const validUntil = claimValidUntil((cs.operator ?? detail) as { validUntil?: unknown; expiresAt?: unknown });
        // §5: once the actor has an operator, only that operator writes a later AFFILIATION — to renew
        // or change the relation. Naming, or being signed by, another organization re-points nothing.
        if (subject.operator && (String(org) !== subject.operator.org || e.issuer !== subject.operator.org)) {
          return fail("affiliation_invalid", i);
        }
        subject.operator = {
          org: String(org),
          ...(typeof relation === "string" ? { relation } : {}),
          ...(validUntil ? { validUntil } : {}),
          affiliationEvent: eventChainLink(e),
        };
        break;
      }
      // ── status transitions (v0.3 §4 table; illegal → reject) ──
      case "ACTOR_SUSPENDED": {
        if (subject.status !== "active") return fail("illegal_transition", i);
        subject.status = "suspended"; // preserves everything else
        break;
      }
      case "ACTOR_RESUMED": {
        if (subject.status !== "suspended") return fail("illegal_transition", i);
        subject.status = "active"; // pure un-flip
        break;
      }
      case "ACTOR_RETIRED": {
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
      case "ACTOR_ACCREDITED": {
        // §18 — a registrar's claim about THIS actor. Replaces wholesale, like ASSURANCE_UPDATED:
        // an accreditation is a single coherent statement (level earned BY a method FROM a
        // registrar), and merging fields across two of them would invent a claim nobody made.
        // The claim's own field, `credentialSubject.accreditation`; `agent` for events written before.
        const a = (cs.accreditation ?? detail.accreditation) as ViaActorSubject["accreditation"] | undefined;
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
        // One name on the record: a claim signed before 2026-10-07 says `expiresAt`, and is read as
        // `validUntil` (v0.3 §18.2). The event is not touched; only the fold's output is normalized.
        // The registrar is who SIGNED the event — its issuer (v0.3 §18.2) — never a name the claim
        // states about itself: a claim signed before 2026-10-08 may carry one, and it is not read.
        // A withdrawal for cause (v0.3 §18.2) is a bottom-rung claim whose reason is from a fixed list.
        const w = (a as { withdrawn?: { reason?: unknown } }).withdrawn;
        if (w !== undefined && (a.level !== "unverified" || typeof w !== "object" || w === null || typeof w.reason !== "string" || !WITHDRAWAL_REASONS.has(w.reason))) {
          return fail("accreditation_invalid", i);
        }
        // A published `status` entry is not folded: actor status lists are parked in v0.4 (2026-10-11).
        const { expiresAt: _legacy, validUntil: _stated, registrar: _named, status: _published, withdrawn: _w, ...claim } = a as typeof a & { expiresAt?: string; status?: unknown };
        const until = claimValidUntil(a);
        subject.accreditation = {
          ...claim,
          registrar: e.issuer,
          verifiedAt: a.verifiedAt ?? e.validFrom,
          ...(until ? { validUntil: until } : {}),
          ...(w ? { withdrawn: { reason: w.reason as AccreditationRevocationReason } } : {}),
        };
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
      case "ACTOR_MERGED": {
        // §3.6c — the survivor's half of a merge, as ONE fact: the absorbed actor's identifier
        // (`merge`), its own aliases (`channel`), and the keys of it that survive, each with its own
        // state. The absorbed chain is not replayed: what the survivor holds is stated here, on its
        // own chain, so anyone folding it sees the keys a mandate may be pinned to. A carried key is
        // NOT a `KEY_ADDED` — nothing was enrolled or re-verified; its rung, status and succession
        // are the absorbed actor's, unchanged. Accreditation does not transfer (§3.6 rule 10).
        const claim = parseMergeClaim(cs.merge);
        if (!claim || claim.absorbed === subject.id || claim.aliases.includes(subject.id)) {
          return fail("merge_invalid", i);
        }
        const carriedIds = new Set(claim.keys.map((k) => k.keyId));
        if (carriedIds.size !== claim.keys.length) return fail("duplicate_key", i);
        for (const k of claim.keys) {
          if (key(k.keyId)) return fail("duplicate_key", i);
          if (k.assurance !== undefined && !isAssurance(k.assurance)) return fail("invalid_assurance", i);
          if (k.binding !== undefined && !isBinding(k.binding)) return fail("invalid_binding", i);
          // A rotated key carries its succession only onto a key carried with it: one the survivor
          // would have to find elsewhere is a pointer into nothing.
          if (k.rotatedTo !== undefined && (k.status !== "rotated" || !carriedIds.has(k.rotatedTo) || k.rotatedTo === k.keyId)) {
            return fail("merge_invalid", i);
          }
          if (k.runtime !== undefined) {
            if (subject.actorType !== "agent") return fail("runtime_on_non_agent", i);
            if (!RUNTIME_CLASSES.has(String(k.runtime.class))) return fail("runtime_attestation_invalid", i);
          }
        }
        subject.aliases ??= [];
        // `merge` is checkable — the absorbed chain ends pointing here. What the absorbed actor
        // answered to came WITH it, and points at it, not here: `inherited` says exactly that.
        const named: [string, "merge" | "inherited"][] = [
          [claim.absorbed, "merge"],
          ...claim.aliases.map((a): [string, "inherited"] => [a, "inherited"]),
        ];
        // The alias set is a set: a name the survivor already answers to is left as it is.
        for (const [did, reason] of named) {
          if (!subject.aliases.some((a) => a.did === did)) subject.aliases.push({ did, reason });
        }
        for (const k of claim.keys) {
          const fields = k as unknown as Record<string, unknown>;
          subject.keys.push({
            id: k.keyId,
            ...keyMaterial(fields),
            status: k.status,
            ...(k.rotatedTo ? { rotatedTo: k.rotatedTo } : {}),
            ...(k.attestation ? { attestation: k.attestation } : {}),
            ...(k.runtime ? { runtime: k.runtime } : {}),
            ...keyRung(fields, e.validFrom),
          });
        }
        break;
      }
    }
    // The summary follows the keys (v0.3 §9.1bis rule 5). Derived here, after the event, so a
    // revoked weak key raises the floor and an added weak key lowers it without anyone asserting.
    if (KEY_EVENTS.has(kind)) {
      deriveSummary(subject);
      deriveRuntimeSummary(subject);
    }
  }

  return subject ? { ok: true, subject } : fail("empty_chain");
}

/** The events after which the summary is re-derived. `ASSURANCE_UPDATED` derives inside its case. */
const KEY_EVENTS: ReadonlySet<string> = new Set(["KEY_ADDED", "KEY_ROTATED", "KEY_REVOKED", "ATTESTATION_RENEWED", "ACTOR_MERGED"]);

// ── The merge claim (v0.3 §3.6c) — what `MERGED` carries ─────────────────────

/** One key of the absorbed actor as `MERGED` carries it onto the survivor — its state, unchanged. */
export interface MergedKey {
  /** The id the key has on the SURVIVOR — the value of its `keySuccession` entry. */
  keyId: string;
  /** Written as `publicKeyJwk`; a claim signed before 2026-10-11 may say `jwk`, and is read as written. */
  publicKeyJwk?: Jwk;
  publicKeyMultibase?: string;
  /** `active` or `rotated`: a revoked key does not survive a merge and is never carried. */
  status: "active" | "rotated";
  /** Present only on a `rotated` key whose successor is carried by the same event. */
  rotatedTo?: string;
  attestation?: AttestationRef;
  assurance?: Assurance;
  binding?: Binding;
  root?: string;
  verifiedAt?: string;
  runtime?: RuntimeAttestation;
}

/** `credentialSubject.merge` of a `MERGED` event (v0.3 §3.6c). */
export interface MergeClaim {
  /** The actor retired into this one — recorded as an alias with reason `merge`. */
  absorbed: string;
  /** The absorbed actor's own aliases — recorded with reason `inherited`. */
  aliases: string[];
  /** The absorbed actor's keys that survive. */
  keys: MergedKey[];
}

/** Read a `merge` claim off an event; null when it is not one (the fold then fails `merge_invalid`). */
function parseMergeClaim(raw: unknown): MergeClaim | null {
  const m = (raw ?? {}) as { absorbed?: unknown; aliases?: unknown; keys?: unknown };
  if (typeof m.absorbed !== "string" || !m.absorbed) return null;
  const aliases = m.aliases === undefined ? [] : m.aliases;
  const keys = m.keys === undefined ? [] : m.keys;
  if (!Array.isArray(aliases) || aliases.some((a) => typeof a !== "string" || !a)) return null;
  if (!Array.isArray(keys)) return null;
  for (const k of keys as Record<string, unknown>[]) {
    if (!k || typeof k !== "object" || typeof k.keyId !== "string" || !k.keyId) return null;
    // §3.6c rule 2: a revoked key does not survive a merge — it is left out, never carried dead.
    if (k.status !== "active" && k.status !== "rotated") return null;
    if (k.rotatedTo !== undefined && typeof k.rotatedTo !== "string") return null;
    if (typeof k.publicKeyMultibase !== "string" && !eventJwk(k)) return null;
    const att = k.attestation as { event?: unknown; kind?: unknown } | undefined;
    if (att !== undefined && (typeof att !== "object" || att === null || typeof att.event !== "string" || typeof att.kind !== "string")) return null;
    if (k.runtime !== undefined && (typeof k.runtime !== "object" || k.runtime === null)) return null;
  }
  return { absorbed: m.absorbed, aliases: aliases as string[], keys: keys as MergedKey[] };
}

/**
 * Build both halves of a merge from the ABSORBED actor's state (v0.3 §3.6c): the `merge` claim the
 * survivor's `MERGED` carries, and the `keySuccession` the absorbed actor's `RETIRED` carries.
 *
 * Every key that is not revoked survives, with the state it has — a `rotated` key stays rotated and
 * keeps its succession when its successor survives too. Nothing is re-graded and nothing is
 * invented: the claim is the absorbed actor's own keys. A key keeps the id its own DID gave it
 * (v0.3 §3.6c, 2026-10-11 — never renumbered under the survivor's DID), so `keySuccession` maps each
 * surviving key to itself. A reader still translates through it, so a chain that renumbered reads.
 *
 * `held` names key ids the survivor already has: they are mapped in `keySuccession` and left out of
 * the claim, because the fold refuses a key id it already holds (`duplicate_key`).
 */
export function buildMergeClaim(
  absorbed: ViaActorSubject,
  opts: { held?: ReadonlySet<string> } = {},
): { merge: MergeClaim; keySuccession: Record<string, string> } {
  const keySuccession: Record<string, string> = {};
  for (const k of absorbed.keys) if (k.status !== "revoked") keySuccession[k.id] = k.id;
  const carried = absorbed.keys.filter((k) => k.status !== "revoked" && !opts.held?.has(keySuccession[k.id]!));
  const carriedIds = new Set(carried.map((k) => keySuccession[k.id]!));
  const keys = carried.map((k): MergedKey => {
    const successor = k.rotatedTo ? keySuccession[k.rotatedTo] : undefined;
    return {
      keyId: keySuccession[k.id]!,
      ...(k.publicKeyMultibase ? { publicKeyMultibase: k.publicKeyMultibase } : {}),
      ...(k.publicKeyJwk ? { publicKeyJwk: k.publicKeyJwk } : {}),
      status: k.status as "active" | "rotated",
      // A successor that was revoked (or is already the survivor's) is not carried: the pointer ends.
      ...(k.status === "rotated" && successor && carriedIds.has(successor) ? { rotatedTo: successor } : {}),
      ...(k.attestation ? { attestation: k.attestation } : {}),
      ...(k.assurance ? { assurance: k.assurance } : {}),
      ...(k.binding ? { binding: k.binding } : {}),
      ...(k.root ? { root: k.root } : {}),
      ...(k.verifiedAt ? { verifiedAt: k.verifiedAt } : {}),
      ...(k.runtime ? { runtime: k.runtime } : {}),
    };
  });
  return {
    merge: { absorbed: absorbed.id, aliases: (absorbed.aliases ?? []).map((a) => a.did), keys },
    keySuccession,
  };
}

/**
 * The cross-chain check of a `MERGED` (v0.3 §5.2) — does the claim state only what the absorbed
 * actor's own chain holds? A fold sees one chain, so it cannot answer this; the appender, and any
 * auditor holding both chains, can.
 *
 * `MERGED` puts keys on an actor with no evidence of its own, so it must not be a way to add one:
 * every key it carries MUST be the target of a `keySuccession` entry of the absorbed actor, whose
 * source key is not revoked and matches in material, status and rung; every alias MUST be one of
 * the absorbed actor's; and the absorbed actor MUST be retired INTO this one, of the same type.
 */
export function checkMergeClaim(
  claim: unknown,
  survivor: Pick<ViaActorSubject, "id" | "actorType">,
  absorbed: ViaActorSubject,
): { ok: true } | { ok: false; reason: "merge_invalid" | "merge_target_invalid" } {
  const m = parseMergeClaim(claim);
  if (!m) return { ok: false, reason: "merge_invalid" };
  const bad = { ok: false, reason: "merge_target_invalid" } as const;
  if (m.absorbed !== absorbed.id || absorbed.status !== "retired" || absorbed.succeededBy !== survivor.id) return bad;
  if (absorbed.actorType !== survivor.actorType) return bad;
  const known = new Set((absorbed.aliases ?? []).map((a) => a.did));
  if (m.aliases.some((a) => !known.has(a))) return bad;
  const sourceOf = new Map(Object.entries(absorbed.keySuccession ?? {}).map(([from, to]) => [to, from]));
  const same = (a: unknown, b: unknown) => canonicalizeRFC8785(a ?? null) === canonicalizeRFC8785(b ?? null);
  const carried = new Set(m.keys.map((k) => k.keyId));
  for (const k of m.keys) {
    const source = absorbed.keys.find((x) => x.id === sourceOf.get(k.keyId));
    if (!source || source.status === "revoked" || source.status !== k.status) return bad;
    // The claim's JWK under either name (a claim signed before 2026-10-11 says `jwk`, §3.1).
    if (!same(source.publicKeyJwk, eventJwk(k as unknown as Record<string, unknown>)) || source.publicKeyMultibase !== k.publicKeyMultibase) return bad;
    if (source.assurance !== k.assurance || source.binding !== k.binding || source.root !== k.root) return bad;
    if (source.verifiedAt !== k.verifiedAt || !same(source.runtime, k.runtime) || !same(source.attestation, k.attestation)) return bad;
    // The succession it carries is the source's own, translated — never a new one, and never
    // dropped while the successor is carried too (a pin on the rotated key would stop at it).
    const successor = source.rotatedTo ? absorbed.keySuccession?.[source.rotatedTo] : undefined;
    if (k.rotatedTo !== (successor && carried.has(successor) ? successor : undefined)) return bad;
  }
  return { ok: true };
}

// ── Party resolution across a merge (v0.3 §3.6) ─────────────────────────────

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
 * not. An actor with no `existedSince` (a record computed before the fold always set it) sorts as
 * younger: never silently win on missing data.
 */
export function chooseSurvivor(
  a: ViaActorSubject,
  b: ViaActorSubject,
): { survivor: ViaActorSubject; absorbed: ViaActorSubject } {
  // §3.6c: the party's age (`existedSince`); missing sorts last.
  const age = (s: ViaActorSubject) => s.existedSince ?? "\uffff";
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

// ── The record (v0.3 §3.1 / §5) — the fold, bound to the chain it is the fold of ──

export type ActorRecordResult = { ok: true; record: ViaActorRecord } | { ok: false; reason: string; at?: number };

/**
 * Fold a WHOLE chain (genesis first) into its record: the folded state plus the chain position —
 * the genesis and head links, and how many events were folded. Unsigned: v0.3 issues no signed
 * copy of a record (that is v0.4's).
 */
export function foldActorRecord(events: ViaEvent[]): ActorRecordResult {
  const folded = foldActorChain(events);
  if (!folded.ok) return folded;
  return {
    ok: true,
    record: {
      ...folded.subject,
      chain: {
        genesisEvent: eventChainLink(events[0]!),
        headEvent: eventChainLink(events[events.length - 1]!),
        sequence: events.length,
      },
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
 * `operator` projects PRESENCE plus the DID, never the event — a rule may ask "is this
 * agent affiliated, and to whom", never "what did the affiliation say". Reading the claim is the
 * verifier's job, through the pointer.
 *
 * FRESHNESS. `verifiedAt` is projected for the record, not for a rule to compare with the clock:
 * the CEL context has no `now`, and a rule that names it errors and denies (v0.3 §16.8). Attestation
 * age is bounded only by the mandate entry's `maxAttestationStaleness`, enforced as A8 (§16.4, §16.7)
 * against THIS key's `verifiedAt` when a `presentingKey` is given — so renewing one key does not
 * refresh a sibling's claim — and curable by `ATTESTATION_RENEWED` moving it forward.
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
   * A supplied key never borrows the summary (§9.1bis rule 4): one with no rung of its own is
   * `pop` / `self`. The fold already writes that rung; the default here covers a caller's own key.
   */
  presentingKey?: Pick<ActorKeyState, "assurance" | "binding" | "verifiedAt" | "root" | "runtime">,
): Record<string, unknown> {
  const assurance = presentingKey ? (presentingKey.assurance ?? "pop") : subject.assurance;
  const binding = presentingKey ? (presentingKey.binding ?? "self") : subject.binding;
  const verifiedAt = presentingKey ? presentingKey.verifiedAt : subject.verifiedAt;
  const root = presentingKey ? presentingKey.root : subject.root;
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
    // The RUNTIME axis (v0.3 §9.4ter). CATEGORICAL — a mandate writes `agent.runtime in ["tee"]`,
    // never a rank comparison, and there is no helper that would let it. Absent evidence projects
    // as the literal string "none": a rule must be able to say "I require an attested environment"
    // and have that FAIL for an actor that has never presented one, which an undefined field
    // would not do reliably in CEL.
    // KEY-SCOPED when authorizing (§9.3): the presenting key's own runtime, with NO fallback — a
    // key no attestation names is `none`, whatever its siblings run in. Without a presenting key
    // (reporting) the actor's summary.
    runtime: (presentingKey ? presentingKey.runtime : subject.runtime)?.class ?? "none",
    // When the class was established, so a mandate can bound freshness itself. Not compared here:
    // a projection that silently expired a claim would hide which rule rejected the request.
    ...((presentingKey ? presentingKey.runtime : subject.runtime)?.at
      ? { runtimeAt: (presentingKey ? presentingKey.runtime : subject.runtime)!.at }
      : {}),
  };
}

export interface ActorAudit {
  ok: boolean;
  /** `fold_failed:<reason>` | `chain_binding_mismatch` (the record's `chain` is not a position on this chain) | `record_outdated` (older than the fold: every stored value matches, newer derived fields are absent — recompute) | `record_mismatch` (a stored value disagrees with the chain) */
  reason?: string;
}

/**
 * The audit primitive (v0.3 §5): RE-FOLD AND DIFF. A record names a PREFIX of the chain —
 * `chain[0..headEvent]` — so events appended after it make it stale without making it wrong.
 * Correct iff the named genesis and head are on the chain, `sequence` is the head's position, and
 * `fold(chain[0..headEvent]) == record`. The chain is authoritative — on any disagreement the
 * record is what is wrong.
 */
export function auditActorRecord(record: ViaActorRecord, events: ViaEvent[]): ActorAudit {
  const { chain, ...stored } = record;
  if (events.length === 0 || chain.genesisEvent !== eventChainLink(events[0]!)) {
    return { ok: false, reason: "chain_binding_mismatch" };
  }
  const head = events.findIndex((e) => eventChainLink(e) === chain.headEvent);
  if (head < 0 || chain.sequence !== head + 1) return { ok: false, reason: "chain_binding_mismatch" };
  const folded = foldActorChain(events.slice(0, head + 1));
  if (!folded.ok) return { ok: false, reason: `fold_failed:${folded.reason}` };
  const fresh = folded.subject as unknown as Record<string, unknown>;
  const kept = stored as unknown as Record<string, unknown>;
  if (canonicalizeRFC8785(fresh) === canonicalizeRFC8785(kept)) return { ok: true };
  // The fold learns to derive new fields over time (`existedSince`, `runtime`…). A
  // record computed before such a field existed still says nothing FALSE — every value it carries
  // matches — it is merely older than the fold. That is `record_outdated`: recompute it. A stored
  // value that disagrees with the chain is the lie this audit exists to catch.
  const differing = [...new Set([...Object.keys(fresh), ...Object.keys(kept)])].filter(
    (k) => canonicalizeRFC8785({ v: fresh[k] }) !== canonicalizeRFC8785({ v: kept[k] }),
  );
  const onlyMissing = differing.every((k) => kept[k] === undefined && fresh[k] !== undefined);
  return { ok: false, reason: onlyMissing ? "record_outdated" : "record_mismatch" };
}
