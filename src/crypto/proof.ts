import { canonicalizeRFC8785 } from "./canonicalize.js";
import { sha256 } from "./digest.js";
import { signMultibase, verifyMultibase } from "./ed25519.js";

export type ProofPurpose = "assertionMethod" | "authentication";

/**
 * The unified VIA event taxonomy (spec §0.5.4). Every signed fact is a `VIAEvent`
 * whose kind is one of these. The embedded securing `STAMP` proof carries its
 * kind in the proof's `event` field; standalone events carry it in
 * `credentialSubject.event`.
 */
/**
 * The unified VIAEvent taxonomy — the **single source of truth**, declared as a runtime value so
 * both the type ({@link EventType}) and the runtime map ({@link EventTypeEnum}) derive from it. A
 * change here can't drift a hand-maintained mirror, because there is none.
 *
 * v0.3 extends the v0.2 set with the actor-scoped lifecycle (v0.3 §3.4), key management and the
 * two-phase execution outcomes; `EXPIRE`/`EXHAUST` came the other way, from v0.2 §19.
 */
export const EVENT_TYPES = [
  "ISSUE",
  "ACCEPT",
  "REJECT",
  "STAMP",
  "REVOKE",
  // Terminal by the mandate's own signed limits; actor = platform (observer, not authority).
  // EXPIRE: `validUntil` passed. EXHAUST (§19 Bounded-Use): the last `maxExecutions` use was spent —
  // a distinct type, not EXPIRE (whose claim the still-future signed `validUntil` would contradict
  // for an early exhaustion) and not REVOKE (which asserts "withdrawn" about a mandate used exactly
  // as agreed).
  "EXPIRE",
  "EXHAUST",
  "CANCEL",
  "VP_CREATED",
  "VERIFICATION_APPROVED",
  "VERIFICATION_DENIED",
  "AGENT_REGISTERED",
  // §18 operator verification — an org's signed link to an agent/operator
  // (`relation: operates|vouches`) and a regulator's licence attestation.
  "AFFILIATION",
  "REGULATORY",
  // v0.3 §2.1 two-phase outcomes — the execution result after a
  // VERIFICATION_APPROVED decision (agent-attested, gateway-signed).
  // CREDENTIAL-scoped: they name a credential URN, never an actor DID.
  "ACTION_COMPLETED",
  "ACTION_FAILED",
  // v0.3 §17.4 — the grantor's fresh co-sign of ONE call (or their refusal): a consent act like
  // ACCEPT/REJECT, credential-scoped, the grantor as actor. What a VERIFICATION_APPROVED that
  // rested on a step-up references (§9.9).
  "STEP_UP_APPROVED",
  "STEP_UP_DECLINED",
  // v0.3 §3.4 — the ACTOR-SCOPED lifecycle taxonomy (subject = the actor DID,
  // not a credential URN). Lifecycle-only: per-action and per-boot facts stay
  // off the actor chain (v0.3 §2/§9.5).
  "ACTOR_REGISTERED", // genesis; subsumes AGENT_REGISTERED (kept above as deprecated alias)
  "KEY_ADDED",
  "KEY_ROTATED",
  "KEY_REVOKED",
  "ATTESTATION_RENEWED",
  "ASSURANCE_UPDATED",
  "FORK_EVIDENCE", // clone detection — evidence points, the triggered kill events mutate
  "SUSPENDED",
  "RESUMED",
  "RETIRED",
  // v0.3 §9.4ter — the RUNTIME axis. Written when the key-holding process's environment CLASS
  // changes, not per session: per-boot volume stays off the actor chain (§9.5), and freshness is
  // proven at presentation like the PoP, not by writing an event per boot.
  // v0.3 §3.6 — a prior identifier that resolves to this actor: a per-channel DID, or a party
  // absorbed by a merge. State-neutral apart from the alias set.
  // v0.3 §18 — a registrar's accreditation of THIS actor (KYB for an organization, KYC for a
  // person). An agent never carries one: it INHERITS its operator's, via AFFILIATION.
  "ACCREDITED",
  "ALIAS_ADDED",
  // v0.3 §3.6 — the survivor's half of a merge, in ONE event: the absorbed identifier, its aliases,
  // and its live keys with their own state. Replaces `ALIAS_ADDED (merge)` + a `KEY_ADDED` per key.
  "MERGED",
  "RUNTIME_ATTESTED",
  "SNAPSHOT_ISSUED",
  "DELEGATED",
] as const;

export type EventType = (typeof EVENT_TYPES)[number];

/**
 * Runtime map of {@link EVENT_TYPES} for consumers that need a **value**, not a type — Swagger's
 * `enum:` and class-validator's `@IsEnum`.
 */
export const EventTypeEnum = Object.fromEntries(EVENT_TYPES.map((t) => [t, t])) as unknown as {
  readonly [K in EventType]: K;
};

/** The same name at type position resolves to the event union — so `EventTypeEnum` works as both a
 * value (`EventTypeEnum.STAMP`, `enum: EventTypeEnum`) and a type (`(e: EventTypeEnum) => …`). */
export type EventTypeEnum = EventType;

/**
 * @deprecated Use {@link EventType}. Legacy authorization-subset alias kept for one
 * migration window; the v0.1 `CANCELED_STAMP` is retired (see spec §0.5.4).
 */
export type LifecycleAction = "ISSUE" | "ACCEPT" | "REJECT" | "REVOKE" | "STAMP" | "CANCELED_STAMP";

/**
 * A W3C Data Integrity proof using the **real** `eddsa-jcs-2022` cryptosuite
 * (spec §0.5.2). For the mandate's securing `STAMP`, `event` names the securing
 * event and is carried inside `proofConfig`, so it is covered by the signature.
 * (`lifecycleAction` is the deprecated predecessor of `event`, kept for one
 * migration window; the legacy `actionProof` side-hash is not needed — N21.)
 */
export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: "eddsa-jcs-2022";
  proofPurpose: ProofPurpose;
  verificationMethod: string;
  created: string;
  /** The securing event kind (spec §0.5.4) — used by the mandate's `STAMP` proof. */
  event?: EventType;
  /** @deprecated Use {@link DataIntegrityProof.event}. */
  lifecycleAction?: LifecycleAction;
  domain?: string;
  challenge?: string;
  proofValue: string;
}

export interface CreateProofParams {
  /** The document to secure (any existing `proof` is ignored for hashing). */
  document: Record<string, unknown>;
  /** Raw 32-byte Ed25519 private key (the platform decrypts it from KMS). */
  privateKey: Uint8Array;
  verificationMethod: string;
  proofPurpose: ProofPurpose;
  created?: string;
  /** The securing event kind (spec §0.5.4) — committed inside `proofConfig`. */
  event?: EventType;
  /** @deprecated Use {@link CreateProofParams.event}. */
  lifecycleAction?: LifecycleAction;
  domain?: string;
  challenge?: string;
}

type ProofOptions = Omit<DataIntegrityProof, "proofValue">;

function buildProofOptions(p: CreateProofParams): ProofOptions {
  return {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: p.created ?? new Date().toISOString(),
    verificationMethod: p.verificationMethod,
    proofPurpose: p.proofPurpose,
    ...(p.event ? { event: p.event } : {}),
    ...(p.lifecycleAction ? { lifecycleAction: p.lifecycleAction } : {}),
    ...(p.domain ? { domain: p.domain } : {}),
    ...(p.challenge ? { challenge: p.challenge } : {}),
  };
}

function documentWithoutProof(document: Record<string, unknown>): Record<string, unknown> {
  const { proof: _p, ...rest } = document;
  return rest;
}

/** hashData = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document-without-proof)). */
function hashData(proofConfig: Record<string, unknown>, doc: Record<string, unknown>): Uint8Array {
  const a = sha256(canonicalizeRFC8785(proofConfig));
  const b = sha256(canonicalizeRFC8785(doc));
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function proofConfigOf(options: ProofOptions, document: Record<string, unknown>): Record<string, unknown> {
  const ctx = document["@context"];
  return ctx === undefined ? { ...options } : { "@context": ctx, ...options };
}

/** Create a Data Integrity proof over `document` (real `eddsa-jcs-2022`). */
export function createDataIntegrityProof(params: CreateProofParams): DataIntegrityProof {
  const options = buildProofOptions(params);
  const proofConfig = proofConfigOf(options, params.document);
  const data = hashData(proofConfig, documentWithoutProof(params.document));
  return { ...options, proofValue: signMultibase(data, params.privateKey) };
}

/** Verify a single Data Integrity proof against `document` and a raw public key. */
export function verifyDataIntegrityProof(
  document: Record<string, unknown>,
  proof: DataIntegrityProof,
  publicKey: Uint8Array,
): boolean {
  if (proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "eddsa-jcs-2022") return false;
  const { proofValue, ...options } = proof;
  const proofConfig = proofConfigOf(options, document);
  const data = hashData(proofConfig, documentWithoutProof(document));
  return verifyMultibase(data, proofValue, publicKey);
}
