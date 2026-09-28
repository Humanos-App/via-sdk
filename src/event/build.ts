import { viaUrn } from "../urn.js";
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import { createDataIntegrityProof, verifyDataIntegrityProof, type EventType } from "../crypto/proof.js";
import { VIA_PLATFORM_DID } from "../did/web.js";
import { stampMandate, type ResolvePublicKey } from "../mandate/build.js";
import {
  TYPE_VC,
  TYPE_VIA_EVENT,
  VIA_CONTEXTS,
  VIA_SPEC_VERSION,
  type SpecVersion,
  type ViaEvent,
  type ViaMandateCredential,
} from "../types.js";

export interface BuildEventInput {
  eventId?: string;
  /**
   * What this event is ABOUT — becomes `credentialSubject.id`.
   *
   * A credential URN for a credential-scoped event, an actor DID for an actor-scoped one
   * (v0.3 §3.4). Deliberately not called `credentialId`: the wire field has always been a plain
   * subject identifier, and the old name implied a constraint the format never had.
   */
  subject: string;
  event: EventType;
  actor: string;
  /** The asserting actor's DID; defaults to the platform. */
  issuer?: string;
  validFrom?: string;
  /** SRI of the prior event in the credential's chain (null at the root). */
  previousEvent?: string | null;
  role?: string;
  reason?: string;
  evaluations?: unknown[];
  executionParams?: Record<string, unknown>;
  targetVerifier?: string;
  /** §16.9 — agent-binding detail (e.g. rung evidence on a `VERIFICATION_*` event). */
  agent?: Record<string, unknown>;
  /** §18 — operator detail (`AFFILIATION` org/relation, `REGULATORY` licence). */
  operator?: Record<string, unknown>;
  /** §18 — `ACCREDITED` detail: the registrar's claim about THIS actor's identity. */
  accreditation?: Record<string, unknown>;
  /** §17.4 — step-up detail: `{ id, method, termsDigest, tool }` on `STEP_UP_*`; the reference on a `VERIFICATION_*`. */
  stepUp?: Record<string, unknown>;
  /** §20.3 — which machinery governed this decision. */
  enforcement?: string;
  /** §20.6 — `{ id, version, verdict }` of the reviewer that took part. */
  review?: Record<string, unknown>;
  /**
   * Content-bound: the credential to hash (e.g. a {@link ViaMandateCredential}), or a
   * precomputed digest. Any existing `proof` is stripped before hashing (spec v0.2-new §5.4).
   */
  credential?: BindableCredential;
  credentialDigest?: string;
}

/** A credential to content-bind against — a mandate, an event, or any VC-shaped object. */
export type BindableCredential = Record<string, unknown> | object;

/**
 * Compute the content-binding digest of a credential (spec v0.2-new §5.4):
 * `SRI(canonicalizeRFC8785(credential-without-proof))`.
 */
export function credentialDigestOf(credential: BindableCredential): string {
  return computeSRI(canonicalizeRFC8785({ ...(credential as Record<string, unknown>), proof: undefined }));
}

/**
 * Build the **unsigned** `VIAEvent` (spec v0.2-new §5). When `credential` is given, the event
 * is content-bound: its `credentialDigest` is computed over the proofless credential.
 * Otherwise it is reference-bound (commits only to `credentialSubject.id`).
 */
export function buildEvent(input: BuildEventInput): ViaEvent {
  const credentialDigest =
    input.credentialDigest ?? (input.credential ? credentialDigestOf(input.credential) : undefined);
  return {
    "@context": [...VIA_CONTEXTS],
    id: input.eventId ?? viaUrn("event"),
    type: [TYPE_VC, TYPE_VIA_EVENT],
    specVersion: VIA_SPEC_VERSION as SpecVersion,
    issuer: input.issuer ?? VIA_PLATFORM_DID,
    validFrom: input.validFrom ?? new Date().toISOString(),
    credentialSubject: {
      id: input.subject,
      event: input.event,
      actor: input.actor,
      ...(credentialDigest ? { credentialDigest } : {}),
      ...(input.previousEvent !== undefined ? { previousEvent: input.previousEvent } : {}),
      ...(input.role ? { role: input.role } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
      ...(input.evaluations ? { evaluations: input.evaluations } : {}),
      ...(input.executionParams ? { executionParams: input.executionParams } : {}),
      ...(input.targetVerifier ? { targetVerifier: input.targetVerifier } : {}),
      ...(input.agent ? { agent: input.agent } : {}),
      ...(input.stepUp ? { stepUp: input.stepUp } : {}),
      ...(input.enforcement ? { enforcement: input.enforcement } : {}),
      ...(input.review ? { review: input.review } : {}),
      ...(input.operator ? { operator: input.operator } : {}),
      ...(input.accreditation ? { accreditation: input.accreditation } : {}),
    },
  };
}

/**
 * Sign a `VIAEvent` with `eddsa-jcs-2022` (spec v0.2-new §5.2). The event *kind* lives in the
 * signed body (`credentialSubject.event`), so no `event` tag is added to the proof.
 */
/** The signing material for an event/proof — a raw Ed25519 seed + its verification method. */
export interface EventSigner {
  privateKey: Uint8Array;
  verificationMethod: string;
  created?: string;
}

export function signEvent(event: ViaEvent, signer: EventSigner): ViaEvent {
  const proof = createDataIntegrityProof({
    document: event as unknown as Record<string, unknown>,
    privateKey: signer.privateKey,
    verificationMethod: signer.verificationMethod,
    proofPurpose: "assertionMethod",
    ...(signer.created ? { created: signer.created } : {}),
  });
  return { ...event, proof };
}

/**
 * Verify a `VIAEvent`'s signature. When the event is content-bound and the referenced
 * `credential` is supplied, also recompute and compare `credentialDigest` (spec v0.2-new §5.4).
 */
export async function verifyEvent(
  event: ViaEvent,
  resolvePublicKey: (vmId: string) => Uint8Array | Promise<Uint8Array>,
  opts?: { credential?: BindableCredential },
): Promise<{ valid: boolean; reason?: string }> {
  if (!event.proof) return { valid: false, reason: "event has no proof" };
  // What was signed, not only who signed it: a correctly signed artifact of another kind is not an event.
  if (!Array.isArray(event.type) || !event.type.includes(TYPE_VIA_EVENT)) return { valid: false, reason: "type_invalid" };
  let sigValid: boolean;
  try {
    const key = await resolvePublicKey(event.proof.verificationMethod);
    sigValid = verifyDataIntegrityProof(event as unknown as Record<string, unknown>, event.proof, key);
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }
  if (!sigValid) return { valid: false, reason: "signature_invalid" };
  const digest = event.credentialSubject.credentialDigest;
  if (digest && opts?.credential && credentialDigestOf(opts.credential) !== digest) {
    return { valid: false, reason: "credentialDigest_mismatch" };
  }
  return { valid: true };
}

/**
 * Verify the ordering of a credential's event chain (spec v0.2-new §5.4): each event's
 * `previousEvent` must equal `SRI(canonicalizeRFC8785(prior-event))` (the full prior
 * event, including its proof). The first event's `previousEvent` may be null or a root.
 * Returns the first ordering failure.
 */
export async function walkEventChain(events: ViaEvent[]): Promise<{ ok: boolean; reason?: string }> {
  for (let i = 1; i < events.length; i++) {
    const expected = eventChainLink(events[i - 1]!);
    if (events[i]!.credentialSubject.previousEvent !== expected) {
      return { ok: false, reason: `previousEvent_mismatch_at_${i}` };
    }
  }
  return { ok: true };
}

/** The next event's `previousEvent` — `SRI(JCS(the whole prior signed event))` (spec v0.2-new §5.4). */
export function eventChainLink(prior: ViaEvent): string {
  return computeSRI(canonicalizeRFC8785(prior));
}

export interface EventAudit {
  urn: string;
  event: EventType;
  actor: string;
  issuer: string;
  validFrom: string;
  /** Content-bound (commits to the credential's bytes via credentialDigest) vs reference-bound. */
  contentBound: boolean;
  /** The event's own signature verifies against the resolved signer key. */
  signatureValid: boolean;
  /** previousEvent == SRI(JCS(prior event)) — null-at-root; the tamper-evidence link. */
  chainLinkValid: boolean;
}

export interface ChainAudit {
  credentialUrn: string;
  /** The chain is intact AND every event's signature + link verified. */
  ok: boolean;
  /** Present when not ok — the walkEventChain reason, or a signature/link failure marker. */
  reason?: string;
  eventCount: number;
  events: EventAudit[];
}

/**
 * Audit a credential's `VIAEvent` chain (spec v0.2-new §5.4) — the audit-side reader, kept OFF the verify
 * critical path. Given the events in chain order (root first), it (1) walks the `previousEvent`
 * links (`walkEventChain` — the tamper-evidence: altering any event's bytes changes its SRI and
 * breaks the next link) and (2) re-verifies each event's signature against its resolved signer key.
 * Pure — the caller loads the events and supplies `resolvePublicKey` (do the I/O outside). A resolver
 * failure or a bad signature surfaces as `signatureValid: false`, never a throw.
 */
export async function auditEventChain(
  credentialUrn: string,
  events: ViaEvent[],
  resolvePublicKey: ResolvePublicKey,
): Promise<ChainAudit> {
  const walk = await walkEventChain(events);

  const audited: EventAudit[] = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i]!;
    const cs = e.credentialSubject;
    const prevLink = cs.previousEvent ?? null;
    const chainLinkValid = i === 0 ? prevLink === null : prevLink === eventChainLink(events[i - 1]!);

    let signatureValid = false;
    try {
      signatureValid = (await verifyEvent(e, resolvePublicKey)).valid;
    } catch {
      signatureValid = false;
    }

    audited.push({
      urn: e.id,
      event: cs.event as EventType,
      actor: cs.actor,
      issuer: e.issuer,
      validFrom: e.validFrom,
      contentBound: cs.credentialDigest != null,
      signatureValid,
      chainLinkValid,
    });
  }

  const allValid = audited.every((a) => a.signatureValid && a.chainLinkValid);
  const ok = walk.ok && allValid;
  return {
    credentialUrn,
    ok,
    reason: ok ? undefined : !walk.ok ? walk.reason : "signature_or_link_invalid",
    eventCount: events.length,
    events: audited,
  };
}

// ============================================================================
// Chained construction — build + sign an event linked to its predecessor, and
// the issuance consent ceremony (spec v0.2-new §9). Pure; the caller supplies keys.
// ============================================================================

export interface BuildChainedEventInput {
  /** What this event is about — a credential URN or an actor DID. See {@link BuildEventInput.subject}. */
  subject: string;
  /** The event's own `id` (URN); defaults to a fresh `urn:via:event:<uuid>`. Set to reuse a
   *  pre-generated URN (e.g. the response's receipt URN) so the emitted event stays referable. */
  eventId?: string;
  event: EventType;
  actor: string;
  issuer?: string;
  /** Content-bound (ISSUE/ACCEPT/REJECT): the proofless credential to hash, or a precomputed digest. */
  credential?: Record<string, unknown>;
  credentialDigest?: string;
  /** The prior SIGNED event to chain from; `null` at the ISSUE root; omit to leave the chain link off. */
  previous?: ViaEvent | null;
  /** The event instant (`validFrom`); defaults to now. */
  validFrom?: string;
  // reference-bound payload (operational events)
  reason?: string;
  evaluations?: unknown[];
  executionParams?: Record<string, unknown>;
  targetVerifier?: string;
  role?: string;
  /** §16.9 — agent-binding detail (v0.3: also actor-lifecycle event detail). */
  agent?: Record<string, unknown>;
  /** §18 — operator detail (`AFFILIATION` org/relation, `REGULATORY` licence). */
  operator?: Record<string, unknown>;
  /** §18 — `ACCREDITED` detail: the registrar's claim about THIS actor's identity. */
  accreditation?: Record<string, unknown>;
  /** §2.2/§17.4 — step-up detail: `{ id, method, termsDigest, tool }` on `STEP_UP_*`; the reference on a `VERIFICATION_*`. */
  stepUp?: Record<string, unknown>;
  /** §20.3 — which machinery governed this decision. */
  enforcement?: string;
  /** §20.6 — `{ id, version, verdict }` of the reviewer that took part. */
  review?: Record<string, unknown>;
  signer: EventSigner;
}

/**
 * Build + sign a `VIAEvent`, chained to `previous` (`previousEvent = SRI(prior)`, `null` at root).
 * Content-bound when `credential`/`credentialDigest` is given, else reference-bound. Pure.
 */
export function buildChainedEvent(input: BuildChainedEventInput): ViaEvent {
  const previousEvent =
    input.previous === undefined
      ? undefined
      : input.previous === null
        ? null
        : eventChainLink(input.previous);
  const unsigned = buildEvent({
    subject: input.subject,
    ...(input.eventId ? { eventId: input.eventId } : {}),
    event: input.event,
    actor: input.actor,
    ...(input.validFrom ? { validFrom: input.validFrom } : {}),
    ...(input.issuer ? { issuer: input.issuer } : {}),
    ...(input.credential ? { credential: input.credential } : {}),
    ...(input.credentialDigest ? { credentialDigest: input.credentialDigest } : {}),
    ...(previousEvent !== undefined ? { previousEvent } : {}),
    ...(input.reason ? { reason: input.reason } : {}),
    ...(input.evaluations ? { evaluations: input.evaluations } : {}),
    ...(input.executionParams ? { executionParams: input.executionParams } : {}),
    ...(input.targetVerifier ? { targetVerifier: input.targetVerifier } : {}),
    ...(input.role ? { role: input.role } : {}),
    ...(input.agent ? { agent: input.agent } : {}),
    ...(input.operator ? { operator: input.operator } : {}),
    ...(input.accreditation ? { accreditation: input.accreditation } : {}),
    ...(input.stepUp ? { stepUp: input.stepUp } : {}),
    ...(input.enforcement ? { enforcement: input.enforcement } : {}),
    ...(input.review ? { review: input.review } : {}),
  });
  return signEvent(unsigned, input.signer);
}

/** One signing party (issuer, grantor, or the Humanos stamp) — its actor + Ed25519 key. */
export interface IssuanceParty {
  actor: string;
  verificationMethod: string;
  privateKey: Uint8Array;
  /** Instant this party's event/proof is stamped with (`validFrom` + proof `created`). */
  at?: string;
}

export interface IssuanceInput {
  /** The proofless wire mandate (its `id` is the credential URN). */
  mandate: ViaMandateCredential;
  issuer: IssuanceParty;
  /** Each grantor's decision, in order. */
  grantors: (IssuanceParty & { accepted: boolean })[];
  stamp: { verificationMethod: string; privateKey: Uint8Array; at?: string };
}

export interface IssuanceResult {
  /** The content-bound event chain: ISSUE (root) then one ACCEPT/REJECT per grantor. */
  events: ViaEvent[];
  /** The securing STAMP proof for the credential, or `null` when a REJECT terminated the ceremony. */
  stampProof: Record<string, unknown> | null;
  status: "ACTIVE" | "REJECTED";
}

/**
 * Build the v0.2 issuance artifacts (spec v0.2-new §5/§9): the content-bound event chain
 * ISSUE→ACCEPT/REJECT…, and the securing `STAMP` — emitted only when the policy is satisfied
 * (all grantors ACCEPT, zero REJECT). A REJECT terminates the ceremony: no STAMP, status REJECTED.
 * Pure — the caller persists `events` (as rows) + `stampProof` (the credential's `proof`).
 */
export function buildIssuanceEvents(input: IssuanceInput): IssuanceResult {
  const urn = input.mandate.id;
  const events: ViaEvent[] = [];

  let prev: ViaEvent | null = null;
  const issue = buildChainedEvent({
    subject: urn,
    event: "ISSUE",
    actor: input.issuer.actor,
    credential: input.mandate as unknown as Record<string, unknown>,
    previous: null,
    validFrom: input.issuer.at,
    signer: {
      privateKey: input.issuer.privateKey,
      verificationMethod: input.issuer.verificationMethod,
      created: input.issuer.at,
    },
  });
  events.push(issue);
  prev = issue;

  let anyReject = false;
  for (const g of input.grantors) {
    const ev = buildChainedEvent({
      subject: urn,
      event: g.accepted ? "ACCEPT" : "REJECT",
      actor: g.actor,
      credential: input.mandate as unknown as Record<string, unknown>,
      previous: prev,
      validFrom: g.at,
      signer: { privateKey: g.privateKey, verificationMethod: g.verificationMethod, created: g.at },
    });
    events.push(ev);
    prev = ev;
    if (!g.accepted) anyReject = true;
  }

  const status = anyReject ? "REJECTED" : "ACTIVE";
  const stampProof = anyReject
    ? null
    : (stampMandate(input.mandate, {
        privateKey: input.stamp.privateKey,
        verificationMethod: input.stamp.verificationMethod,
        created: input.stamp.at,
      }).proof as unknown as Record<string, unknown>);

  return { events, stampProof, status };
}
