import { viaUrn } from "../urn.js";
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import { canonicalEventType, createDataIntegrityProof, verifyDataIntegrityProof, type EventType } from "../crypto/proof.js";
import type { Jwk } from "../crypto/p256.js";
import { didFromUrl } from "../did/web.js";
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

/**
 * An event kind's own fields (v0.3 §2.0) — written directly in `credentialSubject`, beside the core,
 * with no wrapper object. A value that is itself a structure (a claim, a pointer, a map) stays one
 * object under its own name. §2.0's tables say which fields each kind carries; a writer writes only
 * those. There is no `actor` (a `"0.2"` field: `issuer` is the signer, §2), no `agent` wrapper (written
 * before 2026-10-11) and no `role` (never written).
 */
export interface EventFields {
  /** Why the event was recorded, for the audit — any kind MAY carry it. */
  reason?: string;
  // ── about a mandate ──
  evaluations?: unknown[];
  executionParams?: Record<string, unknown>;
  targetVerifier?: string;
  /** §20.3 — which machinery governed a `VERIFICATION_*` decision. */
  enforcement?: string;
  /** §2.2/§17.4 — `{ id, method, termsDigest, tool }` on `STEP_UP_*`; the reference on a `VERIFICATION_*`. */
  stepUp?: Record<string, unknown>;
  /** §20.6 — `{ id, version, verdict }` of the reviewer that took part. */
  review?: Record<string, unknown>;
  /** §9.9 — what the presenting client declared itself to be: `{ declared: true, name, version }`. */
  client?: Record<string, unknown>;
  /** §2.1 — on `ACTION_*`: the `id` of the `VERIFICATION_APPROVED` the outcome closes. */
  decision?: string;
  /** §18.2/§18.5 — with `accreditation_revoked`: why the registrar withdrew it. */
  revocationReason?: string;
  /** §0.6.1 — on a `VERIFICATION_APPROVED`: the call's tool is one the version marks unrestricted. */
  unrestricted?: boolean;
  /** §21.3 — the organization's policy version a decision was checked against. */
  policyDigest?: string;
  /** §21.5 — on a policy-scoped event: the agent whose chain it is on (not `agent`, a legacy container). */
  agentDid?: string;
  // ── about an organization's policy (`POLICY_PUBLISHED`, §21.2) ──
  policy?: string;
  version?: number;
  publishedBy?: string;
  /** How the member confirmed: `webauthn` | `otp` (§21.2). */
  publishedWith?: string;
  /** §9.9/§16.9 — the rung relied on at presentation. */
  keyIdEvaluated?: string;
  assuranceEvaluated?: string;
  bindingEvaluated?: string;
  rootUsed?: string;
  attestationFreshnessAt?: string;
  popNonceRef?: string;
  /** §18.7 — whose identity was relied on. */
  levelEvaluated?: string;
  methodEvaluated?: string;
  registrarUsed?: string;
  affiliationRef?: string;
  // ── about an actor ──
  actorType?: string;
  keyId?: string;
  publicKeyJwk?: Jwk;
  publicKeyMultibase?: string;
  assurance?: string;
  binding?: string;
  root?: string;
  verifiedAt?: string;
  bootstrapAnchor?: string;
  existedSince?: string;
  attestationKind?: string;
  degradedFrom?: string;
  anchoredBy?: Record<string, unknown>;
  authorizedBy?: string;
  predecessorId?: string;
  runtime?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
  alias?: string;
  /** `ALIAS_ADDED` — why it aliases: `channel` | `merge` (§3.6). Not `reason`, which any event may carry. */
  aliasReason?: string;
  /** `ACTOR_AFFILIATED` — `{ org, relation, validUntil? }` (§18.4). */
  operator?: Record<string, unknown>;
  /** `ACTOR_ACCREDITED` — the registrar's claim (§18.2, §18.3bis). */
  accreditation?: Record<string, unknown>;
  /** `ACTOR_MERGED` — `{ absorbed, aliases, keys }` (§3.6c). */
  merge?: Record<string, unknown>;
  /** `ACTOR_RETIRED` on a merge (§3.6c). */
  succeededBy?: string;
  keySuccession?: Record<string, string>;
}

export interface BuildEventInput extends EventFields {
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
  /**
   * The DID that signs the event (v0.3 §2: an event's `issuer` is its signer). Required: this builder
   * signs nothing, so it cannot know who will — `buildChainedEvent`, which signs, fills it in.
   */
  issuer: string;
  validFrom?: string;
  /** SRI of the prior event in the chain (null at its first event). */
  previousEvent?: string | null;
  /**
   * Content-bound: the credential to hash (e.g. a {@link ViaMandateCredential}), or a
   * precomputed digest. Any existing `proof` is stripped before hashing (spec §0.5.4).
   */
  credential?: BindableCredential;
  credentialDigest?: string;
}

/** Fields a `"0.3"` event never carries (v0.3 §2.0). A builder refuses them rather than write them. */
const NOT_V03_FIELDS = ["actor", "agent", "role"] as const;

/** A credential to content-bind against — a mandate, an event, or any VC-shaped object. */
export type BindableCredential = Record<string, unknown> | object;

/**
 * Compute the content-binding digest of a credential (spec §0.5.4):
 * `SRI(canonicalizeRFC8785(credential-without-proof))`.
 */
export function credentialDigestOf(credential: BindableCredential): string {
  return computeSRI(canonicalizeRFC8785({ ...(credential as Record<string, unknown>), proof: undefined }));
}

/**
 * Build the **unsigned** `VIAEvent` (spec §0.5). When `credential` is given, the event
 * is content-bound: its `credentialDigest` is computed over the proofless credential.
 * Otherwise it is reference-bound (commits only to `credentialSubject.id`).
 */
export function buildEvent(input: BuildEventInput): ViaEvent {
  const { eventId, subject, event, issuer, validFrom, previousEvent, credential, credentialDigest: given, ...fields } = input;
  for (const name of NOT_V03_FIELDS) {
    if (name in fields) throw new Error(`a "0.3" event carries no \`${name}\` (v0.3 §2.0)`);
  }
  // Never defaulted: an event that says Humanos and is signed by someone else is refused by a verifier.
  if (!issuer) throw new Error("an event states its issuer — the DID that signs it (v0.3 §2)");
  const credentialDigest = given ?? (credential ? credentialDigestOf(credential) : undefined);
  // The kind's own fields, directly in credentialSubject (§2.0); an absent or empty value is left out.
  const detail = Object.fromEntries(
    Object.entries(fields).filter(([, v]) => v !== undefined && v !== null && v !== ""),
  );
  return {
    "@context": [...VIA_CONTEXTS],
    id: eventId ?? viaUrn("event"),
    type: [TYPE_VC, TYPE_VIA_EVENT],
    specVersion: VIA_SPEC_VERSION as SpecVersion,
    issuer,
    validFrom: validFrom ?? new Date().toISOString(),
    credentialSubject: {
      id: subject,
      event,
      ...(credentialDigest ? { credentialDigest } : {}),
      ...(previousEvent !== undefined ? { previousEvent } : {}),
      ...detail,
    },
  };
}

/**
 * Sign a `VIAEvent` with `eddsa-jcs-2022` (spec §0.5.2). The event *kind* lives in the
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
 * `credential` is supplied, also recompute and compare `credentialDigest` (spec §0.5.4).
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
 * Verify the ordering of a credential's event chain (spec §0.5.4): each event's
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

/**
 * Who signed an event (v0.3 §2): a `"0.2"` event's `actor`, else its `issuer`. On an event the platform
 * signed before 2026-10-09 `issuer` may say Humanos while another party's key signed; those carry `actor`.
 */
export function signerOf(e: ViaEvent): string {
  return e.credentialSubject.actor ?? e.issuer ?? (e.proof ? didFromUrl(e.proof.verificationMethod) : "");
}

/** The next event's `previousEvent` — `SRI(JCS(the whole prior signed event))` (spec §0.5.4). */
export function eventChainLink(prior: ViaEvent): string {
  return computeSRI(canonicalizeRFC8785(prior));
}

export interface EventAudit {
  urn: string;
  /** The kind in today's vocabulary — an old name read as the new one (v0.3 §3.4). */
  event: EventType;
  /**
   * Who asserted the event — its signer. `issuer` on a `"0.3"` event, which carries no `actor`
   * (v0.3 §2); the `actor` field on a `"0.2"` one, whose `issuer` may be the platform while another
   * party's key signed. Kept under this name because readers (the platform's API) show it.
   */
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
 * Audit a credential's `VIAEvent` chain (spec §0.5.4) — the audit-side reader, kept OFF the verify
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
      event: canonicalEventType(cs.event) as EventType,
      actor: signerOf(e),
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
// the issuance consent ceremony (spec §0.9). Pure; the caller supplies keys.
// ============================================================================

export interface BuildChainedEventInput extends EventFields {
  /** What this event is about — a credential URN or an actor DID. See {@link BuildEventInput.subject}. */
  subject: string;
  /** The event's own `id` (URN); defaults to a fresh `urn:via:event:<uuid>`. Set to reuse a
   *  pre-generated URN (e.g. the response's receipt URN) so the emitted event stays referable. */
  eventId?: string;
  event: EventType;
  /** The signer's DID (v0.3 §2); defaults to the DID of `signer.verificationMethod` — whoever signs. */
  issuer?: string;
  /** Content-bound (ISSUE/ACCEPT/REJECT): the proofless credential to hash, or a precomputed digest. */
  credential?: Record<string, unknown>;
  credentialDigest?: string;
  /** The prior SIGNED event to chain from; `null` at the chain's first event; omit to leave the link off. */
  previous?: ViaEvent | null;
  /** The event instant (`validFrom`); defaults to now. */
  validFrom?: string;
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
  const { previous: _previous, signer, issuer, eventId, validFrom, credential, credentialDigest, ...rest } = input;
  const unsigned = buildEvent({
    ...rest,
    ...(eventId ? { eventId } : {}),
    // §2: the signer is the issuer — by default whoever's key signs.
    issuer: issuer ?? didFromUrl(signer.verificationMethod),
    ...(validFrom ? { validFrom } : {}),
    ...(credential ? { credential } : {}),
    ...(credentialDigest ? { credentialDigest } : {}),
    ...(previousEvent !== undefined ? { previousEvent } : {}),
  });
  return signEvent(unsigned, signer);
}

/** One signing party (issuer or grantor) — its DID + Ed25519 key. */
export interface IssuanceParty {
  /** The party's DID: its event's `issuer`, since it signs (v0.3 §2). */
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
 * Build the v0.2 issuance artifacts (spec §0.5/§0.9): the content-bound event chain
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
    issuer: input.issuer.actor,
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
      issuer: g.actor,
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
