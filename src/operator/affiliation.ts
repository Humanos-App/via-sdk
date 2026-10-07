// Affiliation + regulatory attestations (§18) — both ride the v0.2-new §5 `VIAEvent` primitive,
// so signing, chaining and one verify routine come for free.
//
// AFFILIATION is the ∧ half of operator inheritance: the registrar says "Acme is
// KYB-verified", and the ORG says "agent X operates for us". Without the org's own
// signature any agent could write `operator: acme` and inherit the green check — so
// the link must be unforgeable, not merely asserted. `relation: "vouches"` is the same
// act pointed at a third party (an org endorsing its vendor's operator).
import { buildEvent, signEvent, verifyEvent } from "../event/build.js";
import { didFromUrl } from "../did/web.js";
import type { ViaEvent } from "../types.js";
import { claimValidUntil } from "./types.js";
import type { AffiliationRelation } from "./types.js";

export interface AffiliationSigner {
  /** Ed25519 private key of the ORG making the claim (never the registrar's). */
  privateKey: Uint8Array;
  verificationMethod: string;
  created?: string;
}

export interface BuildAffiliationInput {
  /** Who the claim is about — an agent DID (`operates`) or an operator id (`vouches`). */
  subject: string;
  /** The org asserting it (also the signer). */
  org: string;
  relation: AffiliationRelation;
  /** Affiliations decay too — a vendor relationship ends, staff leave. */
  validUntil?: string;
  eventId?: string;
  validFrom?: string;
  previousEvent?: string | null;
}

/** Build + sign an `AFFILIATION` event, signed by the org itself. */
export function buildAffiliation(input: BuildAffiliationInput, signer: AffiliationSigner): ViaEvent {
  const ev = buildEvent({
    subject: input.subject,
    event: "AFFILIATION",
    actor: input.org,
    issuer: input.org,
    eventId: input.eventId,
    validFrom: input.validFrom,
    previousEvent: input.previousEvent ?? null,
    operator: {
      org: input.org,
      relation: input.relation,
      ...(input.validUntil ? { validUntil: input.validUntil } : {}),
    },
  });
  return signEvent(ev, signer);
}

export interface BuildAccreditationInput {
  /** The organization or person being accredited — never an agent (§18.4). */
  subject: string;
  level: "unverified" | "domain" | "verified";
  method: string;
  /** The root that performed the verification — Humanos today, a QTSP or registry later (§18.9). */
  registrar: string;
  subjectType?: "individual" | "organization";
  verifiedAt?: string;
  /** When the claim lapses (v0.3 §18.2). */
  validUntil?: string;
  /** Pointer to an EXTERNAL credential, when the accreditation came from outside. */
  credential?: { id: string; digestSRI?: string; location?: string };
  /**
   * Published, offline-checkable revocation (O3). An accreditation must be withdrawable without a
   * live registrar call — a struck-off operator that kept trading until its mandate expired is the
   * failure this exists to prevent.
   */
  status?: Record<string, unknown>;
  previousEvent?: string | null;
  validFrom?: string;
}

/**
 * `ACCREDITED` (§18) — a registrar's claim that this actor's identity was verified to a level.
 *
 * A VIAEvent signed by the REGISTRAR, on the accredited actor's own chain — the same shape as
 * {@link buildAffiliation} (an org's claim about an agent) and {@link buildRegulatory} (a
 * regulator's claim about a licence). Third-party claims about an actor are events signed by their
 * author; that pattern already existed and this follows it.
 *
 * **There is deliberately no separate credential artifact.** An earlier draft had a
 * `VIAOperatorCredential`, which put the same claims in a second top-level type that nothing
 * issued. Folding the chain now reproduces the accreditation, which is the property the actor model
 * exists to give and a standalone credential could not provide. Where a FOREIGN registrar issues in
 * its own format, this event points at that credential rather than re-typing it as ours — evidence
 * by reference, exactly as `keys[].attestation` handles an attestation quote.
 */
export function buildAccreditation(
  input: BuildAccreditationInput & {
    /** The registrar asserting it — Humanos today, a QTSP or registry later (§18.9). */
    registrarDid: string;
  },
  signer: AffiliationSigner,
): ViaEvent {
  const at = input.validFrom ?? new Date().toISOString();
  const ev = buildEvent({
    subject: input.subject,
    event: "ACCREDITED",
    // The registrar asserts it and the registrar signs it. Humanos is the registrar today, so both
    // are currently us — the separation is what lets an external registrar take over without a
    // shape change, not a claim of independence today (§18.9).
    actor: input.registrarDid,
    issuer: input.registrarDid,
    previousEvent: input.previousEvent ?? null,
    validFrom: at,
    accreditation: {
      level: input.level,
      method: input.method,
      registrar: input.registrar,
      ...(input.subjectType ? { subjectType: input.subjectType } : {}),
      verifiedAt: input.verifiedAt ?? at,
      ...(input.validUntil ? { validUntil: input.validUntil } : {}),
      ...(input.credential ? { credential: input.credential } : {}),
      ...(input.status ? { status: input.status } : {}),
    },
  });
  return signEvent(ev, signer);
}

export interface BuildRegulatoryInput {
  /** The operator holding the licence. */
  subject: string;
  /** Who attests it (a regulator, or the registrar acting on a register check). */
  attestedBy: string;
  /** e.g. `ASF` | `BdP` | `EBA`. */
  regulator: string;
  licence: { type: string; number?: string };
  validUntil?: string;
  eventId?: string;
  validFrom?: string;
  previousEvent?: string | null;
}

/**
 * Build + sign a `REGULATORY` attestation — "this operator holds licence L from
 * regulator R". Deliberately **not** a rung: regulation is domain-specific
 * ("regulated as *what*?") so it is matched categorically in CEL, never ranked.
 */
export function buildRegulatory(input: BuildRegulatoryInput, signer: AffiliationSigner): ViaEvent {
  const ev = buildEvent({
    subject: input.subject,
    event: "REGULATORY",
    actor: input.attestedBy,
    issuer: input.attestedBy,
    eventId: input.eventId,
    validFrom: input.validFrom,
    previousEvent: input.previousEvent ?? null,
    operator: {
      regulator: input.regulator,
      licence: input.licence,
      ...(input.validUntil ? { validUntil: input.validUntil } : {}),
    },
  });
  return signEvent(ev, signer);
}

/**
 * **O2** — verify an affiliation: the signature must be valid AND the signer must be
 * the org the event names. An event claiming "agent X belongs to Acme" that Acme never
 * signed is exactly the spoof this catches.
 */
export async function verifyAffiliation(
  event: ViaEvent,
  resolvePublicKey: (vmId: string) => Uint8Array | Promise<Uint8Array>,
  expected: { subject: string; org?: string; relation?: AffiliationRelation; now?: Date },
): Promise<{ valid: boolean; reason?: string }> {
  const cs = event.credentialSubject;
  if (cs.event !== "AFFILIATION") return { valid: false, reason: "not an AFFILIATION event" };
  if (cs.id !== expected.subject) return { valid: false, reason: "affiliation subject mismatch" };

  // §18 puts the claim in `operator`; affiliations written before that was honoured carry it in `agent`.
  const op = (cs.operator ?? cs.agent ?? {}) as { org?: string; relation?: string; validUntil?: string; expiresAt?: string };
  if (!op.org) return { valid: false, reason: "affiliation names no org" };
  if (expected.org && op.org !== expected.org) return { valid: false, reason: "affiliation org mismatch" };
  if (expected.relation && op.relation !== expected.relation) return { valid: false, reason: "affiliation relation mismatch" };

  // The org must have signed it ITSELF — this is what makes inheritance unforgeable.
  // Checking the `issuer` LABEL is not enough: anyone can write `issuer: acme`. The
  // SIGNING KEY must belong to the org, so bind the proof's verificationMethod to it
  // (same check v0.2-new §8 step 1 makes for the VP holder).
  if (event.issuer !== op.org) return { valid: false, reason: "affiliation not signed by the named org" };
  if (!event.proof) return { valid: false, reason: "affiliation has no proof" };
  if (didFromUrl(event.proof.verificationMethod) !== op.org) {
    return { valid: false, reason: "affiliation signing key does not belong to the named org" };
  }

  // `validUntil`; `expiresAt` on an affiliation signed before 2026-10-07 — read as written.
  const until = claimValidUntil(op);
  if (until && (expected.now ?? new Date()) > new Date(until)) {
    return { valid: false, reason: "affiliation expired" };
  }

  const v = await verifyEvent(event, resolvePublicKey);
  return v.valid ? { valid: true } : { valid: false, reason: v.reason ?? "affiliation signature invalid" };
}
