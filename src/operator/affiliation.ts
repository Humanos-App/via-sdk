// Affiliation + regulatory attestations (§18) — both ride the §5 `VIAEvent` primitive,
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
  expiresAt?: string;
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
      ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
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
  expiresAt?: string;
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
      ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
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

  const op = (cs.operator ?? {}) as { org?: string; relation?: string; expiresAt?: string };
  if (!op.org) return { valid: false, reason: "affiliation names no org" };
  if (expected.org && op.org !== expected.org) return { valid: false, reason: "affiliation org mismatch" };
  if (expected.relation && op.relation !== expected.relation) return { valid: false, reason: "affiliation relation mismatch" };

  // The org must have signed it ITSELF — this is what makes inheritance unforgeable.
  // Checking the `issuer` LABEL is not enough: anyone can write `issuer: acme`. The
  // SIGNING KEY must belong to the org, so bind the proof's verificationMethod to it
  // (same check §8 step 1 makes for the VP holder).
  if (event.issuer !== op.org) return { valid: false, reason: "affiliation not signed by the named org" };
  if (!event.proof) return { valid: false, reason: "affiliation has no proof" };
  if (didFromUrl(event.proof.verificationMethod) !== op.org) {
    return { valid: false, reason: "affiliation signing key does not belong to the named org" };
  }

  if (op.expiresAt && (expected.now ?? new Date()) > new Date(op.expiresAt)) {
    return { valid: false, reason: "affiliation expired" };
  }

  const v = await verifyEvent(event, resolvePublicKey);
  return v.valid ? { valid: true } : { valid: false, reason: v.reason ?? "affiliation signature invalid" };
}
