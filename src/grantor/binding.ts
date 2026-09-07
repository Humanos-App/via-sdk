// Grantor Binding (§17) — the human-side symmetry of §16. The grantor holds a
// passkey; Humanos (the authority root) verifies the assertion on ITS OWN origin and
// signs a `grantorBinding` into the mandate. These are the pure primitives; the
// stateful ceremony (nonce store, mandate issuance) is the caller's (M7 / platform).
//
// v0.3: the grantor is an ACTOR (§3.5). Nothing here mints a DID — v0.2 derived one per
// passkey thumbprint, which §3.6 forbids; the grantor DID is the person's actor DID and
// the passkey is one of that actor's keys (`KEY_ADDED`, §16.3bis). `cnf.jkt` selects it.
import { actionHash } from "../agent/pop.js";
import { jwkThumbprint, type Jwk } from "../crypto/p256.js";
import { verifyWebauthnAssertion, type WebauthnAssertionInput } from "../crypto/webauthn.js";
import type { AgentReasonCode } from "../agent/types.js";

/** §17.5 fail-closed reasons. `action_hash_mismatch` (§16.7) is shared: same check, same code. */
export type GrantorReasonCode = "grantor_not_enrolled" | "grantor_challenge_invalid" | "grantor_assertion_invalid";

/**
 * The signed record of the human who authorized issuance (§17.2). `cnf` is the RFC 7800
 * `{jkt}` object (D2 — the full passkey JWK stays at the issuer; only its thumbprint is
 * bound). `method` says HOW the human authenticated; it is not a rung — the passkey's rung
 * lives on the person's key entry (§16.3bis). v0.2 wrote the same fact as
 * `assurance: "passkey"`; that encoding is still READ (`grantorBindingMethod`), never written.
 */
export interface GrantorBinding {
  grantor: string; // the person's actor DID, == mandate.grantor
  cnf: { jkt: string }; // RFC 7638 thumbprint of the grantor's passkey
  method: "webauthn";
  verifiedAt: string; // ISO
}

/** The v0.2 wire shape, accepted on read only. */
export interface LegacyGrantorBinding {
  grantor: string;
  cnf: { jkt: string };
  assurance: "passkey";
  verifiedAt: string;
}

/** How the grantor authenticated, from either encoding; `null` if the object is neither. */
export function grantorBindingMethod(gb: GrantorBinding | LegacyGrantorBinding | Record<string, unknown>): "webauthn" | null {
  const o = gb as Record<string, unknown>;
  if (o.method === "webauthn") return "webauthn";
  if (o.assurance === "passkey") return "webauthn"; // v0.2 encoding (§17.2)
  return null;
}

export type { WebauthnAssertionInput as WebauthnAssertion };

/**
 * Enrol a passkey for a grantor: the passkey's thumbprint (`cnf`) beside the person's actor
 * DID. The public JWK is retained by the caller; recording the key on the actor as
 * `KEY_ADDED` (§16.3bis) is the platform's write, not this function's. Any WebAuthn key family
 * is accepted (P-256, RSA, Ed25519 — §16.6bis); the thumbprint is RFC 7638 for all three.
 */
export function enrollGrantor(jwk: Jwk, grantorDid: string): { did: string; cnf: string } {
  if (!grantorDid || !grantorDid.startsWith("did:")) throw new Error("grantorDid (the person's actor DID) required");
  if (!jwk || !jwk.kty) throw new Error("jwk (public) required");
  return { did: grantorDid, cnf: jwkThumbprint(jwk) };
}

/** The exact thing the passkey authorizes — a mandate scope, or a specific step-up payment (§17.3/§17.4). */
export type GrantorTerms =
  | { purpose: "mandate"; agentDid: string; constraints: unknown[] }
  | { purpose: "stepup"; mandateId: string; amount: number; currency?: string; item?: string };

/** Compute the `termsDigest` bound into the grantor challenge — a `digestSRI` over the authorized terms. */
export function grantorTermsDigest(t: GrantorTerms): string {
  return t.purpose === "stepup"
    ? actionHash(`stepup:${t.mandateId}`, "purchase", { amount: t.amount, currency: t.currency ?? "USD", item: t.item ?? "" })
    : actionHash(`grant:${t.agentDid}`, "grant", { constraints: t.constraints });
}

/**
 * Verify a grantor's passkey assertion against the expected challenge, at the ISSUER's
 * own origin (§17.1). A tampered `termsDigest` is `action_hash_mismatch` — the same check
 * as §16.7's, so the same code. Anything else that fails the assertion (wrong key, wrong
 * origin, flags) is `grantor_assertion_invalid` (§17.5): the agent's `pop_invalid` is never
 * reported for a human's assertion.
 */
export async function verifyGrantorAssertion(
  assertion: WebauthnAssertionInput,
  grantorPublicJwk: Jwk,
  expected: { nonce: string; termsDigest: string; rpId: string; origin: string },
): Promise<{ ok: boolean; reason?: AgentReasonCode | GrantorReasonCode }> {
  const v = await verifyWebauthnAssertion(assertion, grantorPublicJwk, {
    nonce: expected.nonce,
    actionHash: expected.termsDigest,
    rpId: expected.rpId,
    origin: expected.origin,
  });
  if (v.ok) return { ok: true };
  return { ok: false, reason: v.reason === "action_hash_mismatch" ? "action_hash_mismatch" : "grantor_assertion_invalid" };
}

/** Build the signed-into-the-mandate `grantorBinding` after a successful verify (§17.2). */
export function buildGrantorBinding(grantorDid: string, thumbprint: string, verifiedAt: string): GrantorBinding {
  return { grantor: grantorDid, cnf: { jkt: thumbprint }, method: "webauthn", verifiedAt };
}
