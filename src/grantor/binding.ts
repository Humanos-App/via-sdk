// Grantor Binding (§17) — the human-side symmetry of §16. The grantor holds a
// passkey; Humanos (the authority root) verifies the assertion on ITS OWN origin and
// signs a `grantorBinding` into the mandate. These are the pure primitives; the
// stateful ceremony (nonce store, mandate issuance) is the caller's (M7 / platform).
// Ported from kya/verifier.ts (enrollGrantor / grantorChallenge / grantorVerify).
import { actionHash } from "../agent/pop.js";
import { jwkThumbprint, type Jwk } from "../crypto/p256.js";
import { verifyWebauthnAssertion, type WebauthnAssertionInput } from "../crypto/webauthn.js";
import type { AgentReasonCode } from "../agent/types.js";

/** §17.5 fail-closed reasons (the low-level webauthn codes surface through, per §17.5). */
export type GrantorReasonCode = "grantor_not_enrolled" | "grantor_challenge_invalid" | "grantor_assertion_invalid";

/**
 * The signed record of the human who authorized issuance (§17.2). `cnf` is the RFC
 * 7800 `{jkt}` object (D2 — the full passkey JWK stays at the issuer; only its
 * thumbprint is bound). `assurance:"passkey"` is a separate namespace from the agent
 * assurance ladder (§16.3).
 */
export interface GrantorBinding {
  grantor: string; // the Humanos-issued grantor DID, == mandate.grantor
  cnf: { jkt: string }; // RFC 7638 thumbprint of the grantor's passkey
  assurance: "passkey";
  verifiedAt: string; // ISO
}

export type { WebauthnAssertionInput as WebauthnAssertion };

/** Derive the Humanos-issued grantor DID from the passkey thumbprint (§17.1). */
export function grantorDidFromThumbprint(cnf: string, host: string): string {
  const h = host.replace(/^https?:\/\//, "").replace(/[/:].*$/, "") || "humanos.tech";
  return `did:web:${h}:user:${cnf.slice(0, 12)}`;
}

/** Register a passkey → its thumbprint (`cnf`) + Humanos DID. The public JWK is retained by the caller. */
export function enrollGrantor(jwk: Jwk, host: string): { did: string; cnf: string } {
  if (!jwk || jwk.kty !== "EC" || !jwk.x || !jwk.y) throw new Error("jwk (EC P-256 public) required");
  const cnf = jwkThumbprint(jwk);
  return { did: grantorDidFromThumbprint(cnf, host), cnf };
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
 * own origin (§17.1). A tampered `termsDigest` surfaces as `action_hash_mismatch`, a
 * wrong key as `pop_invalid` (§17.5); otherwise `grantor_assertion_invalid`.
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
  return v.ok ? { ok: true } : { ok: false, reason: v.reason ?? "grantor_assertion_invalid" };
}

/** Build the signed-into-the-mandate `grantorBinding` after a successful verify (§17.2). */
export function buildGrantorBinding(grantorDid: string, thumbprint: string, verifiedAt: string): GrantorBinding {
  return { grantor: grantorDid, cnf: { jkt: thumbprint }, assurance: "passkey", verifiedAt };
}
