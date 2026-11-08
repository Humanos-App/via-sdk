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
/** The KIND of channel a code went to — never the address: the mandate travels to relying parties. */
export type GrantorChannel = "email" | "sms";

/** Authenticated by a WebAuthn credential with user verification. `cnf` names the key. */
export interface WebauthnGrantorBinding {
  grantor: string; // the person's actor DID, == mandate.grantor
  cnf: { jkt: string }; // RFC 7638 thumbprint of the grantor's passkey
  method: "webauthn";
  verifiedAt: string; // ISO — when the ASSERTION was verified, never when the decision was taken
  /**
   * §17.3 — the digest the assertion actually signed, over the EXACT thing authorized
   * (`grantorTermsDigest`). Present ⇒ the passkey signed *these terms for this agent*, and a
   * reader can recompute it from the mandate body and check. Absent ⇒ the assertion proved the
   * person was present holding the key, and nothing about what they approved: still a real fact,
   * a weaker one, and the difference is now legible instead of inferred.
   */
  termsDigest?: string;
  /**
   * §17.1–§17.2 — the issuer's page the ceremony ran on, the assertion's signed `origin`. Written on every
   * new passkey binding, so absent means only "not recorded" (a binding from before the field).
   */
  origin?: string;
  /** The page around it, the signed `topOrigin` — present only when the ceremony ran in another page's frame. */
  topOrigin?: string;
}

/** Where a passkey ceremony ran, as the assertion's client data signed it (§17.1–§17.2). */
export interface GrantorCeremonyPage {
  origin: string;
  /** Only when the ceremony ran in a frame another page embeds. */
  topOrigin?: string;
}

/**
 * Authenticated by a single-use code to a channel the grantor controls (§0.9).
 *
 * No `cnf`: there is no key. What it records is that the ordinary path HAPPENED — before this shape
 * existed, a code-approved mandate carried nothing at all, so absence of a binding meant both "a
 * code" and "nobody wrote it down", and a reader could not tell which.
 */
export interface OtpGrantorBinding {
  grantor: string;
  method: "otp";
  channel: GrantorChannel;
  verifiedAt: string; // ISO — when the CODE was verified
}

export type GrantorBinding = WebauthnGrantorBinding | OtpGrantorBinding;

/** The v0.2 wire shape, accepted on read only. */
export interface LegacyGrantorBinding {
  grantor: string;
  cnf: { jkt: string };
  assurance: "passkey";
  verifiedAt: string;
}

/** How the grantor authenticated, from either encoding; `null` if the object is neither. */
export function grantorBindingMethod(
  gb: GrantorBinding | LegacyGrantorBinding | Record<string, unknown>,
): "webauthn" | "otp" | null {
  const o = gb as Record<string, unknown>;
  // §17.2 (2026-11-08): `"passkey"` is the method's name; readers learn it before any issuer writes it,
  // so the label returned stays `"webauthn"` until the writers switch (OPEN #633).
  if (o.method === "webauthn" || o.method === "passkey") return "webauthn";
  if (o.method === "otp") return "otp";
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

/**
 * The exact thing the passkey authorizes (§17.3/§17.4): a mandate scope, or one step-up.
 *
 * A step-up over a TOOL CALL binds `{ mandateId, action, params }` — the SAME digest the agent's
 * PoP carries as `action_hash` (§16.6), so the human co-signs the very transaction the agent
 * signed and a verifier compares one value against both proofs. The purchase-shaped variant is the
 * v0.2-era example and stays for its callers.
 */
export type GrantorTerms =
  | {
      purpose: "mandate";
      agentDid: string;
      constraints: unknown[];
      /**
       * §20.1 — the words the person is being shown. An input to the digest because they are what
       * the person is actually agreeing to: a signature over the constraints alone would let the
       * sentence beside them change without breaking anything.
       */
      description?: { text: string; lang: string; author: string };
      /** The grant's lifetime in seconds, when it has one (§17.3). */
      ttlSeconds?: number;
    }
  | { purpose: "stepup"; mandateId: string; action: string; params: Record<string, unknown> }
  | { purpose: "stepup"; mandateId: string; amount: number; currency?: string; item?: string };

/** Compute the `termsDigest` bound into the grantor challenge — a `digestSRI` over the authorized terms. */
export function grantorTermsDigest(t: GrantorTerms): string {
  if (t.purpose === "stepup") {
    if ("action" in t) return actionHash(t.mandateId, t.action, t.params);
    return actionHash(`stepup:${t.mandateId}`, "purchase", { amount: t.amount, currency: t.currency ?? "USD", item: t.item ?? "" });
  }
  return actionHash(`grant:${t.agentDid}`, "grant", {
    constraints: t.constraints,
    // Both are OMITTED when absent rather than sent as null: JCS keeps an explicit null and drops
    // an undefined key, so writing them unconditionally would change the digest of every mandate
    // that has neither — including the ones a deployment already signed.
    ...(t.description ? { description: t.description } : {}),
    ...(t.ttlSeconds !== undefined ? { ttlSeconds: t.ttlSeconds } : {}),
  });
}

/**
 * §17.3 — the `termsDigest` a grantor's passkey signs when it APPROVES A MANDATE: over the mandate
 * as it will be issued — every bound agent, the action pinned and its digest, the values fixed,
 * the words shown, `enforcement`, `stepUp`, `maxExecutions`, the verifiers in `authorizedDIDs`, and
 * the validity window — with only what the approval itself fills in left out (`grantor`,
 * `grantorBinding`). Over the WHOLE body rather than a list of fields, so a term added to the
 * mandate later is covered without anyone remembering to add it here; and naming the mandate's id,
 * so one approval cannot be replayed onto another mandate with equal terms.
 *
 * Supersedes the field-list `{ purpose: "mandate", agentDid, constraints, … }` digest, which named one
 * agent and omitted the rest — a person approved agent A, and agent B bound beside it got the same
 * authority.
 */
export function mandateBodyTermsDigest(credential: {
  id: string;
  validFrom?: string;
  validUntil?: string;
  credentialSubject: { id: string; mandate: Record<string, unknown> };
}): string {
  const { grantor: _g, grantorBinding: _b, ...terms } = credential.credentialSubject.mandate;
  return actionHash(`grant:${credential.id}`, "grant", {
    subject: credential.credentialSubject.id,
    mandate: terms,
    ...(credential.validFrom ? { validFrom: credential.validFrom } : {}),
    ...(credential.validUntil ? { validUntil: credential.validUntil } : {}),
  });
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

/**
 * Build the signed-into-the-mandate `grantorBinding` after a successful passkey verify (§17.2).
 *
 * `termsDigest` is what turns "the person was present" into "the person approved THESE terms".
 * It is optional because a deployment whose ceremony binds only a session nonce (§17.3's status
 * note) has nothing to put there, and writing a digest nobody signed would be worse than leaving
 * the field out.
 */
export function buildGrantorBinding(
  grantorDid: string,
  thumbprint: string,
  verifiedAt: string,
  termsDigest?: string,
  page?: GrantorCeremonyPage,
): WebauthnGrantorBinding {
  return {
    grantor: grantorDid,
    cnf: { jkt: thumbprint },
    method: "webauthn",
    verifiedAt,
    ...(termsDigest ? { termsDigest } : {}),
    ...(page ? { origin: page.origin, ...(page.topOrigin ? { topOrigin: page.topOrigin } : {}) } : {}),
  };
}

/**
 * The same field for the code path (§17.2): who consented, how they were reached, and when that was
 * verified. `verifiedAt` is the instant the CODE was accepted, not the instant of the decision.
 *
 * Deliberately not a `cnf`-shaped object with an empty key: a reader must be able to tell at a glance
 * that no key signed anything here. What this buys is that absence of a binding now means exactly
 * one thing — nobody recorded it — so no verifier has to guess a method from an empty field.
 */
export function buildOtpGrantorBinding(
  grantorDid: string,
  channel: GrantorChannel,
  verifiedAt: string,
): OtpGrantorBinding {
  return { grantor: grantorDid, method: "otp", channel, verifiedAt };
}
