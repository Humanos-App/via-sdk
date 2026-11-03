// WebAuthn assertion verification — shared by the §16 `webauthn` agent rung and the
// §17 grantor passkey. Verifies a `navigator.credentials.get` assertion: clientData
// (type/origin/challenge), the rpIdHash + user-present flag in authenticatorData, and
// the ES256 signature over `authenticatorData ‖ SHA-256(clientDataJSON)`. Ported
// byte-faithfully from `kya/crypto`. The `challenge` is `b64u(nonce · actionHash)`.
import { sha256 } from "./digest.js";
import { toBase64Url, fromBase64Url } from "./encoding.js";
import { verifyES256, type Jwk } from "./p256.js";
import type { AgentReasonCode } from "../agent/types.js";

const te = new TextEncoder();

export interface WebauthnAssertionInput {
  authenticatorDataB64: string;
  clientDataJSONB64: string;
  signatureB64: string;
}

/** Verify a WebAuthn assertion against the credential's public key (`cnf`) and the expected ceremony. */
export async function verifyWebauthnAssertion(
  a: WebauthnAssertionInput,
  cnf: Jwk,
  expected: { nonce: string; actionHash: string; rpId: string; origin: string },
): Promise<{ ok: boolean; reason?: AgentReasonCode }> {
  try {
    const clientDataJSON = fromBase64Url(a.clientDataJSONB64);
    const cd = JSON.parse(Buffer.from(clientDataJSON).toString("utf8")) as {
      type?: string;
      origin?: string;
      challenge?: string;
    };
    if (cd.type !== "webauthn.get" || cd.origin !== expected.origin) return { ok: false, reason: "pop_invalid" };
    const wantChallenge = toBase64Url(te.encode(`${expected.nonce}.${expected.actionHash}`));
    if (cd.challenge !== wantChallenge) return { ok: false, reason: "action_hash_mismatch" };

    const authData = fromBase64Url(a.authenticatorDataB64);
    if (authData.length < 37) return { ok: false, reason: "pop_invalid" };
    const rpIdHash = authData.slice(0, 32);
    if (!bytesEqual(rpIdHash, sha256(te.encode(expected.rpId)))) return { ok: false, reason: "pop_invalid" };
    if ((authData[32]! & 0x01) === 0) return { ok: false, reason: "pop_invalid" }; // require user-present

    // WebAuthn signs authenticatorData ‖ SHA-256(clientDataJSON). verifyES256 accepts
    // the DER signature real authenticators emit (and raw r‖s from our sim).
    const signed = concat(authData, sha256(clientDataJSON));
    const ok = await verifyES256(signed, fromBase64Url(a.signatureB64), cnf);
    return ok ? { ok: true } : { ok: false, reason: "pop_invalid" };
  } catch {
    return { ok: false, reason: "pop_invalid" };
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const o = new Uint8Array(a.length + b.length);
  o.set(a, 0);
  o.set(b, a.length);
  return o;
}
