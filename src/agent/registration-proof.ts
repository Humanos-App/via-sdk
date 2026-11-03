// Registration proof (§16.5) — the key being registered signs the registration nonce, so a
// registration proves the registrant HOLDS the key, not merely that it knows the public half.
// Without it anyone could register a public key they do not hold, first come first served, and
// lock its owner out (decided 2026-10-14). A compact JWS like the PoP (§16.6), with its own `typ`
// so neither can ever pass as the other.
import { toBase64Url, fromBase64Url } from "../crypto/encoding.js";
import { signES256, verifyES256, jwkThumbprint, type Jwk } from "../crypto/p256.js";
import { algForKey } from "./pop.js";

/** The registration proof's JWS `typ`. Never `via-pop+jwt`: a call's PoP is not a registration's. */
export const REG_PROOF_TYP = "via-reg+jwt";

/** The registration proof's payload (§16.5). */
export interface RegProofPayload {
  /** Thumbprint of the key being registered — the key that signs. */
  cnf: { jkt: string };
  /** The verifier's DID, as its registration challenge returned it. */
  aud: string;
  /** The `regNonce` the challenge issued. */
  nonce: string;
  iat: number;
}

const te = new TextEncoder();

/**
 * Sign a `via-reg+jwt` (ES256) with the key being registered: a private JWK, or a delegated signer
 * for a key that never leaves its KMS or enclave (raw r‖s over the bytes, as `signES256` returns).
 */
export async function buildRegistrationProof(
  payload: RegProofPayload,
  key: Jwk | ((bytes: Uint8Array) => Promise<Uint8Array>),
): Promise<string> {
  const header = { alg: "ES256", typ: REG_PROOF_TYP };
  const signingInput = `${toBase64Url(te.encode(JSON.stringify(header)))}.${toBase64Url(te.encode(JSON.stringify(payload)))}`;
  const bytes = te.encode(signingInput);
  const sig = typeof key === "function" ? await key(bytes) : await signES256(bytes, key);
  return `${signingInput}.${toBase64Url(sig)}`;
}

/**
 * Check a registration proof against the key being registered, the verifier's own DID and the
 * nonce it issued. True only when all hold: `typ` `via-reg+jwt`, an ES256 signature by THAT key
 * (agent keys are P-256, §16.2 — the key decides the algorithm, never the header), `cnf.jkt` its
 * thumbprint, `aud` and `nonce` the expected values. Whether the nonce is still outstanding is the
 * caller's check, against its challenge store.
 */
export async function verifyRegistrationProof(
  jws: unknown,
  expected: { jwk: Jwk; aud: string; nonce: string },
): Promise<boolean> {
  if (typeof jws !== "string") return false;
  const parts = jws.split(".");
  if (parts.length !== 3) return false;
  if (algForKey(expected.jwk) !== "ES256") return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as { alg?: unknown; typ?: unknown };
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as Partial<RegProofPayload> | null;
    if (header.typ !== REG_PROOF_TYP || header.alg !== "ES256") return false;
    if (!payload || payload.cnf?.jkt !== jwkThumbprint(expected.jwk)) return false;
    if (payload.aud !== expected.aud || payload.nonce !== expected.nonce || typeof payload.iat !== "number") return false;
    return await verifyES256(te.encode(`${parts[0]}.${parts[1]}`), fromBase64Url(parts[2]!), expected.jwk);
  } catch {
    return false;
  }
}
