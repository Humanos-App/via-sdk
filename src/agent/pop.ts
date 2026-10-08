// Proof-of-Possession (§16.6) — the per-action authenticator. A compact JWS
// (`typ: via-pop+jwt`, `alg: ES256`) signed inside the agent's confinement
// boundary. Split into decode (A1) + signature check (A3) so the verify path
// (§16.7) can select the bound key (A2) between them.
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import { toBase64Url, fromBase64Url } from "../crypto/encoding.js";
import { signES256, verifyES256, type Jwk } from "../crypto/p256.js";
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import type { AgentReasonCode } from "./types.js";

const te = new TextEncoder();

/**
 * Sign/verify a JWS for the three algorithms a PoP may use.
 *
 * ES256 keeps the SDK's own P-256 path — it is the hot one, and it is already audited. RS256 and
 * EdDSA go through Node's JWK import, which exists precisely so a WebAuthn credential we did not
 * choose the shape of can still be checked.
 *
 * The `alg` is always passed IN, never read from the token: every caller here has already derived
 * it from the key.
 */
async function signJws(alg: string, data: Uint8Array, privateJwk: Jwk): Promise<Uint8Array> {
  if (alg === "ES256") return signES256(data, privateJwk);
  const key = createPrivateKey({ key: privateJwk as never, format: "jwk" });
  // EdDSA takes no digest — the algorithm fixes it. RS256 is RSASSA-PKCS1-v1_5 with SHA-256.
  return new Uint8Array(alg === "EdDSA" ? nodeSign(null, data, key) : nodeSign("sha256", data, key));
}

async function verifyJws(alg: string, data: Uint8Array, sig: Uint8Array, publicJwk: Jwk): Promise<boolean> {
  if (alg === "ES256") return verifyES256(data, sig, publicJwk);
  try {
    const key = createPublicKey({ key: publicJwk as never, format: "jwk" });
    return alg === "EdDSA" ? nodeVerify(null, data, key, sig) : nodeVerify("sha256", data, key, sig);
  } catch {
    return false; // an unimportable key is a refusal, not an exception
  }
}

/** The PoP payload (§16.6). `cnf.jkt` selects the bound key; `action_hash` binds the transaction. */
export interface PopPayload {
  cnf: { jkt: string }; // RFC 7800 confirmation — thumbprint selector (D2)
  aud: string; // the verifier
  nonce: string; // server-issued, single-use
  iat: number;
  action_hash: string; // digestSRI( JCS({ mandateId, action, params }) )
}

/**
 * `action_hash` — the §0.5.3 `digestSRI` (`sha256-` + base64) of
 * `JCS({ mandateId, action, params })`. Binds a PoP to *this* transaction, closing
 * the base-spec gap that `executionParams` reach verify unsigned (§16.6).
 */
export function actionHash(mandateId: string, action: string, params: Record<string, unknown>): string {
  return computeSRI(canonicalizeRFC8785({ mandateId, action, params }));
}

/**
 * The algorithm a key can sign with — derived from the KEY, never read from a header (§16.6).
 *
 * This is the whole of RFC 8725 §3.1 in one function. If a verifier selects its verification
 * routine from the JWS header, an attacker chooses the algorithm; the only safe order is to resolve
 * the key first and let the key say what it may do. Returns null for anything unrecognised —
 * symmetric algorithms and `none` never appear here, so they can never be selected.
 */
export function algForKey(jwk: Jwk): "ES256" | "RS256" | "EdDSA" | null {
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "EdDSA";
  if (jwk.kty === "RSA") {
    // A 512-bit RSA key is forgeable today. `n` is base64url of the big-endian modulus, so its byte
    // length is the key size: 2048 bits = 256 bytes. Without this floor an attacker registers a
    // tiny key and every signature it makes verifies honestly.
    const n = typeof jwk.n === "string" ? jwk.n : "";
    const bytes = Math.floor((n.length * 3) / 4);
    return bytes >= 256 ? "RS256" : null;
  }
  return null;
}

/**
 * Which algorithms an actor's PoP may use (§16.6).
 *
 * **Agents are ES256-only, and that is not an oversight.** §16.2 chose P-256 deliberately:
 * hardware substrates speak it and Ed25519 has no attestation ecosystem — and the ISSUER controls
 * an agent's key, so the choice is ours to make.
 *
 * **A person's key is chosen by their authenticator, not by us.** Windows Hello on a TPM registers
 * RS256; some security keys emit EdDSA. Holding people to ES256 would exclude them from ever
 * presenting directly — a §17.4 step-up, a grantor re-authorization — on an algorithm constraint
 * written for a different key family.
 */
export function allowedPopAlgs(actorType?: string): ReadonlySet<string> {
  return actorType === "user" || actorType === "organization"
    ? new Set(["ES256", "RS256", "EdDSA"])
    : new Set(["ES256"]);
}

/**
 * Build a signed `via-pop+jwt` over the payload, signed with the private JWK.
 *
 * The header's `alg` is DERIVED from the key rather than passed in: a caller that could name the
 * algorithm could name one the key cannot honour, and the mismatch would only surface at the
 * verifier as an unexplained signature failure.
 */
export async function buildPoP(payload: PopPayload, privateJwk: Jwk): Promise<string> {
  const alg = algForKey(privateJwk);
  if (!alg) throw new Error("unsupported PoP key: expected EC P-256, RSA >= 2048, or OKP Ed25519");
  const header = { alg, typ: "via-pop+jwt" };
  const h = toBase64Url(te.encode(JSON.stringify(header)));
  const p = toBase64Url(te.encode(JSON.stringify(payload)));
  const signingInput = `${h}.${p}`;
  const sig = await signJws(alg, te.encode(signingInput), privateJwk);
  return `${signingInput}.${toBase64Url(sig)}`;
}

export interface DecodedPoP {
  ok: boolean;
  payload?: PopPayload;
  /** The bound-key selector thumbprint (A2). */
  jkt?: string;
  alg?: string;
  reason?: AgentReasonCode;
}

/**
 * Decode + structural check (§16.7 **A1**): `typ == via-pop+jwt`, a *recognised* `alg`, and a
 * usable `cnf` thumbprint. Does NOT check the signature, and deliberately does NOT decide whether
 * the algorithm is ACCEPTABLE — that needs the key, which the caller resolves at A2 before calling
 * {@link verifyPoPSignature} (A3).
 *
 * The header's `alg` is therefore read only to reject obvious garbage. It never selects a
 * verification routine (RFC 8725 §3.1); {@link algForKey} does that from the resolved key.
 * Tolerates a bare-string `cnf` during the kya migration window (target form is `{jkt}`).
 */
export function decodePoP(jws: string): DecodedPoP {
  try {
    const parts = jws.split(".");
    if (parts.length !== 3) return { ok: false, reason: "pop_invalid" };
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as { alg?: string; typ?: string };
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as PopPayload & { cnf?: unknown };
    if (header.typ !== "via-pop+jwt") return { ok: false, reason: "pop_invalid" };
    // Recognised-but-not-yet-authorised. `none` and every symmetric `HS*` die here and can never
    // reach the key-based check below.
    if (!header.alg || !["ES256", "RS256", "EdDSA"].includes(header.alg)) {
      return { ok: false, reason: "pop_invalid" };
    }
    const cnf = payload?.cnf as { jkt?: string } | string | undefined;
    const jkt = typeof cnf === "string" ? cnf : cnf?.jkt;
    if (!payload || typeof jkt !== "string") return { ok: false, reason: "pop_invalid" };
    return { ok: true, payload, jkt, alg: header.alg };
  } catch {
    return { ok: false, reason: "pop_invalid" };
  }
}

/**
 * Signature check (§16.7 **A3**) — the JWS over `header.payload`, against the bound key's JWK.
 *
 * **The key decides the algorithm.** The header's `alg` must MATCH what the resolved key can do, and
 * a mismatch is a refusal rather than a fallback: that is the algorithm-confusion defence, and it
 * only works in this order. `allowed` additionally scopes by actor type — an agent presenting an
 * RS256 PoP is refused even though the key could sign it, because §16.2 fixed agent keys at P-256.
 */
export async function verifyPoPSignature(
  jws: string,
  publicJwk: Jwk,
  allowed: ReadonlySet<string> = allowedPopAlgs(),
): Promise<boolean> {
  const parts = jws.split(".");
  if (parts.length !== 3) return false;
  const expected = algForKey(publicJwk);
  if (!expected || !allowed.has(expected)) return false;
  let header: { alg?: string };
  try {
    header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as { alg?: string };
  } catch {
    return false;
  }
  if (header.alg !== expected) return false; // the header claimed something this key cannot do
  const signingInput = te.encode(`${parts[0]}.${parts[1]}`);
  return verifyJws(expected, signingInput, fromBase64Url(parts[2]!), publicJwk);
}
