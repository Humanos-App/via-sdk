// Proof-of-Possession (§16.6) — the per-action authenticator. A compact JWS
// (`typ: via-pop+jwt`, `alg: ES256`) signed inside the agent's confinement
// boundary. Split into decode (A1) + signature check (A3) so the verify path
// (§16.7) can select the bound key (A2) between them.
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { computeSRI } from "../crypto/digest.js";
import { toBase64Url, fromBase64Url } from "../crypto/encoding.js";
import { signES256, verifyES256, type Jwk } from "../crypto/p256.js";
import type { AgentReasonCode } from "./types.js";

const te = new TextEncoder();

/** The PoP payload (§16.6). `cnf.jkt` selects the bound key; `action_hash` binds the transaction. */
export interface PopPayload {
  cnf: { jkt: string }; // RFC 7800 confirmation — thumbprint selector (D2)
  aud: string; // the verifier
  nonce: string; // server-issued, single-use
  iat: number;
  action_hash: string; // digestSRI( JCS({ mandateId, action, params }) )
}

/**
 * `action_hash` — the §5.3 `digestSRI` (`sha256-` + base64) of
 * `JCS({ mandateId, action, params })`. Binds a PoP to *this* transaction, closing
 * the base-spec gap that `executionParams` reach verify unsigned (§16.6).
 */
export function actionHash(mandateId: string, action: string, params: Record<string, unknown>): string {
  return computeSRI(canonicalizeRFC8785({ mandateId, action, params }));
}

/** Build a signed `via-pop+jwt` (ES256) over the payload — signed with the agent's private JWK. */
export async function buildPoP(payload: PopPayload, privateJwk: Jwk): Promise<string> {
  const header = { alg: "ES256", typ: "via-pop+jwt" };
  const h = toBase64Url(te.encode(JSON.stringify(header)));
  const p = toBase64Url(te.encode(JSON.stringify(payload)));
  const signingInput = `${h}.${p}`;
  const sig = await signES256(te.encode(signingInput), privateJwk);
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
 * Decode + structural check (§16.7 **A1**): `typ == via-pop+jwt`, `alg == ES256`
 * (RFC 8725 §3.11 / D3 — ES256 only), and a usable `cnf` thumbprint. Does NOT check
 * the signature — the caller resolves the bound key (A2) then calls
 * {@link verifyPoPSignature} (A3). Tolerates a bare-string `cnf` during the kya
 * migration window (target form is the RFC 7800 object `{jkt}`).
 */
export function decodePoP(jws: string): DecodedPoP {
  try {
    const parts = jws.split(".");
    if (parts.length !== 3) return { ok: false, reason: "pop_invalid" };
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as { alg?: string; typ?: string };
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as PopPayload & { cnf?: unknown };
    if (header.typ !== "via-pop+jwt") return { ok: false, reason: "pop_invalid" };
    if (header.alg !== "ES256") return { ok: false, reason: "pop_invalid" }; // D3
    const cnf = payload?.cnf as { jkt?: string } | string | undefined;
    const jkt = typeof cnf === "string" ? cnf : cnf?.jkt;
    if (!payload || typeof jkt !== "string") return { ok: false, reason: "pop_invalid" };
    return { ok: true, payload, jkt, alg: header.alg };
  } catch {
    return { ok: false, reason: "pop_invalid" };
  }
}

/** Signature check (§16.7 **A3**) — the JWS signature over `header.payload`, against the bound key's JWK. */
export async function verifyPoPSignature(jws: string, publicJwk: Jwk): Promise<boolean> {
  const parts = jws.split(".");
  if (parts.length !== 3) return false;
  const signingInput = te.encode(`${parts[0]}.${parts[1]}`);
  return verifyES256(signingInput, fromBase64Url(parts[2]!), publicJwk);
}
