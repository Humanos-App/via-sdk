// P-256 / ES256 — the agent-key curve (VIA §16.2). The base spec is Ed25519-only;
// agent binding (§16) needs P-256 because hardware substrates (AWS KMS, WebAuthn,
// W3C DBSC, AWS Nitro) speak it. Ported to be byte-compatible with `kya/crypto`
// during Phase 3 convergence: WebCrypto ECDSA-P-256, signatures are raw r‖s (64
// bytes) == JWS ES256; verify also accepts DER (real WebAuthn) by normalising.
import { webcrypto } from "node:crypto";
import { sha256 } from "./digest.js";
import { canonicalizeRFC8785 } from "./canonicalize.js";
import { toBase64Url } from "./encoding.js";

const subtle = webcrypto.subtle;
const EC_ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const ES256 = { name: "ECDSA", hash: "SHA-256" } as const;
const te = new TextEncoder();

/** A JSON Web Key. `d` present ⇒ private. For agents this is always EC/P-256. */
export type Jwk = { kty: string; crv?: string; x?: string; y?: string; d?: string; [k: string]: unknown };

export interface P256KeyPair {
  /** Full private JWK (carries `d`) — held inside the agent's confinement boundary. */
  privateJwk: Jwk;
  /** Public JWK `{kty,crv,x,y}` — the `cnf.jwk` bound into the mandate (§16.4). */
  publicJwk: Jwk;
}

/** Generate a fresh P-256 keypair, returned as JWKs (the portable agent-key form). */
export async function generateP256Key(): Promise<P256KeyPair> {
  const kp = (await subtle.generateKey(EC_ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const privateJwk = (await subtle.exportKey("jwk", kp.privateKey)) as Jwk;
  const publicJwk = cleanPublicJwk((await subtle.exportKey("jwk", kp.publicKey)) as Jwk);
  return { privateJwk, publicJwk };
}

/** The public half `{kty,crv,x,y}` of a JWK — drops `d` and any non-canonical members. */
export function cleanPublicJwk(jwk: Jwk): Jwk {
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

/** ES256 sign — returns the raw `r‖s` (64-byte) signature (== JWS ES256, == our COSE). */
export async function signES256(message: Uint8Array, privateJwk: Jwk): Promise<Uint8Array> {
  const key = await subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: privateJwk.x, y: privateJwk.y, d: privateJwk.d },
    EC_ALG,
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle.sign(ES256, key, message));
}

/** ES256 verify — accepts raw `r‖s` (WebCrypto/our sim) OR DER (real WebAuthn), normalising DER→raw. */
export async function verifyES256(message: Uint8Array, signature: Uint8Array, publicJwk: Jwk): Promise<boolean> {
  try {
    const key = await subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: publicJwk.x, y: publicJwk.y },
      EC_ALG,
      false,
      ["verify"],
    );
    const raw = signature.length === 64 ? signature : derToRawEcdsa(signature);
    if (!raw) return false;
    return await subtle.verify(ES256, key, raw, message);
  } catch {
    return false;
  }
}

/**
 * RFC 7638 JWK thumbprint — base64url(SHA-256(canonical JSON of the REQUIRED
 * members)). EC → `{crv,kty,x,y}`; OKP → `{crv,kty,x}`; RSA → `{e,kty,n}`. This is
 * the `jkt` a PoP uses to select its bound key (§16.6). Byte-identical to
 * `kya/crypto` `jwkThumbprint`.
 */
export function jwkThumbprint(jwk: Jwk): string {
  let required: Record<string, unknown>;
  if (jwk.kty === "EC") required = { crv: jwk.crv, kty: "EC", x: jwk.x, y: jwk.y };
  else if (jwk.kty === "OKP") required = { crv: jwk.crv, kty: "OKP", x: jwk.x };
  else if (jwk.kty === "RSA") required = { e: jwk.e, kty: "RSA", n: jwk.n };
  else throw new Error(`jwkThumbprint: unsupported kty ${jwk.kty}`);
  return toBase64Url(sha256(te.encode(canonicalizeRFC8785(required))));
}

// DER SEQUENCE{ INTEGER r, INTEGER s } → 64-byte r‖s (P-256). Ported from kya/crypto.
function derToRawEcdsa(der: Uint8Array): Uint8Array | null {
  try {
    if (der[0] !== 0x30) return null;
    let i = 2;
    if (der[1]! & 0x80) i = 2 + (der[1]! & 0x7f); // long-form length
    if (der[i] !== 0x02) return null;
    const rLen = der[i + 1]!;
    const r = der.slice(i + 2, i + 2 + rLen);
    i = i + 2 + rLen;
    if (der[i] !== 0x02) return null;
    const sLen = der[i + 1]!;
    const s = der.slice(i + 2, i + 2 + sLen);
    const rt = trimOrPad(r);
    const st = trimOrPad(s);
    const out = new Uint8Array(64);
    out.set(rt, 32 - rt.length);
    out.set(st, 64 - st.length);
    return out;
  } catch {
    return null;
  }
}

function trimOrPad(x: Uint8Array): Uint8Array {
  let start = 0;
  while (start < x.length - 1 && x[start] === 0) start++;
  return x.slice(start, x.length);
}
