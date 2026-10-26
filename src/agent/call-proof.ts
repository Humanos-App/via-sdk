// The call proof (§16.16) — the verifier's `allow`, shown to the party the agent calls. A compact JWS
// (`typ: via-call-proof+jwt`) signed when the decision is made, naming its receiver (`aud`), the one
// call it covers (`action_hash`), a life of at most five minutes and a single-use `jti`. The receiver
// checks it offline against the signer's published key. Redemption at Humanos is the platform's.
import { randomUUID } from "node:crypto";
import { signRaw, verifyRaw } from "../crypto/ed25519.js";
import { toBase64Url, fromBase64Url } from "../crypto/encoding.js";
import { didFromUrl } from "../did/web.js";
import type { EventSigner } from "../event/build.js";
import type { ResolvePublicKey } from "../mandate/build.js";
import { actionHash, policyActionHash } from "./pop.js";

/** The call proof's JWS `typ`. Never `via-pop+jwt`: the agent's proof is not the verifier's. */
export const CALL_PROOF_TYP = "via-call-proof+jwt";
/** The HTTP header that carries it (§16.16). */
export const CALL_PROOF_HEADER = "Humanos-Call-Proof";
/** Where an MCP `tools/call` carries it: `params._meta["tech.humanos/call-proof"]` (§16.16). */
export const CALL_PROOF_META_KEY = "tech.humanos/call-proof";
/** `exp − iat` at most this many seconds (§16.16). */
export const CALL_PROOF_MAX_LIFETIME = 300;

/** The claims (§16.16). Exactly one of `mandate` and `policy` (§21.4). */
export interface CallProofClaims {
  /** The verifier's DID — the signer of the `VERIFICATION_APPROVED` it presents. */
  iss: string;
  /** The agent's DID. */
  sub: string;
  /** The party the call goes to: its DID, or its origin. */
  aud: string;
  mandate?: string;
  policy?: string;
  /** The `VERIFICATION_APPROVED` event's URN. */
  decision: string;
  action_hash: string;
  iat: number;
  exp: number;
  jti: string;
}

/** The call a proof covers: its tool or operation, and its arguments. */
export interface CallProofCall {
  action: string;
  params: Record<string, unknown>;
}

/** Why a receiver refused a call proof — one reason per check of §16.16, in order. */
export type CallProofReason =
  | "call_proof_invalid"
  | "signature_invalid"
  | "aud_mismatch"
  | "call_proof_expired"
  | "action_hash_mismatch"
  | "call_proof_replayed";

const te = new TextEncoder();

/**
 * Sign a call proof for an `allow` (§16.16), with the key that signs the decision event — the
 * verifier's Ed25519 key, so `alg` is `EdDSA` and `kid` its verification method, which must be under
 * `iss`. `action_hash` is computed from `call`, bound to `mandate` or, with no mandate, `policy`.
 */
export function buildCallProof(
  input: {
    iss: string;
    sub: string;
    aud: string;
    decision: string;
    call: CallProofCall;
    /** Seconds since the epoch; defaults to now. */
    iat?: number;
    /** Defaults to, and may not exceed, {@link CALL_PROOF_MAX_LIFETIME}. */
    ttlSeconds?: number;
    jti?: string;
  } & ({ mandate: string; policy?: never } | { policy: string; mandate?: never }),
  signer: EventSigner,
): string {
  const ttl = input.ttlSeconds ?? CALL_PROOF_MAX_LIFETIME;
  if (!(ttl > 0 && ttl <= CALL_PROOF_MAX_LIFETIME)) {
    throw new Error(`a call proof lives between 1 and ${CALL_PROOF_MAX_LIFETIME} seconds`);
  }
  if (didFromUrl(signer.verificationMethod) !== input.iss) {
    throw new Error("the call proof's key must be a verification method of its iss");
  }
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const claims: CallProofClaims = {
    iss: input.iss,
    sub: input.sub,
    aud: input.aud,
    ...(input.mandate !== undefined ? { mandate: input.mandate } : { policy: input.policy }),
    decision: input.decision,
    action_hash: _callHash(input, input.call),
    iat,
    exp: iat + ttl,
    jti: input.jti ?? randomUUID(),
  };
  const header = { alg: "EdDSA", typ: CALL_PROOF_TYP, kid: signer.verificationMethod };
  const signingInput = `${toBase64Url(te.encode(JSON.stringify(header)))}.${toBase64Url(te.encode(JSON.stringify(claims)))}`;
  return `${signingInput}.${toBase64Url(signRaw(te.encode(signingInput), signer.privateKey))}`;
}

/**
 * The receiver's check (§16.16), in order; the first failure refuses the call: `typ` and the
 * signature under the key `kid` names, resolved from `iss`'s DID document; `aud` is the receiver;
 * `iat ≤ now ≤ exp` within `skewSeconds`; `action_hash` is the call received; `jti` not seen before.
 *
 * `consumeJti` records a `jti` until its `exp` and answers `true` the first time, `false` after.
 */
export async function verifyCallProof(
  token: unknown,
  opts: {
    /** The receiver: its DID or origin — several when it answers to more than one. */
    audience: string | readonly string[];
    resolvePublicKey: ResolvePublicKey;
    call: CallProofCall;
    consumeJti: (jti: string, exp: number) => boolean | Promise<boolean>;
    now?: Date;
    /** Defaults to 30. */
    skewSeconds?: number;
  },
): Promise<{ ok: true; claims: CallProofClaims } | { ok: false; reason: CallProofReason }> {
  const decoded = _decode(token);
  if (!decoded) return { ok: false, reason: "call_proof_invalid" };
  const { kid, claims, signingInput, signature } = decoded;

  try {
    const key = await opts.resolvePublicKey(kid);
    if (!verifyRaw(te.encode(signingInput), signature, key)) return { ok: false, reason: "signature_invalid" };
  } catch {
    return { ok: false, reason: "signature_invalid" }; // an unresolvable key proves nothing
  }

  const audiences: readonly string[] = typeof opts.audience === "string" ? [opts.audience] : opts.audience;
  if (!audiences.includes(claims.aud)) return { ok: false, reason: "aud_mismatch" };

  const now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const skew = opts.skewSeconds ?? 30;
  if (claims.iat > now + skew || now - skew > claims.exp) return { ok: false, reason: "call_proof_expired" };

  if (claims.action_hash !== _callHash(claims, opts.call)) return { ok: false, reason: "action_hash_mismatch" };

  if (!(await opts.consumeJti(claims.jti, claims.exp))) return { ok: false, reason: "call_proof_replayed" };
  return { ok: true, claims };
}

/** `action_hash` as the PoP's (§16.6): over `mandate` as `mandateId`, or under a policy, over `policy` (§21.4). */
function _callHash(authority: { mandate?: string; policy?: string }, call: CallProofCall): string {
  return authority.mandate !== undefined
    ? actionHash(authority.mandate, call.action, call.params)
    : policyActionHash(authority.policy!, call.action, call.params);
}

/** The structural half of check 1: a three-part JWS, `typ`, `EdDSA`, a `kid` under `iss`, well-formed claims. */
function _decode(token: unknown): { kid: string; claims: CallProofClaims; signingInput: string; signature: Uint8Array } | null {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as { alg?: unknown; typ?: unknown; kid?: unknown };
    const c = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as Partial<CallProofClaims> | null;
    if (header.typ !== CALL_PROOF_TYP || header.alg !== "EdDSA" || typeof header.kid !== "string") return null;
    if (!c || typeof c !== "object") return null;
    const strings = [c.iss, c.sub, c.aud, c.decision, c.action_hash, c.jti];
    if (!strings.every((s) => typeof s === "string" && s.length > 0)) return null;
    if ((typeof c.mandate === "string") === (typeof c.policy === "string")) return null; // exactly one
    if (!Number.isInteger(c.iat) || !Number.isInteger(c.exp)) return null;
    if (!(c.exp! > c.iat! && c.exp! - c.iat! <= CALL_PROOF_MAX_LIFETIME)) return null;
    if (didFromUrl(header.kid) !== c.iss) return null; // the key must be the signer's
    return { kid: header.kid, claims: c as CallProofClaims, signingInput: `${parts[0]}.${parts[1]}`, signature: fromBase64Url(parts[2]!) };
  } catch {
    return null;
  }
}
