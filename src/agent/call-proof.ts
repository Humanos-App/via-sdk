// The call proof (§16.16) — the verifier's `allow`, shown to the party the agent calls, with the platform's word on
// the agent beside it. Two compact JWS signed when the decision is made, for the same call and receiver:
// - the decision token (`typ: via-call-proof+jwt`): its receiver (`aud`), the one call it covers (`action_hash`), a
//   life of at most five minutes and a single-use `jti`. The platform signs it with its own key when it verifies for
//   an organization, and names the organization in `verifier` (2026-11-01);
// - the record token (`typ: via-agent-record+jwt`): the agent's record as the verification resolved it, signed by
//   the platform and bound to the decision token by `sub`, `aud` and `jti` (2026-11-01).
// The receiver checks both offline against their signers' published keys. Redemption at Humanos is the platform's.
import { randomUUID } from "node:crypto";
import { signRaw, verifyRaw } from "../crypto/ed25519.js";
import { toBase64Url, fromBase64Url } from "../crypto/encoding.js";
import { didFromUrl } from "../did/web.js";
import type { ActorStatus, BootstrapAnchor } from "../actor/model.js";
import type { EventSigner } from "../event/build.js";
import type { ResolvePublicKey } from "../mandate/build.js";
import type { AccreditationLevel, AccreditationMethod } from "../operator/types.js";
import type { Assurance, Binding } from "./types.js";
import { actionHash, policyActionHash } from "./pop.js";

/** The call proof's JWS `typ`. Never `via-pop+jwt`: the agent's proof is not the verifier's. */
export const CALL_PROOF_TYP = "via-call-proof+jwt";
/** The HTTP header that carries it (§16.16). */
export const CALL_PROOF_HEADER = "Humanos-Call-Proof";
/** Where an MCP `tools/call` carries it: `params._meta["tech.humanos/call-proof"]` (§16.16). */
export const CALL_PROOF_META_KEY = "tech.humanos/call-proof";
/** `exp − iat` at most this many seconds (§16.16). */
export const CALL_PROOF_MAX_LIFETIME = 300;
/** The record token's JWS `typ` (§16.16). */
export const AGENT_RECORD_TYP = "via-agent-record+jwt";
/** The HTTP header that carries the record token, beside {@link CALL_PROOF_HEADER}. */
export const AGENT_RECORD_HEADER = "Humanos-Agent-Record";
/** Where an MCP `tools/call` carries the record token: `params._meta["tech.humanos/agent-record"]`. */
export const AGENT_RECORD_META_KEY = "tech.humanos/agent-record";

/** The claims (§16.16). Exactly one of `mandate` and `policy` (§21.4). */
export interface CallProofClaims {
  /** Who signs it: the platform's DID when the platform verifies for an organization, otherwise the verifier's. */
  iss: string;
  /** The organization the platform verified for — present only when `iss` is a platform DID. */
  verifier?: string;
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

/** The agent's record as a receiver reads it (§16.16): the same fields to every receiver, nothing naming a person. */
export interface AgentRecordSummary {
  status: ActorStatus;
  /** The record's summary (§9.1bis rule 5); both absent when the record carries neither. */
  assurance?: Assurance;
  binding?: Binding;
  bootstrapAnchor: BootstrapAnchor;
  /** Who stands behind the agent: the record's `operator.org` and its effective accreditation (§18.4). */
  operator: { org: string; level: AccreditationLevel; method?: AccreditationMethod; registrar?: string };
}

/** The record token's claims (§16.16): `sub`, `aud`, `jti` are the decision token's own. */
export interface AgentRecordClaims {
  /** The platform's DID. */
  iss: string;
  sub: string;
  aud: string;
  jti: string;
  iat: number;
  exp: number;
  agent: AgentRecordSummary;
}

/** Why a receiver refused a call proof — one reason per check of §16.16, in order. */
export type CallProofReason =
  | "call_proof_invalid"
  | "signature_invalid"
  | "issuer_untrusted"
  | "aud_mismatch"
  | "call_proof_expired"
  | "action_hash_mismatch"
  | "call_proof_replayed"
  | "agent_record_missing"
  | "agent_record_invalid"
  | "agent_record_untrusted"
  | "agent_record_signature_invalid"
  | "agent_record_mismatch"
  | "agent_record_expired";

const te = new TextEncoder();
const STATUSES: readonly string[] = ["active", "suspended", "retired"];
const ASSURANCES: readonly string[] = ["pop", "device", "hardware"];
const BINDINGS: readonly string[] = ["self", "custodial", "attested"];
const ANCHORS: readonly string[] = ["api_key", "person", "manual"];
const LEVELS: readonly string[] = ["unverified", "domain", "verified"];
const METHODS: readonly string[] = ["dns-challenge", "kyc-doc", "kyb-registry", "eidas-substantial", "eidas-high"];

/**
 * Sign a call proof for an `allow` (§16.16), with the key that signs for `iss` — the platform's when it verifies for
 * an organization, which `verifier` then names. `alg` is `EdDSA` and `kid` the key's verification method, which must
 * be under `iss`. `action_hash` is computed from `call`, bound to `mandate` or, with no mandate, `policy`.
 */
export function buildCallProof(
  input: {
    iss: string;
    /** The organization the platform verified for; only with a platform `iss`. */
    verifier?: string;
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
    ...(input.verifier !== undefined ? { verifier: input.verifier } : {}),
    sub: input.sub,
    aud: input.aud,
    ...(input.mandate !== undefined ? { mandate: input.mandate } : { policy: input.policy }),
    decision: input.decision,
    action_hash: _callHash(input, input.call),
    iat,
    exp: iat + ttl,
    jti: input.jti ?? randomUUID(),
  };
  return _sign(CALL_PROOF_TYP, claims, signer);
}

/**
 * Sign the record token for a decision token just built (§16.16), with the platform's key: `iss` is the signer's
 * DID, and `sub`, `aud`, `jti`, `iat` and `exp` are the decision token's, so the record covers its call and lapses
 * with it. `agent` is the record the verification resolved; only its summary fields are signed, whatever else the
 * object carries.
 */
export function buildAgentRecord(decisionToken: string, agent: AgentRecordSummary, signer: EventSigner): string {
  const decision = _decode(decisionToken);
  if (!decision) throw new Error("an agent record is built for a well-formed decision token");
  const { sub, aud, jti, iat, exp } = decision.claims;
  const claims: AgentRecordClaims = {
    iss: didFromUrl(signer.verificationMethod),
    sub,
    aud,
    jti,
    iat,
    exp,
    agent: _summaryOf(agent),
  };
  return _sign(AGENT_RECORD_TYP, claims, signer);
}

/**
 * The receiver's check (§16.16), in order; the first failure refuses the call: `typ` and the signature under the key
 * `kid` names, resolved from `iss`'s DID document, and a platform `iss` one the receiver trusts; `aud` is the
 * receiver; `iat ≤ now ≤ exp` within `skewSeconds`; `action_hash` is the call received; `jti` not seen before. Then,
 * with a record token: its `typ`, a trusted platform `iss` and its signature; its `sub`, `aud` and `jti` the decision
 * token's, and its life within `now` and the decision token's.
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
    /** The platform DIDs this receiver trusts: a decision token naming a `verifier`, and every record token, is signed by one. */
    trustedPlatforms?: readonly string[];
    /** The record token carried beside the decision token. */
    agentRecord?: unknown;
    /** Refuse a call that carries no record token — a receiver MAY require one. */
    requireAgentRecord?: boolean;
    now?: Date;
    /** Defaults to 30. */
    skewSeconds?: number;
  },
): Promise<{ ok: true; claims: CallProofClaims; agent?: AgentRecordSummary } | { ok: false; reason: CallProofReason }> {
  const decoded = _decode(token);
  if (!decoded) return { ok: false, reason: "call_proof_invalid" };
  const { claims } = decoded;
  if (!(await _signed(decoded, opts.resolvePublicKey))) return { ok: false, reason: "signature_invalid" };
  const trusted = opts.trustedPlatforms ?? [];
  if (claims.verifier !== undefined && !trusted.includes(claims.iss)) return { ok: false, reason: "issuer_untrusted" };

  const audiences: readonly string[] = typeof opts.audience === "string" ? [opts.audience] : opts.audience;
  if (!audiences.includes(claims.aud)) return { ok: false, reason: "aud_mismatch" };

  const now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const skew = opts.skewSeconds ?? 30;
  if (!_live(claims, now, skew)) return { ok: false, reason: "call_proof_expired" };

  if (claims.action_hash !== _callHash(claims, opts.call)) return { ok: false, reason: "action_hash_mismatch" };

  if (!(await opts.consumeJti(claims.jti, claims.exp))) return { ok: false, reason: "call_proof_replayed" };

  if (opts.agentRecord === undefined) {
    return opts.requireAgentRecord ? { ok: false, reason: "agent_record_missing" } : { ok: true, claims };
  }
  const record = _decodeRecord(opts.agentRecord);
  if (!record) return { ok: false, reason: "agent_record_invalid" };
  if (!trusted.includes(record.claims.iss)) return { ok: false, reason: "agent_record_untrusted" };
  if (!(await _signed(record, opts.resolvePublicKey))) return { ok: false, reason: "agent_record_signature_invalid" };
  const r = record.claims;
  if (r.sub !== claims.sub || r.aud !== claims.aud || r.jti !== claims.jti || r.exp > claims.exp) {
    return { ok: false, reason: "agent_record_mismatch" };
  }
  if (!_live(r, now, skew)) return { ok: false, reason: "agent_record_expired" };
  return { ok: true, claims, agent: r.agent };
}

/** `action_hash` as the PoP's (§16.6): over `mandate` as `mandateId`, or under a policy, over `policy` (§21.4). */
function _callHash(authority: { mandate?: string; policy?: string }, call: CallProofCall): string {
  return authority.mandate !== undefined
    ? actionHash(authority.mandate, call.action, call.params)
    : policyActionHash(authority.policy!, call.action, call.params);
}

/** A compact EdDSA JWS of `claims`, `kid` the signer's verification method. */
function _sign(typ: string, claims: CallProofClaims | AgentRecordClaims, signer: EventSigner): string {
  const header = { alg: "EdDSA", typ, kid: signer.verificationMethod };
  const signingInput = `${toBase64Url(te.encode(JSON.stringify(header)))}.${toBase64Url(te.encode(JSON.stringify(claims)))}`;
  return `${signingInput}.${toBase64Url(signRaw(te.encode(signingInput), signer.privateKey))}`;
}

/** The signature under the key `kid` names; an unresolvable key proves nothing. */
async function _signed(jws: { kid: string; signingInput: string; signature: Uint8Array }, resolve: ResolvePublicKey): Promise<boolean> {
  try {
    return verifyRaw(te.encode(jws.signingInput), jws.signature, await resolve(jws.kid));
  } catch {
    return false;
  }
}

function _live(c: { iat: number; exp: number }, now: number, skew: number): boolean {
  return c.iat <= now + skew && now - skew <= c.exp;
}

/** Only the summary's fields, so nothing else on the record — a person's DID in `anchoredBy` — is ever signed. */
function _summaryOf(a: AgentRecordSummary): AgentRecordSummary {
  const { org, level, method, registrar } = a.operator;
  return {
    status: a.status,
    ...(a.assurance !== undefined ? { assurance: a.assurance } : {}),
    ...(a.binding !== undefined ? { binding: a.binding } : {}),
    bootstrapAnchor: a.bootstrapAnchor,
    operator: { org, level, ...(method !== undefined ? { method } : {}), ...(registrar !== undefined ? { registrar } : {}) },
  };
}

/** A three-part EdDSA JWS of `typ`, with a `kid` under its claims' `iss`, and a life of at most five minutes. */
function _parts(token: unknown, typ: string): { kid: string; claims: Record<string, unknown>; signingInput: string; signature: Uint8Array } | null {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as { alg?: unknown; typ?: unknown; kid?: unknown };
    const c = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as Record<string, unknown> | null;
    if (header.typ !== typ || header.alg !== "EdDSA" || typeof header.kid !== "string") return null;
    if (!c || typeof c !== "object") return null;
    if (!Number.isInteger(c.iat) || !Number.isInteger(c.exp)) return null;
    const iat = c.iat as number;
    const exp = c.exp as number;
    if (!(exp > iat && exp - iat <= CALL_PROOF_MAX_LIFETIME)) return null;
    if (didFromUrl(header.kid) !== c.iss) return null; // the key must be the signer's
    return { kid: header.kid, claims: c, signingInput: `${parts[0]}.${parts[1]}`, signature: fromBase64Url(parts[2]!) };
  } catch {
    return null;
  }
}

function _strings(c: Record<string, unknown>, keys: readonly string[]): boolean {
  return keys.every((k) => typeof c[k] === "string" && (c[k] as string).length > 0);
}

/** The structural half of check 1: `typ`, `EdDSA`, a `kid` under `iss`, well-formed claims. */
function _decode(token: unknown): { kid: string; claims: CallProofClaims; signingInput: string; signature: Uint8Array } | null {
  const p = _parts(token, CALL_PROOF_TYP);
  if (!p) return null;
  const c = p.claims;
  if (!_strings(c, ["iss", "sub", "aud", "decision", "action_hash", "jti"])) return null;
  if (c.verifier !== undefined && !_strings(c, ["verifier"])) return null;
  if ((typeof c.mandate === "string") === (typeof c.policy === "string")) return null; // exactly one
  return { ...p, claims: c as unknown as CallProofClaims };
}

/** Step 6's structural half: `typ`, `EdDSA`, a `kid` under `iss`, and a summary in the spec's vocabulary. */
function _decodeRecord(token: unknown): { kid: string; claims: AgentRecordClaims; signingInput: string; signature: Uint8Array } | null {
  const p = _parts(token, AGENT_RECORD_TYP);
  if (!p) return null;
  const c = p.claims;
  if (!_strings(c, ["iss", "sub", "aud", "jti"]) || !_isSummary(c.agent)) return null;
  return { ...p, claims: c as unknown as AgentRecordClaims };
}

function _isSummary(a: unknown): a is AgentRecordSummary {
  if (!a || typeof a !== "object") return false;
  const s = a as Record<string, unknown>;
  const o = s.operator as Record<string, unknown> | undefined;
  const oneOf = (v: unknown, set: readonly string[], optional = false) => (v === undefined ? optional : typeof v === "string" && set.includes(v));
  return (
    oneOf(s.status, STATUSES) &&
    oneOf(s.assurance, ASSURANCES, true) &&
    oneOf(s.binding, BINDINGS, true) &&
    oneOf(s.bootstrapAnchor, ANCHORS) &&
    !!o &&
    typeof o === "object" &&
    typeof o.org === "string" &&
    oneOf(o.level, LEVELS) &&
    oneOf(o.method, METHODS, true) &&
    (o.registrar === undefined || typeof o.registrar === "string")
  );
}
