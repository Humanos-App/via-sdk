// Agent Binding (§16.5) — REGISTRATION. `registerChallenge` issues a single-use
// registration nonce the enclave must echo inside its attestation quote;
// `registerAgentKey` validates the submitted evidence into a locked `BoundKey`,
// binding that nonce (single-use + unexpired) for the attested path.
//
// Ported from kya/verifier.ts (`registerChallenge` / `registerAgentKey`). The kya
// version reaches into an in-memory VerifierState + calls the sim-KMS over HTTP; the
// SDK injects both — the nonce store and the DescribeKey oracle — so the library does
// no I/O of its own (matching the VerifyDeps dependency-injection style).
import { randomBytes } from "node:crypto";
import { computeSRI } from "../crypto/digest.js";
import { fromBase64Url } from "../crypto/encoding.js";
import { jwkThumbprint, type Jwk } from "../crypto/p256.js";
import {
  NO_ROOTS,
  type PinnedRoots,
  validateCoseAttestation,
  validateCustody,
  readWebauthnClientData,
  validateWebauthnAttestation,
  readAttestationNonce,
  type DescribeKey,
} from "./attestation.js";
import type { BoundKey, ConfinementEvidence, ConfinementResult } from "./types.js";

// ── Registration-nonce store (single-use) ────────────────────────────────────

/**
 * A store for outstanding, single-use registration nonces. Injected — the SDK holds no
 * state. `put` records a freshly minted nonce with its expiry; `take` returns `{exp}` for
 * a nonce that is still outstanding (never issued, expired-and-evicted, or already
 * consumed → `null`); `consume` marks it used so it can never be replayed.
 */
export interface RegChallengeStore {
  put(regNonce: string, exp: number): void | Promise<void>;
  take(regNonce: string): { exp: number } | null | Promise<{ exp: number } | null>;
  consume(regNonce: string): void | Promise<void>;
}

/** A ready-to-use in-memory {@link RegChallengeStore} (mirrors kya's `regChallenges` + `seenRegNonces`). */
export function createRegChallengeStore(): RegChallengeStore {
  const outstanding = new Map<string, { exp: number }>();
  const consumed = new Set<string>();
  return {
    put(regNonce, exp) {
      outstanding.set(regNonce, { exp });
    },
    take(regNonce) {
      if (consumed.has(regNonce)) return null;
      return outstanding.get(regNonce) ?? null;
    },
    consume(regNonce) {
      outstanding.delete(regNonce);
      consumed.add(regNonce);
    },
  };
}

// ── registerChallenge ─────────────────────────────────────────────────────────

export interface RegisterChallengeDeps {
  /** Epoch-ms clock — injected so callers/tests can advance it. Default `Date.now`. */
  now?: () => number;
  /**
   * Nonce freshness window in seconds. Default 60.
   *
   * UNSOURCED: this carried a `spec §10` citation that resolves to nothing — v0.2-new §10 is
   * Status & events, v0.3 §10 is Migration, and no document here states a 30–60s window. The
   * value matches what the platform's challenge store uses; treat it as an implementation default
   * until §16.5 is given an explicit TTL bound.
   */
  ttlSeconds?: number;
  /** Nonce source — default 18 cryptographically-random bytes, base64url. */
  randomNonce?: () => string;
  /** Optional persistence — when provided, the minted nonce is recorded for {@link registerAgentKey}. */
  store?: RegChallengeStore;
}

export interface RegisterChallenge {
  /** Single-use nonce the enclave echoes inside its attestation quote. */
  regNonce: string;
  /** Absolute expiry, epoch ms. */
  exp: number;
  /** Freshness window in seconds (echo of the configured/default ttl). */
  ttl: number;
}

/**
 * Mint a fresh, single-use registration nonce (§16.5). Binding an attested REGISTRATION
 * to a live challenge is what stops a captured-but-valid quote from being replayed to
 * bind a key the attacker doesn't control (real AWS Nitro is always nonce-challenged).
 * When a {@link RegChallengeStore} is injected the nonce is persisted; otherwise the
 * caller persists the returned `{ regNonce, exp }` itself.
 */
export async function registerChallenge(deps: RegisterChallengeDeps = {}): Promise<RegisterChallenge> {
  const now = deps.now ? deps.now() : Date.now();
  const ttl = deps.ttlSeconds ?? 60;
  const regNonce = deps.randomNonce ? deps.randomNonce() : randomBytes(18).toString("base64url");
  const exp = now + ttl * 1000;
  await deps.store?.put(regNonce, exp);
  return { regNonce, exp, ttl };
}

// ── registerAgentKey ───────────────────────────────────────────────────────────

export interface RegisterAgentKeyInput {
  /** The key being bound. For key-carrying evidence (webauthn / attestation-eat) the
   *  bound key is DERIVED from the evidence; if a `cnf` is still supplied it MUST match. */
  cnf: { jwk: Jwk };
  evidence: ConfinementEvidence;
  /** The nonce issued by {@link registerChallenge}; required (and bound) for `attestation-eat`. */
  regNonce?: string;
}

export interface RegisterAgentKeyDeps {
  /** Epoch-ms clock. Default `Date.now`. */
  now?: () => number;
  /** Pinned Nitro CA roots (PEM) for the `attestation-eat` path. */
  nitroRoots?: PinnedRoots;
  /**
   * Pinned PCR values (index -> lowercase hex) for the `attestation-eat` path — WHICH WORKLOAD.
   * Roots prove the key is in an enclave from a vendor you trust; PCRs prove it is running the
   * image you built. Omitted means unchecked, and the granted rung then means the weaker thing.
   */
  expectedPcrs?: Record<string, string>;
  /**
   * Image id -> expected measurements, granting `runtime: tee` (v0.3 §9.4ter). Distinct from
   * `expectedPcrs`, which gates the assurance rung and refuses on mismatch.
   */
  expectedMeasurements?: Record<string, Record<string, string>>;
  /** Pinned FIDO/vendor roots (PEM) for the `webauthn` path. */
  fidoRoots?: PinnedRoots;
  /** Custody oracle (injected — replaces kya's HTTP DescribeKey) for the `custody` path. */
  describeKey?: DescribeKey;
  /** Single-use registration-nonce store — required to bind the `attestation-eat` nonce. */
  store?: RegChallengeStore;
}

/**
 * Validate registration evidence into a locked `BoundKey` (§16.5). `evidence.type` picks
 * the validator; the returned key MUST equal the submitted `cnf`. Registration is where
 * the rung is LOCKED (principle P-B). Returns a {@link ConfinementResult} — a `BoundKey`
 * on success, or `{ ok:false, reason }` on any failure (fail-closed).
 *
 * Reason codes: `attestation_nonce_invalid` (missing/expired/replayed/mismatched reg
 * nonce), `attestation_key_mismatch` (evidence-embedded key ≠ submitted cnf), plus
 * whatever the underlying validator returns (`custody_reference_invalid`,
 * `attestation_chain_invalid`, `pop_invalid`).
 */
export async function registerAgentKey(
  input: RegisterAgentKeyInput,
  deps: RegisterAgentKeyDeps = {},
): Promise<ConfinementResult> {
  const now = deps.now ? deps.now() : Date.now();
  const ev = input.evidence;
  let result: ConfinementResult;

  // Evidence arrives from an UNTRUSTED client, so the discriminator cannot be assumed to be
  // one of ours. Without this, an unknown (or absent) `type` matched no case, left `result`
  // unassigned, and threw on the `result.ok` read below — turning "reject this registration"
  // into an unhandled exception on the endpoint that mints identities. A validator documented
  // as fail-closed has to fail closed on the malformed input too, not just the invalid-but-
  // well-formed input.
  //
  // It is also what a client sending the AGENT SDK's evidence hits: that shape discriminates on
  // `kind`, not `type`, so every field below reads `undefined`.
  if (!ev || typeof ev !== "object" || typeof (ev as { type?: unknown }).type !== "string") {
    return { ok: false, reason: "custody_reference_invalid" };
  }

  switch (ev.type) {
    case "none":
      // No confinement evidence — freshness only. -> pop / self.
      result = { ok: true, cnf: input.cnf, assurance: "pop", binding: "self", verifiedAt: now };
      break;
    case "device-self":
      // Platform ASSERTS non-exportable and the RP cannot verify it — so `pop`, per §16.5's table.
      // A claim is not evidence: this differs from `none` only in what the CHAIN records about what
      // was asserted, never in what the verifier may credit. `device` is not "asserted a device";
      // it is "chained to a platform-authenticator root", which is why webauthn's row reads
      // `device`/`hardware` PER ROOT. The rung is which anchor you reached, not which claim you made.
      result = { ok: true, cnf: input.cnf, assurance: "pop", binding: "self", verifiedAt: now };
      break;
    case "custody":
      // RP-verified non-exportability via the injected DescribeKey oracle + GetPublicKey == cnf.
      if (!deps.describeKey) return { ok: false, reason: "custody_reference_invalid" };
      result = await validateCustody(ev.ref, input.cnf.jwk, deps.describeKey);
      break;
    case "attestation-eat": {
      // Freshness FIRST: the quote must echo THIS registration's single-use nonce, and
      // that nonce must be an outstanding, unexpired, unconsumed challenge. The nonce is
      // covered by the COSE signature, so validateCoseAttestation makes the echoed value
      // trustworthy — but gating on liveness here means a captured, still-valid quote
      // cannot be replayed to bind a key the attacker never controlled.
      const embedded = readAttestationNonce(ev.docB64);
      const rc = input.regNonce ? await deps.store?.take(input.regNonce) : null;
      if (
        !embedded ||
        !input.regNonce ||
        embedded !== input.regNonce ||
        !rc ||
        now > rc.exp
      ) {
        return { ok: false, reason: "attestation_nonce_invalid" };
      }
      result = await validateCoseAttestation(ev.docB64, deps.nitroRoots ?? NO_ROOTS, deps.expectedPcrs, deps.expectedMeasurements);
      if (result.ok) await deps.store?.consume(input.regNonce);
      break;
    }
    case "webauthn": {
      // Freshness FIRST, exactly as the COSE path does it (v0.3 §16.5: "the verifier MUST bind the
      // attestation to the `regNonce` … outstanding, unexpired, and single-use").
      //
      // WHY THIS MATTERS HERE MORE THAN ANYWHERE. The bound key is DERIVED from the evidence
      // (`authData` carries the credential public key), so possession is never proven by the
      // submitter — the attestation IS the whole claim. Without this gate a captured
      // {attestationObject, clientDataJSON} pair re-registers the same credential under a different
      // actor, in a different organization, at the full attested rung.
      //
      // `challenge` is inside `clientDataJSON`, which the attestation statement signs
      // (authData ‖ SHA-256(clientDataJSON)) — so a forged challenge breaks that signature and the
      // validator below rejects it. Checking `type` refuses an assertion (`webauthn.get`) replayed
      // as a registration.
      const client = readWebauthnClientData(ev.clientDataJSONB64);
      const rc = input.regNonce ? await deps.store?.take(input.regNonce) : null;
      if (
        !client ||
        client.type !== "webauthn.create" ||
        !input.regNonce ||
        client.challenge !== input.regNonce ||
        !rc ||
        now > rc.exp
      ) {
        return { ok: false, reason: "attestation_nonce_invalid" };
      }
      result = await validateWebauthnAttestation(ev.attestationObjectB64, ev.clientDataJSONB64, deps.fidoRoots ?? NO_ROOTS);
      if (result.ok) await deps.store?.consume(input.regNonce);
      break;
    }
    default:
      // A string `type` that is not one of ours. Also the arm a NEW ConfinementEvidence variant
      // lands in if it is added to the union without a validator here — refused, not crashed.
      return { ok: false, reason: "custody_reference_invalid" };
  }

  if (!result.ok) return result;

  // The bound cnf is the key the EVIDENCE proves. For key-carrying evidence
  // (webauthn / attestation-eat) it is DERIVED from the evidence and the client MAY omit
  // its own cnf. If the client DID submit a real key, it must match — the rung means
  // nothing unless the confined key IS the key being bound.
  const boundJkt = jwkThumbprint(result.cnf.jwk);
  const submitted = input.cnf?.jwk;
  if (submitted && submitted.x && submitted.y && jwkThumbprint(submitted) !== boundJkt) {
    return { ok: false, reason: "attestation_key_mismatch" };
  }

  const bound: BoundKey = {
    cnf: result.cnf,
    assurance: result.assurance,
    binding: result.binding,
    root: result.root,
    custodyRef: result.custodyRef ?? null,
    verifiedAt: result.verifiedAt,
  };
  // Model C: pin the raw attestation quote's digest into the (to-be-signed) key so a
  // relying party can re-validate confinement to public roots itself (§16.12).
  if (ev.type === "attestation-eat") {
    bound.attestationDigestSRI = computeSRI(fromBase64Url(ev.docB64));
  }
  return { ok: true, ...bound };
}
