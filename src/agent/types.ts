// Agent Binding (§16) shared types — the confinement ladder + reason codes.
// Ported from kya/contract.ts as the SDK's canonical §16 vocabulary (Phase 3).

import type { Jwk } from "../crypto/p256.js";

/** Confinement strength the verifier could prove (ordinal — CEL floors compare the rank). */
export type Assurance = "pop" | "device" | "hardware";

/**
 * The RUNTIME axis — what environment the key-holding process runs in (v0.3 §9.4ter).
 *
 * CATEGORICAL, never ordinal. There is no `runtimeRank` and mandates match with `in`, never `>=`.
 * The four values are not four strengths of one thing: `app` attests an application bundle, `host`
 * attests a boot chain, `tee` attests a launch measurement. Asking whether `app` is "more" than
 * `host` has no answer, and inventing one would let a mandate accept a class it never considered.
 *
 * It attests the VIA KEY-HOLDING PROCESS or its host — never the calling application. An MCP client
 * telling us what it is is not evidence about where our key lives (§9.4ter, B6).
 *
 * Orthogonal to `assurance`, which is about the KEY. An HSM-held key used by a plain container is
 * `assurance: hardware, runtime: none`; a key inside an enclave running a pinned image is
 * `assurance: hardware, runtime: tee`. One statement about the key, one about the environment.
 */
export type Runtime = "none" | "app" | "host" | "tee";

/**
 * A runtime attestation, as recorded on the actor chain and re-checked at presentation.
 *
 * TIME-VARYING, which is why it is not folded into a stamped value the way `assurance` is: a
 * process restarts, is redeployed, migrates. `at` is when this class was established; a verifier
 * that needs freshness bounds it explicitly (§9.4ter).
 */
export interface RuntimeAttestation {
  class: Runtime;
  /** ISO-8601 — when this class was established. Absent/expired evaluates as `none`. */
  at: string;
  /** The mechanism that produced it (`nitro`, `sev-snp`, `tdx`, `app-attest`, `play-integrity`, `tpm`). */
  mechanism?: string;
  /** SHA-256 of the matched pinned root's DER, hex — the anchor the environment chained to. */
  rootFingerprint?: string | null;
  /** The image identifier whose expected measurement matched (`tee` only). */
  measurementId?: string;
  /** SRI chain-link of the event carrying the raw attestation. Evidence by reference (§9.4). */
  event?: string;
}
/** How the key is held. */
export type Binding = "self" | "custodial" | "attested";
/** The pinned trust anchor confinement chained to. */
export type Root = "aws-nitro" | "fido" | (string & {});

export const ASSURANCE_RANK: Record<Assurance, number> = { pop: 1, device: 2, hardware: 3 };
/** Ordinal rank of an assurance level (§16.8 `assuranceRank`). */
export function assuranceRank(a: Assurance): number {
  return ASSURANCE_RANK[a];
}
/** True iff `actual` meets or exceeds the `floor` assurance (§16.8). */
export function meets(actual: Assurance, floor: Assurance): boolean {
  return ASSURANCE_RANK[actual] >= ASSURANCE_RANK[floor];
}

/** Agent-binding deny reasons (§16.7 A1–A8 + registration §16.5). */
export type AgentReasonCode =
  | "agent_not_bound"
  | "pop_invalid"
  | "pop_replayed"
  | "nonce_expired"
  | "aud_mismatch"
  | "action_hash_mismatch"
  | "custody_reference_invalid"
  | "attestation_chain_invalid"
  | "attestation_key_mismatch"
  | "attestation_nonce_invalid"
  | "attestation_pcr_mismatch"
  | "attestation_stale"
  | "root_not_accepted"
  | "agent_assurance_insufficient"
  | "agent_binding_insufficient";

// ── Registration / attestation (§16.5) ───────────────────────────────────────
// The confinement vocabulary produced by validating registration evidence. A
// `BoundKey` is the one confinement-verified key an agent presents at a given rung;
// registration is where the rung is LOCKED (principle P-B). Ported from kya/contract.ts.

/**
 * A KMS/HSM custody handle (§16.5). The verifier resolves it via an injected
 * DescribeKey oracle to confirm non-exportability + that the advertised public key
 * matches the `cnf` being bound.
 */
export interface CustodyRef {
  provider: string; // e.g. "sim-kms" | "aws-kms"
  region: string;
  keySpec: string; // ECC_NIST_P256
  keyId: string;
  arnClass: string;
}

/**
 * A single confinement-verified key for an agent DID (produced by registration).
 * The SAME mandate can carry one BoundKey per rung; the verifier picks the key
 * named in the PoP and evaluates THAT key's rung.
 */
export interface BoundKey {
  cnf: { jwk: Jwk };
  /**
   * v0.3 D7 — pin by KEY ID resolved through the VIAActor instead of raw JWK
   * material. When present, a v0.3 verifier MUST resolve the id through the
   * actor's current snapshot (rotation succession included; per-key revocation
   * bits win) and use the resolved key(s); a verifier that cannot resolve the
   * actor MUST fail closed. Absent ⇒ the v0.2 raw-material pin (still honored —
   * the high-assurance option).
   */
  keyRef?: { actor: string; keyId: string };
  assurance: Assurance;
  binding: Binding;
  root?: Root;
  custodyRef?: CustodyRef | null;
  /** Seconds; attested re-attest window (attested rungs only). */
  maxAttestationStaleness?: number;
  /** Epoch ms — registration locked the rung here (principle P-B). */
  verifiedAt: number;
  /**
   * Model C: digest of the raw attestation quote, pinned into the signed mandate,
   * so a relying party can re-validate confinement to public roots itself instead of
   * trusting the registrar's signed rung. Set for attested keys only. `b64u(sha256(docB64 bytes))`.
   */
  attestationDigestSRI?: string;
  /**
   * What was SEEN while grading, recorded whether or not a rung was granted (a degrade is the case
   * you most want to audit later). Never an input to grading — it exists so a rung can be
   * re-examined after the fact, and so a FIDO MDS layer has somewhere to attach.
   */
  evidence?: RegistrationEvidenceRecord;
  /**
   * The RUNTIME claim this evidence additionally established (v0.3 §9.4ter), if any. Separate from
   * the rung above: registration grades the KEY, this describes the ENVIRONMENT it was graded in.
   */
  runtime?: RuntimeAttestation;
}

/** Observed facts from a registration quote. Descriptive; grading never reads it back. */
export interface RegistrationEvidenceRecord {
  /** SHA-256 of the matched pinned root's DER, hex — or `null` when the chain reached none. */
  rootFingerprint: string | null;
  /** WebAuthn only: the authenticator model, signed inside authData. Null if not declared. */
  aaguid?: string | null;
  /** WebAuthn only: the raw authData flags byte (UP/UV/BE/BS/AT/ED). */
  authDataFlags?: number;
  /** The attestation statement format as presented (`packed`, `tpm`, `none`, …). */
  fmt?: string;
}

/** Confinement evidence submitted at REGISTRATION; establishes the rung (§16.5). */
export type ConfinementEvidence =
  | { type: "none" } // -> pop/self
  | { type: "device-self"; nonExportable: true; note?: string } // -> pop/self (a CLAIM is not evidence)
  | { type: "custody"; ref: CustodyRef } // -> pop/custodial (oracle upgrades the BINDING, not the rung)
  | { type: "attestation-eat"; docB64: string } // COSE_Sign1 -> hardware/attested (nitro), pop/self unpinned
  | { type: "webauthn"; attestationObjectB64: string; clientDataJSONB64: string }; // -> hardware/attested (fido), pop/self unpinned

/** The output of validating evidence — a `BoundKey` on success, or a deny reason (§16.5). */
export type ConfinementResult = ({ ok: true } & BoundKey) | { ok: false; reason: AgentReasonCode };

/**
 * A minted Nitro CA chain + a leaf ES256 signer (sim/test side, §16.5). `chainPems`
 * is leaf..intermediate with the root EXCLUDED (pinned out-of-band, as real Nitro ships).
 */
export interface NitroCa {
  rootPem: string;
  chainPems: string[];
  leafPublicJwk: Jwk;
  /** COSE_Sign1 signature by the leaf key (raw r‖s). */
  leafSign(message: Uint8Array): Promise<Uint8Array>;
  /**
   * The leaf's PRIVATE key, so a dev CA can be persisted and rebuilt.
   *
   * Needed because pinning a root is out-of-band by design: a verifier must have the root in its
   * configuration BEFORE an attestation arrives, which means minting the CA, restarting the
   * verifier with its root, and only then producing a quote. `leafSign` is a closure, so without
   * this the CA cannot survive the restart and the attested path is untestable outside a single
   * process.
   *
   * Optional so a caller that never persists is unaffected. Dev material by definition — this
   * whole module is the attestation PRODUCER, which nothing in a production path should be.
   */
  leafPrivateJwk?: Jwk;
}
