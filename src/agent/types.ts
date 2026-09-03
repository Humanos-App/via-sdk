// Agent Binding (§16) shared types — the confinement ladder + reason codes.
// Ported from kya/contract.ts as the SDK's canonical §16 vocabulary (Phase 3).

import type { Jwk } from "../crypto/p256.js";

/** Confinement strength the verifier could prove (ordinal — CEL floors compare the rank). */
export type Assurance = "pop" | "device" | "hardware";
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
}

/** Confinement evidence submitted at REGISTRATION; establishes the rung (§16.5). */
export type ConfinementEvidence =
  | { type: "none" } // -> pop
  | { type: "device-self"; nonExportable: true; note?: string } // -> device (self-asserted)
  | { type: "custody"; ref: CustodyRef } // -> hardware/custodial (verifier calls DescribeKey)
  | { type: "attestation-eat"; docB64: string } // COSE_Sign1 -> hardware/attested (nitro)
  | { type: "webauthn"; attestationObjectB64: string; clientDataJSONB64: string }; // -> pop | hardware/attested(fido)

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
