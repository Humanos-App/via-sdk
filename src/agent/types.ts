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
  /**
   * ISO-8601 — when this class was established. Absent/expired evaluates as `none`.
   *
   * Deliberately NOT `validFrom` (considered 2026-10-07, when `expiresAt` became `validUntil`). It is
   * when the environment was CHECKED, the family of `verifiedAt` — rules read it as
   * `agent.runtimeAt` beside `agent.verifiedAt`. `validFrom` is when a signed statement was made,
   * and the event carrying this attestation has one of its own with a different value: a `MERGED`
   * signed in October carries a runtime attested in March.
   */
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
export const BINDINGS: readonly Binding[] = ["self", "custodial", "attested"];

/** Token guards — a fold or a writer that accepts anything else fails OPEN: an unknown rung ranks as NaN. */
export function isAssurance(x: unknown): x is Assurance {
  return typeof x === "string" && x in ASSURANCE_RANK;
}
export function isBinding(x: unknown): x is Binding {
  return typeof x === "string" && (BINDINGS as readonly string[]).includes(x);
}
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
  /**
   * The agent's DID (§16.4) — IDENTITY, never authentication: the PoP is checked against `cnf`,
   * and the DID says whose key that is, whichever way it is pinned. Exposed to rules as
   * `agent.did`. OPTIONAL on this type only because registration (§16.5) produces a key before a
   * DID exists for it; `buildMandate` REQUIRES it on every entry it signs, so a signed mandate
   * always carries it. When `keyId` is present it is a key OF this actor (`<did>#key-N`).
   */
  did?: string;
  cnf: { jwk: Jwk };
  /**
   * v0.3 §7 — pin by KEY ID (`<did>#key-N`) resolved through the VIAActor named by `did`, instead
   * of by raw JWK material. When present, a v0.3 verifier MUST resolve the id through the actor's
   * current state (rotation succession included; per-key revocation bits win) and check the PoP
   * against the resulting usable set; a verifier that cannot resolve the actor MUST fail closed.
   * Absent ⇒ the v0.2 raw-material pin: `cnf` is the whole binding (still honored — the
   * high-assurance option). The actor is `did`; there is no second copy of it here.
   */
  keyId?: string;
  assurance: Assurance;
  binding: Binding;
  root?: Root;
  custodyRef?: CustodyRef | null;
  /** Seconds; the mandate's re-attest window (§16.4, A8), set by its author at issuance — never by registration. */
  maxAttestationStaleness?: number;
  /**
   * When registration locked the rung (principle P-B). ON THE WIRE this is an ISO-8601 string —
   * v0.3 §16.4, and what `buildMandate` writes. A NUMBER (epoch ms) is what v0.2 verifiers
   * produced and what artifacts signed under v0.2 carry; a v0.3 verifier MUST still read those,
   * so both are accepted here and normalized through {@link boundKeyVerifiedAtMs}.
   */
  verifiedAt: string | number;
  /**
   * Model C: digest of the raw attestation quote, pinned into the signed mandate,
   * so a relying party can re-validate confinement to public roots itself instead of
   * trusting the registrar's signed rung. Set for attested keys only. An SRI string (§16.4):
   * `sha256-` + standard base64 of SHA-256 over the decoded quote bytes.
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
/**
 * Registration evidence (§16.5). `proof` is a `via-reg+jwt` by the key being registered over the
 * `regNonce` (`buildRegistrationProof`): every key the agent holds proves possession when it enters the
 * chain. Attested evidence that reaches a pinned root proves it itself; attested evidence that degrades
 * proves nothing, so it carries `proof` too (decided 2026-10-14).
 */
export type ConfinementEvidence =
  | { type: "none" } // REFUSED since 2026-10-14 (`pop_invalid`): it proves nothing; chains that recorded it read as written
  | { type: "device-self"; proof: string; nonExportable?: boolean; note?: string } // -> pop/self (a CLAIM is not evidence)
  | { type: "custody"; ref: CustodyRef; proof: string } // -> pop/custodial (oracle upgrades the BINDING, not the rung)
  | { type: "attestation-eat"; docB64: string; proof?: string } // COSE_Sign1 -> hardware/attested (nitro); unpinned -> pop/self, with `proof`
  | { type: "webauthn"; attestationObjectB64: string; clientDataJSONB64: string; proof?: string }; // -> hardware/attested (fido); unpinned -> pop/self, with `proof`

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

/**
 * `verifiedAt` as epoch ms, whichever encoding the entry carries — the ISO string v0.3 writes or
 * the number v0.2-signed artifacts still have. NaN for a string that does not parse, which the
 * A8 staleness check then treats as "no usable freshness" (a comparison with NaN is false, so an
 * entry with a re-attest window and an unreadable instant is denied as stale).
 */
export function boundKeyVerifiedAtMs(bk: Pick<BoundKey, "verifiedAt">): number {
  return typeof bk.verifiedAt === "number" ? bk.verifiedAt : Date.parse(bk.verifiedAt);
}

