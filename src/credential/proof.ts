/**
 * The credential-level signer — the single place that decides HOW a credential
 * proof is produced.
 *
 * A credential is secured by exactly ONE proof: the Humanos `STAMP`, whose
 * kind is committed inside the signed `proofConfig` as `event`. Every other
 * lifecycle fact (ISSUE, the consents, REVOKE, the operational events) is a
 * standalone `ViaEvent` row — see `event/build.ts` — not an entry in a proof set.
 *
 * This is the proof half of {@link stampMandate}: same bytes, but it returns the
 * proof rather than the credential carrying it, which is what a caller persisting
 * to a `proof` column wants.
 *
 * The `action`/`actionProof` side fields, the five-value proof-action taxonomy, and
 * the `lifecycleAction` predecessor of `event` were all legacy; they went with it
 * (docs/VIA/legacy.md §1.4).
 *
 * v0.3 inherits this unchanged: v0.3 replaced the RECEIPT model, not credential
 * securing. The file is here because the v0.3 fork dropped it, not because the
 * securing model moved.
 */
import { createDataIntegrityProof, type DataIntegrityProof } from "../crypto/proof.js";

export type CredentialProof = DataIntegrityProof;

export interface CredentialProofSigner {
  /** Raw 32-byte Ed25519 private key (the platform decrypts it from KMS). */
  privateKey: Uint8Array;
  verificationMethod: string;
  /** Proof `created`; defaults to now. */
  created?: string;
}

/** Produce the securing `STAMP` proof for `credential`. */
export function signCredentialProof(
  credential: Record<string, unknown>,
  signer: CredentialProofSigner,
): CredentialProof {
  return createDataIntegrityProof({
    document: credential,
    privateKey: signer.privateKey,
    verificationMethod: signer.verificationMethod,
    proofPurpose: "assertionMethod",
    created: signer.created ?? new Date().toISOString(),
    event: "STAMP",
  });
}
