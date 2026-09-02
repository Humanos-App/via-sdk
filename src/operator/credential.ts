// The registrar-signed operator verification credential (§18). A W3C VC secured by a
// single Data Integrity proof — the same shape as the mandate's STAMP, because it is
// the same kind of artifact: a durable, presentable claim with expiry + revocation.
import { randomUUID } from "node:crypto";
import { createDataIntegrityProof, verifyDataIntegrityProof } from "../crypto/proof.js";
import { VIA_PLATFORM_DID } from "../did/web.js";
import { TYPE_VC, VIA_CONTEXTS, VIA_SPEC_VERSION, type SpecVersion } from "../types.js";
import type { OperatorClaims, ViaOperatorCredential } from "./types.js";

export const TYPE_VIA_OPERATOR = "VIAOperatorCredential";

export interface OperatorSigner {
  /** Ed25519 private key of the registrar. */
  privateKey: Uint8Array;
  verificationMethod: string;
  created?: string;
}

export interface BuildOperatorCredentialInput extends OperatorClaims {
  credentialId?: string;
  /** Defaults to the platform DID (Humanos is the registrar today). */
  issuer?: string;
  validFrom?: string;
}

/** Build the **unsigned** operator credential; secure it with {@link signOperatorCredential}. */
export function buildOperatorCredential(input: BuildOperatorCredentialInput): ViaOperatorCredential {
  const { credentialId, issuer, validFrom, ...claims } = input;
  return {
    "@context": [...VIA_CONTEXTS],
    id: credentialId ?? `urn:via:operator:${randomUUID()}`,
    type: [TYPE_VC, TYPE_VIA_OPERATOR],
    specVersion: VIA_SPEC_VERSION as SpecVersion,
    issuer: issuer ?? VIA_PLATFORM_DID,
    validFrom: validFrom ?? claims.verifiedAt,
    ...(claims.expiresAt ? { validUntil: claims.expiresAt } : {}),
    credentialSubject: { ...claims },
  };
}

/** Sign the operator credential with the registrar's key (`assertionMethod`). */
export function signOperatorCredential(credential: ViaOperatorCredential, signer: OperatorSigner): ViaOperatorCredential {
  const proof = createDataIntegrityProof({
    document: credential as unknown as Record<string, unknown>,
    privateKey: signer.privateKey,
    verificationMethod: signer.verificationMethod,
    proofPurpose: "assertionMethod",
    ...(signer.created ? { created: signer.created } : {}),
  });
  return { ...credential, proof };
}

/**
 * **O1** — verify the credential's signature against the registrar's key. A forged
 * or altered credential (e.g. a self-claimed `verified`) fails here.
 */
export async function verifyOperatorCredential(
  credential: ViaOperatorCredential,
  resolvePublicKey: (vmId: string) => Uint8Array | Promise<Uint8Array>,
): Promise<{ valid: boolean; reason?: string }> {
  if (!credential.proof) return { valid: false, reason: "operator credential has no proof" };
  try {
    const key = await resolvePublicKey(credential.proof.verificationMethod);
    const valid = verifyDataIntegrityProof(credential as unknown as Record<string, unknown>, credential.proof, key);
    return valid ? { valid: true } : { valid: false, reason: "signature invalid" };
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }
}
