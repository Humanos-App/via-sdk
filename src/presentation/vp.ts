import { randomBytes } from "node:crypto";
import { createDataIntegrityProof, verifyDataIntegrityProof } from "../crypto/proof.js";
import { TYPE_VP, VIA_CONTEXTS, type VerifiablePresentation, type ViaMandateCredential } from "../types.js";

export interface GenerateChallengeContext {
  actionType: string;
  mandateId: string;
  nonce?: string;
  /** Epoch ms (caller supplies; SDK avoids hidden clock reads where possible). */
  timestamp?: number;
}

/** Challenge string. With context: `{actionType}_{mandateId}_{timestamp}_{nonce}` (platform format). */
export function generateChallenge(ctx?: GenerateChallengeContext): string {
  if (!ctx) return randomBytes(32).toString("hex");
  const ts = ctx.timestamp ?? Date.now();
  const nonce = ctx.nonce ?? randomBytes(16).toString("hex"); // 128-bit CSPRNG nonce
  return `${ctx.actionType}_${ctx.mandateId}_${ts}_${nonce}`;
}

export interface BuildPresentationInput {
  /** The mandate to present — carries its single securing STAMP proof (spec §0.7.1). */
  credential: ViaMandateCredential;
  /** Presenter/signer DID — Humanos (N14). */
  holder: string;
  /** Humanos stamp key. */
  privateKey: Uint8Array;
  verificationMethod: string;
  created?: string;
  /** Audience binding (§0.7.3). */
  domain?: string;
  challenge?: string;
}

/** Build a full-disclosure VP: the secured VC (with its single STAMP proof) + a Humanos `authentication` proof. */
export function buildPresentation(input: BuildPresentationInput): VerifiablePresentation {
  const vp: VerifiablePresentation = {
    "@context": [...VIA_CONTEXTS],
    type: [TYPE_VP],
    holder: input.holder,
    verifiableCredential: input.credential,
  };
  vp.proof = createDataIntegrityProof({
    document: vp as unknown as Record<string, unknown>,
    privateKey: input.privateKey,
    verificationMethod: input.verificationMethod,
    proofPurpose: "authentication",
    ...(input.created ? { created: input.created } : {}),
    ...(input.domain ? { domain: input.domain } : {}),
    ...(input.challenge ? { challenge: input.challenge } : {}),
  });
  return vp;
}

/** True if a bound domain matches the verifier domain or any subdomain of it (§0.7.3). */
export function domainMatches(boundDomain: string, verifierDomain: string): boolean {
  return boundDomain === verifierDomain || boundDomain.endsWith(`.${verifierDomain}`);
}

export interface VerifiedPresentation {
  valid: boolean;
  holder: string;
  credential: ViaMandateCredential;
  domain?: string;
  challenge?: string;
}

/** Verify the VP's (Humanos) proof. Domain/challenge enforcement happens in the verify flow (§0.8). */
export async function verifyPresentation(
  vp: VerifiablePresentation,
  resolvePublicKey: (vmId: string) => Uint8Array | Promise<Uint8Array>,
): Promise<VerifiedPresentation> {
  const base = {
    holder: vp.holder,
    credential: vp.verifiableCredential,
    domain: vp.proof?.domain,
    challenge: vp.proof?.challenge,
  };
  if (!vp.proof) return { ...base, valid: false };
  try {
    const key = await resolvePublicKey(vp.proof.verificationMethod);
    return { ...base, valid: verifyDataIntegrityProof(vp as unknown as Record<string, unknown>, vp.proof, key) };
  } catch {
    return { ...base, valid: false };
  }
}
