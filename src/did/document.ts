import { encodePublicKeyMultibase, decodePublicKeyMultibase } from "../crypto/ed25519.js";
import { verificationMethodId } from "./web.js";

/** DID Core + Multikey contexts (D-c). */
export const DID_CONTEXT = [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/multikey/v1",
] as const;

export interface VerificationMethod {
  id: string;
  type: "Multikey";
  controller: string;
  publicKeyMultibase: string;
}

export interface DidDocument {
  "@context": string[];
  id: string;
  controller?: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
}

export interface BuildDidDocumentInput {
  did: string;
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  keyFragment?: string;
  controller?: string;
}

/** Build a DID document; the key is authorized for both `assertionMethod` and `authentication`. */
export function buildDidDocument(input: BuildDidDocumentInput): DidDocument {
  const fragment = input.keyFragment ?? "key-1";
  const vmId = verificationMethodId(input.did, fragment);
  const controller = input.controller ?? input.did;
  const vm: VerificationMethod = {
    id: vmId,
    type: "Multikey",
    controller,
    publicKeyMultibase: encodePublicKeyMultibase(input.publicKey),
  };
  return {
    "@context": [...DID_CONTEXT],
    id: input.did,
    ...(controller !== input.did ? { controller } : {}),
    verificationMethod: [vm],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
}

export function findVerificationMethod(doc: DidDocument, vmId: string): VerificationMethod | undefined {
  return doc.verificationMethod.find((vm) => vm.id === vmId);
}

export function isAuthorizedFor(
  doc: DidDocument,
  vmId: string,
  purpose: "assertionMethod" | "authentication",
): boolean {
  return doc[purpose].includes(vmId);
}

/**
 * Resolve a verification-method id to its raw Ed25519 public key (decoding the
 * Multikey `publicKeyMultibase`). Optionally assert the key is authorized for a
 * proof purpose. Composes with `verify` / `verifyStamp` / `verifyEvent` as a
 * `resolvePublicKey` once a DID document has been fetched.
 */
export function resolveVerificationKey(
  doc: DidDocument,
  vmId: string,
  purpose?: "assertionMethod" | "authentication",
): Uint8Array {
  const vm = findVerificationMethod(doc, vmId);
  if (!vm) throw new Error(`verification method not found: ${vmId}`);
  if (vm.type !== "Multikey") throw new Error(`unsupported verification method type: ${vm.type}`);
  if (purpose && !isAuthorizedFor(doc, vmId, purpose)) {
    throw new Error(`${vmId} is not authorized for ${purpose}`);
  }
  return decodePublicKeyMultibase(vm.publicKeyMultibase);
}
