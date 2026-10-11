import { encodePublicKeyMultibase, decodePublicKeyMultibase } from "../crypto/ed25519.js";
import { cleanPublicJwk, type Jwk } from "../crypto/p256.js";
import { verificationMethodId } from "./web.js";

/** DID Core + Multikey contexts (D-c). */
export const DID_CONTEXT = [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/multikey/v1",
] as const;

/**
 * The context that defines `JsonWebKey` and `publicKeyJwk` (v0.3 §0.3.3). A document listing an
 * agent's key names it: a JSON-LD processor drops a term no context defines, so without it the key
 * reads as one with no material (checked by expansion, 2026-10-11).
 */
export const DID_JWK_CONTEXT = "https://w3id.org/security/jwk/v1";

/** An Ed25519 key (organizations, people, Humanos) — v0.3 §0.3.2. */
export interface MultikeyMethod {
  id: string;
  type: "Multikey";
  controller: string;
  publicKeyMultibase: string;
}

/**
 * A P-256 agent key (v0.3 §16.2), published as `JsonWebKey` + `publicKeyJwk` — the W3C name. A reader
 * also accepts `JsonWebKey2020`, the older community-group name for the same thing, which documents
 * served before 2026-10-11 used.
 */
export interface JsonWebKeyMethod {
  id: string;
  type: "JsonWebKey" | "JsonWebKey2020";
  controller: string;
  publicKeyJwk: Jwk;
}

export type VerificationMethod = MultikeyMethod | JsonWebKeyMethod;

/** The verification-method types that carry a JWK; the first is the one a writer uses. */
export const JWK_METHOD_TYPES: readonly string[] = ["JsonWebKey", "JsonWebKey2020"];

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
  /** Raw 32-byte Ed25519 public key — or, for an agent, `publicKeyJwk` instead. */
  publicKey?: Uint8Array;
  /** An agent's P-256 public key, published as `JsonWebKey` (v0.3 §16.2). */
  publicKeyJwk?: Jwk;
  keyFragment?: string;
  /**
   * Who may change the DOCUMENT — the document-level `controller`, absent unless given. Never the
   * key's: a verification method's `controller` is always the DID itself (v0.3 §0.3.3), or W3C's
   * verifier rejects it (Controlled Identifiers v1.0 §3.3, step 10).
   */
  controller?: string;
}

/** Build a DID document; the key is authorized for both `assertionMethod` and `authentication`. */
export function buildDidDocument(input: BuildDidDocumentInput): DidDocument {
  const fragment = input.keyFragment ?? "key-1";
  const vmId = verificationMethodId(input.did, fragment);
  // The key's controller is the DID itself, whoever holds the key (v0.3 §0.3.3).
  const controller = input.did;
  if (!input.publicKey === !input.publicKeyJwk) {
    throw new Error("a DID document key is either an Ed25519 publicKey or a publicKeyJwk, exactly one");
  }
  const vm: VerificationMethod = input.publicKeyJwk
    ? { id: vmId, type: "JsonWebKey", controller, publicKeyJwk: cleanPublicJwk(input.publicKeyJwk) }
    : { id: vmId, type: "Multikey", controller, publicKeyMultibase: encodePublicKeyMultibase(input.publicKey!) };
  return {
    "@context": input.publicKeyJwk ? [...DID_CONTEXT, DID_JWK_CONTEXT] : [...DID_CONTEXT],
    id: input.did,
    ...(input.controller && input.controller !== input.did ? { controller: input.controller } : {}),
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
  if (vm.type !== "Multikey") {
    throw new Error(`${vmId} is a ${vm.type}, not an Ed25519 Multikey — read it with resolveVerificationJwk`);
  }
  if (purpose && !isAuthorizedFor(doc, vmId, purpose)) {
    throw new Error(`${vmId} is not authorized for ${purpose}`);
  }
  return decodePublicKeyMultibase(vm.publicKeyMultibase);
}

/**
 * Resolve a verification-method id to an agent's public JWK (v0.3 §16.2) — `JsonWebKey`, or the older
 * `JsonWebKey2020`. Optionally assert the key is authorized for a proof purpose.
 */
export function resolveVerificationJwk(
  doc: DidDocument,
  vmId: string,
  purpose?: "assertionMethod" | "authentication",
): Jwk {
  const vm = findVerificationMethod(doc, vmId);
  if (!vm) throw new Error(`verification method not found: ${vmId}`);
  if (!JWK_METHOD_TYPES.includes(vm.type) || !("publicKeyJwk" in vm) || typeof vm.publicKeyJwk !== "object") {
    throw new Error(`${vmId} is a ${vm.type}, not a JsonWebKey`);
  }
  if (purpose && !isAuthorizedFor(doc, vmId, purpose)) {
    throw new Error(`${vmId} is not authorized for ${purpose}`);
  }
  return vm.publicKeyJwk;
}
