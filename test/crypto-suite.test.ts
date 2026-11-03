/**
 * Cryptosuite regression guards.
 *
 * Pins the full `eddsa-jcs-2022` proof pipeline (canonicalize → hashData →
 * Ed25519 → base58) to a fixed known-answer, and pins the `canonicalize` (RFC
 * 8785) library's output. If a dependency upgrade changes any of these bytes,
 * these tests fail loudly rather than silently producing incompatible proofs.
 */
import { describe, it, expect } from "vitest";
import { createDataIntegrityProof, verifyDataIntegrityProof } from "../src/crypto/proof.js";
import { canonicalizeRFC8785 } from "../src/crypto/canonicalize.js";
import { publicKeyFromPrivate } from "../src/crypto/ed25519.js";

const SEED = new Uint8Array(32).fill(7);
// Pinned proofValue for the fixed document + params below (Ed25519 is deterministic).
const KAT_PROOFVALUE = "z2GuneiEfKCKxenpgCNS12vo29PJpW78SoJ7ErM3ts8GN6A4geriF4zxBKSM1iLo6CGNU4Uw6NsEMjSNnLrkXTQAv";

const document = {
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://via.humanos.tech/ns/v1"],
  id: "urn:via:credential:kat-1",
  type: ["VerifiableCredential", "VIAMandate"],
  issuer: "did:web:humanos.tech",
  credentialSubject: { id: "did:web:humanos.tech:org:kat", mandate: { scope: "humanos.credential.request" } },
};
const params = {
  privateKey: SEED,
  verificationMethod: "did:web:humanos.tech#key-1",
  proofPurpose: "assertionMethod" as const,
  created: "2026-06-25T00:00:00.000Z",
  lifecycleAction: "ISSUE" as const,
};

describe("eddsa-jcs-2022 proof pipeline — known-answer (canonicalize + hashData + Ed25519 + base58)", () => {
  it("produces the pinned proofValue for fixed inputs", () => {
    expect(createDataIntegrityProof({ document, ...params }).proofValue).toBe(KAT_PROOFVALUE);
  });

  it("verifies, and rejects document AND proofConfig tampering", () => {
    const pub = publicKeyFromPrivate(SEED);
    const proof = createDataIntegrityProof({ document, ...params });
    expect(verifyDataIntegrityProof(document, proof, pub)).toBe(true);

    // document body tamper
    expect(verifyDataIntegrityProof({ ...document, issuer: "did:web:evil" }, proof, pub)).toBe(false);
    // proofConfig is signed under the real suite → tampering any of these fails
    expect(verifyDataIntegrityProof(document, { ...proof, lifecycleAction: "STAMP" }, pub)).toBe(false);
    expect(verifyDataIntegrityProof(document, { ...proof, created: "2030-01-01T00:00:00.000Z" }, pub)).toBe(false);
    expect(verifyDataIntegrityProof(document, { ...proof, proofPurpose: "authentication" }, pub)).toBe(false);
    expect(verifyDataIntegrityProof(document, { ...proof, verificationMethod: "did:web:evil#key-1" }, pub)).toBe(false);
  });
});

describe("RFC 8785 (JCS) — pins the `canonicalize` library output", () => {
  it("canonicalizes a tricky object exactly (key order, numbers, -0, empties, unicode)", () => {
    const edge = { z: [3, 1], a: 1.5, b: 0.1, c: 1e21, d: -0, e: [], f: {}, g: "café", h: true, i: null, k: -7 };
    expect(canonicalizeRFC8785(edge)).toBe(
      '{"a":1.5,"b":0.1,"c":1e+21,"d":0,"e":[],"f":{},"g":"café","h":true,"i":null,"k":-7,"z":[3,1]}',
    );
  });
});
