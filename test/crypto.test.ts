import { describe, it, expect } from "vitest";
import { canonicalizeRFC8785 } from "../src/crypto/canonicalize.js";
import { computeSRI, sha256Hex } from "../src/crypto/digest.js";
import {
  generateEd25519Key,
  signRaw,
  verifyRaw,
  signMultibase,
  verifyMultibase,
  encodePublicKeyMultibase,
  decodePublicKeyMultibase,
} from "../src/crypto/ed25519.js";
import { createDataIntegrityProof, verifyDataIntegrityProof } from "../src/crypto/proof.js";

describe("digest / SRI", () => {
  it("sha256 hex is stable", () => {
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

describe("ed25519", () => {
  it("signs and verifies (raw + multibase); rejects wrong key", () => {
    const k = generateEd25519Key();
    const other = generateEd25519Key();
    expect(k.publicKey.length).toBe(32);
    expect(k.privateKey.length).toBe(32);

    const sig = signRaw("via", k.privateKey);
    expect(sig.length).toBe(64);
    expect(verifyRaw("via", sig, k.publicKey)).toBe(true);
    expect(verifyRaw("via", sig, other.publicKey)).toBe(false);

    const mb = signMultibase("via", k.privateKey);
    expect(mb.startsWith("z")).toBe(true);
    expect(verifyMultibase("via", mb, k.publicKey)).toBe(true);
  });
  it("publicKeyMultibase round-trips (0xed01)", () => {
    const k = generateEd25519Key();
    const mb = encodePublicKeyMultibase(k.publicKey);
    expect(mb.startsWith("z6Mk")).toBe(true);
    expect([...decodePublicKeyMultibase(mb)]).toEqual([...k.publicKey]);
  });
});

describe("eddsa-jcs-2022 Data Integrity proof", () => {
  const doc = {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://via.humanos.tech/ns/v1"],
    id: "urn:via:credential:abc",
    type: ["VerifiableCredential", "VIAMandate"],
    issuer: "did:web:humanos.tech",
    credentialSubject: { id: "did:web:humanos.tech:org:1", mandate: { scope: "humanos.credential.request" } },
  };

  it("creates and verifies a proof; tamper fails", () => {
    const k = generateEd25519Key();
    const proof = createDataIntegrityProof({
      document: doc,
      privateKey: k.privateKey,
      verificationMethod: "did:web:humanos.tech#key-1",
      proofPurpose: "assertionMethod",
      created: "2026-06-23T00:00:00.000Z",
      lifecycleAction: "ISSUE",
    });
    expect(proof.cryptosuite).toBe("eddsa-jcs-2022");
    expect(proof.proofValue.startsWith("z")).toBe(true);
    expect((proof as unknown as Record<string, unknown>).actionProof).toBeUndefined(); // N21 — dropped

    expect(verifyDataIntegrityProof(doc, proof, k.publicKey)).toBe(true);
    // tamper the document
    expect(verifyDataIntegrityProof({ ...doc, issuer: "did:web:evil" }, proof, k.publicKey)).toBe(false);
  });

  it("lifecycleAction is committed by the signature (N21)", () => {
    const k = generateEd25519Key();
    const proof = createDataIntegrityProof({
      document: doc,
      privateKey: k.privateKey,
      verificationMethod: "did:web:humanos.tech#key-1",
      proofPurpose: "assertionMethod",
      lifecycleAction: "ISSUE",
    });
    // flipping lifecycleAction must invalidate the proof (it's inside proofConfig)
    const tampered = { ...proof, lifecycleAction: "STAMP" as const };
    expect(verifyDataIntegrityProof(doc, tampered, k.publicKey)).toBe(false);
  });

  it("event (the STAMP kind) is committed by the signature (spec §0.5.2)", () => {
    const k = generateEd25519Key();
    const proof = createDataIntegrityProof({
      document: doc,
      privateKey: k.privateKey,
      verificationMethod: "did:web:humanos.tech#key-1",
      proofPurpose: "assertionMethod",
      event: "STAMP",
    });
    expect(proof.event).toBe("STAMP");
    expect(verifyDataIntegrityProof(doc, proof, k.publicKey)).toBe(true);
    // flipping event must invalidate the proof (it's inside proofConfig)
    const tampered = { ...proof, event: "REVOKE" as const };
    expect(verifyDataIntegrityProof(doc, tampered, k.publicKey)).toBe(false);
  });
});
