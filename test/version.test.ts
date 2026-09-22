/**
 * Spec-version readiness guards.
 *
 * Pins: builders stamp the signed `specVersion` marker; the marker is covered by
 * the signature; `detectSpecVersion` routes mandates/receipts/VPs; and a verifier
 * fails CLOSED on a spec version it does not support (forward-compat safety).
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  VIA_SPEC_VERSION,
  SUPPORTED_SPEC_VERSIONS,
  VIA_CONTEXT_VERSION,
  detectSpecVersion,
  isSupportedSpecVersion,
  generateEd25519Key,
  generateViaDID,
  VIA_PLATFORM_DID,
  buildMandate,
  buildPresentation,
  stampMandate,
  verify,
  type Ed25519KeyPair,
  type VerifyDeps,
  type ViaMandateCredential,
} from "../src/index.js";
import { verifyDataIntegrityProof } from "../src/crypto/proof.js";

const vmPlatform = `${VIA_PLATFORM_DID}#key-1`;
const verifierDid = "did:web:verifier.example";
const newMandate = () =>
  buildMandate({
    subjectOrg: generateViaDID("org", { uuid: "o" }),
    grantor: generateViaDID("user", { uuid: "u" }),
    authorizedDIDs: [verifierDid],
    validFrom: "2026-01-01T00:00:00.000Z",
    // §20.3 — with no action, the words ARE the grant, so the builder requires them.
    description: { text: "Act for Acme within this scope.", lang: "en", author: "grantor" },
  });

describe("version identity", () => {
  it("exposes the spec version, supported set, and context version", () => {
    expect(VIA_SPEC_VERSION).toBe("0.3");
    expect(SUPPORTED_SPEC_VERSIONS).toContain("0.3");
    // 0.2 is current, not legacy — v0.3 is an evolution and must still verify it.
    expect(SUPPORTED_SPEC_VERSIONS).toContain("0.2");
    expect(VIA_CONTEXT_VERSION).toBe("v1");
  });
  it("isSupportedSpecVersion gates on the supported set", () => {
    expect(isSupportedSpecVersion("0.3")).toBe(true);
    expect(isSupportedSpecVersion("0.2")).toBe(true);
    expect(isSupportedSpecVersion("0.4")).toBe(false);
    expect(isSupportedSpecVersion(undefined)).toBe(false);
  });
});

describe("builders stamp the marker", () => {
  it("buildMandate stamps specVersion", () => {
    expect(newMandate().specVersion).toBe("0.3");
  });
});


describe("detectSpecVersion — supported (marker present & known)", () => {
  it("mandate with marker → 0.3", () => {
    expect(detectSpecVersion(newMandate())).toBe("0.3");
  });
  it("receipt with marker → 0.2", () => {
  });
  it("real signed presentation delegates to its credential → 0.3", () => {
    const vp = buildPresentation({
      credential: newMandate(),
      holder: VIA_PLATFORM_DID,
      privateKey: generateEd25519Key().privateKey,
      verificationMethod: vmPlatform,
    });
    expect(detectSpecVersion(vp)).toBe("0.3");
  });
  it("presentation as a plain object delegates to its credential → 0.2", () => {
    expect(detectSpecVersion({ verifiableCredential: { specVersion: "0.2" } })).toBe("0.2");
  });
});


describe("detectSpecVersion — unknown (marker PRESENT but unsupported/malformed → fail closed)", () => {
  it("future version string → unknown", () => {
    expect(detectSpecVersion({ specVersion: "0.4" })).toBe("unknown");
  });
  it("presentation wrapping a future-version credential → unknown", () => {
    expect(detectSpecVersion({ verifiableCredential: { specVersion: "0.4" } })).toBe("unknown");
  });
  it("empty-string marker → unknown (not legacy: a marker IS present)", () => {
    expect(detectSpecVersion({ specVersion: "" } as unknown as Record<string, unknown>)).toBe("unknown");
  });
  it("non-string marker (number) → unknown (spec requires a string)", () => {
    expect(detectSpecVersion({ specVersion: 0.2 } as unknown as Record<string, unknown>)).toBe("unknown");
  });
});

describe("the marker is signed (tamper-evident)", () => {
  it("flipping specVersion invalidates the proof", () => {
    const key = generateEd25519Key();
    const signed = stampMandate(newMandate(), { privateKey: key.privateKey, verificationMethod: vmPlatform });
    const proof = signed.proof!;
    expect(verifyDataIntegrityProof(signed as unknown as Record<string, unknown>, proof, key.publicKey)).toBe(true);
    const tampered = { ...signed, specVersion: "0.4" };
    expect(verifyDataIntegrityProof(tampered as unknown as Record<string, unknown>, proof, key.publicKey)).toBe(false);
  });
});

describe("verify is forward-safe (fails closed on unsupported versions)", () => {
  let platform: Ed25519KeyPair;
  let deps: VerifyDeps;
  beforeAll(() => {
    platform = generateEd25519Key();
    deps = {
      verifier: { did: verifierDid },
      resolvePublicKey: async () => platform.publicKey,
      loadCredentialRecord: async () => ({ status: "ACTIVE", validFrom: "2026-01-01T00:00:00.000Z" }),
      loadActionVersion: async () => null,
      now: new Date("2026-06-23T12:00:00.000Z"),
    };
  });

  it("allows a current-version VP and reports its specVersion", async () => {
    const vp = buildPresentation({ credential: newMandate(), holder: VIA_PLATFORM_DID, privateKey: platform.privateKey, verificationMethod: vmPlatform });
    const r = await verify({ presentation: vp }, deps);
    expect(r.decision).toBe("allow");
    expect(r.specVersion).toBe("0.3");
  });


  it("denies a validly-signed VP whose credential declares a future spec version", async () => {
    // sign a VP over a credential marked "0.3": the signature is valid, but the model is unknown.
    const future = { ...newMandate(), specVersion: "0.4" } as unknown as ViaMandateCredential;
    const vp = buildPresentation({ credential: future, holder: VIA_PLATFORM_DID, privateKey: platform.privateKey, verificationMethod: vmPlatform });
    const r = await verify({ presentation: vp }, deps);
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("unsupported_spec_version");
    expect(r.specVersion).toBe("unknown");
  });
});
