import { describe, it, expect } from "vitest";
import {
  generateEd25519Key,
  generateViaDID,
  buildDidDocument,
  resolveVerificationKey,
  StatusList,
  checkCredentialStatus,
  buildEvidence,
  MEDIA_TYPE_PATTERN,
  computeSRI,
  buildMandate,
  stampMandate,
  verifyStamp,
} from "../src/index.js";

describe("resolveVerificationKey", () => {
  const k = generateEd25519Key();
  const did = generateViaDID("org", { uuid: "o" });
  const doc = buildDidDocument({ did, publicKey: k.publicKey });

  it("decodes the Multikey VM to the raw public key (optionally checking purpose)", () => {
    expect([...resolveVerificationKey(doc, `${did}#key-1`)]).toEqual([...k.publicKey]);
    expect([...resolveVerificationKey(doc, `${did}#key-1`, "assertionMethod")]).toEqual([...k.publicKey]);
  });
  it("throws on an unknown verification method", () => {
    expect(() => resolveVerificationKey(doc, `${did}#key-2`)).toThrow();
  });
  it("composes as a resolvePublicKey for verifyStamp", async () => {
    let m = buildMandate({
      subjectOrg: did,
      grantor: "did:web:humanos.tech:user:u",
      authorizedDIDs: ["did:web:v.example"],
      validFrom: "2026-01-01T00:00:00.000Z",
      description: { text: "Act for this org within this scope.", lang: "en", author: "grantor" },
      enforcement: "none",
    });
    m = stampMandate(m, { privateKey: k.privateKey, verificationMethod: `${did}#key-1` });
    const r = await verifyStamp(m, (vmId) => resolveVerificationKey(doc, vmId, "assertionMethod"));
    expect(r.valid).toBe(true);
  });
});

describe("checkCredentialStatus", () => {
  const sl = new StatusList("https://status.humanos.tech/1", "revocation", 1024);
  const i = sl.allocateIndex();
  const entry = sl.entry(i);

  it("reads the bit (false → true after revoke); purpose mismatch throws", () => {
    let cred = sl.toStatusListCredential("did:web:humanos.tech", "2026-01-01T00:00:00.000Z");
    expect(checkCredentialStatus(entry, cred)).toEqual({ statusPurpose: "revocation", value: false });

    sl.set(i, true);
    cred = sl.toStatusListCredential("did:web:humanos.tech", "2026-01-01T00:00:00.000Z");
    expect(checkCredentialStatus(entry, cred).value).toBe(true);

    const wrong = { ...cred, credentialSubject: { ...cred.credentialSubject, statusPurpose: "suspension" as const } };
    expect(() => checkCredentialStatus(entry, wrong)).toThrow(/mismatch/);
  });
});

describe("buildEvidence", () => {
  it("computes the SRI from content and defaults id/type", () => {
    const e = buildEvidence({ content: "consent-bytes", mediaType: "application/pdf", location: "https://api.humanos.tech/evidence/x" });
    expect(e.id.startsWith("urn:via:evidence:")).toBe(true);
    expect(e.type).toEqual(["VIAEvidence"]);
    expect(e.digestSRI).toBe(computeSRI("consent-bytes"));
    expect(e.mediaType).toBe("application/pdf");
  });
  it("accepts a precomputed digestSRI and requires one of content/digestSRI", () => {
    const e = buildEvidence({ digestSRI: "sha256-abc", location: "https://x", id: "urn:via:evidence:fixed" });
    expect(e.digestSRI).toBe("sha256-abc");
    expect(e.id).toBe("urn:via:evidence:fixed");
    expect(() => buildEvidence({ location: "https://x" })).toThrow();
  });

  // @invariant v0.3 §12: an evidence `mediaType` is signed, so it is a bare lowercase type/subtype —
  // a parameter or a capital would be a second spelling of one type inside a signature, and two
  // equivalent credentials would stop comparing equal. Refused before signing, never normalized.
  it("accepts a bare lowercase media type and refuses any other spelling", () => {
    const entry = (mediaType: string) => buildEvidence({ digestSRI: "sha256-abc", location: "https://x", mediaType });
    for (const ok of ["application/pdf", "application/json", "image/svg+xml", "application/vnd.humanos.consent-v1+json"]) {
      expect(entry(ok).mediaType, ok).toBe(ok);
      expect(MEDIA_TYPE_PATTERN.test(ok), ok).toBe(true);
    }
    for (const bad of ["application/json;charset=utf-8", "Application/PDF", "application/json ", " application/json", "pdf", "application/", "/pdf", "a/b/c", ""]) {
      expect(() => entry(bad), JSON.stringify(bad)).toThrow(/invalid mediaType/);
    }
    // Stating none is allowed: the entry simply carries no `mediaType`.
    expect(buildEvidence({ digestSRI: "sha256-abc", location: "https://x" })).not.toHaveProperty("mediaType");
  });
});
