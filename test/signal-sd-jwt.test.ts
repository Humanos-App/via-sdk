import { describe, it, expect, beforeAll } from "vitest";
import { generateEd25519Key, VIA_PLATFORM_DID, type Ed25519KeyPair } from "../src/index.js";
import { buildSdJwtSignal, redactSdJwtSignal, verifySdJwtSignal, SD_JWT_TYP, VIA_SIGNAL_VCT } from "../src/signal/sd-jwt.js";
import { fromBase64Url, fromUtf8 } from "../src/crypto/encoding.js";

let platform: Ed25519KeyPair;
let sdJwt: string;
const signal = {
  id: "urn:via:signal:11111111-2222-4333-8444-555555555555",
  kind: "RiskSignal",
  issuer: VIA_PLATFORM_DID,
  validFrom: "2026-09-09T04:30:00.000Z",
  validUntil: "2099-09-11T04:30:00.000Z",
  credentialSubject: {
    actor: "did:web:humanos.tech:agent:RRJyvYvj0T-ZRBU-",
    actorSnapshot: { id: "urn:via:snapshot:x", sequence: 3 },
    window: { from: "2026-08-10T04:30:00.000Z", to: "2026-09-09T04:30:00.000Z", startEvent: "urn:via:event:a", endEvent: "urn:via:event:z" },
    score: 31,
    trust: 0.63,
    components: { identity: 0.6, compliance: 0.66, exposure: 0.825, anomaly: 1 },
    evidence: { identity: [{ name: "affiliated", delta: 0.2, evidence: ["urn:via:event:aff"] }] },
    remediations: [{ summary: "Put an expiry on 2 open-ended authorizations", evidence: ["urn:via:credential:travel"] }],
    previousSignal: "urn:via:signal:00000000-2222-4333-8444-555555555555",
  },
};

beforeAll(async () => {
  platform = generateEd25519Key();
  sdJwt = await buildSdJwtSignal({ signal, issuerPrivateKey: platform.privateKey, issuerVerificationMethod: `${VIA_PLATFORM_DID}#key-1`, disclosable: ["evidence", "remediations"] });
});

describe("VIASignal as an SD-JWT (§9.0 sense 3, Appendix A)", () => {
  it("issues a dc+sd-jwt typed VIASignal + kind, with the disclosable claims as disclosures", () => {
    const header = JSON.parse(fromUtf8(fromBase64Url(sdJwt.split(".")[0]!))) as Record<string, unknown>;
    expect(header.typ).toBe(SD_JWT_TYP);
    expect(header.kid).toBe(`${VIA_PLATFORM_DID}#key-1`);
    expect(sdJwt.split("~").length).toBe(4); // jwt ~ evidence ~ remediations ~
    const payload = JSON.parse(fromUtf8(fromBase64Url(sdJwt.split(".")[1]!))) as Record<string, unknown>;
    expect(payload.vct).toBe(VIA_SIGNAL_VCT);
    expect(payload.type).toEqual(["VerifiableCredential", "VIASignal", "RiskSignal"]);
    expect(JSON.stringify(payload)).not.toContain("urn:via:event:aff"); // disclosable claims are hashed, not inline
    expect(JSON.stringify(payload)).toContain('"score":31'); // the number itself is always present
  });

  it("the owner's copy verifies with everything; a redacted copy verifies with the numbers only — one signature", async () => {
    const full = await verifySdJwtSignal({ sdJwt, issuerPublicKey: platform.publicKey });
    const cs = full.claims.credentialSubject as Record<string, unknown>;
    expect(full.valid).toBe(true);
    expect(cs.score).toBe(31);
    expect(cs.evidence).toBeDefined();
    expect(cs.remediations).toBeDefined();

    const partner = await redactSdJwtSignal(sdJwt, []);
    expect(partner.split("~").length).toBe(2); // jwt ~ (no disclosures)
    const seen = await verifySdJwtSignal({ sdJwt: partner, issuerPublicKey: platform.publicKey });
    const pcs = seen.claims.credentialSubject as Record<string, unknown>;
    expect(pcs.score).toBe(31);
    expect(pcs.actor).toBe(signal.credentialSubject.actor);
    expect(pcs.evidence).toBeUndefined();
    expect(pcs.remediations).toBeUndefined();
    expect(partner.split("~")[0]).toBe(sdJwt.split("~")[0]); // the same issuer-signed bytes
  });

  it("refuses another key, a tampered body, an expired signal, and a non-signal", async () => {
    const other = generateEd25519Key();
    await expect(verifySdJwtSignal({ sdJwt, issuerPublicKey: other.publicKey })).rejects.toThrow();
    const [jwt, ...rest] = sdJwt.split("~");
    const [h, p, s] = jwt!.split(".");
    const tampered = [h, p!.slice(0, -2) + "AA", s].join(".") + "~" + rest.join("~");
    await expect(verifySdJwtSignal({ sdJwt: tampered, issuerPublicKey: platform.publicKey })).rejects.toThrow();
    const expired = await buildSdJwtSignal({ signal: { ...signal, validUntil: "2026-01-01T00:00:00.000Z" }, issuerPrivateKey: platform.privateKey, issuerVerificationMethod: "k" });
    await expect(verifySdJwtSignal({ sdJwt: expired, issuerPublicKey: platform.publicKey })).rejects.toThrow(/expired/);
    const notSignal = await buildSdJwtSignal({ signal: { ...signal, kind: "Thing" }, issuerPrivateKey: platform.privateKey, issuerVerificationMethod: "k" });
    // Still a VIASignal by type; the kind is the third type. A body without the VIASignal type is refused:
    expect((await verifySdJwtSignal({ sdJwt: notSignal, issuerPublicKey: platform.publicKey })).valid).toBe(true);
  });
});
