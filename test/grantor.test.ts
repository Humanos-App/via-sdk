import { describe, it, expect, beforeAll } from "vitest";
import { generateP256Key, signES256, jwkThumbprint, type P256KeyPair } from "../src/crypto/p256.js";
import { verifyWebauthnAssertion } from "../src/crypto/webauthn.js";
import {
  enrollGrantor,
  grantorDidFromThumbprint,
  grantorTermsDigest,
  verifyGrantorAssertion,
  buildGrantorBinding,
} from "../src/grantor/binding.js";
import { createHash } from "node:crypto";

const te = new TextEncoder();
const RP_ID = "humanos.tech";
const ORIGIN = "https://humanos.tech";

// Mint a WebAuthn `get` assertion the way a passkey would (challenge = b64u(nonce·termsDigest)),
// signing authenticatorData ‖ SHA-256(clientDataJSON) with the credential's P-256 key.
async function mintAssertion(
  key: P256KeyPair,
  opts: { nonce: string; termsDigest: string; rpId?: string; origin?: string; up?: boolean },
) {
  const rpIdHash = new Uint8Array(createHash("sha256").update(Buffer.from(opts.rpId ?? RP_ID, "utf8")).digest());
  const authData = new Uint8Array(37);
  authData.set(rpIdHash, 0);
  authData[32] = opts.up === false ? 0x00 : 0x01; // user-present flag
  const clientData = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(te.encode(`${opts.nonce}.${opts.termsDigest}`)).toString("base64url"),
      origin: opts.origin ?? ORIGIN,
    }),
    "utf8",
  );
  const cdHash = new Uint8Array(createHash("sha256").update(clientData).digest());
  const signed = new Uint8Array(authData.length + cdHash.length);
  signed.set(authData, 0);
  signed.set(cdHash, authData.length);
  const sig = await signES256(signed, key.privateJwk);
  return {
    authenticatorDataB64: Buffer.from(authData).toString("base64url"),
    clientDataJSONB64: clientData.toString("base64url"),
    signatureB64: Buffer.from(sig).toString("base64url"),
  };
}

let key: P256KeyPair, cnf: string;
beforeAll(async () => {
  key = await generateP256Key();
  cnf = jwkThumbprint(key.publicJwk);
});

describe("§17 grantor binding (M5)", () => {
  it("enroll derives a did:web user DID from the passkey thumbprint", () => {
    const { did, cnf: c } = enrollGrantor(key.publicJwk, ORIGIN);
    expect(c).toBe(cnf);
    expect(did).toBe(`did:web:humanos.tech:user:${cnf.slice(0, 12)}`);
    expect(grantorDidFromThumbprint(cnf, "https://demo.example.com:443")).toBe(
      `did:web:demo.example.com:user:${cnf.slice(0, 12)}`,
    );
  });

  it("termsDigest is a digestSRI, deterministic and purpose/scope-sensitive", () => {
    const m = grantorTermsDigest({ purpose: "mandate", agentDid: "did:web:x:agent:1", constraints: [{ type: "amount_max", value: 100 }] });
    const s = grantorTermsDigest({ purpose: "stepup", mandateId: "m1", amount: 250, currency: "USD", item: "gpu" });
    expect(m).toMatch(/^sha256-/);
    expect(s).toMatch(/^sha256-/);
    expect(m).not.toBe(s);
    expect(grantorTermsDigest({ purpose: "stepup", mandateId: "m1", amount: 250, item: "gpu" })).toBe(s); // USD default
    expect(grantorTermsDigest({ purpose: "stepup", mandateId: "m1", amount: 999, item: "gpu" })).not.toBe(s);
  });

  it("verifies a valid grantor assertion and builds the binding", async () => {
    const nonce = "n-abc";
    const termsDigest = grantorTermsDigest({ purpose: "stepup", mandateId: "m1", amount: 250, item: "gpu" });
    const assertion = await mintAssertion(key, { nonce, termsDigest });
    const v = await verifyGrantorAssertion(assertion, key.publicJwk, { nonce, termsDigest, rpId: RP_ID, origin: ORIGIN });
    expect(v.ok).toBe(true);

    const gb = buildGrantorBinding(grantorDidFromThumbprint(cnf, ORIGIN), cnf, "2026-07-20T00:00:00.000Z");
    expect(gb).toEqual({
      grantor: `did:web:humanos.tech:user:${cnf.slice(0, 12)}`,
      cnf: { jkt: cnf }, // D2: RFC 7800 object form
      assurance: "passkey",
      verifiedAt: "2026-07-20T00:00:00.000Z",
    });
  });

  it("tampered terms → action_hash_mismatch (signed a different payment)", async () => {
    const nonce = "n-abc";
    const realTerms = grantorTermsDigest({ purpose: "stepup", mandateId: "m1", amount: 250, item: "gpu" });
    const signedTerms = grantorTermsDigest({ purpose: "stepup", mandateId: "m1", amount: 5000, item: "gpu" });
    const assertion = await mintAssertion(key, { nonce, termsDigest: signedTerms }); // human signed 5000...
    const v = await verifyGrantorAssertion(assertion, key.publicJwk, { nonce, termsDigest: realTerms, rpId: RP_ID, origin: ORIGIN }); // ...verifier expects 250
    expect(v.ok).toBe(false);
    expect(v.reason).toBe("action_hash_mismatch");
  });

  it("wrong origin (agent's page, not Humanos's) → pop_invalid", async () => {
    const nonce = "n-abc";
    const termsDigest = grantorTermsDigest({ purpose: "mandate", agentDid: "a", constraints: [] });
    const assertion = await mintAssertion(key, { nonce, termsDigest, origin: "https://evil-agent.app" });
    const v = await verifyGrantorAssertion(assertion, key.publicJwk, { nonce, termsDigest, rpId: RP_ID, origin: ORIGIN });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe("pop_invalid");
  });

  it("wrong key → pop_invalid", async () => {
    const other = await generateP256Key();
    const nonce = "n-abc";
    const termsDigest = grantorTermsDigest({ purpose: "mandate", agentDid: "a", constraints: [] });
    const assertion = await mintAssertion(key, { nonce, termsDigest });
    const v = await verifyGrantorAssertion(assertion, other.publicJwk, { nonce, termsDigest, rpId: RP_ID, origin: ORIGIN });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe("pop_invalid");
  });

  it("verifyWebauthnAssertion rejects a cleared user-present flag", async () => {
    const nonce = "n";
    const termsDigest = grantorTermsDigest({ purpose: "mandate", agentDid: "a", constraints: [] });
    const assertion = await mintAssertion(key, { nonce, termsDigest, up: false });
    const v = await verifyWebauthnAssertion(assertion, key.publicJwk, { nonce, actionHash: termsDigest, rpId: RP_ID, origin: ORIGIN });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe("pop_invalid");
  });
});
