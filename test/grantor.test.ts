import { describe, it, expect, beforeAll } from "vitest";
import { generateP256Key, signES256, jwkThumbprint, type P256KeyPair } from "../src/crypto/p256.js";
import { verifyWebauthnAssertion } from "../src/crypto/webauthn.js";
import {
  enrollGrantor,
  grantorBindingMethod,
  grantorTermsDigest,
  verifyGrantorAssertion,
  buildGrantorBinding,
  buildOtpGrantorBinding,
} from "../src/grantor/binding.js";
import { createHash } from "node:crypto";

const te = new TextEncoder();
const RP_ID = "humanos.tech";
const ORIGIN = "https://humanos.tech";
/** The grantor is a PERSON ACTOR (§3.5): one DID per party, never one per passkey (§3.6). */
const GRANTOR = "did:web:humanos.tech:user:68c0a1b2c3d4e5f6a7b8c9d0";

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
  it("enroll returns the passkey thumbprint beside the person's actor DID — it mints nothing (§3.6)", () => {
    const { did, cnf: c } = enrollGrantor(key.publicJwk, GRANTOR);
    expect(c).toBe(cnf);
    expect(did).toBe(GRANTOR);
    // Any WebAuthn key family enrols (§16.6bis); the thumbprint is RFC 7638 for each.
    const rsa = { kty: "RSA", n: "AQAB-n", e: "AQAB" };
    expect(enrollGrantor(rsa, GRANTOR).cnf).toBe(jwkThumbprint(rsa));
    expect(() => enrollGrantor(key.publicJwk, "")).toThrow(/actor DID/);
    expect(() => enrollGrantor(key.publicJwk, "user:abc")).toThrow(/actor DID/);
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

  it("verifies a valid grantor assertion and builds the binding with `method`, not a rung", async () => {
    const nonce = "n-abc";
    const termsDigest = grantorTermsDigest({ purpose: "stepup", mandateId: "m1", amount: 250, item: "gpu" });
    const assertion = await mintAssertion(key, { nonce, termsDigest });
    const v = await verifyGrantorAssertion(assertion, key.publicJwk, { nonce, termsDigest, rpId: RP_ID, origin: ORIGIN });
    expect(v.ok).toBe(true);

    const gb = buildGrantorBinding(GRANTOR, cnf, "2026-07-20T00:00:00.000Z");
    expect(gb).toEqual({
      grantor: GRANTOR,
      cnf: { jkt: cnf }, // D2: RFC 7800 object form
      method: "webauthn",
      verifiedAt: "2026-07-20T00:00:00.000Z",
    });
    expect(gb).not.toHaveProperty("assurance");
    expect(grantorBindingMethod(gb)).toBe("webauthn");
  });

  it("reads the v0.2 encoding (`assurance: \"passkey\"`) as the same fact, and nothing else as one", () => {
    expect(grantorBindingMethod({ grantor: GRANTOR, cnf: { jkt: cnf }, assurance: "passkey", verifiedAt: "2026-01-01T00:00:00.000Z" })).toBe("webauthn");
    expect(grantorBindingMethod({ grantor: GRANTOR, cnf: { jkt: cnf }, assurance: "hardware", verifiedAt: "x" })).toBeNull();
    expect(grantorBindingMethod({})).toBeNull();
  });

  it("builds the otp arm with the channel KIND and no cnf — the ordinary path is recorded too", () => {
    const gb = buildOtpGrantorBinding(GRANTOR, "email", "2026-01-01T00:00:00.000Z");
    expect(gb).toEqual({ grantor: GRANTOR, method: "otp", channel: "email", verifiedAt: "2026-01-01T00:00:00.000Z" });
    // @invariant no key is named, because none signed: a reader must see that at a glance.
    expect("cnf" in gb).toBe(false);
    expect(grantorBindingMethod(gb)).toBe("otp");
  });

  it("carries the channel's KIND, never the address — the mandate travels to relying parties", () => {
    const sms = buildOtpGrantorBinding(GRANTOR, "sms", "2026-01-01T00:00:00.000Z");
    expect(sms.channel).toBe("sms");
    expect(JSON.stringify(sms)).not.toMatch(/@|\+\d/);
  });

  it("an absent binding is not a method: nothing reads as otp unless it says so", () => {
    // The reason the otp arm exists. Absence used to mean four things — code-approved, pre-§17.2,
    // multi-grantor, no session — and a reader had to guess which.
    expect(grantorBindingMethod({})).toBeNull();
    expect(grantorBindingMethod({ grantor: GRANTOR, verifiedAt: "x" })).toBeNull();
    expect(grantorBindingMethod({ grantor: GRANTOR, method: "sms-code", verifiedAt: "x" })).toBeNull();
  });

  it("tampered terms → action_hash_mismatch (signed a different payment) — the one code shared with §16.7", async () => {
    const nonce = "n-abc";
    const realTerms = grantorTermsDigest({ purpose: "stepup", mandateId: "m1", amount: 250, item: "gpu" });
    const signedTerms = grantorTermsDigest({ purpose: "stepup", mandateId: "m1", amount: 5000, item: "gpu" });
    const assertion = await mintAssertion(key, { nonce, termsDigest: signedTerms }); // human signed 5000...
    const v = await verifyGrantorAssertion(assertion, key.publicJwk, { nonce, termsDigest: realTerms, rpId: RP_ID, origin: ORIGIN }); // ...verifier expects 250
    expect(v.ok).toBe(false);
    expect(v.reason).toBe("action_hash_mismatch");
  });

  it("wrong origin (agent's page, not Humanos's) → grantor_assertion_invalid, never the agent's pop_invalid (§17.5)", async () => {
    const nonce = "n-abc";
    const termsDigest = grantorTermsDigest({ purpose: "mandate", agentDid: "a", constraints: [] });
    const assertion = await mintAssertion(key, { nonce, termsDigest, origin: "https://evil-agent.app" });
    const v = await verifyGrantorAssertion(assertion, key.publicJwk, { nonce, termsDigest, rpId: RP_ID, origin: ORIGIN });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe("grantor_assertion_invalid");
  });

  it("wrong key → grantor_assertion_invalid", async () => {
    const other = await generateP256Key();
    const nonce = "n-abc";
    const termsDigest = grantorTermsDigest({ purpose: "mandate", agentDid: "a", constraints: [] });
    const assertion = await mintAssertion(key, { nonce, termsDigest });
    const v = await verifyGrantorAssertion(assertion, other.publicJwk, { nonce, termsDigest, rpId: RP_ID, origin: ORIGIN });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe("grantor_assertion_invalid");
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

describe("§17.4 — a step-up over a tool call co-signs the agent's own action_hash", () => {
  it("the terms digest of { mandateId, action, params } IS the PoP action_hash for the same call", async () => {
    const { actionHash } = await import("../src/agent/pop.js");
    const params = { tool: "slack_send_message", channel_id: "C0BVB1KBPG8", message: "ship it" };
    const digest = grantorTermsDigest({ purpose: "stepup", mandateId: "urn:via:credential:m", action: "slack_send_message", params });
    expect(digest).toBe(actionHash("urn:via:credential:m", "slack_send_message", params));
    // Any change to the call is a different digest — the human's yes does not travel to another call.
    expect(grantorTermsDigest({ purpose: "stepup", mandateId: "urn:via:credential:m", action: "slack_send_message", params: { ...params, channel_id: "C0OTHER" } })).not.toBe(digest);
  });

  it("the purchase-shaped variant still digests as before", () => {
    const a = grantorTermsDigest({ purpose: "stepup", mandateId: "urn:via:credential:m", amount: 120, currency: "EUR", item: "hotel" });
    const b = grantorTermsDigest({ purpose: "stepup", mandateId: "urn:via:credential:m", amount: 120, currency: "EUR", item: "hotel" });
    expect(a).toBe(b);
    expect(a).toMatch(/^sha256-/);
  });
});
