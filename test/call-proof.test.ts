import { describe, it, expect } from "vitest";
import {
  generateEd25519Key,
  buildCallProof,
  verifyCallProof,
  actionHash,
  policyActionHash,
  outcomeParams,
  CALL_PROOF_MAX_LIFETIME,
  type CallProofCall,
} from "../src/index.js";
import { signRaw } from "../src/crypto/ed25519.js";

const ISS = "did:web:acme-bank.example";
const VM = `${ISS}#key-1`;
const key = generateEd25519Key();
const other = generateEd25519Key();
const signer = { privateKey: key.privateKey, verificationMethod: VM };
const resolvePublicKey = (vm: string) => {
  if (vm !== VM) throw new Error("unknown key");
  return key.publicKey;
};

const AUD = "https://api.provider.example";
const MANDATE = "urn:via:credential:9c1e";
const POLICY = "urn:via:policy:4d2a";
const CALL: CallProofCall = { action: "transfer", params: { amount: 10, to: "PT50" } };
const IAT = 1_790_000_000;
const AT = new Date(IAT * 1000 + 60_000);

const proof = (over: Partial<Parameters<typeof buildCallProof>[0]> = {}) =>
  buildCallProof(
    { iss: ISS, sub: "did:web:humanos.tech:agent:a1", aud: AUD, mandate: MANDATE, decision: "urn:via:event:d1", call: CALL, iat: IAT, jti: "j-1", ...over } as Parameters<typeof buildCallProof>[0],
    signer,
  );

/** A receiver's jti store: first use answers true. */
const store = () => {
  const seen = new Set<string>();
  return (jti: string) => (seen.has(jti) ? false : (seen.add(jti), true));
};

const check = (token: unknown, over: Partial<Parameters<typeof verifyCallProof>[1]> = {}) =>
  verifyCallProof(token, { audience: AUD, resolvePublicKey, call: CALL, consumeJti: store(), now: AT, ...over });

/** Re-sign a proof's header and claims after a change — a forgery by a holder of the key. */
const resign = (token: string, edit: (h: Record<string, unknown>, c: Record<string, unknown>) => void, privateKey = key.privateKey) => {
  const [h, c] = token.split(".").slice(0, 2).map((p) => JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as Record<string, unknown>);
  edit(h!, c!);
  const input = `${Buffer.from(JSON.stringify(h)).toString("base64url")}.${Buffer.from(JSON.stringify(c)).toString("base64url")}`;
  return `${input}.${Buffer.from(signRaw(new TextEncoder().encode(input), privateKey)).toString("base64url")}`;
};

describe("§16.16 the call proof", () => {
  it("is accepted by its receiver, with the claims it was signed with", async () => {
    const r = await check(proof());
    expect(r).toEqual({
      ok: true,
      claims: {
        iss: ISS,
        sub: "did:web:humanos.tech:agent:a1",
        aud: AUD,
        mandate: MANDATE,
        decision: "urn:via:event:d1",
        action_hash: actionHash(MANDATE, CALL.action, CALL.params),
        iat: IAT,
        exp: IAT + CALL_PROOF_MAX_LIFETIME,
        jti: "j-1",
      },
    });
  });

  it("binds the policy in place of the mandate for a decision under the organization's policy (§21.4)", async () => {
    const r = await check(proof({ mandate: undefined, policy: POLICY } as never));
    expect(r.ok && r.claims.action_hash).toBe(policyActionHash(POLICY, CALL.action, CALL.params));
    expect(r.ok && "mandate" in r.claims).toBe(false);
  });

  it("is signed EdDSA, with the decision signer's verification method as kid", () => {
    const header = JSON.parse(Buffer.from(proof().split(".")[0]!, "base64url").toString("utf8"));
    expect(header).toEqual({ alg: "EdDSA", typ: "via-call-proof+jwt", kid: VM });
  });

  // @refusal
  it("is never built with a life over five minutes, or with a key outside its iss", () => {
    expect(() => proof({ ttlSeconds: CALL_PROOF_MAX_LIFETIME + 1 })).toThrow(/between 1 and 300/);
    expect(() => proof({ iss: "did:web:other.example" })).toThrow(/verification method of its iss/);
  });

  // @refusal
  it.each([
    ["a token of another type", (t: string) => resign(t, (h) => (h.typ = "via-pop+jwt"))],
    ["a header naming another algorithm", (t: string) => resign(t, (h) => (h.alg = "ES256"))],
    ["a kid outside iss", (t: string) => resign(t, (h) => (h.kid = "did:web:other.example#key-1"))],
    ["both a mandate and a policy", (t: string) => resign(t, (_h, c) => (c.policy = POLICY))],
    ["a life over five minutes", (t: string) => resign(t, (_h, c) => (c.exp = (c.iat as number) + CALL_PROOF_MAX_LIFETIME + 1))],
    ["not a JWS", () => "not.a-jws"],
  ])("refuses as invalid — %s", async (_name, mangle) => {
    expect(await check(mangle(proof()))).toEqual({ ok: false, reason: "call_proof_invalid" });
  });

  // @refusal
  it.each([
    ["a signature by another key", (t: string) => resign(t, () => {}, other.privateKey)],
    ["claims changed after signing", (t: string) => {
      const [h, , s] = t.split(".");
      return `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(t.split(".")[1]!, "base64url").toString()), aud: "x" })).toString("base64url")}.${s}`;
    }],
  ])("refuses the signature — %s", async (_name, mangle) => {
    expect(await check(mangle(proof()))).toEqual({ ok: false, reason: "signature_invalid" });
  });

  // @refusal
  it("refuses a key its resolver cannot find", async () => {
    expect(await check(proof(), { resolvePublicKey: () => { throw new Error("no such key"); } })).toEqual({ ok: false, reason: "signature_invalid" });
  });

  // @refusal
  it("refuses a proof for another receiver", async () => {
    expect(await check(proof({ aud: "did:web:other.example" }))).toEqual({ ok: false, reason: "aud_mismatch" });
  });

  it("accepts any of the receiver's names", async () => {
    expect((await check(proof({ aud: "did:web:provider.example" }), { audience: [AUD, "did:web:provider.example"] })).ok).toBe(true);
  });

  // @refusal
  it.each([
    ["after exp", new Date((IAT + CALL_PROOF_MAX_LIFETIME + 31) * 1000)],
    ["before iat", new Date((IAT - 31) * 1000)],
  ])("refuses a proof outside its life, beyond the skew — %s", async (_name, now) => {
    expect(await check(proof(), { now })).toEqual({ ok: false, reason: "call_proof_expired" });
  });

  it("allows the receiver's clock skew at either end", async () => {
    expect((await check(proof(), { now: new Date((IAT + CALL_PROOF_MAX_LIFETIME + 30) * 1000) })).ok).toBe(true);
    expect((await check(proof(), { now: new Date((IAT - 30) * 1000) })).ok).toBe(true);
  });

  // @refusal
  it.each([
    ["other params", { ...CALL, params: { amount: 11, to: "PT50" } }],
    ["another tool", { ...CALL, action: "withdraw" }],
  ])("refuses a proof for another call — %s", async (_name, call) => {
    expect(await check(proof(), { call })).toEqual({ ok: false, reason: "action_hash_mismatch" });
  });

  // @refusal
  it("refuses a jti seen before", async () => {
    const consumeJti = store();
    expect((await check(proof(), { consumeJti })).ok).toBe(true);
    expect(await check(proof(), { consumeJti })).toEqual({ ok: false, reason: "call_proof_replayed" });
  });

  // @invariant §16.16: the checks run in order, so a forged proof never spends its jti.
  it("never consumes a jti for a proof that fails an earlier check", async () => {
    const seen: string[] = [];
    await check(proof(), { call: { ...CALL, action: "withdraw" }, consumeJti: (j) => (seen.push(j), true) });
    expect(seen).toEqual([]);
  });
});

describe("§2.1 outcomeParams — the outcome report, as the agent signs it", () => {
  // The golden vectors the platform's outcome-params.spec.ts and agent-sdk pin: a change of shape or key
  // order fails here instead of every report failing with action_hash_mismatch.
  it.each([
    ["failed, with the error", outcomeParams("urn:via:event:golden", "failed", "carrier timeout"), "sha256-4tU+bpbcVH3SreXW2ZiVj8QEQu58OnLZPc0MRfr7cfA="],
    ["completed", outcomeParams("urn:via:event:golden", "completed"), "sha256-2yRGCiqttP5rmvG/RjaNjsM4PPXcubQigkRRiAbYr9Q="],
  ])("hashes to the shared golden vector — %s", (_name, params, hash) => {
    expect(actionHash("urn:via:credential:golden", "report_outcome", params)).toBe(hash);
  });
});
