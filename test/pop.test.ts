import { describe, it, expect, beforeAll } from "vitest";
import { createHash } from "node:crypto";
import {
  algForKey,
  allowedPopAlgs,
  generateP256Key,
  jwkThumbprint,
  actionHash,
  buildPoP,
  decodePoP,
  verifyPoPSignature,
  canonicalizeRFC8785,
  type P256KeyPair,
  type PopPayload,
} from "../src/index.js";

let key: P256KeyPair, jkt: string;
beforeAll(async () => {
  key = await generateP256Key();
  jkt = jwkThumbprint(key.publicJwk);
});

const mkPayload = (): PopPayload => ({
  cnf: { jkt },
  aud: "fidelidade.pt",
  nonce: "n-123",
  iat: 1751792400,
  action_hash: actionHash("urn:via:credential:1", "transfer_funds", { amount: 40000 }),
});

describe("actionHash (§16.6 / §0.5.3)", () => {
  it("is the self-describing sha256- digestSRI form", () => {
    const h = actionHash("m1", "pay", { amount: 10 });
    expect(h).toMatch(/^sha256-[A-Za-z0-9+/]+=*$/); // sha256- + standard base64
  });
  it("is deterministic and param-sensitive", () => {
    expect(actionHash("m1", "pay", { amount: 10 })).toBe(actionHash("m1", "pay", { amount: 10 }));
    expect(actionHash("m1", "pay", { amount: 10 })).not.toBe(actionHash("m1", "pay", { amount: 11 }));
  });
  it("matches an independent digestSRI computation (kya interop formula)", () => {
    const canonical = canonicalizeRFC8785({ mandateId: "m1", action: "pay", params: { amount: 10 } });
    const expected = "sha256-" + createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("base64");
    expect(actionHash("m1", "pay", { amount: 10 })).toBe(expected);
  });
});

describe("PoP build/decode/verify (§16.6–§16.7)", () => {
  it("build → decode round-trips; jkt (A2 selector) is extracted", async () => {
    const jws = await buildPoP(mkPayload(), key.privateJwk);
    const d = decodePoP(jws);
    expect(d.ok).toBe(true);
    expect(d.alg).toBe("ES256");
    expect(d.jkt).toBe(jkt);
    expect(d.payload?.aud).toBe("fidelidade.pt");
  });

  it("verifies the signature (A3) and rejects a tampered payload", async () => {
    const jws = await buildPoP(mkPayload(), key.privateJwk);
    expect(await verifyPoPSignature(jws, key.publicJwk)).toBe(true);
    // splice a different (valid) payload onto the original header+sig → sig must fail
    const [h, , s] = jws.split(".");
    const forgedPayload = Buffer.from(JSON.stringify({ ...mkPayload(), aud: "evil.com" })).toString("base64url");
    expect(await verifyPoPSignature(`${h}.${forgedPayload}.${s}`, key.publicJwk)).toBe(false);
  });

  it("A1 rejects a wrong typ, and `none`/`HS256`, which can never reach the key check", async () => {
    const p = Buffer.from(JSON.stringify(mkPayload())).toString("base64url");
    const hdr = (h: object) => Buffer.from(JSON.stringify(h)).toString("base64url");
    expect(decodePoP(`${hdr({ alg: "ES256", typ: "jwt" })}.${p}.x`).reason).toBe("pop_invalid");
    expect(decodePoP(`${hdr({ alg: "none", typ: "via-pop+jwt" })}.${p}.x`).reason).toBe("pop_invalid");
    expect(decodePoP(`${hdr({ alg: "HS256", typ: "via-pop+jwt" })}.${p}.x`).reason).toBe("pop_invalid");
    // EdDSA and RS256 are now RECOGNISED at decode. Whether they are ACCEPTABLE needs the key, and
    // that decision deliberately lives at A3 — deciding it here would mean choosing a verification
    // routine from a header, which is the confusion this design exists to prevent.
    expect(decodePoP(`${hdr({ alg: "EdDSA", typ: "via-pop+jwt" })}.${p}.x`).ok).toBe(true);
  });

  it("tolerates a bare-string cnf during the kya migration window", () => {
    const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "via-pop+jwt" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ ...mkPayload(), cnf: jkt })).toString("base64url"); // cnf = bare string
    const d = decodePoP(`${header}.${payload}.x`);
    expect(d.ok).toBe(true);
    expect(d.jkt).toBe(jkt);
  });
});

// ── §16.6 multi-algorithm PoP (F19) ──────────────────────────────────────────
//
// The security property is ORDER: resolve the key, derive the algorithm from it, then require the
// header to match. A verifier that picks its routine from the header lets an attacker pick the
// algorithm (RFC 8725 §3.1). These tests exist to keep that order.

describe("§16.6 — the KEY decides the algorithm", () => {
  it("derives the algorithm from each key type", async () => {
    const ec = (await generateP256Key()).publicJwk;
    expect(algForKey(ec)).toBe("ES256");
    expect(algForKey({ kty: "OKP", crv: "Ed25519", x: "abc" })).toBe("EdDSA");
    expect(algForKey({ kty: "RSA", n: "A".repeat(344), e: "AQAB" })).toBe("RS256"); // ~2048-bit
  });

  it("REFUSES an undersized RSA key — a 512-bit key is forgeable and would verify honestly", () => {
    expect(algForKey({ kty: "RSA", n: "A".repeat(86), e: "AQAB" })).toBeNull(); // ~512-bit
  });

  it("refuses key types it cannot name", () => {
    expect(algForKey({ kty: "oct", k: "secret" })).toBeNull();          // symmetric — never
    expect(algForKey({ kty: "EC", crv: "P-521", x: "a", y: "b" })).toBeNull();
  });

  it("CONFUSION — a header claiming an algorithm the key cannot do is refused", async () => {
    const { privateJwk, publicJwk } = await generateP256Key();
    const jws = await buildPoP(mkPayload(), privateJwk);
    const [, p, sig] = jws.split(".");
    // Same signature, same key, header rewritten to RS256. The signature is genuinely valid for the
    // EC key — only the claimed algorithm is a lie, and that alone must be fatal.
    const forged = `${Buffer.from(JSON.stringify({ alg: "RS256", typ: "via-pop+jwt" })).toString("base64url")}.${p}.${sig}`;
    expect(await verifyPoPSignature(forged, publicJwk)).toBe(false);
  });

  it("scopes by actor type: an AGENT presenting RS256 is refused even with a valid key", async () => {
    const rsa = { kty: "RSA", n: "A".repeat(344), e: "AQAB" };
    // The key could sign RS256, but §16.2 fixed agent keys at P-256 — the issuer chooses those.
    expect(allowedPopAlgs("agent").has("RS256")).toBe(false);
    expect(allowedPopAlgs("user").has("RS256")).toBe(true);
    expect(await verifyPoPSignature("a.b.c", rsa, allowedPopAlgs("agent"))).toBe(false);
  });

  it("round-trips an Ed25519 PoP — a person's security key", async () => {
    const { generateKeyPairSync } = await import("node:crypto");
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const priv = privateKey.export({ format: "jwk" }) as never;
    const pub = publicKey.export({ format: "jwk" }) as never;
    const jws = await buildPoP(mkPayload(), priv);
    expect(await verifyPoPSignature(jws, pub, allowedPopAlgs("user"))).toBe(true);
    expect(await verifyPoPSignature(jws, pub, allowedPopAlgs("agent"))).toBe(false); // agents: ES256 only
  });
});
