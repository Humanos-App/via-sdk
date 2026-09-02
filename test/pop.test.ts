import { describe, it, expect, beforeAll } from "vitest";
import { createHash } from "node:crypto";
import {
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

describe("actionHash (§16.6 / §5.3)", () => {
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

  it("rejects a wrong typ or non-ES256 alg (A1 / D3)", async () => {
    const p = Buffer.from(JSON.stringify(mkPayload())).toString("base64url");
    const badTyp = Buffer.from(JSON.stringify({ alg: "ES256", typ: "jwt" })).toString("base64url");
    const badAlg = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "via-pop+jwt" })).toString("base64url");
    expect(decodePoP(`${badTyp}.${p}.x`).reason).toBe("pop_invalid");
    expect(decodePoP(`${badAlg}.${p}.x`).reason).toBe("pop_invalid");
  });

  it("tolerates a bare-string cnf during the kya migration window", () => {
    const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "via-pop+jwt" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ ...mkPayload(), cnf: jkt })).toString("base64url"); // cnf = bare string
    const d = decodePoP(`${header}.${payload}.x`);
    expect(d.ok).toBe(true);
    expect(d.jkt).toBe(jkt);
  });
});
