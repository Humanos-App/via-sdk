import { describe, it, expect, beforeAll } from "vitest";
import { createSign, createPrivateKey } from "node:crypto";
import {
  generateP256Key,
  signES256,
  verifyES256,
  jwkThumbprint,
  cleanPublicJwk,
  type P256KeyPair,
} from "../src/index.js";

const te = new TextEncoder();
const msg = te.encode("via-pop signing input");

let a: P256KeyPair, b: P256KeyPair;
beforeAll(async () => {
  a = await generateP256Key();
  b = await generateP256Key();
});

describe("P-256 / ES256 (M1)", () => {
  it("generates a clean EC/P-256 keypair (public has no d)", () => {
    expect(a.publicJwk).toEqual({ kty: "EC", crv: "P-256", x: expect.any(String), y: expect.any(String) });
    expect(a.privateJwk.d).toBeTypeOf("string");
    expect(a.publicJwk.x).toBe(a.privateJwk.x); // same key, public half
  });

  it("sign→verify round-trips; signature is raw r‖s (64 bytes)", async () => {
    const sig = await signES256(msg, a.privateJwk);
    expect(sig.length).toBe(64);
    expect(await verifyES256(msg, sig, a.publicJwk)).toBe(true);
  });

  it("rejects a tampered message", async () => {
    const sig = await signES256(msg, a.privateJwk);
    expect(await verifyES256(te.encode("via-pop signing inpuT"), sig, a.publicJwk)).toBe(false);
  });

  it("rejects the wrong key", async () => {
    const sig = await signES256(msg, a.privateJwk);
    expect(await verifyES256(msg, sig, b.publicJwk)).toBe(false);
  });

  it("accepts a DER signature (the real-WebAuthn carrier), normalising DER→raw", async () => {
    const priv = createPrivateKey({ key: a.privateJwk, format: "jwk" } as never);
    const der = createSign("SHA256").update(Buffer.from(msg)).sign(priv); // DER ECDSA by default
    expect(der.length).not.toBe(64); // it's DER, not raw
    expect(await verifyES256(msg, new Uint8Array(der), a.publicJwk)).toBe(true);
  });

  it("jwkThumbprint (RFC 7638) is stable, public-derivable, and unique per key", () => {
    const t1 = jwkThumbprint(a.publicJwk);
    const t2 = jwkThumbprint(cleanPublicJwk(a.privateJwk)); // from the private key's public half
    expect(t1).toBe(t2);
    expect(t1).toMatch(/^[A-Za-z0-9_-]{43}$/); // base64url of a 32-byte SHA-256
    expect(jwkThumbprint(b.publicJwk)).not.toBe(t1);
  });

  it("jwkThumbprint matches an independent RFC 7638 computation", async () => {
    // Recompute the canonical form by hand: EC required members, lexicographic, no ws.
    const { createHash } = await import("node:crypto");
    const j = a.publicJwk;
    const canonical = `{"crv":"${j.crv}","kty":"EC","x":"${j.x}","y":"${j.y}"}`;
    const expected = createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("base64url");
    expect(jwkThumbprint(a.publicJwk)).toBe(expected);
  });
});
