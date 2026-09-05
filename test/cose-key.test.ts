import { describe, expect, it } from "vitest";
import { Encoder } from "cbor-x";
import { coseKeyToJwk } from "../src/agent/attestation.js";

// COSE_Key label maps differ PER KEY TYPE and the negative labels collide: EC2 `-1` is the curve
// where RSA `-1` is the modulus. Reading them without `kty` first is how an RSA passkey looks like
// a malformed EC one — which is what Windows Hello on a TPM would have hit.
const cbor = new Encoder({ tagUint8Array: false, useRecords: false, mapsAsObjects: false });
const enc = (m: Map<number, unknown>) => new Uint8Array(cbor.encode(m));
const b = (n: number, fill: number) => Buffer.alloc(n, fill);

describe("coseKeyToJwk — every algorithm the RP accepts", () => {
  it("EC2 / ES256 → an EC P-256 JWK", () => {
    const k = coseKeyToJwk(enc(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, b(32, 1)], [-3, b(32, 2)]])));
    expect(k?.kty).toBe("EC");
    expect(k?.crv).toBe("P-256");
    expect(k?.x).toBeTruthy();
    expect(k?.y).toBeTruthy();
  });

  it("RSA / RS256 → an RSA JWK — Windows Hello on a TPM", () => {
    const k = coseKeyToJwk(enc(new Map<number, unknown>([[1, 3], [3, -257], [-1, b(256, 9)], [-2, Buffer.from([1, 0, 1])]])));
    expect(k?.kty).toBe("RSA");
    expect((k as { n?: string }).n).toBeTruthy();
    expect((k as { e?: string }).e).toBe("AQAB"); // 65537
  });

  it("OKP / EdDSA → an OKP Ed25519 JWK", () => {
    const k = coseKeyToJwk(enc(new Map<number, unknown>([[1, 1], [3, -8], [-1, 6], [-2, b(32, 3)]])));
    expect(k?.kty).toBe("OKP");
    expect(k?.crv).toBe("Ed25519");
  });

  it("READS the curve rather than assuming P-256", () => {
    // An EC2 key on P-384 labelled "P-256" would be a JWK that says something false about itself.
    const k = coseKeyToJwk(enc(new Map<number, unknown>([[1, 2], [3, -35], [-1, 2], [-2, b(48, 1)], [-3, b(48, 2)]])));
    expect(k?.crv).toBe("P-384");
  });

  it("REGRESSION — an RSA key is not misread as a malformed EC key", () => {
    // Before `kty` was read first, this took RSA's `-1` (modulus) as a curve label and its `-2`
    // (exponent) as x, found no `-3`, and returned null. A real passkey, silently unrecorded.
    const rsa = enc(new Map<number, unknown>([[1, 3], [3, -257], [-1, b(256, 9)], [-2, Buffer.from([1, 0, 1])]]));
    expect(coseKeyToJwk(rsa)).not.toBeNull();
  });

  it("declines what it cannot name honestly", () => {
    expect(coseKeyToJwk(enc(new Map<number, unknown>([[1, 4]])))).toBeNull();          // unknown kty
    expect(coseKeyToJwk(enc(new Map<number, unknown>([[1, 2], [-1, 99]])))).toBeNull(); // unknown curve
    expect(coseKeyToJwk(enc(new Map<number, unknown>([[1, 3], [-1, b(8, 1)]])))).toBeNull(); // RSA, no exponent
  });
});
