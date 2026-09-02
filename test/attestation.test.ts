// §16.5 — agent registration + attestation validators (ported from kya/crypto.test.ts,
// adapted to the SDK's injected deps). Proves: valid custody → custodial; valid COSE
// quote → hardware/attested; regNonce mismatch → attestation_nonce_invalid; embedded
// key ≠ cnf → attestation_key_mismatch; broken chain → attestation_chain_invalid; and
// an unverifiable quote DEGRADES to pop/self (§16.5 normative — never fails open).
import { describe, expect, it } from "vitest";
import { Encoder } from "cbor-x";
import {
  generateP256Key,
  jwkThumbprint,
  validateCustody,
  validateCoseAttestation,
  validateWebauthnAttestation,
  readAttestationNonce,
  registerChallenge,
  registerAgentKey,
  createRegChallengeStore,
  sha256,
  toBase64Url,
  fromBase64Url,
  type Jwk,
  type CustodyRef,
  type KeyDescription,
} from "../src/index.js";
import { mintNitroCa, buildCoseAttestation } from "./helpers/sim-attest.js";

const te = new TextEncoder();

const CUSTODY_REF: CustodyRef = {
  provider: "sim-kms",
  region: "eu-west-1",
  keySpec: "ECC_NIST_P256",
  keyId: "key-abc",
  arnClass: "arn:aws:kms:...",
};

// A DescribeKey oracle that vouches for `cnf` as a non-exportable P-256 custody key.
function describeKeyFor(cnf: Jwk, over: Partial<KeyDescription> = {}) {
  return async (): Promise<KeyDescription> => ({
    origin: "SIM_KMS",
    exportable: false,
    keySpec: "ECC_NIST_P256",
    keyId: CUSTODY_REF.keyId,
    publicJwk: cnf,
    ...over,
  });
}

describe("validateCustody (§16.5 · custodial)", () => {
  it("non-exportable + advertised key == cnf → hardware/custodial", async () => {
    const { publicJwk } = await generateP256Key();
    const res = await validateCustody(CUSTODY_REF, publicJwk, describeKeyFor(publicJwk));
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("hardware");
      expect(res.binding).toBe("custodial");
      expect(res.custodyRef).toEqual(CUSTODY_REF);
      expect(jwkThumbprint(res.cnf.jwk)).toBe(jwkThumbprint(publicJwk));
    }
  });

  it("exportable key → custody_reference_invalid (fail closed)", async () => {
    const { publicJwk } = await generateP256Key();
    const res = await validateCustody(CUSTODY_REF, publicJwk, describeKeyFor(publicJwk, { exportable: true }));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("custody_reference_invalid");
  });

  it("advertised key ≠ cnf → custody_reference_invalid", async () => {
    const a = await generateP256Key();
    const b = await generateP256Key();
    const res = await validateCustody(CUSTODY_REF, b.publicJwk, describeKeyFor(a.publicJwk));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("custody_reference_invalid");
  });

  it("unknown key (oracle returns null) → custody_reference_invalid", async () => {
    const { publicJwk } = await generateP256Key();
    const res = await validateCustody(CUSTODY_REF, publicJwk, async () => null);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("custody_reference_invalid");
  });
});

describe("validateCoseAttestation (§16.5 · attested / Nitro)", () => {
  it("valid quote chained to the pinned root → hardware/attested/aws-nitro, cnf round-trips", async () => {
    const ca = await mintNitroCa();
    const key = await generateP256Key();
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk, nonceB64: toBase64Url(te.encode("nonce-1")) });
    const res = await validateCoseAttestation(doc, [ca.rootPem]);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("hardware");
      expect(res.binding).toBe("attested");
      expect(res.root).toBe("aws-nitro");
      expect(res.maxAttestationStaleness).toBe(86400);
      expect(jwkThumbprint(res.cnf.jwk)).toBe(jwkThumbprint(key.publicJwk));
    }
  });

  it("root NOT pinned → attestation_chain_invalid", async () => {
    const ca = await mintNitroCa();
    const other = await mintNitroCa();
    const key = await generateP256Key();
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk });
    const res = await validateCoseAttestation(doc, [other.rootPem]);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_chain_invalid");
  });

  it("tampered payload (signature no longer covers it) → attestation_chain_invalid", async () => {
    const ca = await mintNitroCa();
    const key = await generateP256Key();
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk });
    const raw = fromBase64Url(doc);
    raw[raw.length - 10] ^= 0xff;
    const res = await validateCoseAttestation(toBase64Url(raw), [ca.rootPem]);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_chain_invalid");
  });

  it("no pinned roots at all → attestation_chain_invalid (never fails open)", async () => {
    const ca = await mintNitroCa();
    const key = await generateP256Key();
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk });
    const res = await validateCoseAttestation(doc, []);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_chain_invalid");
  });
});

describe("readAttestationNonce", () => {
  it("round-trips the embedded challenge nonce; null when absent", async () => {
    const ca = await mintNitroCa();
    const key = await generateP256Key();
    const nonceB64 = toBase64Url(te.encode("reg-nonce-xyz"));
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk, nonceB64 });
    expect(readAttestationNonce(doc)).toBe(nonceB64);
    const noNonce = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk });
    expect(readAttestationNonce(noNonce)).toBeNull();
  });
});

// A synthetic 'packed' attestation drives the STRICT verifier: the statement signature
// is actually checked and the x5c must chain to a pinned root before hardware/attested.
describe("validateWebauthnAttestation (packed) — strict verification + honest degrade", () => {
  const cbor = new Encoder({ useRecords: false, mapsAsObjects: true, tagUint8Array: false });
  const RP_ID = "example.com";
  const ORIGIN = "https://example.com";

  function pemToDer(pem: string): Uint8Array {
    const b = pem.replace(/-----BEGIN CERTIFICATE-----/g, "").replace(/-----END CERTIFICATE-----/g, "").replace(/\s+/g, "");
    return new Uint8Array(Buffer.from(b, "base64"));
  }
  function concatAll(parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  function buildAuthData(credJwk: Jwk): Uint8Array {
    const rpIdHash = sha256(te.encode(RP_ID));
    const flags = new Uint8Array([0x41]); // UP | AT
    const signCount = new Uint8Array([0, 0, 0, 1]);
    const aaguid = new Uint8Array(16);
    const credId = new Uint8Array([9, 9, 9, 9]);
    const credIdLen = new Uint8Array([0, credId.length]);
    const x = fromBase64Url(String(credJwk.x));
    const y = fromBase64Url(String(credJwk.y));
    const coseKey = new Uint8Array(cbor.encode(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(x)], [-3, Buffer.from(y)]])));
    return concatAll([rpIdHash, flags, signCount, aaguid, credIdLen, credId, coseKey]);
  }
  async function credKey(): Promise<Jwk> {
    const { publicJwk } = await generateP256Key();
    return publicJwk;
  }
  async function buildPacked(
    ca: Awaited<ReturnType<typeof mintNitroCa>>,
    credJwk: Jwk,
    opts?: { forgeSig?: boolean },
  ): Promise<{ aoB64: string; clientDataJSONB64: string }> {
    const clientDataJSON = te.encode(JSON.stringify({ type: "webauthn.create", challenge: toBase64Url(te.encode("reg-challenge")), origin: ORIGIN }));
    const authData = buildAuthData(credJwk);
    const verificationData = concatAll([authData, sha256(clientDataJSON)]);
    const sig = new Uint8Array(await ca.leafSign(verificationData));
    if (opts?.forgeSig) sig[0] ^= 0xff;
    const ao = cbor.encode({
      fmt: "packed",
      attStmt: { alg: -7, sig: Buffer.from(sig), x5c: [Buffer.from(pemToDer(ca.chainPems[0]!)), Buffer.from(pemToDer(ca.chainPems[1]!))] },
      authData: Buffer.from(authData),
    });
    return { aoB64: toBase64Url(new Uint8Array(ao)), clientDataJSONB64: toBase64Url(clientDataJSON) };
  }

  it("packed statement + PINNED root → hardware/attested/fido, cnf == credential key", async () => {
    const ca = await mintNitroCa();
    const jwk = await credKey();
    const { aoB64, clientDataJSONB64 } = await buildPacked(ca, jwk);
    const res = await validateWebauthnAttestation(aoB64, clientDataJSONB64, [ca.rootPem]);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("hardware");
      expect(res.binding).toBe("attested");
      expect(res.root).toBe("fido");
      expect(jwkThumbprint(res.cnf.jwk)).toBe(jwkThumbprint(jwk));
    }
  });

  it("valid statement but NO pinned root → DEGRADE to pop/self, key still bound (never fails open)", async () => {
    const ca = await mintNitroCa();
    const jwk = await credKey();
    const { aoB64, clientDataJSONB64 } = await buildPacked(ca, jwk);
    const res = await validateWebauthnAttestation(aoB64, clientDataJSONB64, []);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("pop");
      expect(res.binding).toBe("self");
      expect(jwkThumbprint(res.cnf.jwk)).toBe(jwkThumbprint(jwk));
    }
  });

  it("FORGED statement signature (root pinned) → attestation_chain_invalid", async () => {
    const ca = await mintNitroCa();
    const jwk = await credKey();
    const { aoB64, clientDataJSONB64 } = await buildPacked(ca, jwk, { forgeSig: true });
    const res = await validateWebauthnAttestation(aoB64, clientDataJSONB64, [ca.rootPem]);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_chain_invalid");
  });

  it("fmt 'none' (synced passkey) → DEGRADE to pop/self", async () => {
    const jwk = await credKey();
    const ao = cbor.encode({ fmt: "none", attStmt: {}, authData: Buffer.from(buildAuthData(jwk)) });
    const res = await validateWebauthnAttestation(toBase64Url(new Uint8Array(ao)), toBase64Url(te.encode("{}")), []);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("pop");
      expect(res.binding).toBe("self");
    }
  });
});

describe("registerChallenge / registerAgentKey (§16.5)", () => {
  it("evidence 'none' → pop/self", async () => {
    const { publicJwk } = await generateP256Key();
    const res = await registerAgentKey({ cnf: { jwk: publicJwk }, evidence: { type: "none" } });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("pop");
      expect(res.binding).toBe("self");
      expect(jwkThumbprint(res.cnf.jwk)).toBe(jwkThumbprint(publicJwk));
    }
  });

  it("evidence 'device-self' → device/self (self-asserted, not RP-verifiable)", async () => {
    const { publicJwk } = await generateP256Key();
    const res = await registerAgentKey({ cnf: { jwk: publicJwk }, evidence: { type: "device-self", nonExportable: true } });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("device");
      expect(res.binding).toBe("self");
    }
  });

  it("custody evidence via injected DescribeKey → hardware/custodial", async () => {
    const { publicJwk } = await generateP256Key();
    const res = await registerAgentKey(
      { cnf: { jwk: publicJwk }, evidence: { type: "custody", ref: CUSTODY_REF } },
      { describeKey: describeKeyFor(publicJwk) },
    );
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("hardware");
      expect(res.binding).toBe("custodial");
      expect(res.custodyRef).toEqual(CUSTODY_REF);
    }
  });

  it("attested registration with a matching, single-use regNonce → hardware/attested + pinned digest", async () => {
    const ca = await mintNitroCa();
    const key = await generateP256Key();
    const store = createRegChallengeStore();
    const { regNonce } = await registerChallenge({ store });
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk, nonceB64: regNonce });

    const res = await registerAgentKey(
      { cnf: { jwk: key.publicJwk }, evidence: { type: "attestation-eat", docB64: doc }, regNonce },
      { store, nitroRoots: [ca.rootPem] },
    );
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("hardware");
      expect(res.binding).toBe("attested");
      expect(res.root).toBe("aws-nitro");
      expect(res.attestationDigestSRI).toBe(toBase64Url(sha256(fromBase64Url(doc))));
    }

    // Single-use: the very same nonce cannot be replayed for a second binding.
    const replay = await registerAgentKey(
      { cnf: { jwk: key.publicJwk }, evidence: { type: "attestation-eat", docB64: doc }, regNonce },
      { store, nitroRoots: [ca.rootPem] },
    );
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.reason).toBe("attestation_nonce_invalid");
  });

  it("regNonce mismatch (quote echoes a different nonce) → attestation_nonce_invalid", async () => {
    const ca = await mintNitroCa();
    const key = await generateP256Key();
    const store = createRegChallengeStore();
    const { regNonce } = await registerChallenge({ store });
    // Quote echoes SOME nonce, but the caller presents a different (also-outstanding) one.
    const otherChallenge = await registerChallenge({ store });
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk, nonceB64: otherChallenge.regNonce });

    const res = await registerAgentKey(
      { cnf: { jwk: key.publicJwk }, evidence: { type: "attestation-eat", docB64: doc }, regNonce },
      { store, nitroRoots: [ca.rootPem] },
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_nonce_invalid");
  });

  it("expired regNonce → attestation_nonce_invalid", async () => {
    const ca = await mintNitroCa();
    const key = await generateP256Key();
    const store = createRegChallengeStore();
    let clock = 1_000_000;
    const { regNonce } = await registerChallenge({ store, now: () => clock, ttlSeconds: 60 });
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk, nonceB64: regNonce });
    clock += 61_000; // past the 60s window

    const res = await registerAgentKey(
      { cnf: { jwk: key.publicJwk }, evidence: { type: "attestation-eat", docB64: doc }, regNonce },
      { store, nitroRoots: [ca.rootPem], now: () => clock },
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_nonce_invalid");
  });

  it("embedded attested key ≠ submitted cnf → attestation_key_mismatch", async () => {
    const ca = await mintNitroCa();
    const attested = await generateP256Key(); // the key the quote actually attests
    const other = await generateP256Key(); // a DIFFERENT key the client claims
    const store = createRegChallengeStore();
    const { regNonce } = await registerChallenge({ store });
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: attested.publicJwk, nonceB64: regNonce });

    const res = await registerAgentKey(
      { cnf: { jwk: other.publicJwk }, evidence: { type: "attestation-eat", docB64: doc }, regNonce },
      { store, nitroRoots: [ca.rootPem] },
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_key_mismatch");
  });

  it("attested quote that does NOT chain to a pinned root → attestation_chain_invalid", async () => {
    const ca = await mintNitroCa();
    const other = await mintNitroCa();
    const key = await generateP256Key();
    const store = createRegChallengeStore();
    const { regNonce } = await registerChallenge({ store });
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: key.publicJwk, nonceB64: regNonce });

    const res = await registerAgentKey(
      { cnf: { jwk: key.publicJwk }, evidence: { type: "attestation-eat", docB64: doc }, regNonce },
      { store, nitroRoots: [other.rootPem] }, // wrong pinned root
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_chain_invalid");
  });

  it("unverifiable webauthn quote (no pinned FIDO root) DEGRADES to pop/self via registerAgentKey", async () => {
    const ca = await mintNitroCa();
    const key = await generateP256Key();
    // Reuse the packed builder shape inline: a valid statement, but the registrar pins no FIDO root.
    const cbor = new Encoder({ useRecords: false, mapsAsObjects: true, tagUint8Array: false });
    const rpIdHash = sha256(te.encode("example.com"));
    const x = fromBase64Url(String(key.publicJwk.x));
    const y = fromBase64Url(String(key.publicJwk.y));
    const coseKey = new Uint8Array(cbor.encode(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(x)], [-3, Buffer.from(y)]])));
    const authData = new Uint8Array([...rpIdHash, 0x41, 0, 0, 0, 1, ...new Uint8Array(16), 0, 4, 9, 9, 9, 9, ...coseKey]);
    const clientDataJSON = te.encode(JSON.stringify({ type: "webauthn.create", challenge: "x", origin: "https://example.com" }));
    const verificationData = new Uint8Array([...authData, ...sha256(clientDataJSON)]);
    const sig = new Uint8Array(await ca.leafSign(verificationData));
    const ao = cbor.encode({ fmt: "packed", attStmt: { alg: -7, sig: Buffer.from(sig), x5c: [Buffer.from(pemToDerLocal(ca.chainPems[0]!)), Buffer.from(pemToDerLocal(ca.chainPems[1]!))] }, authData: Buffer.from(authData) });

    const res = await registerAgentKey(
      { cnf: { jwk: key.publicJwk }, evidence: { type: "webauthn", attestationObjectB64: toBase64Url(new Uint8Array(ao)), clientDataJSONB64: toBase64Url(clientDataJSON) } },
      { fidoRoots: [] }, // registrar pins NO fido root → provenance unverifiable → degrade
    );
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("pop");
      expect(res.binding).toBe("self");
      expect(jwkThumbprint(res.cnf.jwk)).toBe(jwkThumbprint(key.publicJwk));
    }
  });
});

function pemToDerLocal(pem: string): Uint8Array {
  const b = pem.replace(/-----BEGIN CERTIFICATE-----/g, "").replace(/-----END CERTIFICATE-----/g, "").replace(/\s+/g, "");
  return new Uint8Array(Buffer.from(b, "base64"));
}
