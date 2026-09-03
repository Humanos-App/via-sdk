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
import { mintNitroCa, restoreNitroCa, buildCoseAttestation } from "./helpers/sim-attest.js";

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
  it("non-exportable + advertised key == cnf → pop/CUSTODIAL (the oracle fact lives in `binding`)", async () => {
    const { publicJwk } = await generateP256Key();
    const res = await validateCustody(CUSTODY_REF, publicJwk, describeKeyFor(publicJwk));
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("pop");
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

const SIM_REF = {
  provider: "sim-kms",
  region: "dev-1",
  keySpec: "ECC_NIST_P256",
  keyId: "ladder-test",
  arnClass: "key",
};

describe("restoreNitroCa — a dev CA that outlives its process", () => {
  it("a restored CA signs quotes the ORIGINAL root still validates", async () => {
    // Root pinning is out-of-band by design: the verifier has the root before any attestation
    // arrives. So testing the attested path end to end means mint -> restart the verifier with the
    // root -> sign, and the CA has to survive that restart. `leafSign` is a closure, so this is
    // what makes the sequence possible at all.
    const original = await mintNitroCa();
    const saved = JSON.parse(
      JSON.stringify({
        rootPem: original.rootPem,
        chainPems: original.chainPems,
        leafPublicJwk: original.leafPublicJwk,
        leafPrivateJwk: original.leafPrivateJwk,
      }),
    );

    const restored = await restoreNitroCa(saved);
    const { publicJwk } = await generateP256Key();
    const doc = await buildCoseAttestation(restored, { publicKeyJwk: publicJwk });

    // Validated against the ORIGINAL root — the point being that the restored signer is the same
    // authority, not merely a working one.
    const res = await validateCoseAttestation(doc, [original.rootPem]);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.assurance).toBe("hardware");
  });

  it("a restored CA is still refused by an unrelated root", async () => {
    const a = await mintNitroCa();
    const restored = await restoreNitroCa({
      rootPem: a.rootPem, chainPems: a.chainPems,
      leafPublicJwk: a.leafPublicJwk, leafPrivateJwk: a.leafPrivateJwk!,
    });
    const { publicJwk } = await generateP256Key();
    const doc = await buildCoseAttestation(restored, { publicKeyJwk: publicJwk });
    const other = await mintNitroCa();
    expect((await validateCoseAttestation(doc, [other.rootPem])).ok).toBe(false);
  });
});

describe("the assurance ladder (§16.5) — the rung is which ANCHOR you reached", () => {
  /**
   * `assurance` is "the strength of confinement the verifier could PROVE", and `hardware` is
   * defined as "a hardware root chained to a pinned anchor". So the rung tracks what is
   * TRANSFERABLE — what a verifier could hand an insurer — not where the key happens to live.
   *
   * `binding` carries the storage fact separately, and `custodial` is defined as "a custody oracle
   * reports it". Crediting that oracle report as `assurance: hardware` too would double-count one
   * fact across both axes, which is what the two-axis split exists to prevent.
   */
  it("nothing but a pinned chain earns above `pop`", async () => {
    const { publicJwk } = await generateP256Key();

    // no evidence at all
    const none = await registerAgentKey({ cnf: { jwk: publicJwk }, evidence: { type: "none" } });
    expect(none.ok && [none.assurance, none.binding]).toEqual(["pop", "self"]);

    // an ASSERTION of non-exportability — strictly more words, no more proof
    const asserted = await registerAgentKey({
      cnf: { jwk: publicJwk },
      evidence: { type: "device-self", nonExportable: true },
    });
    expect(asserted.ok && [asserted.assurance, asserted.binding]).toEqual(["pop", "self"]);

    // an ORACLE-verified non-exportable KMS key: the verifier did real, unforgeable work, and the
    // fact is recorded — in `binding`. The response is unsigned, so it is testimony, not a document.
    const custody = await registerAgentKey(
      { cnf: { jwk: publicJwk }, evidence: { type: "custody", ref: SIM_REF } },
      { describeKey: () => ({ exportable: false, publicJwk, keySpec: "ECC_NIST_P256" }) },
    );
    expect(custody.ok && [custody.assurance, custody.binding]).toEqual(["pop", "custodial"]);

    // a COSE_Sign1 chained to a PINNED root — transferable evidence, and the only thing here that
    // is. (It also binds a live nonce, which is why this path alone needs a store.)
    const ca = await mintNitroCa();
    const store = createRegChallengeStore();
    const { regNonce } = await registerChallenge({ store });
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: publicJwk, nonceB64: regNonce });
    const attested = await registerAgentKey(
      { cnf: { jwk: publicJwk }, evidence: { type: "attestation-eat", docB64: doc }, regNonce },
      { store, nitroRoots: [ca.rootPem] },
    );
    expect(attested.ok && [attested.assurance, attested.binding]).toEqual(["hardware", "attested"]);

    // …and the SAME document without the root pinned earns nothing at all.
    const store2 = createRegChallengeStore();
    const c2 = await registerChallenge({ store: store2 });
    const doc2 = await buildCoseAttestation(ca, { publicKeyJwk: publicJwk, nonceB64: c2.regNonce });
    const unpinned = await registerAgentKey(
      { cnf: { jwk: publicJwk }, evidence: { type: "attestation-eat", docB64: doc2 }, regNonce: c2.regNonce },
      { store: store2, nitroRoots: [] },
    );
    expect(unpinned.ok).toBe(false);
  });
});

describe("PCR pinning (§16.5) — WHICH workload, not merely which vendor", () => {
  const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

  it("matching PCRs still grant hardware/attested", async () => {
    const ca = await mintNitroCa();
    const { publicJwk } = await generateP256Key();
    const pcrs = { 0: new Uint8Array(48).fill(0xab), 1: new Uint8Array(48).fill(0xcd) };
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: publicJwk, pcrs });
    const res = await validateCoseAttestation(doc, [ca.rootPem], { "0": hex(pcrs[0]), "1": hex(pcrs[1]) });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.assurance).toBe("hardware");
  });

  it("a DIFFERENT workload on the SAME trusted hardware is refused", async () => {
    // The attack roots alone cannot see: an attacker who can rent the same vendor's enclaves gets
    // a document that passes chain validation. Only the measurements distinguish their image.
    const ca = await mintNitroCa();
    const { publicJwk } = await generateP256Key();
    const doc = await buildCoseAttestation(ca, {
      publicKeyJwk: publicJwk,
      pcrs: { 0: new Uint8Array(48).fill(0x99) }, // some other image
    });
    const res = await validateCoseAttestation(doc, [ca.rootPem], { "0": hex(new Uint8Array(48).fill(0xab)) });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_pcr_mismatch");
  });

  it("a PCR the document does not carry is a mismatch, not a pass", async () => {
    const ca = await mintNitroCa();
    const { publicJwk } = await generateP256Key();
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: publicJwk, pcrs: { 0: new Uint8Array(48) } });
    const res = await validateCoseAttestation(doc, [ca.rootPem], { "8": hex(new Uint8Array(48).fill(0x11)) });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_pcr_mismatch");
  });

  it("pinning NOTHING skips the check — the weaker claim, asked for explicitly", async () => {
    const ca = await mintNitroCa();
    const { publicJwk } = await generateP256Key();
    const doc = await buildCoseAttestation(ca, { publicKeyJwk: publicJwk, pcrs: { 0: new Uint8Array(48).fill(0x99) } });
    for (const pins of [undefined, {}]) {
      const res = await validateCoseAttestation(doc, [ca.rootPem], pins);
      expect(res.ok).toBe(true);
    }
  });

  it("registerAgentKey passes the pins through", async () => {
    const ca = await mintNitroCa();
    const { publicJwk } = await generateP256Key();
    const store = createRegChallengeStore();
    const { regNonce } = await registerChallenge({ store });
    const doc = await buildCoseAttestation(ca, {
      publicKeyJwk: publicJwk,
      pcrs: { 0: new Uint8Array(48).fill(0x99) },
      nonceB64: regNonce,
    });
    const res = await registerAgentKey(
      { cnf: { jwk: publicJwk }, evidence: { type: "attestation-eat", docB64: doc }, regNonce },
      { store, nitroRoots: [ca.rootPem], expectedPcrs: { "0": hex(new Uint8Array(48).fill(0xab)) } },
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("attestation_pcr_mismatch");
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
  // Evidence is UNTRUSTED client input. A validator documented as fail-closed has to fail closed
  // on the malformed payload too, not only the invalid-but-well-formed one. Before this, an
  // unrecognised discriminator matched no switch arm, left `result` unassigned and THREW on the
  // `result.ok` read — an unhandled exception on the endpoint that mints identities, reachable by
  // anyone who can send a request body.
  //
  // The `{kind:"none"}` case is not hypothetical: that is exactly what the agent SDK's
  // `RegistrationEvidence` looks like, and it discriminates on `kind`, not `type`.
  it.each([
    ["unknown type", { type: "bogus" }],
    ["no discriminator", {}],
    ["the agent SDK's `kind` shape", { kind: "none" }],
    ["null", null],
    ["undefined", undefined],
    ["a string", "none"],
    ["a number", 42],
  ])("malformed evidence (%s) is REFUSED, never thrown", async (_label, evidence) => {
    const { publicJwk } = await generateP256Key();
    const res = await registerAgentKey({
      cnf: { jwk: publicJwk },
      evidence: evidence as never,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("custody_reference_invalid");
  });

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

  it("evidence 'device-self' → pop/self — a claim is not evidence", async () => {
    const { publicJwk } = await generateP256Key();
    const res = await registerAgentKey({ cnf: { jwk: publicJwk }, evidence: { type: "device-self", nonExportable: true } });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("pop");
      expect(res.binding).toBe("self");
    }
  });

  it("custody evidence via injected DescribeKey → pop/custodial", async () => {
    const { publicJwk } = await generateP256Key();
    const res = await registerAgentKey(
      { cnf: { jwk: publicJwk }, evidence: { type: "custody", ref: CUSTODY_REF } },
      { describeKey: describeKeyFor(publicJwk) },
    );
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.assurance).toBe("pop");
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
