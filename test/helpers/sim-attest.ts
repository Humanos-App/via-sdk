// Sim-Nitro side (TEST HELPER, not shipped) — mint a CA chain + build a real-shape
// AWS-Nitro COSE_Sign1 attestation document, so the §16.5 validators can be exercised
// against valid AND invalid quotes. Ported from kya/crypto/index.ts (`mintNitroCa` /
// `buildCoseAttestation`). Round-trips with `validateCoseAttestation`.
import { webcrypto } from "node:crypto";
import { Encoder } from "cbor-x";
import * as x509 from "@peculiar/x509";
import type { Jwk, NitroCa } from "../../src/index.js";

// WebCrypto value/handle types (lib excludes DOM; these live in node's webcrypto namespace).
type CryptoKeyPair = webcrypto.CryptoKeyPair;

// @peculiar needs a WebCrypto provider; set once at module load.
x509.cryptoProvider.set(webcrypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0]);

const subtle = webcrypto.subtle;
const cbor = new Encoder({ useRecords: false, mapsAsObjects: true, tagUint8Array: false });

const EC_ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const ES256 = { name: "ECDSA", hash: "SHA-256" } as const;
// COSE_Sign1 protected header {1: -7} (alg ES256), canonical bytes.
const COSE_PROTECTED_ES256 = Buffer.from("a10126", "hex");
const EMPTY = Buffer.alloc(0);

function fromB64u(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Mint root (CN=Nitro-Root-G1) → intermediate → leaf (CN=enclave-signer), all ECDSA
 * P-256, each signed by its issuer. Returns the pinned root PEM, the chain
 * (leaf..intermediate, root excluded — as real Nitro ships), the leaf public JWK, and a
 * leaf ES256 signer for the COSE_Sign1 quote.
 */
export async function mintNitroCa(): Promise<NitroCa> {
  const signingAlgorithm = ES256;
  const [rootKeys, interKeys, leafKeys] = await Promise.all([genEcKeypair(), genEcKeypair(), genEcKeypair()]);
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000);

  const root = await x509.X509CertificateGenerator.createSelfSigned({
    name: "CN=Nitro-Root-G1",
    keys: rootKeys,
    serialNumber: randomSerial(),
    notBefore,
    notAfter,
    signingAlgorithm,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(rootKeys.publicKey),
    ],
  });
  const intermediate = await x509.X509CertificateGenerator.create({
    subject: "CN=Nitro-Intermediate",
    issuer: root.subject,
    publicKey: interKeys.publicKey,
    signingKey: rootKeys.privateKey,
    signingAlgorithm,
    serialNumber: randomSerial(),
    notBefore,
    notAfter,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(interKeys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(rootKeys.publicKey),
    ],
  });
  const leaf = await x509.X509CertificateGenerator.create({
    subject: "CN=enclave-signer",
    issuer: intermediate.subject,
    publicKey: leafKeys.publicKey,
    signingKey: interKeys.privateKey,
    signingAlgorithm,
    serialNumber: randomSerial(),
    notBefore,
    notAfter,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      await x509.SubjectKeyIdentifierExtension.create(leafKeys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(interKeys.publicKey),
    ],
  });

  const leafPublicJwk = (await subtle.exportKey("jwk", leafKeys.publicKey)) as Jwk;
  const leafSign = async (message: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await subtle.sign(ES256, leafKeys.privateKey, message));

  return {
    rootPem: root.toString("pem"),
    chainPems: [leaf.toString("pem"), intermediate.toString("pem")],
    leafPublicJwk: cleanEcJwk(leafPublicJwk),
    leafSign,
  };
}

/**
 * Build a real-shape AWS-Nitro COSE_Sign1 attestation document. The attested key is
 * embedded as a raw uncompressed EC point (04‖x‖y) under `public_key`. Root is EXCLUDED
 * from cabundle (pinned out-of-band), matching real Nitro. Round-trips with
 * `validateCoseAttestation`.
 */
export async function buildCoseAttestation(
  ca: NitroCa,
  args: { publicKeyJwk: Jwk; pcrs?: Record<number, Uint8Array>; nonceB64?: string; userDataB64?: string },
): Promise<string> {
  const leafDer = pemToDer(ca.chainPems[0]!);
  const interDer = pemToDer(ca.chainPems[1]!);

  const pcrs: Record<string, Uint8Array> = {};
  if (args.pcrs) {
    for (const [k, v] of Object.entries(args.pcrs)) pcrs[k] = v;
  } else {
    pcrs["0"] = new Uint8Array(48);
    pcrs["1"] = new Uint8Array(48);
    pcrs["2"] = new Uint8Array(48);
  }

  const payloadMap = {
    module_id: "i-0sim0enclave-enc0000000000000000",
    digest: "SHA256", // NITRO SIM: real Nitro is SHA384; sim standardises on SHA256.
    timestamp: Date.now(),
    pcrs,
    certificate: Buffer.from(leafDer),
    cabundle: [Buffer.from(interDer)],
    public_key: Buffer.from(jwkToRawPoint(args.publicKeyJwk)),
    user_data: args.userDataB64 ? Buffer.from(fromB64u(args.userDataB64)) : null,
    nonce: args.nonceB64 ? Buffer.from(fromB64u(args.nonceB64)) : null,
  };
  const payloadBytes = cbor.encode(payloadMap);

  const sigStruct = cbor.encode(["Signature1", COSE_PROTECTED_ES256, EMPTY, payloadBytes]);
  const signature = await ca.leafSign(new Uint8Array(sigStruct));

  const coseSign1 = [COSE_PROTECTED_ES256, {}, payloadBytes, Buffer.from(signature)];
  return b64u(cbor.encode(coseSign1));
}

// ── local helpers ─────────────────────────────────────────────────────────────

async function genEcKeypair(): Promise<CryptoKeyPair> {
  return subtle.generateKey(EC_ALG, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
}

function randomSerial(): string {
  return Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString("hex");
}

function cleanEcJwk(jwk: Jwk): Jwk {
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

function jwkToRawPoint(jwk: Jwk): Uint8Array {
  const x = fromB64u(String(jwk.x));
  const y = fromB64u(String(jwk.y));
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 33 - x.length);
  out.set(y, 65 - y.length);
  return out;
}

function pemToDer(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  return new Uint8Array(Buffer.from(base64, "base64"));
}
