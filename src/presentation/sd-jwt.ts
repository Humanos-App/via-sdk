import { randomBytes } from "node:crypto";
import { SDJwtInstance } from "@sd-jwt/core";
import type { DisclosureFrame, PresentationFrame, Hasher } from "@sd-jwt/core";
import { signRaw, verifyRaw } from "../crypto/ed25519.js";
import { sha256 } from "../crypto/digest.js";
import { toBase64Url, fromBase64Url, fromUtf8 } from "../crypto/encoding.js";
import type { ViaMandateCredential } from "../types.js";

/**
 * SD-JWT VC selective-disclosure presentation (spec v0.2-new §7.2, D-f — additive).
 *
 * Ed25519 / `typ: dc+sd-jwt`. `userParams` (per key) and `evidence` are
 * selectively disclosable; `action`, `scope`, `grantor`, `context` are always
 * present. A presentation MUST disclose the `userParams` its action rules
 * reference, else CEL fails at verify.
 */
export const VIA_VCT = "https://via.humanos.tech/vct/mandate";
export const SD_JWT_TYP = "dc+sd-jwt";

const sdHasher: Hasher = (data, _alg) => sha256(typeof data === "string" ? data : new Uint8Array(data));
const sdSalt = () => toBase64Url(new Uint8Array(randomBytes(16)));
const edSigner = (privateKey: Uint8Array) => (data: string) => toBase64Url(signRaw(data, privateKey));
const edVerifier = (publicKey: Uint8Array) => (data: string, sig: string) => verifyRaw(data, fromBase64Url(sig), publicKey);

function ed25519PublicJwk(pub: Uint8Array): Record<string, unknown> {
  return { kty: "OKP", crv: "Ed25519", x: toBase64Url(pub) };
}
function pubFromJwk(jwk: { x: string }): Uint8Array {
  return fromBase64Url(jwk.x);
}
function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export interface BuildSdJwtMandateInput {
  credential: ViaMandateCredential;
  /** Issuer (Humanos) raw Ed25519 private key. */
  issuerPrivateKey: Uint8Array;
  issuerVerificationMethod: string;
  /** Holder (agent) raw Ed25519 public key — bound as `cnf`. */
  holderPublicKey: Uint8Array;
  vct?: string;
  iat?: number;
}

/** Issue the SD-JWT VC (Humanos-signed, all disclosures attached). */
export async function buildSdJwtMandate(input: BuildSdJwtMandateInput): Promise<string> {
  const c = input.credential;
  const userParams = c.credentialSubject.mandate.userParams;
  const payload: Record<string, unknown> = {
    iss: c.issuer,
    vct: input.vct ?? VIA_VCT,
    iat: input.iat ?? nowSeconds(),
    cnf: { jwk: ed25519PublicJwk(input.holderPublicKey) },
    "@context": c["@context"],
    id: c.id,
    type: c.type,
    validFrom: c.validFrom,
    ...(c.validUntil ? { validUntil: c.validUntil } : {}),
    credentialSubject: c.credentialSubject,
    ...(c.evidence ? { evidence: c.evidence } : {}),
    ...(c.credentialStatus ? { credentialStatus: c.credentialStatus } : {}),
  };

  const frame: Record<string, unknown> = {};
  if (userParams && Object.keys(userParams).length > 0) {
    frame.credentialSubject = { mandate: { userParams: { _sd: Object.keys(userParams) } } };
  }
  if (c.evidence) frame._sd = ["evidence"];

  const sd = new SDJwtInstance<Record<string, unknown>>({
    signer: edSigner(input.issuerPrivateKey),
    signAlg: "EdDSA",
    hasher: sdHasher,
    hashAlg: "sha-256",
    saltGenerator: sdSalt,
  });
  return sd.issue(payload, frame as DisclosureFrame<Record<string, unknown>>, {
    header: { typ: SD_JWT_TYP, kid: input.issuerVerificationMethod },
  });
}

export interface PresentSdJwtInput {
  sdJwt: string;
  /** Holder (agent) raw Ed25519 private key — signs the KB-JWT. */
  holderPrivateKey: Uint8Array;
  disclose: { userParams?: string[]; evidence?: boolean };
  audience: string;
  nonce: string;
  iat?: number;
}

/** Derive a selectively-disclosed presentation + key-binding JWT. */
export async function presentSdJwt(input: PresentSdJwtInput): Promise<string> {
  const frame: Record<string, unknown> = {};
  if (input.disclose.userParams?.length) {
    frame.credentialSubject = {
      mandate: { userParams: Object.fromEntries(input.disclose.userParams.map((k) => [k, true])) },
    };
  }
  if (input.disclose.evidence) frame.evidence = true;

  const holderSd = new SDJwtInstance<Record<string, unknown>>({
    kbSigner: edSigner(input.holderPrivateKey),
    kbSignAlg: "EdDSA",
    hasher: sdHasher,
    hashAlg: "sha-256",
    saltGenerator: sdSalt,
  });
  return holderSd.present(input.sdJwt, frame as PresentationFrame<Record<string, unknown>>, {
    kb: { payload: { aud: input.audience, nonce: input.nonce, iat: input.iat ?? nowSeconds() } },
  });
}

export interface VerifiedSdJwt {
  valid: boolean;
  claims: Record<string, unknown>;
  audience?: string;
  nonce?: string;
}

/** Verify an SD-JWT VC presentation: issuer signature + KB-JWT (holder key from `cnf`) + nonce/audience. */
export async function verifySdJwtPresentation(input: {
  presentation: string;
  issuerPublicKey: Uint8Array;
  nonce: string;
  audience?: string;
}): Promise<VerifiedSdJwt> {
  // An EMPTY nonce is not "no nonce" to the underlying verifier — it reads as opting OUT of key
  // binding, so the presentation would verify without the holder proving anything. Refuse it here
  // rather than pass it down. (Fix from the platform's dev line, ported upstream 2026-09-12: it
  // lived only in the vendored copy, which `sync-via-sdk` overwrites wholesale.)
  if (typeof input.nonce !== "string" || input.nonce.length === 0) {
    throw new Error("SD-JWT verification requires a non-empty nonce");
  }
  // holder key for KB comes from the issuer-signed `cnf`
  const issuerJwt = input.presentation.split("~", 1)[0]!;
  const payloadJson = JSON.parse(fromUtf8(fromBase64Url(issuerJwt.split(".")[1]!))) as {
    cnf?: { jwk?: { x: string } };
  };
  const holderJwk = payloadJson.cnf?.jwk;
  if (!holderJwk) throw new Error("SD-JWT missing cnf.jwk for key binding");
  const holderPub = pubFromJwk(holderJwk);

  const verifierSd = new SDJwtInstance<Record<string, unknown>>({
    verifier: edVerifier(input.issuerPublicKey),
    hasher: sdHasher,
    hashAlg: "sha-256",
    kbVerifier: (data: string, sig: string) => verifyRaw(data, fromBase64Url(sig), holderPub),
  });
  const result = await verifierSd.verify(input.presentation, { keyBindingNonce: input.nonce });

  const aud = result.kb?.payload.aud as string | undefined;
  if (input.audience && aud !== input.audience) {
    throw new Error(`audience mismatch: expected ${input.audience}, got ${aud}`);
  }
  return {
    valid: true,
    claims: result.payload as Record<string, unknown>,
    audience: aud,
    nonce: result.kb?.payload.nonce as string | undefined,
  };
}
