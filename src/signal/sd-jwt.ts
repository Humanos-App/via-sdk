import { randomBytes } from "node:crypto";
import { SDJwtInstance } from "@sd-jwt/core";
import type { DisclosureFrame, Hasher, PresentationFrame } from "@sd-jwt/types";
import { signRaw, verifyRaw } from "../crypto/ed25519.js";
import { sha256 } from "../crypto/digest.js";
import { toBase64Url, fromBase64Url, fromUtf8 } from "../crypto/encoding.js";

/**
 * A `VIASignal` as an SD-JWT (spec v0.3 §9.0 sense 3; Appendix A is the illustrative shape).
 *
 * A Signal is a DERIVED product the network issues to consumers — a risk assessment, a
 * continuous-compliance statement — computed from the chains and never a field in any artifact
 * (§9.10). This module carries one: Ed25519 / `typ: dc+sd-jwt`, signed by the platform, with the
 * claims a consumer may or may not be shown (the evidence behind each factor, the remediations)
 * SELECTIVELY DISCLOSABLE — the same signature serves the data owner, who sees everything, and a
 * partner under a sharing grant, who sees the numbers. No holder key binding: a Signal is not
 * presented BY an agent, it is fetched ABOUT one, and its audience is whoever the platform hands
 * it to. The derivation logic stays outside the protocol (§9.11); the carrier is what this pins.
 */
export const VIA_SIGNAL_VCT = "https://via.humanos.tech/vct/signal";
export const SD_JWT_TYP = "dc+sd-jwt";

const sdHasher: Hasher = (data, _alg) => sha256(typeof data === "string" ? data : new Uint8Array(data));
const sdSalt = () => toBase64Url(new Uint8Array(randomBytes(16)));
const edSigner = (privateKey: Uint8Array) => (data: string) => toBase64Url(signRaw(data, privateKey));
const edVerifier = (publicKey: Uint8Array) => (data: string, sig: string) => verifyRaw(data, fromBase64Url(sig), publicKey);
const nowSeconds = () => Math.floor(Date.now() / 1000);

/** The body of a Signal: Appendix A's frame, with the kind's own assertions under `credentialSubject`. */
export interface ViaSignalBody {
  /** `urn:via:signal:<uuid>` */
  id: string;
  /** The kind, e.g. `RiskSignal`, `ContinuousComplianceSignal`. Appended to the VC types. */
  kind: string;
  /** The platform DID. */
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: Record<string, unknown> & {
    actor: string;
    actorSnapshot?: { id: string; sequence: number };
    window?: { from: string; to: string; startEvent?: string; endEvent?: string };
    previousSignal?: string;
  };
}

export interface BuildSdJwtSignalInput {
  signal: ViaSignalBody;
  /** Platform raw Ed25519 private key. */
  issuerPrivateKey: Uint8Array;
  issuerVerificationMethod: string;
  /** Top-level keys of `credentialSubject` a consumer may be shown or not — disclosed to the owner, withheld from others. */
  disclosable?: string[];
  vct?: string;
  iat?: number;
}

/** Issue the Signal: Humanos-signed, every disclosure attached (the data owner's copy). */
export async function buildSdJwtSignal(input: BuildSdJwtSignalInput): Promise<string> {
  const s = input.signal;
  const validUntilSeconds = s.validUntil ? Math.floor(new Date(s.validUntil).getTime() / 1000) : undefined;
  const payload: Record<string, unknown> = {
    iss: s.issuer,
    vct: input.vct ?? VIA_SIGNAL_VCT,
    iat: input.iat ?? nowSeconds(),
    ...(validUntilSeconds ? { exp: validUntilSeconds } : {}),
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://via.humanos.tech/ns/signals/v1"],
    id: s.id,
    type: ["VerifiableCredential", "VIASignal", s.kind],
    issuer: s.issuer,
    validFrom: s.validFrom,
    ...(s.validUntil ? { validUntil: s.validUntil } : {}),
    credentialSubject: s.credentialSubject,
  };
  const disclosable = (input.disclosable ?? []).filter((k) => k in s.credentialSubject);
  const frame: Record<string, unknown> = disclosable.length ? { credentialSubject: { _sd: disclosable } } : {};
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

/**
 * Redact: the same signed Signal with only the named `credentialSubject` keys disclosed. Done by
 * the ISSUER at hand-out (no key binding), which is what makes one signature serve two audiences.
 */
export async function redactSdJwtSignal(sdJwt: string, disclose: string[]): Promise<string> {
  const sd = new SDJwtInstance<Record<string, unknown>>({ hasher: sdHasher, hashAlg: "sha-256", saltGenerator: sdSalt });
  const frame = disclose.length ? { credentialSubject: Object.fromEntries(disclose.map((k) => [k, true])) } : {};
  return sd.present(sdJwt, frame as PresentationFrame<Record<string, unknown>>);
}

export interface VerifiedSdJwtSignal {
  valid: boolean;
  /** The claims as disclosed in THIS copy — withheld claims are simply absent. */
  claims: Record<string, unknown>;
  kid?: string;
}

/** Verify a Signal against the platform's public key: signature, disclosures' digests, expiry. */
export async function verifySdJwtSignal(input: { sdJwt: string; issuerPublicKey: Uint8Array; now?: number }): Promise<VerifiedSdJwtSignal> {
  const issuerJwt = input.sdJwt.split("~", 1)[0]!;
  const header = JSON.parse(fromUtf8(fromBase64Url(issuerJwt.split(".")[0]!))) as { typ?: string; kid?: string };
  if (header.typ !== SD_JWT_TYP) throw new Error(`not a ${SD_JWT_TYP}: typ=${String(header.typ)}`);
  const sd = new SDJwtInstance<Record<string, unknown>>({ verifier: edVerifier(input.issuerPublicKey), hasher: sdHasher, hashAlg: "sha-256" });
  const result = await sd.verify(input.sdJwt);
  const claims = result.payload as Record<string, unknown>;
  const exp = typeof claims.exp === "number" ? claims.exp : undefined;
  const now = input.now ?? nowSeconds();
  if (exp !== undefined && exp < now) throw new Error(`signal expired at ${new Date(exp * 1000).toISOString()}`);
  const type = claims.type as unknown;
  if (!Array.isArray(type) || !type.includes("VIASignal")) throw new Error("not a VIASignal");
  return { valid: true, claims, ...(header.kid ? { kid: header.kid } : {}) };
}
