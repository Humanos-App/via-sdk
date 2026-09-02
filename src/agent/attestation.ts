// Agent Binding (§16.5) — CONFINEMENT VALIDATORS (the security-critical core).
// Ported byte-faithfully from kya/crypto/index.ts: the COSE_Sign1 Sig_structure
// verify + full X.509 chain-to-a-pinned-root is the load-bearing check and is kept
// identical. The ONLY structural change from kya is dependency injection: the SDK
// never does HTTP, so `validateCustody` takes an injected DescribeKey oracle instead
// of calling a sim-KMS over the network (matching the SDK's VerifyDeps style).
//
// Signing semantics (READ before touching signatures): ES256 = ECDSA P-256 with
// SHA-256 OVER THE MESSAGE. WebCrypto hashes for you, so the leaf/keystore `sign`
// always takes the *message* bytes (the COSE Sig_structure) — never a pre-hashed
// digest. WebCrypto ECDSA signatures are raw r‖s (64 bytes) == JWS ES256 == our COSE.
//
// NITRO SIM NOTE: real AWS Nitro uses ES384/P-384 for the quote; the sim standardises
// on ES256/P-256 for interop with KMS/WebAuthn/DBSC. The VALIDATION LOGIC (Sig_structure
// verify + X.509 chain to a pinned root) is byte-for-byte identical — only the
// curve/hash constant differs.
import { X509Certificate as NodeX509Certificate, verify as nodeVerify } from "node:crypto";
import { Encoder } from "cbor-x";
import { sha256 } from "../crypto/digest.js";
import { toBase64Url, fromBase64Url } from "../crypto/encoding.js";
import { verifyES256, jwkThumbprint, type Jwk } from "../crypto/p256.js";
import type { AgentReasonCode, ConfinementResult, CustodyRef } from "./types.js";

// One CBOR codec for the whole module: plain byte strings (no typed-array tags, so
// COSE bstr fields match a standard decoder), maps decode back to objects.
const cbor = new Encoder({ useRecords: false, mapsAsObjects: true, tagUint8Array: false });

const EMPTY = new Uint8Array(0);
const te = new TextEncoder();

function fail(reason: AgentReasonCode): ConfinementResult {
  return { ok: false, reason };
}

// ── Custody (KMS) — injected DescribeKey oracle ───────────────────────────────

/** What the injected {@link DescribeKey} oracle returns about a custody key. */
export interface KeyDescription {
  /** MUST be `false` for a custodial rung — the KMS asserts the key cannot be exported. */
  exportable: boolean;
  /** The KMS-advertised public key; its thumbprint MUST equal the `cnf` being bound. */
  publicJwk?: Jwk;
  keyId?: string;
  /** e.g. `ECC_NIST_P256`. When present it must be a P-256 spec. */
  keySpec?: string;
  /** e.g. `SIM_KMS` / `AWS_KMS_HSM` — provider origin (advisory). */
  origin?: string;
  [k: string]: unknown;
}

/**
 * Resolve a {@link CustodyRef} to a {@link KeyDescription}. Injected (no HTTP in the
 * SDK): the caller wires the real KMS `DescribeKey` + `GetPublicKey`. Returns `null`
 * (or throws) when the key is unknown — either yields `custody_reference_invalid`.
 */
export type DescribeKey = (ref: CustodyRef) => Promise<KeyDescription | null> | KeyDescription | null;

/**
 * Custodial (KMS) confinement (§16.5·1a): the key is hardware-confined iff the injected
 * DescribeKey oracle says it is non-exportable AND the advertised public-key thumbprint
 * matches the `cnf` being registered. The non-exportability claim + key-match are the
 * load-bearing checks; the injection boundary is what the caller trusts to only describe
 * genuinely hardware-held keys (the `simKmsBaseUrl` HTTP hop in kya, injected here).
 */
export async function validateCustody(
  ref: CustodyRef,
  cnf: Jwk,
  describeKey: DescribeKey,
): Promise<ConfinementResult> {
  try {
    const desc = await describeKey(ref);
    if (
      desc &&
      desc.exportable === false &&
      (desc.keySpec === undefined || desc.keySpec === "ECC_NIST_P256") &&
      desc.publicJwk &&
      jwkThumbprint(desc.publicJwk) === jwkThumbprint(cnf)
    ) {
      // `pop`, not `hardware` — §16.5's table and v0.3 §9.1, which calls the asymmetry deliberate.
      //
      // The oracle fact is NOT discarded: it IS `binding: custodial`, a value defined as "a custody
      // oracle reports it (e.g. KMS `exportable:false`)". Recording it again as `assurance:
      // hardware` double-counts one fact across both axes, which is what the two-axis split exists
      // to prevent — `binding` says how the key is HELD, `assurance` says what could be PROVED.
      //
      // And an unsigned DescribeKey response cannot be PROVED to a third party. It is testimony,
      // not a document: the verifier saw it and cannot hand it to an insurer. `hardware` is defined
      // as "a hardware root chained to a pinned anchor" precisely because that IS transferable.
      // This validator's sibling already agrees — `validateWebauthnAttestation` degrades a real
      // attestation to `pop/self` when it cannot chain to a pinned root.
      return {
        ok: true,
        cnf: { jwk: cnf },
        assurance: "pop",
        binding: "custodial",
        custodyRef: ref,
        verifiedAt: Date.now(),
      };
    }
    return fail("custody_reference_invalid");
  } catch {
    return fail("custody_reference_invalid");
  }
}

// ── Attested (Nitro) — COSE_Sign1 quote → pinned root ─────────────────────────

/**
 * Attested (Nitro) confinement (§16.5·1b): verify the COSE_Sign1 quote signature with
 * the LEAF cert key, chain leaf→cabundle→a PINNED root, and return the embedded attested
 * key as the `cnf`. Fail-closed: any malformed input yields `attestation_chain_invalid`.
 */
/** Lowercase hex — how AWS surfaces PCRs (`nitro-cli describe-eif`), so a pinned value pastes in. */
function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export async function validateCoseAttestation(
  docB64: string,
  pinnedRootsPem: string[],
  /**
   * PCR index -> expected value, lowercase hex. Omit (or pass `{}`) to skip the check and accept
   * the weaker claim: "this key is in AN enclave under a pinned root", not "…running my workload".
   */
  expectedPcrs?: Record<string, string>,
): Promise<ConfinementResult> {
  try {
    const doc = cbor.decode(fromBase64Url(docB64)) as unknown[];
    if (!Array.isArray(doc) || doc.length !== 4) return fail("attestation_chain_invalid");
    const [protectedBytes, , payloadBytes, signature] = doc as [Uint8Array, unknown, Uint8Array, Uint8Array];

    // (0) Protected header must declare the algorithm we actually verify with. The sim
    // standardises on ES256 (COSE alg -7); pinning it here stops a doc that advertises a
    // different/weaker alg from being fed to the ES256 verifier (algorithm-confusion
    // hygiene — a real-Nitro P-384 swap updates BOTH sides).
    const protHdr = cbor.decode(Buffer.from(protectedBytes));
    const protAlg = protHdr instanceof Map ? protHdr.get(1) : (protHdr as Record<number, number>)?.[1];
    if (protAlg !== -7) return fail("attestation_chain_invalid");

    const payload = cbor.decode(Buffer.from(payloadBytes)) as {
      certificate?: Uint8Array;
      cabundle?: Uint8Array[];
      public_key?: Uint8Array;
      pcrs?: Record<string, Uint8Array>;
    };
    if (!payload.certificate || !payload.public_key) return fail("attestation_chain_invalid");

    // (1) COSE_Sign1 signature over the Sig_structure, verified by the leaf key.
    const leaf = new NodeX509Certificate(Buffer.from(payload.certificate));
    const sigStruct = cbor.encode(["Signature1", Buffer.from(protectedBytes), EMPTY, Buffer.from(payloadBytes)]);
    const leafJwk = leaf.publicKey.export({ format: "jwk" }) as Jwk;
    const sigOk = await verifyES256(new Uint8Array(sigStruct), new Uint8Array(signature), leafJwk);
    if (!sigOk) return fail("attestation_chain_invalid");

    // (2) Full X.509 path validation leaf → cabundle → a PINNED root: signature,
    // name-chaining, CA basic-constraints, and validity windows.
    const bundle = (payload.cabundle ?? []).map((der) => new NodeX509Certificate(Buffer.from(der)));
    const chain = [leaf, ...bundle];
    if (!validateCertChain(chain, pinnedRootsPem, Date.now())) return fail("attestation_chain_invalid");

    // (3) PCR pinning — WHICH CODE is running in that enclave.
    //
    // Steps (1)-(2) prove the key lives in AN enclave whose chain reaches a root you pinned. They
    // say nothing about what that enclave is RUNNING: anyone who can rent hardware from the same
    // vendor gets a document that passes them. PCRs are the enclave's own measurements of its
    // image, kernel and application, so pinning them is what turns "some enclave" into "the
    // workload I built".
    //
    // Opt-in, and empty means UNCHECKED, not "matches" — a caller that pins nothing gets the
    // weaker claim it asked for. That is stated here rather than defaulted, because a silent
    // no-op on the check that carries the whole `hardware` rung is exactly the kind of thing that
    // reads as verified for years.
    if (expectedPcrs && Object.keys(expectedPcrs).length > 0) {
      const got = payload.pcrs ?? {};
      for (const [index, want] of Object.entries(expectedPcrs)) {
        const actual = got[index];
        if (!actual || toHex(actual) !== want.trim().toLowerCase()) {
          return fail("attestation_pcr_mismatch");
        }
      }
    }

    // (4) attested cnf = the embedded public_key (raw uncompressed EC point).
    const jwk = rawPointToJwk(payload.public_key);
    return {
      ok: true,
      cnf: { jwk },
      assurance: "hardware",
      binding: "attested",
      root: "aws-nitro",
      verifiedAt: Date.now(),
      maxAttestationStaleness: 86400,
    };
  } catch {
    return fail("attestation_chain_invalid");
  }
}

/**
 * Attested/pop (WebAuthn). The credential public key (from authData) is the `cnf`
 * EITHER WAY. The rung is earned only by evidence the RP can actually check:
 *   • fmt "packed"/"android-key" WITH a batch cert whose attestation-statement signature
 *     verifies AND whose x5c chains to a PINNED FIDO/vendor root → hardware/attested/fido.
 *   • a present-but-INVALID statement signature → attestation_chain_invalid (a genuine
 *     authenticator never emits one; a forgery signal).
 *   • anything we cannot fully verify — fmt "none"/self, no x5c, no pinned root, or a
 *     format we don't implement — → pop/self. We refuse to credit confinement we can't
 *     chain to a trust anchor. This is the §16.5 normative fail-safe: an unverifiable
 *     quote DEGRADES to pop/self, it never fails open.
 */
export async function validateWebauthnAttestation(
  attestationObjectB64: string,
  clientDataJSONB64: string,
  pinnedRootsPem: string[],
): Promise<ConfinementResult> {
  try {
    const ao = cbor.decode(fromBase64Url(attestationObjectB64)) as {
      fmt?: string;
      attStmt?: { x5c?: Uint8Array[]; sig?: Uint8Array; alg?: number };
      authData?: Uint8Array;
    };
    if (!ao.authData) return fail("pop_invalid");
    const jwk = credentialKeyFromAuthData(ao.authData);
    if (!jwk) return fail("pop_invalid");

    // The honest fallback: a real credential key we could not anchor to a trusted
    // authenticator → the lowest rung it has earned.
    const selfRung = (): ConfinementResult => ({
      ok: true,
      cnf: { jwk },
      assurance: "pop",
      binding: "self",
      verifiedAt: Date.now(),
    });

    // Only 'packed'/'android-key' use the sig(authData ‖ clientDataHash) form we verify
    // here. 'tpm'/'apple' have distinct procedures we do NOT implement, so they (and
    // 'none'/no-x5c) fall through to self/pop rather than over-claim.
    const verifiableFmts = new Set(["packed", "android-key"]);
    const x5c = ao.attStmt?.x5c;
    const sig = ao.attStmt?.sig;
    if (!ao.fmt || !verifiableFmts.has(ao.fmt) || !x5c || x5c.length === 0 || !sig) return selfRung();

    // (1) The attestation statement signs authData ‖ SHA-256(clientDataJSON). authData
    // carries the credential public key, so a valid signature by the batch cert binds
    // THAT cert's vouch to THIS exact credential key (the cnf).
    const leaf = new NodeX509Certificate(Buffer.from(x5c[0]!));
    if (leaf.ca) return selfRung(); // a packed attestation leaf is an end-entity cert, never a CA
    const hash = coseHashName(ao.attStmt?.alg);
    if (!hash) return selfRung();
    const verificationData = concat(ao.authData, sha256(fromBase64Url(clientDataJSONB64)));
    if (!verifyLeafSig(leaf, hash, verificationData, sig)) return fail("attestation_chain_invalid"); // present but forged/malformed → reject

    // (2) The batch cert must chain to a PINNED FIDO/vendor root. Without a pinned anchor
    // the authenticator's provenance is unverifiable → self/pop.
    const chain = x5c.map((der) => new NodeX509Certificate(Buffer.from(der)));
    if (!validateCertChain(chain, pinnedRootsPem, Date.now())) return selfRung();

    return { ok: true, cnf: { jwk }, assurance: "hardware", binding: "attested", root: "fido", verifiedAt: Date.now() };
  } catch {
    return fail("pop_invalid");
  }
}

/**
 * Decode-only: the base64url of the COSE quote's `nonce` field (or null). The
 * registration flow uses this to bind an attested registration to a fresh, single-use
 * challenge — the nonce is inside the signed payload, so {@link validateCoseAttestation}'s
 * signature check is what makes this value trustworthy once the doc validates.
 */
export function readAttestationNonce(docB64: string): string | null {
  try {
    const doc = cbor.decode(fromBase64Url(docB64)) as unknown[];
    if (!Array.isArray(doc) || doc.length !== 4) return null;
    const payload = cbor.decode(Buffer.from(doc[2] as Uint8Array)) as { nonce?: Uint8Array | null };
    return payload.nonce ? toBase64Url(Buffer.from(payload.nonce)) : null;
  } catch {
    return null;
  }
}

// ── Internal helpers (ported verbatim from kya/crypto/index.ts) ───────────────

// Verify an attestation-statement signature by a leaf cert's public key. Accepts DER
// ECDSA (what real authenticators emit) OR raw r‖s (ieee-p1363). dsaEncoding is ignored
// for RSA leaves.
function verifyLeafSig(
  leaf: NodeX509Certificate,
  hash: "sha256" | "sha384" | "sha512",
  data: Uint8Array,
  sig: Uint8Array,
): boolean {
  for (const dsaEncoding of ["der", "ieee-p1363"] as const) {
    try {
      if (nodeVerify(hash, Buffer.from(data), { key: leaf.publicKey, dsaEncoding }, Buffer.from(sig))) return true;
    } catch {
      /* try the other encoding */
    }
  }
  return false;
}

// COSE alg id → digest for attestation-statement signature verification. Covers
// ES256/384/512 (EC leaf) and RS256/384/512 (RSA leaf) — the algorithms FIDO batch
// attestation certs use. Node infers the key type from the leaf cert.
function coseHashName(alg: number | undefined): "sha256" | "sha384" | "sha512" | null {
  switch (alg) {
    case -7:
    case -257:
      return "sha256";
    case -35:
    case -258:
      return "sha384";
    case -36:
    case -259:
      return "sha512";
    default:
      return null;
  }
}

// Parse WebAuthn authenticatorData → attested credential COSE key → JWK.
function credentialKeyFromAuthData(authData: Uint8Array): Jwk | null {
  if (authData.length < 37) return null;
  const flags = authData[32]!;
  if ((flags & 0x40) === 0) return null; // AT (attested credential data) must be present
  // rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIdLen(2) + credId + coseKey
  let offset = 37 + 16;
  const credIdLen = (authData[offset]! << 8) | authData[offset + 1]!;
  offset += 2 + credIdLen;
  const coseKeyBytes = authData.slice(offset);
  const cose = cbor.decode(Buffer.from(coseKeyBytes)) as unknown;
  // COSE_Key (EC2): 1=kty, -1=crv, -2=x, -3=y. cbor-x decodes a map with negative integer
  // keys (which real authenticators use) to a Map, not a plain object — so read via
  // coseGet, which handles both Map and object decodings.
  const x = coseGet(cose, -2);
  const y = coseGet(cose, -3);
  if (!x || !y) return null;
  return { kty: "EC", crv: "P-256", x: toBase64Url(x), y: toBase64Url(y) };
}

// Read a COSE_Key label from either a decoded Map (integer keys) or a plain object
// (string keys), returning the value as bytes when present.
function coseGet(cose: unknown, label: number): Uint8Array | undefined {
  const v = cose instanceof Map ? cose.get(label) : (cose as Record<string, unknown>)?.[String(label)];
  return v instanceof Uint8Array ? v : undefined;
}

// Real X.509 path validation for a leaf..intermediate `chain` terminating at a PINNED
// root. At EVERY issuer link it checks all four of:
//   (a) validity window — notBefore ≤ now ≤ notAfter for every cert (incl. root),
//   (b) name chaining    — child.checkIssued(parent) (subject/issuer + AKI/SKI),
//   (c) issuer signature — child.verify(parent.publicKey),
//   (d) CA authority     — parent.ca === true (a non-CA cert may NEVER sign a cert;
//                          without this, a stolen leaf key could mint subs).
// The terminal cert must equal, or be validly issued by, one of the pinned roots.
// Returns false (never throws) on any malformed input — fail closed.
function validateCertChain(chain: NodeX509Certificate[], pinnedRootsPem: string[], nowMs: number): boolean {
  try {
    if (chain.length === 0 || pinnedRootsPem.length === 0) return false;
    for (const c of chain) if (!certValidAt(c, nowMs)) return false;
    for (let i = 0; i < chain.length - 1; i++) {
      const child = chain[i]!;
      const parent = chain[i + 1]!;
      if (!parent.ca) return false; // issuer must be a CA
      if (!(child.checkIssued(parent) && child.verify(parent.publicKey))) return false;
    }
    const top = chain[chain.length - 1]!;
    const roots = pinnedRootsPem.map((pem) => new NodeX509Certificate(pem));
    return roots.some((root) => {
      if (!root.ca || !certValidAt(root, nowMs)) return false;
      if (Buffer.compare(top.raw, root.raw) === 0) return true; // top IS the pinned root
      return top.checkIssued(root) && top.verify(root.publicKey); // top issued by the pinned root
    });
  } catch {
    return false;
  }
}

// notBefore ≤ now ≤ notAfter. Prefers the Date accessors (Node ≥18.9); falls back to
// parsing the RFC-822 validFrom/validTo strings on older runtimes.
function certValidAt(cert: NodeX509Certificate, nowMs: number): boolean {
  const from = certTime(cert, "from");
  const to = certTime(cert, "to");
  if (from === null || to === null) return false;
  return nowMs >= from && nowMs <= to;
}

function certTime(cert: NodeX509Certificate, which: "from" | "to"): number | null {
  const dateProp = which === "from" ? "validFromDate" : "validToDate";
  const strProp = which === "from" ? "validFrom" : "validTo";
  const d = (cert as unknown as Record<string, unknown>)[dateProp];
  if (d instanceof Date && !Number.isNaN(d.getTime())) return d.getTime();
  const s = (cert as unknown as Record<string, string>)[strProp];
  const parsed = s ? Date.parse(s) : NaN;
  return Number.isNaN(parsed) ? null : parsed;
}

function rawPointToJwk(point: Uint8Array): Jwk {
  if (point.length !== 65 || point[0] !== 0x04) {
    throw new Error("public_key: expected 65-byte uncompressed EC point");
  }
  return { kty: "EC", crv: "P-256", x: toBase64Url(point.slice(1, 33)), y: toBase64Url(point.slice(33, 65)) };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
