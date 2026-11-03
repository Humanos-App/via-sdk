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
import { X509Certificate as NodeX509Certificate, verify as nodeVerify, createHash } from "node:crypto";
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
    // No answer — the oracle cannot see that key, or is not there — is UNVERIFIABLE, not wrong: it
    // degrades to pop/self (§16.5), and the key's own `proof` then shows it is held. An answer that
    // names another key, or an exportable one, is wrong evidence and refuses (below).
    if (desc === null) {
      return { ok: true, cnf: { jwk: cnf }, assurance: "pop", binding: "self", verifiedAt: Date.now() };
    }
    if (
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
  pinnedRoots: PinnedRoots,
  /**
   * PCR index -> expected value, lowercase hex. Omit (or pass `{}`) to skip the check and accept
   * the weaker claim: "this key is in AN enclave under a pinned root", not "…running my workload".
   */
  expectedPcrs?: Record<string, string>,
  /**
   * Image identifier -> expected measurements, for the RUNTIME axis (v0.3 §9.4ter). A MAP, not a
   * single set, because a fleet runs several accepted releases at once and pinning one image would
   * mean every deploy is a flag day. A quote matching any entry grants `runtime: tee` and records
   * WHICH entry matched.
   *
   * Separate from `expectedPcrs` on purpose: that gates the assurance rung and refuses on
   * mismatch; this grants a runtime class and a mismatch merely withholds it.
   */
  expectedMeasurements?: Record<string, Record<string, string>>,
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
    // The rung is WHICH list the reached root is in, not merely that one was reached. A TPM vendor
    // EK root and a Nitro root are both "a vendor I trust"; only one of them is a dedicated
    // environment, and one flat list made those the same statement (F10).
    const at = Date.now();
    if (!chainSound(chain, at)) return fail("attestation_chain_invalid");
    const graded = gradeChain(chain, pinnedRoots, at);
    // A sound chain to a root nobody pinned — or a verifier that pins none — is UNVERIFIABLE, not
    // wrong: it degrades to pop/self (§16.5). It proves nothing about who holds the key, so
    // registration then asks for the key's own `proof`; its PCRs are unread, with no anchor behind them.
    if (!graded) {
      return {
        ok: true,
        cnf: { jwk: rawPointToJwk(payload.public_key) },
        assurance: "pop",
        binding: "self",
        verifiedAt: at,
        evidence: { rootFingerprint: null },
      };
    }

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

    // (3b) RUNTIME — WHICH IMAGE, on its own axis (v0.3 §9.4ter).
    //
    // The rung above answers "how confined is the key"; this answers "what is running". They were
    // the same check, which is why §9.4bis had to say `hardware/attested` means two different
    // things depending on whether measurements were pinned. Separating them makes the rung mean one
    // thing and moves the workload claim to `runtime: tee`.
    //
    // Failing to match is NOT an error here: the key really is in an enclave under a pinned root,
    // so the rung stands. What the actor does not get is `tee` — and a mandate that cares says
    // `agent.runtime in ["tee"]`. `expectedPcrs` above stays a hard gate for deployments that
    // already rely on it.
    // §9.4ter(d): `tee` needs BOTH a hardware-list root and a measurement match — a device-list root is a
    // general-purpose host's secure element, not an enclave, whatever its quote's PCRs say.
    const runtime = graded.rung === "hardware" ? matchMeasurement(payload.pcrs ?? {}, expectedMeasurements) : null;

    // (4) attested cnf = the embedded public_key (raw uncompressed EC point).
    const jwk = rawPointToJwk(payload.public_key);
    return {
      ok: true,
      cnf: { jwk },
      assurance: graded.rung,
      binding: "attested",
      root: "aws-nitro",
      verifiedAt: Date.now(),
      evidence: { rootFingerprint: graded.rootFingerprint },
      ...(runtime
        ? {
            runtime: {
              class: "tee" as const,
              at: new Date().toISOString(),
              mechanism: "nitro",
              rootFingerprint: graded.rootFingerprint,
              measurementId: runtime,
            },
          }
        : {}),
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
 *   • a chain that is itself broken — a certificate out of its window, a parent that is not a CA
 *     or did not sign its child, a CA as the leaf → attestation_chain_invalid (wrong evidence).
 *   • anything we cannot fully verify — fmt "none"/self, no x5c, no pinned root, or a
 *     format we don't implement — → pop/self. We refuse to credit confinement we can't
 *     chain to a trust anchor. This is the §16.5 normative fail-safe: an unverifiable
 *     quote DEGRADES to pop/self, it never fails open — and proves no possession, so
 *     registration asks for the key's `proof`.
 */
export async function validateWebauthnAttestation(
  attestationObjectB64: string,
  clientDataJSONB64: string,
  pinnedRoots: PinnedRoots,
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

    // Captured for retro-audit and a future MDS layer; NEITHER grades anything today.
    const evidence = {
      aaguid: aaguidFromAuthData(ao.authData),
      authDataFlags: ao.authData[32]!,
      fmt: ao.fmt ?? "none",
    };

    // BACKUP ELIGIBLE (BE, bit 0x08) clear is required above `pop`. BE=1 means the credential may
    // be synced across a vendor's cloud to devices this attestation never described — Apple and
    // Google passkeys by default. The quote then proves where the key was BORN, not where it lives
    // now, and a rung is a statement about where it lives. Checked before the chain, so a synced
    // credential cannot buy a rung with an otherwise-perfect chain.
    const backupEligible = (evidence.authDataFlags & 0x08) !== 0;

    // The honest fallback: a real credential key we could not anchor to a trusted
    // authenticator → the lowest rung it has earned.
    const selfRung = (): ConfinementResult => ({
      ok: true,
      cnf: { jwk },
      assurance: "pop",
      binding: "self",
      verifiedAt: Date.now(),
      evidence: { ...evidence, rootFingerprint: null },
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
    if (leaf.ca) return fail("attestation_chain_invalid"); // a packed attestation leaf is an end-entity cert, never a CA
    const hash = coseHashName(ao.attStmt?.alg);
    if (!hash) return selfRung();
    const verificationData = concat(ao.authData, sha256(fromBase64Url(clientDataJSONB64)));
    if (!verifyLeafSig(leaf, hash, verificationData, sig)) return fail("attestation_chain_invalid"); // present but forged/malformed → reject

    // (2) The batch cert must chain to a PINNED FIDO/vendor root. Without a pinned anchor
    // the authenticator's provenance is unverifiable → self/pop.
    const chain = x5c.map((der) => new NodeX509Certificate(Buffer.from(der)));
    if (!chainSound(chain, Date.now())) return fail("attestation_chain_invalid"); // broken, not merely unanchored
    const graded = gradeChain(chain, pinnedRoots, Date.now());
    if (!graded) return selfRung();
    if (backupEligible) return selfRung(); // syncable credential — see the BE note above

    return {
      ok: true,
      cnf: { jwk },
      assurance: graded.rung,
      binding: "attested",
      root: "fido",
      verifiedAt: Date.now(),
      evidence: { ...evidence, rootFingerprint: graded.rootFingerprint },
    };
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

/**
 * Decode-only: WebAuthn `clientDataJSON`'s `challenge`, `type` and `origin` (or null).
 *
 * The registration flow binds an attested registration to a fresh, single-use challenge the same
 * way the COSE path does with `readAttestationNonce`. What makes these values trustworthy is the
 * attestation statement's signature over `authData ‖ SHA-256(clientDataJSON)`, which
 * {@link validateWebauthnAttestation} checks: tamper with the challenge and that signature breaks.
 * Reading them is therefore only useful TOGETHER with a validated statement — which is why this is
 * a decode, and the gate lives where the nonce store is.
 */
export function readWebauthnClientData(clientDataJSONB64: string): { challenge: string; type: string; origin?: string } | null {
  try {
    const json = JSON.parse(Buffer.from(fromBase64Url(clientDataJSONB64)).toString("utf8")) as {
      challenge?: unknown;
      type?: unknown;
      origin?: unknown;
    };
    if (typeof json.challenge !== "string" || typeof json.type !== "string") return null;
    return { challenge: json.challenge, type: json.type, ...(typeof json.origin === "string" ? { origin: json.origin } : {}) };
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

/**
 * The AAGUID — 16 bytes naming the authenticator MODEL, at authData[37..53].
 *
 * Inside authData, so it is covered by the attestation signature and therefore trustworthy — unlike
 * `authenticatorAttachment` and `transports`, which the CLIENT reports outside the signed bytes and
 * which must never contribute to a rung. The parser previously stepped over these bytes to reach
 * the COSE key; it records them now. Nothing grades on it yet: it is evidence for retro-audit and
 * the seam where a FIDO MDS lookup lands.
 */
function aaguidFromAuthData(authData: Uint8Array): string | null {
  if (authData.length < 53) return null;
  const hex = Buffer.from(authData.slice(37, 53)).toString("hex");
  if (/^0+$/.test(hex)) return null; // all-zero = the authenticator declined to identify itself
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
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
  return coseKeyToJwk(authData.slice(offset));
}

/**
 * A COSE_Key (EC2 / P-256) → JWK. Exported because it is needed wherever a WebAuthn credential is
 * recorded, not only where an attestation is validated: a passkey enrolment carries the same COSE
 * bytes and has to name the key it is adding.
 *
 * Returns null rather than throwing on anything it does not recognise — a caller recording a key
 * must be able to decline, and an unparseable key is a refusal, not an exception.
 */
export function coseKeyToJwk(coseKeyBytes: Uint8Array): Jwk | null {
  const cose = cbor.decode(Buffer.from(coseKeyBytes)) as unknown;

  // `kty` (label 1) MUST be read FIRST, because the negative labels mean different things per key
  // type: for EC2 `-1` is the curve and `-2` is x, while for RSA `-1` is the modulus and `-2` the
  // exponent. Reading -2/-3 blind — as this did — silently misreads an RSA key as a malformed EC
  // one. cbor-x decodes a map with negative integer keys (which real authenticators use) to a Map
  // rather than a plain object, so every read goes through `coseGet`.
  switch (coseGetNum(cose, 1)) {
    case 2: {
      // EC2 — ES256 (P-256) is what nearly every passkey uses. The curve is READ, not assumed: an
      // EC2 key on P-384 labelled "P-256" would be a JWK that says something false about itself.
      const crvLabel = coseGetNum(cose, -1);
      const crv = crvLabel === 1 ? "P-256" : crvLabel === 2 ? "P-384" : crvLabel === 3 ? "P-521" : null;
      const x = coseGet(cose, -2);
      const y = coseGet(cose, -3);
      if (!crv || !x || !y) return null;
      return { kty: "EC", crv, x: toBase64Url(x), y: toBase64Url(y) };
    }
    case 3: {
      // RSA — RS256. Windows Hello on TPM-backed configurations registers these, because TPMs
      // commonly do RSA; newer Windows does ES256. Supported so those enrolments reach the chain
      // instead of being recorded as a login the actor never gained.
      const n = coseGet(cose, -1);
      const e = coseGet(cose, -2);
      if (!n || !e) return null;
      return { kty: "RSA", n: toBase64Url(n), e: toBase64Url(e) };
    }
    case 1: {
      // OKP — EdDSA. Rare, and some security keys emit it.
      const crvLabel = coseGetNum(cose, -1);
      const crv = crvLabel === 6 ? "Ed25519" : crvLabel === 7 ? "Ed448" : null;
      const x = coseGet(cose, -2);
      if (!crv || !x) return null;
      return { kty: "OKP", crv, x: toBase64Url(x) };
    }
    default:
      return null; // a key type we cannot name honestly is one we decline to record
  }
}

// Read a COSE_Key label from either a decoded Map (integer keys) or a plain object
// (string keys), returning the value as bytes when present.
function coseGet(cose: unknown, label: number): Uint8Array | undefined {
  const v = cose instanceof Map ? cose.get(label) : (cose as Record<string, unknown>)?.[String(label)];
  return v instanceof Uint8Array ? v : undefined;
}

/**
 * The same read for INTEGER-valued labels — `kty` (1), `alg` (3), and the EC2/OKP curve at `-1`.
 *
 * Separate from {@link coseGet} because that one returns byte strings only, so reading `kty`
 * through it silently yields `undefined` and every key type looks unrecognised.
 */
function coseGetNum(cose: unknown, label: number): number | undefined {
  const v = cose instanceof Map ? cose.get(label) : (cose as Record<string, unknown>)?.[String(label)];
  return typeof v === "number" ? v : undefined;
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
/**
 * Roots pinned PER RUNG. One flat list was the F10 trap: it made "I trust this vendor" and "this
 * vendor's hardware earns `hardware`" the same statement, so pinning a TPM vendor root to let
 * Windows Hello register silently granted it the rung a Nitro enclave earns.
 *
 * An operator must now say which rung each root buys. There is no default: a root in neither list
 * chains to nothing and the evidence degrades, which is the safe direction.
 */
export interface PinnedRoots {
  /** Secure element of a GENERAL-PURPOSE host — TPM vendor EK roots, platform authenticators. */
  device: string[];
  /** DEDICATED environment — Nitro, SEV-SNP, TDX, HSM vendor roots, hardware security keys. */
  hardware: string[];
}

/**
 * Which pinned image this quote's measurements match, or `null`.
 *
 * ALL of an entry's indices must match; a partial match is not a match. Absence of a pinned index
 * in the document is a mismatch, never agreement — the same rule §9.4bis states for `expectedPcrs`,
 * for the same reason: a check that treats missing data as passing reads as verified while doing
 * nothing.
 */
function matchMeasurement(
  got: Record<string, Uint8Array>,
  expected?: Record<string, Record<string, string>>,
): string | null {
  if (!expected) return null;
  for (const [imageId, want] of Object.entries(expected)) {
    const indices = Object.entries(want);
    if (indices.length === 0) continue; // an empty entry would match everything
    const all = indices.every(([index, value]) => {
      const actual = got[index];
      return !!actual && toHex(actual) === value.trim().toLowerCase();
    });
    if (all) return imageId;
  }
  return null;
}

/** No roots pinned — every chain reaches nothing and degrades. The safe default, and the one a
 * platform that has not decided which vendors it trusts should be running. */
export const NO_ROOTS: PinnedRoots = { device: [], hardware: [] };

/** SHA-256 of the matched root's DER, hex — recorded as evidence of WHICH anchor was reached. */
function rootFingerprint(root: NodeX509Certificate): string {
  return createHash("sha256").update(root.raw).digest("hex");
}

/**
 * The chain on its own terms (§16.5): every certificate inside its validity window, and every parent a
 * CA that issued and signed its child. Says nothing about roots. A chain that fails here is WRONG
 * evidence — refused as `attestation_chain_invalid` — where a sound chain that reaches no pinned root
 * is only UNVERIFIABLE, and degrades. The two used to be one `null`, so a broken chain degraded in the
 * WebAuthn check and an unpinned one was refused in the quote check (decided 2026-10-14).
 */
function chainSound(chain: NodeX509Certificate[], nowMs: number): boolean {
  try {
    if (chain.length === 0) return false;
    for (const c of chain) if (!certValidAt(c, nowMs)) return false;
    for (let i = 0; i < chain.length - 1; i++) {
      const child = chain[i]!;
      const parent = chain[i + 1]!;
      if (!parent.ca) return false;
      if (!(child.checkIssued(parent) && child.verify(parent.publicKey))) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * The rung the matched root earns for a SOUND chain ({@link chainSound}), or `null` if it reaches no
 * pinned root — unverifiable, which degrades.
 *
 * A root listed under BOTH rungs grades as the LOWER one. Duplication is a config mistake, and the
 * generous reading of a mistake is the one that over-claims.
 */
function gradeChain(
  chain: NodeX509Certificate[],
  roots: PinnedRoots,
  nowMs: number,
): { rung: "device" | "hardware"; rootFingerprint: string } | null {
  const device = matchRoot(chain, roots.device, nowMs);
  if (device) return { rung: "device", rootFingerprint: rootFingerprint(device) };
  const hardware = matchRoot(chain, roots.hardware, nowMs);
  if (hardware) return { rung: "hardware", rootFingerprint: rootFingerprint(hardware) };
  return null;
}

/** The pinned root a sound chain's top reaches, or null. Extracted so {@link gradeChain} can say WHICH. */
function matchRoot(
  chain: NodeX509Certificate[],
  pinnedRootsPem: string[],
  nowMs: number,
): NodeX509Certificate | null {
  try {
    const top = chain[chain.length - 1];
    if (!top) return null;
    for (const pem of pinnedRootsPem) {
      const root = new NodeX509Certificate(pem);
      if (!root.ca || !certValidAt(root, nowMs)) continue;
      if (Buffer.compare(top.raw, root.raw) === 0) return root;
      if (top.checkIssued(root) && top.verify(root.publicKey)) return root;
    }
    return null;
  } catch {
    return null;
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
