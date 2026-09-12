// v0.3 §3.1/§3.2 — the VIAActor as the Verifiable Credential the spec requires.
//
// §5 calls the snapshot a "signed cache" and §3.1 fixes its shape: `type` is
// `["VerifiableCredential","VIAActor"]`, `issuer` is the platform DID, `credentialSubject.id` is the
// actor DID, and the credential carries a SINGLE content-bound securing proof — the Humanos `STAMP`
// — exactly as the mandate does (v0.2-new §5, Variant B). The fold (`issueSnapshot`) produces the
// BODY: the folded subject plus the chain binding. This module is the envelope around it, and the
// signature over the whole.
//
// WHY THE SPLIT. The fold is pure and offline: given events it derives state, and that is what
// `auditActorSnapshot` re-derives and diffs. Signing needs a key and a clock, which the fold must
// not need. So the body stays the unit of derivation and the credential is what leaves the platform.
//
// TWO NAMES, ONE MEANING. The body carries key material as `jwk` — the name the actor EVENTS use,
// which are signed and cannot be renamed. §3.1 publishes it as `publicKeyJwk`. The mapping happens
// here, at the boundary where the artifact is built, so signed history and the published artifact
// can each keep their own vocabulary. `unwrapActorCredential` reverses it, which is what makes
// `fold(chain) == credentialSubject` checkable against a credential.
import { computeSRI } from "../crypto/digest.js";
import { createDataIntegrityProof, verifyDataIntegrityProof } from "../crypto/proof.js";
import { canonicalizeRFC8785 } from "../crypto/canonicalize.js";
import { VIA_PLATFORM_DID } from "../did/web.js";
import { TYPE_VC, VIA_CONTEXTS, VIA_SPEC_VERSION, type SpecVersion, type ViaEvent } from "../types.js";
import { viaUrn } from "../urn.js";
import type { StampSigner, ResolvePublicKey } from "../mandate/build.js";
import { auditActorSnapshot, type ActorAudit, type ActorSnapshot, type ViaActorSubject } from "./model.js";

export const TYPE_VIA_ACTOR = "VIAActor";

/** A `keys[]` entry as §3.1 publishes it: `publicKeyJwk`, never the body's `jwk`. */
export type PublishedActorKey = Omit<ViaActorSubject["keys"][number], "jwk"> & {
  publicKeyJwk?: ViaActorSubject["keys"][number]["jwk"];
};

/**
 * `credentialSubject` per §3.1: the folded subject, with the chain binding and supersession
 * pointer that §5 requires the snapshot to carry.
 */
export type ViaActorCredentialSubject = Omit<ViaActorSubject, "keys"> & {
  keys: PublishedActorKey[];
  chain: ActorSnapshot["chain"];
  supersedes: string | null;
};

export interface ViaActorCredential {
  "@context": string[];
  /** `urn:via:actor:<uuid>` — names THIS issued copy, not the actor (the actor is `credentialSubject.id`). */
  id: string;
  type: string[];
  specVersion: SpecVersion;
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: ViaActorCredentialSubject;
  /** The single securing `STAMP`. Absent until `stampActorCredential`. */
  proof?: ViaMandateProof;
}

/** The Data Integrity proof shape `createDataIntegrityProof` returns. */
type ViaMandateProof = ReturnType<typeof createDataIntegrityProof>;

const publishKeys = (keys: ViaActorSubject["keys"]): PublishedActorKey[] =>
  keys.map(({ jwk, ...rest }) => ({ ...rest, ...(jwk ? { publicKeyJwk: jwk } : {}) }));

const bodyKeys = (keys: PublishedActorKey[]): ViaActorSubject["keys"] =>
  keys.map(({ publicKeyJwk, ...rest }) => ({ ...rest, ...(publicKeyJwk ? { jwk: publicKeyJwk } : {}) }));

/**
 * Wrap a folded snapshot body in the §3.1 envelope. Unsigned — `stampActorCredential` secures it.
 *
 * `id` defaults to a fresh URN because a VC has an `id` and each issuance is a new copy. Pass one
 * to re-wrap an existing copy (a migration re-signing what it already stored) without renaming it.
 */
export function buildActorCredential(
  snapshot: ActorSnapshot,
  opts: { id?: string; issuer?: string } = {},
): ViaActorCredential {
  const { subject, chain, supersedes, validFrom, validUntil } = snapshot;
  return {
    "@context": [...VIA_CONTEXTS],
    id: opts.id ?? viaUrn("actor"),
    type: [TYPE_VC, TYPE_VIA_ACTOR],
    specVersion: (snapshot.specVersion ?? VIA_SPEC_VERSION) as SpecVersion,
    issuer: opts.issuer ?? VIA_PLATFORM_DID,
    validFrom,
    ...(validUntil ? { validUntil } : {}),
    credentialSubject: { ...subject, keys: publishKeys(subject.keys), chain, supersedes },
  };
}

/** Secure the actor credential with the single content-bound Humanos `STAMP` (§3.1). */
export function stampActorCredential(credential: ViaActorCredential, signer: StampSigner): ViaActorCredential {
  const proof = createDataIntegrityProof({
    document: credential as unknown as Record<string, unknown>,
    privateKey: signer.privateKey,
    verificationMethod: signer.verificationMethod,
    proofPurpose: "assertionMethod",
    event: "STAMP",
    ...(signer.created ? { created: signer.created } : {}),
  });
  return { ...credential, proof };
}

/** Build and stamp in one step — what a platform issuing a snapshot wants. */
export function issueActorCredential(
  snapshot: ActorSnapshot,
  signer: StampSigner,
  opts: { id?: string; issuer?: string } = {},
): ViaActorCredential {
  return stampActorCredential(buildActorCredential(snapshot, opts), signer);
}

/** Verify the credential's single securing `STAMP`. */
export async function verifyActorStamp(
  credential: ViaActorCredential,
  resolvePublicKey: ResolvePublicKey,
): Promise<{ valid: boolean; reason?: string }> {
  if (!credential.proof) return { valid: false, reason: "actor credential has no STAMP proof" };
  try {
    const key = await resolvePublicKey(credential.proof.verificationMethod);
    return { valid: verifyDataIntegrityProof(credential as unknown as Record<string, unknown>, credential.proof, key) };
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }
}

/** A stored artifact is a credential when it carries the envelope; otherwise it is a bare body. */
export function isActorCredential(artifact: unknown): artifact is ViaActorCredential {
  const a = artifact as { type?: unknown; credentialSubject?: unknown } | null;
  return Boolean(a && typeof a === "object" && Array.isArray(a.type) && a.type.includes(TYPE_VIA_ACTOR) && a.credentialSubject);
}

/** The body back out of the envelope, `publicKeyJwk` mapped to the fold's `jwk`. */
export function unwrapActorCredential(credential: ViaActorCredential): ActorSnapshot {
  const { chain, supersedes, keys, ...subject } = credential.credentialSubject;
  return {
    specVersion: credential.specVersion,
    subject: { ...(subject as Omit<ViaActorSubject, "keys">), keys: bodyKeys(keys) },
    chain,
    supersedes,
    validFrom: credential.validFrom,
    ...(credential.validUntil ? { validUntil: credential.validUntil } : {}),
  };
}

/**
 * The body of whatever was stored — a §3.1 credential or a pre-envelope bare body.
 *
 * Snapshots issued before the envelope existed are still true: every value they carry matches the
 * chain, and re-folding proves it. Refusing to read them would throw away audit history to make a
 * point about shape.
 */
export function actorSnapshotBody(artifact: ViaActorCredential | ActorSnapshot): ActorSnapshot {
  return isActorCredential(artifact) ? unwrapActorCredential(artifact) : (artifact as ActorSnapshot);
}

/** Re-fold and diff, for either shape (§5's audit primitive). */
export function auditActorArtifact(artifact: ViaActorCredential | ActorSnapshot, events: ViaEvent[]): ActorAudit {
  return auditActorSnapshot(actorSnapshotBody(artifact), events);
}

/**
 * The digest that names one issued copy — what `supersedes` carries.
 *
 * Taken over the artifact AS STORED, so a copy's name commits to exactly what was published: for a
 * credential that includes its `id`, `issuer` and `proof`. `snapshotDigest` in `model.ts` is the
 * same computation over a bare body, and stays for the pre-envelope chain.
 */
export function actorArtifactDigest(artifact: ViaActorCredential | ActorSnapshot): string {
  return computeSRI(canonicalizeRFC8785(artifact as unknown as Record<string, unknown>));
}
