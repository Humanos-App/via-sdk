import { describe, it, expect } from "vitest";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ACTOR_EVENT_TYPES,
  ACTOR_FOLD_VERSION,
  canonicalEventType,
  canonicalizeRFC8785,
  eventChainLink,
  foldActorChain,
  type ViaEvent,
} from "../src/index.js";

/**
 * Guards `ACTOR_FOLD_VERSION` — the number that says which fold produced a stored snapshot.
 *
 * A platform seeds a read from a stored snapshot only when the snapshot's fold version is the
 * current one; an older fold may not derive a field the current one does. That is only safe if
 * the number moves whenever the fold's OUTPUT moves. This test makes a forgotten bump fail the
 * build instead of shipping: it folds fixed "golden" chains that exercise every actor event kind
 * and compares the result with a fixture recorded under the current version.
 *
 * When it fails:
 * - the output changed and the version did not → bump ACTOR_FOLD_VERSION (src/actor/model.ts),
 *   then re-record: `REGEN_FOLD_FIXTURE=1 npx vitest run test/fold-version.test.ts`;
 * - the version changed and the fixture did not → re-record the same way.
 * Re-recording REFUSES when the output changed but the version did not, so it cannot hide a
 * missing bump.
 */

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "fixtures/fold/actor-fold.json");
const REGEN = process.env.REGEN_FOLD_FIXTURE === "1";

const ORG = "did:web:golden.example";
const AGENT = "did:web:humanos.tech:agent:golden-1";
const LEGACY_AGENT = "did:web:humanos.tech:agent:golden-legacy";
const PERSON = "did:web:humanos.tech:user:golden-email";
const CHANNEL = "did:web:humanos.tech:user:golden-phone";
const LEGACY_ORG = "did:web:golden-legacy.example";
const SURVIVOR = "did:web:humanos.tech:agent:golden-survivor";
const ABSORBED = "did:web:humanos.tech:agent:golden-absorbed";
const JWK = (x: string) => ({ kty: "EC", crv: "P-256", x, y: `${x}-y` });

/** A chain of UNSIGNED events with fixed ids and instants — the fold reads content, not proofs. */
function chain(subject: string, issuer: string, steps: [string, Record<string, unknown>][]): ViaEvent[] {
  const out: ViaEvent[] = [];
  steps.forEach(([event, fields], i) => {
    const prev = out[out.length - 1];
    out.push({
      "@context": ["https://www.w3.org/ns/credentials/v2", "https://via.humanos.tech/ns/v1"],
      id: `urn:via:event:golden-${subject.split(":").pop()}-${i + 1}`,
      type: ["VerifiableCredential", "VIAEvent"],
      specVersion: "0.3",
      issuer,
      validFrom: `2026-01-${String(i + 1).padStart(2, "0")}T00:00:00.000Z`,
      credentialSubject: {
        id: subject,
        event,
        actor: issuer,
        previousEvent: prev ? eventChainLink(prev) : null,
        ...fields,
      },
    } as unknown as ViaEvent);
  });
  return out;
}

const HUMANOS = "did:web:humanos.tech";

/** Every actor event kind, and every field the fold derives, appears at least once. */
const GOLDEN: Record<string, ViaEvent[]> = {
  organization: chain(ORG, HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "organization", keyId: `${ORG}#key-1`, publicKeyMultibase: "z6MkGolden", assurance: "pop", binding: "custodial", bootstrapAnchor: "manual", verifiedAt: "2025-05-01T00:00:00.000Z", existedSince: "2024-03-01T00:00:00.000Z" } }],
    ["ACCREDITED", { accreditation: { level: "verified", method: "kyb-registry", registrar: HUMANOS, verifiedAt: "2026-01-02T00:00:00.000Z", validUntil: "2028-01-02T00:00:00.000Z" } }],
    ["AFFILIATION", { operator: { org: "did:web:golden-prod.example", relation: "sandbox_of" } }],
    ["REGULATORY", { agent: { licence: "PT-GOLDEN-1" } }],
    ["SUSPENDED", { reason: "review" }],
    ["RESUMED", { reason: "cleared" }],
    ["SNAPSHOT_ISSUED", { agent: { sequence: 3 } }],
  ]),
  agent: chain(AGENT, HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "agent", keyId: `${AGENT}#key-1`, jwk: JWK("k1"), assurance: "hardware", binding: "attested", bootstrapAnchor: "api_key", attestationKind: "attestation-eat", root: "aws-nitro", verifiedAt: "2026-01-01T00:00:00.000Z", existedSince: "2026-01-01T00:00:00.000Z", lineage: { parent: "did:web:humanos.tech:agent:golden-parent", event: "sha256-delegated" } } }],
    ["AFFILIATION", { operator: { org: ORG, relation: "operates" } }],
    ["KEY_ADDED", { agent: { keyId: `${AGENT}#key-2`, jwk: JWK("k2"), assurance: "device", binding: "custodial" } }],
    ["KEY_ROTATED", { agent: { predecessorId: `${AGENT}#key-1`, keyId: `${AGENT}#key-3`, jwk: JWK("k3"), assurance: "hardware", binding: "attested", attestationKind: "attestation-eat" } }],
    ["ATTESTATION_RENEWED", { agent: { keyId: `${AGENT}#key-3`, attestationKind: "attestation-eat", verifiedAt: "2026-01-05T00:00:00.000Z" } }],
    ["ASSURANCE_UPDATED", { agent: { keyId: `${AGENT}#key-2`, assurance: "pop", binding: "custodial", verifiedAt: "2026-01-06T00:00:00.000Z" } }],
    ["RUNTIME_ATTESTED", { agent: { runtime: { class: "tee", mechanism: "nitro", measurementId: "m-golden" } } }],
    ["KEY_REVOKED", { agent: { keyId: `${AGENT}#key-2` } }],
    ["FORK_EVIDENCE", { agent: { evidence: "sha256-fork" } }],
    ["DELEGATED", { agent: { child: "did:web:humanos.tech:agent:golden-child" } }],
  ]),
  // Written before 2026-09-28: the affiliation's claim in `agent`, still read from there.
  legacyAgentAffiliation: chain(LEGACY_AGENT, HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "agent", keyId: `${LEGACY_AGENT}#key-1`, jwk: JWK("kl"), assurance: "pop", binding: "self", bootstrapAnchor: "api_key" } }],
    ["AFFILIATION", { agent: { org: ORG, relation: "operates" } }],
  ]),
  legacyOrgAccreditation: chain(LEGACY_ORG, HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "organization", keyId: `${LEGACY_ORG}#key-1`, publicKeyMultibase: "z6MkLegacy", assurance: "pop", binding: "custodial", bootstrapAnchor: "manual" } }],
    // Signed before 2026-10-07: the lapse is `expiresAt`, recorded as `validUntil`.
    ["ACCREDITED", { agent: { accreditation: { level: "domain", method: "dns-challenge", registrar: HUMANOS, expiresAt: "2027-01-02T00:00:00.000Z" } } }],
  ]),
  person: chain(PERSON, HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "user", keyId: `${PERSON}#key-1`, publicKeyMultibase: "z6MkPerson", assurance: "pop", binding: "custodial", bootstrapAnchor: "manual", existedSince: "2023-06-01T00:00:00.000Z" } }],
    ["KEY_ADDED", { agent: { keyId: `${PERSON}#key-2`, jwk: JWK("pk"), assurance: "device", binding: "self", webauthId: "wa-golden" } }],
    ["KEY_ADDED", { agent: { keyId: `${PERSON}#key-3`, publicKeyMultibase: "z6MkChannel", assurance: "pop", binding: "custodial", carriedFrom: `${CHANNEL}#key-1` } }],
    ["ALIAS_ADDED", { agent: { alias: CHANNEL, aliasReason: "merge" } }],
    // Reserved on a person's chain (v0.3 §3.4): a person's affiliation is parked in v0.4 §12.
    ["ACTOR_AFFILIATED", { operator: { org: ORG, relation: "operates" } }],
  ]),
  // Its only key revoked: no usable key carries a rung, so the actor has none (§9.1bis rule 5).
  noUsableKey: chain("did:web:humanos.tech:agent:golden-revoked", HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "agent", keyId: "did:web:humanos.tech:agent:golden-revoked#key-1", jwk: JWK("kr"), assurance: "hardware", binding: "attested", root: "aws-nitro", bootstrapAnchor: "api_key", verifiedAt: "2026-01-01T00:00:00.000Z" } }],
    ["KEY_REVOKED", { agent: { keyId: "did:web:humanos.tech:agent:golden-revoked#key-1" } }],
  ]),
  // A key added with no rung of its own: pop/self, never the actor's grade (§9.1bis rule 4).
  runglessKey: chain("did:web:humanos.tech:agent:golden-rungless", HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "agent", keyId: "did:web:humanos.tech:agent:golden-rungless#key-1", jwk: JWK("rk1"), assurance: "hardware", binding: "attested", root: "aws-nitro", bootstrapAnchor: "api_key", verifiedAt: "2026-01-01T00:00:00.000Z" } }],
    ["KEY_ADDED", { agent: { keyId: "did:web:humanos.tech:agent:golden-rungless#key-2", jwk: JWK("rk2") } }],
  ]),
  // A merge as written since 2026-10-07: the survivor's half is ONE `MERGED` (§3.6c). The chain
  // above (`KEY_ADDED … carriedFrom` + `ALIAS_ADDED` reason `merge`) is how it was written before,
  // and still folds.
  mergedSurvivor: chain(SURVIVOR, HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "agent", keyId: `${SURVIVOR}#key-1`, jwk: JWK("s1"), assurance: "hardware", binding: "attested", root: "aws-nitro", bootstrapAnchor: "api_key", verifiedAt: "2026-01-01T00:00:00.000Z" } }],
    ["MERGED", { merge: {
      absorbed: ABSORBED,
      aliases: [`${ABSORBED}-old`],
      keys: [
        { keyId: `${ABSORBED}#key-1`, jwk: JWK("a1"), status: "rotated", rotatedTo: `${ABSORBED}#key-2`, assurance: "pop", binding: "self", verifiedAt: "2025-11-01T00:00:00.000Z" },
        { keyId: `${ABSORBED}#key-2`, jwk: JWK("a2"), status: "active", assurance: "device", binding: "custodial", verifiedAt: "2025-12-01T00:00:00.000Z", attestation: { event: "sha256-golden-att", kind: "attestation-eat" }, runtime: { class: "tee", mechanism: "nitro", measurementId: "m-absorbed" } },
      ],
    } }],
  ]),
  mergedAbsorbed: chain(ABSORBED, HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "agent", keyId: `${ABSORBED}#key-1`, jwk: JWK("a1"), assurance: "pop", binding: "self", bootstrapAnchor: "api_key", verifiedAt: "2025-11-01T00:00:00.000Z" } }],
    ["KEY_ROTATED", { agent: { predecessorId: `${ABSORBED}#key-1`, keyId: `${ABSORBED}#key-2`, jwk: JWK("a2"), assurance: "device", binding: "custodial", verifiedAt: "2025-12-01T00:00:00.000Z" } }],
    ["RETIRED", { agent: { succeededBy: SURVIVOR, keySuccession: { [`${ABSORBED}#key-1`]: `${ABSORBED}#key-1`, [`${ABSORBED}#key-2`]: `${ABSORBED}#key-2` } } }],
  ]),
  absorbedChannel: chain(CHANNEL, HUMANOS, [
    ["ACTOR_REGISTERED", { agent: { actorType: "user", keyId: `${CHANNEL}#key-1`, publicKeyMultibase: "z6MkChannel", assurance: "pop", binding: "custodial", bootstrapAnchor: "manual", existedSince: "2025-02-01T00:00:00.000Z" } }],
    ["RETIRED", { agent: { succeededBy: PERSON, keySuccession: { [`${CHANNEL}#key-1`]: `${PERSON}#key-3` } } }],
  ]),
};

/** The fold's output for every golden chain, canonicalized so key order never reads as a change. */
function foldAll(): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, events] of Object.entries(GOLDEN)) {
    const r = foldActorChain(events);
    if (!r.ok) throw new Error(`golden chain "${name}" does not fold: ${r.reason} at ${r.at}`);
    out[name] = JSON.parse(canonicalizeRFC8785(r.subject as unknown as Record<string, unknown>));
  }
  return out;
}

type Fixture = { version: number; chains: Record<string, unknown> };
const recorded = (): Fixture | null => (existsSync(FIXTURE) ? (JSON.parse(readFileSync(FIXTURE, "utf8")) as Fixture) : null);
const same = (a: unknown, b: unknown) => canonicalizeRFC8785(a as Record<string, unknown>) === canonicalizeRFC8785(b as Record<string, unknown>);

describe("ACTOR_FOLD_VERSION moves whenever the fold's output does", () => {
  it("the golden chains exercise every actor event kind", () => {
    // The golden chains are signed history: old kind names, read as today's (v0.3 §3.4).
    const used = new Set(Object.values(GOLDEN).flat().map((e) => canonicalEventType(e.credentialSubject.event as string)));
    // A kind the golden chains never fold is a kind this guard cannot see change.
    expect(ACTOR_EVENT_TYPES.filter((k) => !used.has(k))).toEqual([]);
  });

  it("the fold's output on the golden chains is the one recorded for this ACTOR_FOLD_VERSION", () => {
    const now = foldAll();
    const fixture = recorded();

    if (REGEN) {
      // @invariant Re-recording cannot hide a missing bump.
      if (fixture && fixture.version === ACTOR_FOLD_VERSION && !same(fixture.chains, now)) {
        throw new Error(
          `The fold's output changed but ACTOR_FOLD_VERSION is still ${ACTOR_FOLD_VERSION}. ` +
            "Bump it in src/actor/model.ts first — stored snapshots from the old fold must stop seeding reads.",
        );
      }
      mkdirSync(dirname(FIXTURE), { recursive: true });
      writeFileSync(FIXTURE, JSON.stringify({ version: ACTOR_FOLD_VERSION, chains: now }, null, 2) + "\n");
      return;
    }

    expect(fixture, "no fold fixture recorded — run with REGEN_FOLD_FIXTURE=1").not.toBeNull();
    if (fixture!.version !== ACTOR_FOLD_VERSION) {
      throw new Error(
        `ACTOR_FOLD_VERSION is ${ACTOR_FOLD_VERSION} but the fixture was recorded at ${fixture!.version}. ` +
          "Re-record it: REGEN_FOLD_FIXTURE=1 npx vitest run test/fold-version.test.ts",
      );
    }
    if (!same(fixture!.chains, now)) {
      throw new Error(
        `The fold's output changed but ACTOR_FOLD_VERSION did not (still ${ACTOR_FOLD_VERSION}). ` +
          "Bump it in src/actor/model.ts, then re-record: REGEN_FOLD_FIXTURE=1 npx vitest run test/fold-version.test.ts",
      );
    }
  });
});
