/**
 * Deterministic generator for the committed wire fixtures.
 *
 * These fixtures are FROZEN, real artifacts checked into the repo. `wire-fixtures.test.ts`
 * verifies them with current code — the permanent "already-issued artifacts must keep
 * verifying" contract (per spec §13 / VERSIONING.md). Regenerating them is a deliberate
 * act (a new spec version, or an intended wire change), never automatic.
 *
 * Regenerate:  REGEN_FIXTURES=1 npx vitest run test/fixtures.generate.test.ts
 * Then commit the changed files under test/fixtures/ and review the diff carefully —
 * an UNEXPECTED diff means a code change altered a shipped version's wire format.
 */
import { describe, it } from "vitest";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  VIA_PLATFORM_DID,
  generateViaDID,
  buildActionVersion,
  buildActionReference,
  wrapUserParamsWithAction,
  buildCredentialStatusEntry,
  buildMandate,
  stampMandate,
  buildEvent,
  signEvent,
  buildPresentation,
  signMultibase,
  canonicalizeRFC8785,
  computeSRI,
  type VerifiablePresentation,
  type ViaMandateCredential,
} from "../src/index.js";
import { publicKeyFromPrivate } from "../src/crypto/ed25519.js";

// Fixed seeds → reproducible keys. (Public keys are committed in keys.json for verification.)
const SEED_PLATFORM = new Uint8Array(32).fill(11);
const SEED_ORG = new Uint8Array(32).fill(12);
const SEED_USER = new Uint8Array(32).fill(13);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const VERIFIER_DID = "did:web:fidelidade.pt";
const orgDid = generateViaDID("org", { uuid: "fixture-org" });
const userDid = generateViaDID("user", { uuid: "fixture-user" });
const vmPlatform = `${VIA_PLATFORM_DID}#key-1`;
const vmOrg = `${orgDid}#key-1`;
const vmUser = `${userDid}#key-1`;

const REGEN = !!process.env.REGEN_FIXTURES;

(REGEN ? describe : describe.skip)("regenerate wire fixtures (set REGEN_FIXTURES=1)", () => {
  it("writes the committed, frozen v0.2 + legacy fixtures", () => {
    const dir = fileURLToPath(new URL("./fixtures/", import.meta.url));
    const write = (rel: string, value: unknown) => {
      const path = `${dir}${rel}`;
      mkdirSync(path.slice(0, path.lastIndexOf("/")), { recursive: true });
      writeFileSync(path, JSON.stringify(value, null, 2) + "\n");
    };

    // public keys for resolution at verify time
    write("keys.json", {
      [vmPlatform]: hex(publicKeyFromPrivate(SEED_PLATFORM)),
      [vmOrg]: hex(publicKeyFromPrivate(SEED_ORG)),
      [vmUser]: hex(publicKeyFromPrivate(SEED_USER)),
    });

    // ---- v0.2: unified VIAEvent model (spec §5) ----
    // action + mandate (single STAMP) + standalone consent/operational events + presentation.
    const action = buildActionVersion({
      $id: "urn:via:action:fixture-pay-1",
      version: "1",
      userParams: { maxAmount: { type: "number", required: true, description: "claim cap (EUR)" } },
      executionParams: { amount: { type: "number", required: true } },
      rules: [{ name: "amt", conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.maxAmount" }] }],
    });
    write("v0.2/action.json", action);

    let mandate = buildMandate({
      credentialId: "urn:via:credential:fixture-0001",
      subjectOrg: orgDid,
      grantor: userDid,
      authorizedDIDs: [VERIFIER_DID],
      action: buildActionReference(action, "https://api.humanos.tech/actions/fixture-pay-1"),
      userParams: wrapUserParamsWithAction(action, { maxAmount: 2500 }),
      credentialStatus: buildCredentialStatusEntry({ statusListCredential: "https://status.humanos.tech/list/1", statusListIndex: 0 }),
      validFrom: "2026-01-01T00:00:00.000Z",
    });
    // the mandate carries a SINGLE content-bound securing proof — the Humanos STAMP
    mandate = stampMandate(mandate, { privateKey: SEED_PLATFORM, verificationMethod: vmPlatform, created: "2026-01-03T00:00:00.000Z" });
    write("v0.2/mandate.json", mandate);

    // consent events: standalone, content-bound VIAEvents chained by previousEvent (§5.4)
    const issueEvent = signEvent(
      buildEvent({
        eventId: "urn:via:event:fixture-issue",
        credentialId: mandate.id,
        event: "ISSUE",
        actor: orgDid,
        issuer: orgDid,
        credential: mandate,
        previousEvent: null,
        validFrom: "2026-01-01T00:00:00.000Z",
      }),
      { privateKey: SEED_ORG, verificationMethod: vmOrg, created: "2026-01-01T00:00:00.000Z" },
    );
    write("v0.2/event-issue.json", issueEvent);

    const acceptEvent = signEvent(
      buildEvent({
        eventId: "urn:via:event:fixture-accept",
        credentialId: mandate.id,
        event: "ACCEPT",
        actor: userDid,
        issuer: userDid,
        credential: mandate,
        previousEvent: computeSRI(canonicalizeRFC8785(issueEvent)),
        validFrom: "2026-01-02T00:00:00.000Z",
      }),
      { privateKey: SEED_USER, verificationMethod: vmUser, created: "2026-01-02T00:00:00.000Z" },
    );
    write("v0.2/event-accept.json", acceptEvent);

    // operational event: reference-bound VERIFICATION_APPROVED, signed by Humanos
    const verificationEvent = signEvent(
      buildEvent({
        eventId: "urn:via:event:fixture-verification",
        credentialId: mandate.id,
        event: "VERIFICATION_APPROVED",
        actor: VERIFIER_DID,
        previousEvent: computeSRI(canonicalizeRFC8785(acceptEvent)),
        evaluations: [{ rule: "amt", result: "pass" }],
        executionParams: { amount: 100 },
        targetVerifier: "fidelidade.pt",
        validFrom: "2026-01-05T00:00:00.000Z",
      }),
      { privateKey: SEED_PLATFORM, verificationMethod: vmPlatform, created: "2026-01-05T00:00:00.000Z" },
    );
    write("v0.2/event-verification.json", verificationEvent);

    const presentation = buildPresentation({
      credential: mandate,
      holder: VIA_PLATFORM_DID,
      privateKey: SEED_PLATFORM,
      verificationMethod: vmPlatform,
      created: "2026-01-04T00:00:00.000Z",
    });
    write("v0.2/presentation.json", presentation);

    
    // ---- legacy: a pre-0.2 artifact — no specVersion marker, doc-only signed VP ----
    const legacyMandate = buildMandate({
      credentialId: "urn:via:credential:legacy-0001",
      subjectOrg: orgDid,
      grantor: userDid,
      authorizedDIDs: [VERIFIER_DID],
      validFrom: "2026-01-01T00:00:00.000Z",
    });
    delete legacyMandate.specVersion; // predates the marker
    const { proof: _drop, ...credNoProof } = legacyMandate;
    const proofOpts = {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-jcs-2022",
      created: "2026-01-01T00:00:00.000Z",
      verificationMethod: vmPlatform,
      proofPurpose: "authentication",
    } as const;  });
});
