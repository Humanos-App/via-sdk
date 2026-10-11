/**
 * Deterministic generator for the committed wire fixtures.
 *
 * These fixtures are FROZEN, real artifacts checked into the repo. `wire-fixtures.test.ts`
 * verifies them with current code — the permanent "already-issued artifacts must keep
 * verifying" contract (per spec §0.13 / VERSIONING.md). Regenerating them is a deliberate
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
const AGENT_DID = "did:web:humanos.tech:agent:fixture-agent";
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

    // ---- v0.2: unified VIAEvent model (spec §0.5) ----
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
      description: { text: "Act within the pinned action.", lang: "en", author: "issuer" }, enforcement: "rules",
    });
    // These artifacts were signed while v0.2 was current, and the builder is now v0.3 — so the
    // v0.3-only marker and field come back off before the STAMP covers the body. Without this the
    // generator silently rewrites a "v0.2" fixture into something no v0.2 issuer could have
    // produced (`specVersion: "0.3"`, `enforcement: "rules"`), and a regen that was supposed to
    // reproduce frozen bytes instead invalidates the contract they encode. The rig could not
    // reproduce them from the moment VIA_SPEC_VERSION moved; it can again.
    mandate.specVersion = "0.2";
    delete (mandate.credentialSubject.mandate as { enforcement?: unknown }).enforcement;
    delete (mandate.credentialSubject.mandate as { description?: unknown }).description;
    // the mandate carries a SINGLE content-bound securing proof — the Humanos STAMP
    mandate = stampMandate(mandate, { privateKey: SEED_PLATFORM, verificationMethod: vmPlatform, created: "2026-01-03T00:00:00.000Z" });
    write("v0.2/mandate.json", mandate);

    // consent events: standalone, content-bound VIAEvents chained by previousEvent (§0.5.4)
    /**
     * Sign a v0.2-era event: the marker goes back to "0.2", and the `actor` a "0.2" event carries is
     * put back (the builder writes "0.3" events, which have none — v0.3 §2), before the proof covers it.
     */
    const signV02 = (e: ReturnType<typeof buildEvent>, signer: Parameters<typeof signEvent>[1], actor: string) =>
      signEvent({ ...e, specVersion: "0.2", credentialSubject: { ...e.credentialSubject, actor } }, signer);

    const issueEvent = signV02(
      buildEvent({
        eventId: "urn:via:event:fixture-issue",
        subject: mandate.id,
        event: "ISSUE",
        issuer: orgDid,
        credential: mandate,
        previousEvent: null,
        validFrom: "2026-01-01T00:00:00.000Z",
      }),
      { privateKey: SEED_ORG, verificationMethod: vmOrg, created: "2026-01-01T00:00:00.000Z" },
      orgDid,
    );
    write("v0.2/event-issue.json", issueEvent);

    const acceptEvent = signV02(
      buildEvent({
        eventId: "urn:via:event:fixture-accept",
        subject: mandate.id,
        event: "ACCEPT",
        issuer: userDid,
        credential: mandate,
        previousEvent: computeSRI(canonicalizeRFC8785(issueEvent)),
        validFrom: "2026-01-02T00:00:00.000Z",
      }),
      { privateKey: SEED_USER, verificationMethod: vmUser, created: "2026-01-02T00:00:00.000Z" },
      userDid,
    );
    write("v0.2/event-accept.json", acceptEvent);

    // operational event: reference-bound VERIFICATION_APPROVED, signed by Humanos
    const verificationEvent = signV02(
      buildEvent({
        eventId: "urn:via:event:fixture-verification",
        subject: mandate.id,
        event: "VERIFICATION_APPROVED",
        previousEvent: computeSRI(canonicalizeRFC8785(acceptEvent)),
        evaluations: [{ rule: "amt", result: "pass" }],
        executionParams: { amount: 100 },
        targetVerifier: "fidelidade.pt",
        validFrom: "2026-01-05T00:00:00.000Z",
      }),
      { privateKey: SEED_PLATFORM, verificationMethod: vmPlatform, created: "2026-01-05T00:00:00.000Z" },
      VERIFIER_DID,
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

    // ---- v0.3: §20 — the mandate description, enforcement, initiator, and S13 rule applicability ----
    // Two artifacts, because §20.3's two modes are the thing worth freezing: a POLICY whose CEL
    // governs and whose description is issuer-derived, and a SEMANTIC mandate whose words ARE the
    // grant. If a later change stops either verifying, the contract they encode is broken.
    const actionV3 = buildActionVersion({
      $id: "urn:via:action:fixture-slack-1",
      version: "5",
      userParams: {
        allowed_tools: { type: "array", items: "string", required: true, description: "the tools the person allowed" },
        allowed_channels: { type: "array", items: "string", required: true, description: "the channels the person allowed" },
      },
      executionParams: {
        tool: { type: "string", required: true },
        channel_id: { type: "string" },
        list_id: { type: "string" },
      },
      rules: [
        { name: "allowed_tools", description: "Only the tools the person allowed",
          conditions: [{ left: "executionParams.tool", operator: "in", right: "userParams.allowed_tools" }] },
        // S13 — the rule NAMES the tools it governs and the parameter a governed call must carry.
        // The guard it replaces (`!has(executionParams.channel_id) || …`) was skipped by any call
        // that omitted the value, so the person's allowlist bound only the calls that volunteered one.
        { name: "allowed_channels", description: "A channel the person allowed",
          appliesTo: ["slack_send_message", "slack_read_channel"], requires: ["channel_id"],
          conditions: [{ left: "executionParams.channel_id", operator: "in", right: "userParams.allowed_channels" }] },
      ],
    });
    write("v0.3/action.json", actionV3);

    let policy = buildMandate({
      credentialId: "urn:via:credential:fixture-v03-rules",
      subjectOrg: orgDid,
      grantor: userDid,
      authorizedDIDs: [VERIFIER_DID],
      action: { ...buildActionReference(actionV3, "https://api.humanos.tech/actions/fixture-slack-1"), version: 5 },
      userParams: wrapUserParamsWithAction(actionV3, {
        allowed_tools: ["slack_read_channel", "slack_send_message"],
        allowed_channels: ["C0BVB1KBPG8"],
      }),
      // §20.2 — DERIVED from the action and the values the grantor fixed. Prose beside rules that
      // govern may only be the issuer's, or it drifts from what actually runs.
      description: {
        text: "Read and post in one Slack channel (C0BVB1KBPG8), up to 20 times, until 22 Oct 2026.",
        lang: "en",
        author: "issuer",
      },
      initiator: { actor: AGENT_DID, role: "execution", at: "2026-09-22T09:59:00.000Z" },
      maxExecutions: 20,
      validFrom: "2026-09-22T10:00:00.000Z",
      validUntil: "2026-10-22T10:00:00.000Z",
      enforcement: "rules",
    });
    policy = stampMandate(policy, { privateKey: SEED_PLATFORM, verificationMethod: vmPlatform, created: "2026-09-22T10:00:00.000Z" });
    write("v0.3/mandate-rules.json", policy);

    let semantic = buildMandate({
      credentialId: "urn:via:credential:fixture-v03-semantic",
      subjectOrg: orgDid,
      grantor: userDid,
      authorizedDIDs: [VERIFIER_DID],
      enforcement: "semantic",
      // The grantor edited what the agent proposed, so the words are theirs (§20.2's adoption bar).
      description: {
        text: "Draft replies in my support inbox. Never send one without showing it to me first.",
        lang: "en",
        author: "grantor",
        proposedBy: { actor: AGENT_DID, adopted: true },
      },
      stepUp: { triggers: ["verifier"], reasons: ["semantic_review"] },
      initiator: { actor: AGENT_DID, role: "execution", at: "2026-09-22T09:59:00.000Z" },
      validFrom: "2026-09-22T10:00:00.000Z",
      validUntil: "2026-10-22T10:00:00.000Z",
    });
    semantic = stampMandate(semantic, { privateKey: SEED_PLATFORM, verificationMethod: vmPlatform, created: "2026-09-22T10:00:00.000Z" });
    write("v0.3/mandate-semantic.json", semantic);

    const issueV3 = signEvent(
      buildEvent({
        eventId: "urn:via:event:fixture-v03-issue",
        subject: policy.id,
        event: "ISSUE",
        issuer: orgDid,
        credential: policy,
        previousEvent: null,
        validFrom: "2026-09-22T10:00:00.000Z",
      }),
      { privateKey: SEED_ORG, verificationMethod: vmOrg, created: "2026-09-22T10:00:00.000Z" },
    );
    write("v0.3/event-issue.json", issueV3);

    const acceptV3 = signEvent(
      buildEvent({
        eventId: "urn:via:event:fixture-v03-accept",
        subject: policy.id,
        event: "ACCEPT",
        issuer: userDid,
        credential: policy,
        previousEvent: computeSRI(canonicalizeRFC8785(issueV3)),
        validFrom: "2026-09-22T10:01:00.000Z",
      }),
      { privateKey: SEED_USER, verificationMethod: vmUser, created: "2026-09-22T10:01:00.000Z" },
    );
    write("v0.3/event-accept.json", acceptV3);

    // A decision that rested on a step-up a REVIEWER demanded (§9.9 / §20.6): the detail carries
    // who asked, why, and which reader ran — the part a chain cannot be re-checked without.
    const verificationV3 = signEvent(
      buildEvent({
        eventId: "urn:via:event:fixture-v03-verification",
        subject: policy.id,
        event: "VERIFICATION_APPROVED",
        previousEvent: computeSRI(canonicalizeRFC8785(acceptV3)),
        evaluations: [
          { rule: "allowed_tools", result: "pass" },
          { rule: "allowed_channels", result: "pass" },
        ],
        executionParams: { tool: "slack_send_message", channel_id: "C0BVB1KBPG8" },
        stepUp: {
          id: "urn:via:stepup:fixture-v03",
          method: "otp",
          termsDigest: "sha384-fixture",
          tool: "slack_send_message",
          trigger: "verifier",
          reason: "semantic_review",
          reviewer: { id: "reys", version: "2026-09-14" },
        },
        targetVerifier: "fidelidade.pt",
        validFrom: "2026-09-22T10:05:00.000Z",
      }),
      { privateKey: SEED_PLATFORM, verificationMethod: vmPlatform, created: "2026-09-22T10:05:00.000Z" },
    );
    write("v0.3/event-verification.json", verificationV3);

    write(
      "v0.3/presentation-semantic.json",
      buildPresentation({
        credential: semantic,
        holder: VIA_PLATFORM_DID,
        privateKey: SEED_PLATFORM,
        verificationMethod: vmPlatform,
        created: "2026-09-22T10:02:00.000Z",
      }),
    );

    write(
      "v0.3/presentation.json",
      buildPresentation({
        credential: policy,
        holder: VIA_PLATFORM_DID,
        privateKey: SEED_PLATFORM,
        verificationMethod: vmPlatform,
        created: "2026-09-22T10:02:00.000Z",
      }),
    );

    
    // ---- legacy: a pre-0.2 artifact — no specVersion marker, doc-only signed VP ----
    const legacyMandate = buildMandate({
      credentialId: "urn:via:credential:legacy-0001",
      subjectOrg: orgDid,
      grantor: userDid,
      authorizedDIDs: [VERIFIER_DID],
      validFrom: "2026-01-01T00:00:00.000Z",
      // The builder is v0.3 and refuses an action-less mandate with no words (§20.3), but this
      // artifact predates §20 and the marker alike — so it is built to satisfy today's builder and
      // then stripped back to what a pre-0.2 issuer actually produced.
      description: { text: "predates §20", lang: "en", author: "grantor" },
      enforcement: "none",
    });
    delete legacyMandate.specVersion; // predates the marker
    delete (legacyMandate.credentialSubject.mandate as { description?: unknown }).description;
    delete (legacyMandate.credentialSubject.mandate as { enforcement?: unknown }).enforcement;
    const { proof: _drop, ...credNoProof } = legacyMandate;
    const proofOpts = {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-jcs-2022",
      created: "2026-01-01T00:00:00.000Z",
      verificationMethod: vmPlatform,
      proofPurpose: "authentication",
    } as const;  });
});
