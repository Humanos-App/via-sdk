<p align="center"><img src="https://cdn.jsdelivr.net/npm/@humanos-ai/via-sdk/assets/via-blueprint.svg" width="100%"
  alt="VIA Protocol SDK v0.3: a person's mandate pins an agent's key; the agent signs a proof of possession on every call; the verifier checks mandate, agent, proof and rules before the tool runs; the called party checks a call proof offline; every step is a signed, hash-chained event."></p>

# @humanos-ai/via-sdk

The TypeScript SDK for the **VIA Protocol v0.3**: a person grants an AI agent a mandate, and every call the agent
makes is checked against that mandate before the tool runs, with a signed record of each decision. It is a
functions-only library with no network, database or key store: you supply the keys and every lookup.

Mandates and events are W3C Verifiable Credentials 2.0 signed with Ed25519 (`eddsa-jcs-2022`, RFC 8785 JCS). Agents
prove possession of their own P-256 key on each call; rules are CEL. `§N` section numbers are the v0.3 spec's.

## Install

```bash
npm install @humanos-ai/via-sdk        # the v0.3 line (dist-tag latest)
npm install @humanos-ai/via-sdk@next   # the v0.4 draft (branch v04)
```

ESM and CommonJS builds with type declarations; runtime dependencies are bundled. It runs on Node.js (it uses
`node:crypto`) and is tested on Node 22 and 24.

## Quickstart

Issue a mandate that lets one agent pay invoices up to 2,500 EUR, then verify one call.

```ts
import {
  generateEd25519Key, generateP256Key, jwkThumbprint, generateViaDID, VIA_PLATFORM_DID,
  buildActionVersion, buildActionReference, wrapUserParamsWithAction,
  buildMandate, stampMandate, buildPoP, actionHash, verifyAgentDirect,
} from "@humanos-ai/via-sdk";

// Keys. The platform's Ed25519 key stamps mandates. The agent's P-256 key stays with the agent.
const platform = generateEd25519Key();
const platformKey = `${VIA_PLATFORM_DID}#key-1`;
const agent = await generateP256Key();
const agentDid = generateViaDID("agent"); // did:web:humanos.tech:agent:<uuid>
const verifierDid = "did:web:gateway.example.com";

// An action: the tools it covers, its parameters, and rules that compile to CEL.
const action = buildActionVersion({
  $id: "urn:via:action:pay-invoice", version: "1",
  tools: ["pay_invoice"],
  userParams: { maxAmount: { type: "number", required: true, description: "Cap per payment, EUR" } },
  executionParams: { amount: { type: "number", required: true } },
  rules: [{
    name: "under_cap", description: "A payment is at most the cap.",
    conditions: [{ left: "executionParams.amount", operator: "<=", right: "userParams.maxAmount" }],
  }],
});

// The mandate: the person's grant. It pins the action, their values and the agent's key.
const mandate = stampMandate(buildMandate({
  subjectOrg: generateViaDID("org"),
  grantor: generateViaDID("user"),
  authorizedDIDs: [verifierDid],
  authorizedAgents: [{
    did: agentDid, cnf: { jwk: agent.publicJwk },
    assurance: "pop", binding: "self", verifiedAt: new Date().toISOString(),
  }],
  action: buildActionReference(action, "https://example.com/actions/pay-invoice/1"),
  userParams: wrapUserParamsWithAction(action, { maxAmount: 2500 }),
  description: { text: "Pay invoices of up to 2,500 EUR each.", lang: "en", author: "issuer" },
  enforcement: "rules",
  validFrom: "2026-01-01T00:00:00.000Z",
}), { privateKey: platform.privateKey, verificationMethod: platformKey });

// Per call: the verifier issues a single-use nonce; the agent signs a PoP over this exact call.
const nonce = "n-81f2c4";
const call = { action: "pay_invoice", params: { amount: 1200 } };
const pop = await buildPoP({
  cnf: { jkt: jwkThumbprint(agent.publicJwk) },
  aud: verifierDid, nonce, iat: Math.floor(Date.now() / 1000),
  action_hash: actionHash(mandate.id, call.action, call.params),
}, agent.privateJwk);

// The verifier decides. Every lookup is a function you supply.
const result = await verifyAgentDirect(mandate, { pop, ...call }, {
  verifier: { did: verifierDid },
  resolvePublicKey: (vm) => {
    if (vm !== platformKey) throw new Error(`unknown key ${vm}`);
    return platform.publicKey;
  },
  loadCredentialRecord: () => ({ status: "ACTIVE" }),
  loadActionVersion: (id) => (id === action.$id ? action : null),
  // Each agent's keys, resolved through its current record (§8). Here, the signed entries.
  candidates: mandate.credentialSubject.mandate.context.authorizedAgents,
  validateNonce: (n) => (n === nonce ? "ok" : "pop_replayed"),
});

console.log(result.decision, result.evaluations);
// allow [ { rule: 'under_cap', result: 'pass' } ]
```

With `amount: 4000` the same call is denied (`rule_failed`, with the rule's description). Another tool is
`tool_not_covered`, a reused nonce `pop_replayed`, and a mandate edited after its stamp `credential_stamp_invalid`.

### Record the decision and prove it to the service called

Continuing from the quickstart: the verifier signs its decision as an event, the outcome links to it by hash, and the
service the agent calls gets a short-lived call proof that it checks offline (§16.16).

```ts
import {
  buildVerificationEvent, buildOutcomeEvent, eventChainLink, walkEventChain, buildCallProof, verifyCallProof,
} from "@humanos-ai/via-sdk";

const verifierKey = generateEd25519Key();
const signer = { privateKey: verifierKey.privateKey, verificationMethod: `${verifierDid}#key-1` };

// The decision, signed by the verifier. On a live chain, previousEvent: eventChainLink(<the last event>).
const decision = buildVerificationEvent({
  mandateId: mandate.id, decision: "allow", issuer: verifierDid,
  agent: result.agent!, popNonceRef: nonce, enforcement: result.enforcement,
  evaluations: result.evaluations, actionHash: actionHash(mandate.id, call.action, call.params),
}, signer)!;

// The outcome the agent reports (with its own PoP, §2.1), chained to the decision.
const outcome = buildOutcomeEvent({
  mandateId: mandate.id, outcome: "completed", decision: decision.id, issuer: verifierDid,
  previousEvent: eventChainLink(decision),
}, signer);
console.log(await walkEventChain([decision, outcome])); // { ok: true }

// A call proof covers one call, for one receiver, for at most 300 seconds.
const receiver = "https://api.payments.example";
const token = buildCallProof({
  iss: verifierDid, sub: agentDid, aud: receiver, mandate: mandate.id, decision: decision.id, call,
}, signer);

// The receiver's check: trusted signer, signature, audience, lifetime, the call itself, single use.
const seen = new Set<string>();
const check = await verifyCallProof(token, {
  audience: receiver,
  trustedPlatforms: [verifierDid],                // the signers this receiver trusts
  resolvePublicKey: () => verifierKey.publicKey,  // in practice: the `kid` key from iss's DID document
  call,                                           // the call as it arrived
  consumeJti: (jti) => (seen.has(jti) ? false : (seen.add(jti), true)),
});
console.log(check.ok); // true
```

## How verification works

`verifyAgentDirect` checks a call under a mandate (§8, §16.7, §16.11). Checks run in order; the first failure denies
with one reason code, and every result carries `enforcement`, which says what governed it.

1. **The mandate.** The verifier's own copy, loaded by id, never one the agent sends. Its `STAMP` must verify
   (`credential_stamp_invalid`); its spec version and critical extensions must be ones this SDK implements
   (`unsupported_spec_version`, `extension_unsupported`); `enforcement` must fit its shape (`enforcement_invalid`).
2. **Status and audience.** From your record, not the credential: `ACTIVE` (`credential_revoked`, …), within its
   dates (`not_yet_valid`, `expired`), and the verifier listed in `authorizedDIDs` (`verifier_not_authorized`).
3. **The agent.** Its usable keys, resolved through its current record (`candidates`). With none, the call is
   denied (`actor_unresolvable`): there is no offline profile for a bound agent.
4. **The PoP** (A1–A8). Well-formed `via-pop+jwt`; the key selected by thumbprint (`agent_not_bound`); the signature
   checked with the algorithm the key implies, never the header's (`pop_invalid`); `aud` (`aud_mismatch`); the nonce,
   through your `validateNonce` (`pop_replayed`, `nonce_expired`); `action_hash` equal to this call
   (`action_hash_mismatch`); the attestation within its window (`attestation_stale`).
5. **The action.** Found and matching its pinned digest (`action_not_found`, `action_invalid`), covering the tool
   (`tool_not_covered`), and the parameters matching their declared types (`execution_params_invalid:…`).
6. **The rules.** Every rule that governs the call must pass, evaluated in CEL over `userParams`, `executionParams`,
   `constants` and the agent's rung as `agent.*` (`rule_failed`, `required_param_missing`,
   `agent_assurance_insufficient`, …). A `semantic` mandate asks the reviewer you inject instead.
7. **Policy and step-up.** An organization policy passed as `policy` can only narrow the result. When the mandate asks
   for a step-up on every call (`stepUp.triggers` includes `mandate`), or your `requiresStepUp` says the call needs one,
   the answer is `rechallenge` until a fresh grantor approval is shown (`stepUpSatisfied`).

A verifier wired without a nonce check throws instead of verifying. Two other entry points share these checks:

- `verifyAgentCall` decides a call the way §21.3 does: the organization's `VIAPolicy` first, reading a mandate only
  when the policy's entry for the tool says `mandate`. It never answers `rechallenge`.
- `verify` checks a Humanos-signed presentation (§0.7.1, §0.8). A mandate that binds agents is denied there
  (`pop_invalid`): such mandates are verified agent-direct only.

## API by job

Everything below is exported from `@humanos-ai/via-sdk` unless noted. Types ship with each function.

| Job | Functions |
|---|---|
| Keys | `generateEd25519Key`, `publicKeyFromPrivate`, `generateP256Key`, `jwkThumbprint`, `signRaw` / `verifyRaw`, `signES256` / `verifyES256` |
| DIDs and DID documents | `generateViaDID`, `generateDomainDID`, `buildDidDocument`, `resolveVerificationKey`, `resolveVerificationJwk`, `parseDidWeb`, `didWebToUrl`, `didFromUrl`, `VIA_PLATFORM_DID` |
| Actions and rules | `buildActionVersion`, `actionPublishIssues`, `buildActionReference`, `verifyActionReference`, `actionDigestSRI`, `validateExecutionParams`, `evaluateRules`, `generateCelExpression`, `constraintsToRules` (assurance floors and similar, as CEL) |
| Mandates | `buildMandate`, `stampMandate`, `verifyStamp`, `buildEvidence`, `wrapUserParamsWithAction`, `unwrapUserParamValues`, `validateMandateDescription` (§20) |
| Consent | `buildIssuanceEvents` (`ISSUE` and each grantor's `ACCEPT`/`REJECT`, then the `STAMP`), `buildGrantorBinding`, `buildOtpGrantorBinding`, `verifyGrantorAssertion` (passkeys, §17) |
| Agent registration (§16.5) | `registerChallenge`, `registerAgentKey`, `buildRegistrationProof`, `verifyRegistrationProof`, `validateWebauthnAttestation`, `validateCoseAttestation` |
| Agent calls | `buildPoP`, `actionHash`, `verifyAgentDirect`, `verifyAgentCall`, `verifyAgentBinding` (A1–A6 and A8 alone), `outcomeParams` |
| Events and the record | `buildEvent`, `signEvent`, `verifyEvent`, `buildChainedEvent`, `eventChainLink`, `walkEventChain`, `auditEventChain`, `buildVerificationEvent`, `buildOutcomeEvent` |
| Call proofs (§16.16) | `buildCallProof`, `verifyCallProof`, `readCallProof`, `buildAgentRecord`, `CALL_PROOF_HEADER`, `AGENT_RECORD_HEADER` |
| Organization policy (§21) | `evaluatePolicy`, `policyDigest`, `policyPublishIssues`, `policyDefault` |
| Actor records (§3–§5) | `foldActorChain`, `foldActorRecord`, `auditActorRecord`, `resolveSuccession`, `resolvePinnedKeys`, `projectAgentContext` |
| Accreditation (§18) | `buildAccreditation`, `verifyAccreditation`, `buildAffiliation`, `verifyAffiliation` |
| Presentations | `buildPresentation`, `verifyPresentation`, `verify`; SD-JWT VC: `buildSdJwtMandate`, `presentSdJwt`, `verifySdJwtPresentation` |
| Status lists | `StatusList`, `buildCredentialStatusEntry`, `checkCredentialStatus` (W3C Bitstring Status List) |
| Low-level | `canonicalizeRFC8785`, `computeSRI`, `createDataIntegrityProof`, `verifyDataIntegrityProof`, `detectSpecVersion` |

`addProof` and `verifyMandateProofs` remain as deprecated shims: a mandate has one proof, the `STAMP`
(`stampMandate`, `verifyStamp`). Consents are `VIAEvent`s on the mandate's chain, not proofs on the credential.

Two more entry points are kept out of the main one on purpose:

| Import | What it is |
|---|---|
| `@humanos-ai/via-sdk/action/cel` | The rule-to-CEL generator (`generateCelExpression`, `buildTypeResolver`, `operatorsByType`, …). It does not load `node:crypto`, so a browser form can build rules with it. |
| `@humanos-ai/via-sdk/agent/sim` | **Development and tests only.** `mintNitroCa`, `buildCoseAttestation`: a test CA and AWS Nitro-shaped attestations, so the attested tier can be exercised without hardware. A verifier pinning production roots rejects them. |

## What you inject

The SDK fetches nothing, stores nothing and holds no keys: signing functions take raw key material (`privateKey`
bytes or a private JWK), and protecting it is yours. Time is the system clock unless you pass `now`. A verifier
passes in:

- `resolvePublicKey(verificationMethod)`: a signer's public key, normally from its DID document.
- `loadCredentialRecord(id)`: the mandate's status, validity and current `authorizedDIDs` from your record.
- `loadActionVersion(id)`: the pinned action's content.
- `candidates`: each agent's usable keys, resolved through its current record (§8). This is the step that lets a
  suspension, a revoked key or a rotation reach a live mandate.
- `validateNonce(nonce, authority)`: your single-use nonce store. Required.
- Optional: `policy`, `review` (a semantic reviewer), `requiresStepUp`, `loadAccreditation`, `now`.

## Status and spec versions

New artifacts carry `specVersion: "0.3"` (`VIA_SPEC_VERSION`). Verification reads `"0.2"` and `"0.3"`
(`SUPPORTED_SPEC_VERSIONS`), so mandates signed under v0.2 keep verifying, and fails closed on any other value
(`unsupported_spec_version`). The suite has 725 tests, including frozen per-version wire fixtures and known-answer
tests for the cryptography. The SDK has **not been independently audited**, and the v0.3 specification is a draft.

## Branches and releases

| Branch | Implements | npm dist-tag | Versions |
|---|---|---|---|
| `main` | v0.3, the line in use | `latest` | `0.8.x` |
| `v04` | the v0.4 draft: `main` plus v0.4's additions | `next` | `1.0.0-v04.N` |

A fix to v0.3 code lands on `main` first and is merged into `v04`. `v04`'s `package.json` sets `publishConfig.tag`
to `next`, so nothing published from it reaches `latest`. Packages are published from a GitHub release, after CI
(typecheck and tests) passes; a push or a tag alone publishes nothing.

## Development

```bash
npm test           # builds dist/, then runs the vitest suite
npm run typecheck  # tsc --noEmit
npm run build      # tsup: ESM + CJS + d.ts, runtime dependencies bundled
```

Maintainers: release steps and the pre-change checks are in `CONTRIBUTING.md` in the repository.

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0). The `LICENSE` file ships in the package.
