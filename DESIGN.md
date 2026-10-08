# VIA SDK — Design

**Implements:** [`spec/via-protocol-spec-v0.2.md`](../spec/via-protocol-spec-v0.2.md) (the reconciled spec — the source of truth).

## Priorities

1. **Primary — be the spec-correct reference.** The SDK implements v0.2 exactly: real `eddsa-jcs-2022`, RFC-8785 JCS, a `proof` set with `lifecycleAction` (no `actionProof`), standard-base64 SRI, `credentialStatus`, Ed25519/Multikey `did:web`, Action/ActionVersion + CEL, full + SD-JWT presentations, receipts. **Default behavior is v0.2-correct.**
2. **Secondary — optional, transitional compatibility.** A clearly-isolated `legacy` mode + `@humanos/via-protocol`-shaped re-exports exist *only* to ease platform migration. They are not the organizing principle and may be dropped once the platform migrates.

The SDK is a **pure, functions-only library** — no HTTP/endpoints, no DB, no KMS, no network. All I/O (DID resolution, ActionVersion fetch, status reads, KMS decrypt) is **injected** by the caller. The platform's API layer wraps it.

## Structure

```
sdk/src/
  index.ts                  # public v0.2 surface (primary)
  config.ts                 # FormatMode: 'v0.2' (DEFAULT) | 'legacy'
  crypto/
    ed25519.ts              # sign/verify (raw + multibase), base58btc
    canonicalize.ts         # canonicalizeRFC8785() [primary]; canonicalizeLegacy() [compat]
    digest.ts               # computeSRI() base64 [primary] / base64url [compat], sha256
    proof.ts                # createDataIntegrityProof()/verifyProof() — real eddsa-jcs-2022
  did/                      # generateViaDID, generateDomainDID, generateEd25519Key,
                            # encodePublicKeyMultibase, buildDidDocument, parseDidWeb, didWebToUrl
  mandate/                  # buildMandate, addProof (ISSUE/ACCEPT/REJECT/STAMP/REVOKE/CANCELED_STAMP),
                            # verifyMandateProofs
  action/                   # buildActionVersion, generateCelExpression (N13),
                            # validateExecutionParams, actionDigestSRI
  status/                   # buildCredentialStatusEntry, BitstringStatusList build/encode/decode (N15)
  presentation/             # buildPresentation (full, secured VC), buildSdJwtPresentation (D-f),
                            # verifyPresentation
  verify/                   # verify({ presentation, executionParams }, deps) — §0.8 flow
  receipt/                  # buildReceipt, signReceipt, verifyReceipt
  cel/                      # @marcbachmann/cel-js wrapper (evaluate rules)
  context/via-ns-v1.json    # the JSON-LD context (§0.4.4) shipped with the package
  compat/                   # [SECONDARY] legacy.ts: old @humanos/via-protocol export names,
                            # legacy-mode byte-compatible behavior; isolated, optional
```

## Coverage (spec §0.11)

| Area | Functions |
|------|-----------|
| Keys/DID | `generateEd25519Key`, `encodePublicKeyMultibase`, `generateViaDID`, `generateDomainDID`, `buildDidDocument`, `parseDidWeb`, `didWebToUrl` |
| Canonicalize/crypto | `canonicalizeRFC8785`, `createDataIntegrityProof`, `verifyProof`, `computeSRI`, `sha256`, base58 |
| Mandate | `buildMandate`, `addProof`, `verifyMandateProofs` |
| Action | `buildActionVersion`, `generateCelExpression`, `validateExecutionParams`, `actionDigestSRI` |
| Status | `buildCredentialStatusEntry`, `encodeStatusList`, `decodeStatusList`, `buildStatusListCredential` |
| Presentation | `buildPresentation`, `buildSdJwtPresentation`, `verifyPresentation` |
| Verify | `verify({ presentation, executionParams }, deps)` → `{ decision, evaluations, reason? }`; `verifyAny(...)` dual-accepts legacy + v0.2 (reports `format`) for the migration window |
| Receipts | `buildReceipt`, `signReceipt`, `verifyReceipt` |

### Dependency injection for `verify`

```ts
verify(
  { presentation, executionParams },
  {
    resolveVerifier: (apiKey) => Promise<{ did: string; domain?: string }>,
    loadCredentialRecord: (urn) => Promise<{ status: CredentialStatus; validFrom; validUntil }>,
    loadActionVersion: (urn) => Promise<ActionVersion | null>,
    now?: () => Date,
  },
): Promise<VerifyResult>
```

Signing functions take **raw Ed25519 private key bytes** (the platform decrypts via KMS and passes them in).

## FormatMode

`FormatMode` defaults to **`v0.2`** (correct). `legacy` is opt-in (global or per-call) and only affects: canonicalization (`canonicalizeLegacy`), SRI (`base64url`), proof shape (`proofs[]` + `actionProof`, doc-only signing). It exists for the transition window and is documented as secondary.

## End goal — the SDK owns the protocol logic

All VIA protocol logic currently scattered across the old SDK and the platform moves **into** the SDK v0.2; the platform keeps only platform concerns and calls the SDK.

| Platform today | → replaced by SDK v0.2 |
|---|---|
| old SDK `signWithEd25519Multibase`, `canonicalizeJSON`, `generateDIDKey`, `encodePublicKeyMultibase`, `generateChallenge` | `crypto/*`, `did/*`, `presentation/challenge` |
| `apps/api/.../helpers/signature.utils.ts` `verifyEd25519Multibase` | `crypto/ed25519` |
| `shared-backend/.../via/w3cCredential.ts` `signCredential`, `buildW3CCredential`, `computeSRI` | `mandate/*`, `crypto/digest` |
| `shared-backend/.../via/actors.ts` `generateViaDID`, `generateDomainDID` | `did/web` |
| `shared-backend/.../request/generate/user-params.ts` `validate*Params`, `wrap/unwrapUserParams` | `action/execution-params` |
| `frontend/.../mandate/cel.ts` `generateCelExpression` | `action/cel` |
| `apps/api/.../cel-evaluator.service.ts` | `cel` |
| `apps/api/.../presentation.service.ts` `createPresentation` + verify flow | `presentation/*`, `verify` |
| receipt VC building (`receipt.service.ts`) | `receipt/*` |
| (none yet) | `status/*` (N15) |

**Stays in the platform** (injected into the SDK's pure functions): Nest/HTTP, Prisma/DB, KMS encrypt/decrypt, OTP/SMS delivery, `VpChallengeService` (challenge storage + replay state), `ActionCache`, billing, webhooks/activity events, DID-resolution transport.

## Compatibility (secondary, optional — a tiny shim)

Verified: the platform imports only **5 functions + 2 types** from `@humanos/via-protocol` (`signWithEd25519Multibase`, `canonicalizeJSON`, `generateDIDKey`, `encodePublicKeyMultibase`, `generateChallenge`; types `DataIntegrityProof`, `VerifiablePresentation`). So `compat/legacy.ts` only needs to re-export those, in `legacy` mode (byte-identical to today), to be a zero-change drop-in. The old SDK's higher-level builders/clients (`createDataIntegrityProof` with `ecdsa-2019`, `createVerifiablePresentation`, `did:key`, `VIAClient`) are **not** consumed and are not reproduced. If compat proves unnecessary it can be deleted without touching the core.

## Crypto choices

- Ed25519 via Node `crypto`/WebCrypto (matches platform); base58btc + multibase `z`; multicodec `0xed01` for keys.
- RFC-8785 JCS: a vetted implementation, validated against test vectors (legacy canonicalizer ported verbatim for compat).
- SD-JWT VC via a maintained library (Ed25519), `dc+sd-jwt` typ (accept `vc+sd-jwt`), `vct: https://via.humanos.tech/vct/mandate`.
- CEL via [`@marcbachmann/cel-js`](https://www.npmjs.com/package/@marcbachmann/cel-js)
  — a maintained, dependency-free, near-complete CEL implementation. The platform
  currently runs ChromeGG `cel-js@0.8.2` (now deprecated / GitHub-archived); the SDK
  deliberately diverges to the maintained engine. Every form the rule generator emits
  was verified to evaluate identically (operator KATs in `test/cel.test.ts`), so this
  is an engine upgrade, not a semantics change — see RECONCILIATION.md N31/N39.

## Versioning

Four independent axes (spec §0.13, `spec/VERSIONING.md`): the **spec version** (signed
`specVersion` marker on every artifact, `VIA_SPEC_VERSION`), the **JSON-LD context**
version (`…/ns/v1`), the **crypto wire format** (`FormatMode`), and the **package**
semver. Builders stamp `specVersion`; `detectSpecVersion()` reads it; `verify`/`verifyAny`
attach it and **fail closed** (`unsupported_spec_version`) on an unknown value. A
**marker-less** credential is treated as `legacy` and still verified — back-compat with
mandates issued before the marker existed (N40).

## Out of scope (🔮 Planned — not built)

`did:via` agents; multi-`scope[]` + `appliesTo`; `history`/`now`/velocity CEL; `authorizationPolicy`; suspension/resume; broad receipt taxonomy; external (non-Humanos) issuers.

## Testing

Unit tests per module; round-trip tests (build → sign → verify); W3C conformance assertions (proof shape, contexts, status list, SD-JWT); and — for the optional `legacy` mode — byte-equality against platform test vectors.
