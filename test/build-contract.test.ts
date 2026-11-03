/**
 * Build-output contract — guards the platform's integration surface.
 *
 * The platform (`apps/api`, `shared-backend`, CommonJS) `require()`s the BUILT dual-format
 * package: `@humanos-ai/via-sdk/compat` (Phase 0) and `@humanos-ai/via-sdk` (Phase 1). The other
 * suites import `src`, so a tsup-config regression (dropping the CJS format, the `compat`
 * entry, the `exports` map, or un-bundling `canonicalize`) would pass them yet break the
 * platform silently. This fails first.
 *
 * Runs after a build — `npm test` builds via the `pretest` hook. Skipped if `dist/` is absent
 * (e.g. `vitest` watch with no prior build).
 */
import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const compatCjs = fileURLToPath(new URL("../dist/compat/legacy.cjs", import.meta.url));
const compatEsm = new URL("../dist/compat/legacy.js", import.meta.url);
const indexCjs = fileURLToPath(new URL("../dist/index.cjs", import.meta.url));
const built = existsSync(compatCjs) && existsSync(indexCjs);

const COMPAT_FNS = [
  "canonicalizeJSON",
  "signWithEd25519Multibase",
  "encodePublicKeyMultibase",
  "generateChallenge",
  "generateDIDKey",
];

describe.skipIf(!built)("built dual-format /compat contract", () => {
  it("CJS require('@humanos-ai/via-sdk/compat') exposes the 5 platform fns + is self-contained", () => {
    const c = require(compatCjs); // throws if a bundled dep (e.g. canonicalize) isn't inlined
    for (const fn of COMPAT_FNS) expect(typeof c[fn]).toBe("function");
    expect(c.canonicalizeJSON({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
    expect(c.signWithEd25519Multibase("hello", new Uint8Array(32).fill(7)).startsWith("z")).toBe(true);
  });

  it("ESM import of the /compat entry resolves with the same surface", async () => {
    const esm = (await import(compatEsm.href)) as Record<string, unknown>;
    for (const fn of COMPAT_FNS) expect(typeof esm[fn]).toBe("function");
    expect((esm.canonicalizeJSON as (o: unknown) => string)({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it("CJS require of the full index loads (heavy deps resolve under CommonJS — Phase 1)", () => {
    const idx = require(indexCjs);
    for (const fn of ["verifyAny", "generateViaDID", "evaluateRules", "validateExecutionParams"]) {
      expect(typeof idx[fn]).toBe("function");
    }
  });
});
