import { defineConfig } from "tsup";

export default defineConfig({
  // `action/cel` ships as its own entry so browsers can import the CEL generator without
  // evaluating the barrel, which pulls `node:crypto` in via `crypto/ed25519.ts`. The module
  // is pure (one type-only import), so this entry stays crypto-free.
  // `agent/sim` is the third entry for the same reason as `action/cel`: it must NOT be reachable
  // from the barrel. It pulls in `@peculiar/x509`, and `noExternal` below bundles everything —
  // from index.ts that X.509 stack would land in the dist every consumer ships, for a dev utility.
  entry: ["src/index.ts", "src/action/cel.ts", "src/agent/sim.ts"],
  format: ["esm", "cjs"],
  // tsup 8 injects `baseUrl` into declaration compilation, which TypeScript 6 reports as
  // TS5101 (deprecated, gone in 7). Scope the allowance to THIS builder rather than the
  // tsconfig, so the deprecation stays visible everywhere else. Ported from the platform's
  // dev line, which hit it first — and it belongs here because `sync-via-sdk` copies this
  // file wholesale, so a fix that lives only in the vendored copy dies on the next sync.
  dts: { compilerOptions: { ignoreDeprecations: "6.0" } },
  clean: true,
  sourcemap: true,
  target: "es2022",
  // Bundle ALL runtime deps so the dist is fully self-contained CJS — no consumer
  // ever loads raw ESM from node_modules. `canonicalize` has no CJS-resolvable
  // `exports`, and `@marcbachmann/cel-js` / `jose` / `@sd-jwt/*` are ESM-only, which
  // Jest (CommonJS, transformIgnorePatterns skips node_modules) cannot parse. Bundling
  // them in makes the platform's Jest specs + SWC build + Node all load it cleanly.
  noExternal: [/.*/],
});
