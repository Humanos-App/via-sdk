import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/compat/legacy.ts"],
  format: ["esm", "cjs"],
  dts: true,
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
