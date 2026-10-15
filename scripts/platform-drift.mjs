#!/usr/bin/env node
/**
 * What the platform's copy of this SDK (`packages/via-sdk`) holds that sdk-v03 does not — run before
 * an sdk-v03 change, and before a release, so nothing the platform fixed in its copy is lost.
 *
 *   node scripts/platform-drift.mjs                      # origin/dev, origin/stage, origin/main
 *   node scripts/platform-drift.mjs origin/my-branch …   # those refs
 *   node scripts/platform-drift.mjs --all                # every remote branch with a sync.json
 *   PLATFORM=/path/to/agent-mandate-protocol node scripts/platform-drift.mjs
 *
 * The platform records each sync in `packages/via-sdk/sync.json` (the hash of every copied file) and
 * fails CI on an edit it does not record; an edit that had to land first is listed there as
 * `pendingUpstream`. So, per ref:
 *   - pending upstream — a recorded edit: bring it into sdk-v03;
 *   - edited, unrecorded — a file that matches neither the sync nor sdk-v03 (a branch CI did not gate);
 *   - not synced yet — the ref still has what the sync wrote, and sdk-v03 has moved on.
 * Exits 1 when a ref holds an edit to bring upstream. Fetches the platform's remote first (`--no-fetch`
 * skips it). Reads only: it changes neither checkout.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const sdk = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const platform = process.env.PLATFORM ?? resolve(sdk, "..", "agent-mandate-protocol");
const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const COPY = "packages/via-sdk";

const git = (...a) => execFileSync("git", ["-C", platform, ...a], { encoding: "utf8", maxBuffer: 1 << 26 });
const lf = (text) => text.replace(/\r\n/g, "\n");
const sha256 = (text) => createHash("sha256").update(lf(text)).digest("hex");
const blobId = (text) => {
  const body = Buffer.from(lf(text), "utf8");
  return createHash("sha1").update(`blob ${body.length}\0`).update(body).digest("hex");
};

if (!existsSync(join(platform, ".git"))) {
  console.error(`✗ No platform checkout at ${platform}; set PLATFORM.`);
  process.exit(2);
}
if (!flags.has("--no-fetch")) git("fetch", "--quiet", "origin");

// sdk-v03's copied files (what the sync copies: src/** and tsup.config.ts), by path.
const ours = new Map(
  [join(sdk, "tsup.config.ts"), ..._walk(join(sdk, "src"))].map((f) => {
    const text = readFileSync(f, "utf8");
    return [relative(sdk, f).split(sep).join("/"), { blob: blobId(text), sha: sha256(text) }];
  }),
);

const refs = flags.has("--all")
  ? git("for-each-ref", "--format=%(refname:short)", "refs/remotes/origin")
      .split("\n")
      .filter((r) => r && r !== "origin/HEAD" && r !== "origin" && _has(r, `${COPY}/sync.json`))
  : args.filter((a) => !a.startsWith("--")).length
    ? args.filter((a) => !a.startsWith("--"))
    : ["origin/dev", "origin/stage", "origin/main"];

if (!refs.length) console.log("No remote branch has a packages/via-sdk/sync.json yet.");
let toBringUp = 0;
for (const ref of refs) {
  if (!_has(ref, `${COPY}/src/index.ts`)) {
    console.log(`${ref} — no ${COPY} here`);
    continue;
  }
  const manifest = _has(ref, `${COPY}/sync.json`) ? JSON.parse(git("show", `${ref}:${COPY}/sync.json`)) : null;
  // The ref's copied files, by path, from one tree listing.
  const theirs = new Map(
    git("ls-tree", "-r", ref, "--", `${COPY}/src`, `${COPY}/tsup.config.ts`)
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [meta, path] = line.split("\t");
        return [path.slice(COPY.length + 1), meta.split(" ")[2]];
      }),
  );
  const pending = new Set((manifest?.pendingUpstream ?? []).flatMap((p) => p.files));
  const behind = [];
  const unrecorded = [];
  for (const path of [...new Set([...ours.keys(), ...theirs.keys()])].sort()) {
    const blob = theirs.get(path);
    if (blob === ours.get(path)?.blob || pending.has(path)) continue;
    const recorded = manifest?.files[path];
    const sha = blob ? sha256(git("show", `${ref}:${COPY}/${path}`)) : undefined;
    // Still what the sync wrote (or, with no sync.json, a file sdk-v03 changed since): sdk-v03 moved on.
    if (manifest ? sha === recorded : true) behind.push(path);
    else unrecorded.push(`${path} (${!blob ? "removed" : recorded ? "changed" : "added"})`);
  }

  const synced = manifest
    ? `synced from ${manifest.source} ${manifest.version} (${manifest.commit?.slice(0, 9) ?? "no commit"})`
    : "no sync.json (synced before 2026-10-15): a hand edit there cannot be told from an sdk-v03 change";
  console.log(`${ref} — ${synced}`);
  for (const p of manifest?.pendingUpstream ?? []) {
    console.log(`  ⇧ pending upstream since ${p.at} — ${p.reason}: ${p.files.join(", ")}`);
  }
  if (unrecorded.length) console.log(`  ⇧ edited, unrecorded: ${unrecorded.join(", ")}`);
  if (behind.length) {
    console.log(`  · ${manifest ? "not synced yet" : "differs from sdk-v03"}: ${behind.join(", ")}`);
  }
  if (!manifest?.pendingUpstream?.length && !unrecorded.length && !behind.length) console.log("  ✓ same as sdk-v03");
  toBringUp += (manifest?.pendingUpstream?.length ?? 0) + unrecorded.length;
}
process.exit(toBringUp ? 1 : 0);

function _has(ref, path) {
  try {
    execFileSync("git", ["-C", platform, "cat-file", "-e", `${ref}:${path}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function _walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? _walk(join(dir, e.name)) : [join(dir, e.name)],
  );
}
