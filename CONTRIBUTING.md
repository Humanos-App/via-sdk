# Contributing

Notes for maintainers. Usage is in `README.md`.

## Before changing this SDK

Until the Humanos platform installs this package from npm, it holds a copy of `src/` in `packages/via-sdk`,
written by its `pnpm sync:via-sdk`. `npm run platform-drift` lists the edits made there that are not here yet, so
nothing the platform fixed in its copy is lost. Run it before changing this SDK and before a release, and bring what
it lists in first.

## Branches

A fix to v0.3 code lands on `main` first and is merged into `v04`; `git log v04..main` lists what `v04` lacks.
`v04`'s `package.json` sets `publishConfig.tag` to `next`, so nothing published from it reaches `latest`.

## Releasing

1. Bump `version` in `package.json` in a PR (`npm version <new> --no-git-tag-version`). The release workflow does
   not commit the version, so this keeps the repository in step with npm.
2. On GitHub, create a release with a new tag `v<version>` targeting `main` (or `v04`, with a `1.0.0-v04.N`
   version), and publish it.
3. The `release` workflow runs CI (typecheck and tests), sets the version from the tag and publishes to npm with the
   repository's `NPM_TOKEN` secret. It publishes nothing when CI fails. A push or a tag alone publishes nothing.

The README's header image is `assets/via-blueprint.svg`, shipped in the package and loaded from jsDelivr, so a change
to it shows on npm and GitHub only after the next release.
