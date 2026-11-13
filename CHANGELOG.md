# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org/).

## [0.4.7] - 2026-11-13
- README: Examples section.

## [0.4.6] - 2026-11-12
- The `FORCE` prefix gives no hint in refusals and never skips your own deny rules.

## [0.4.5] - 2026-11-12
- Also watches the context-mode fetch tool and the Scrapling MCP.
- Hosts read with the URL parser, every URL in a command segment checked; more ways to run commands (`find -exec`, `awk system()`, `git -c`, `gh api`) checked by deny rules.
- `WEB_UNLOCK_FORCE=1` counts only as a command's env prefix; a 401, or a 403 with a JSON API answer, is not a strike.

## [0.4.4] - 2026-11-11
- Points to the catalog repo's new name, `lucas-tools`.

## [0.4.3] - 2026-11-11
- Catalog renamed to `lucas-tools`.

## [0.4.2] - 2026-11-09
- Docs: one-line description, catalog install, heading names.

## [0.4.1] - 2026-11-09
- The detector recognises the Cloudflare verification page when it comes back through r.jina.ai.

## [0.4.0] - 2026-11-08
- Your own rules file, created on first run at `~/.config/web-unlock-guard/rules.json`.
- Finds the web-unlock plugin and your registry of sites, and lays your `sites.json` over the bundled one.
- Rules apply per command segment.

## [0.3.1] - 2026-11-08
- Windows: retry file reads and renames that collide.
- CI runs the tests on Linux, macOS and Windows; README rewritten.

## [0.3.0] - 2026-11-08
- Fixes for block attribution and false positives found in review.

## [0.2.0] - 2026-11-08
- Fixes for strike-tracking gaps found in review.

## [0.1.0] - 2026-11-08
- First release: hooks that stop retrying a blocked site with the same method.
