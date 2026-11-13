# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org/).

## [0.4.7] - 2026-11-13
- README: Examples section.

## [0.4.6] - 2026-11-12
- The `FORCE` prefix gives no hint in refusals and never skips your own deny rules.

## [0.4.5] - 2026-11-12
- Audit fixes: MCP fetch tools, `FORCE` prefix, host and method parsing, the strike lock, API auth answers.

## [0.4.4] - 2026-11-11
- Maintenance (catalog renamed to `lucas-tools`).

## [0.4.3] - 2026-11-11
- Maintenance (catalog renamed to `lucas-tools`).

## [0.4.2] - 2026-11-09
- Maintenance (shorter description, catalog install instructions).

## [0.4.1] - 2026-11-09
- The detector recognises the Cloudflare verification page when it comes back through r.jina.ai.

## [0.4.0] - 2026-11-08
- Your own rules file, created on first run at `~/.config/web-unlock-guard/rules.json`.
- Finds the web-unlock plugin and your registry of sites, and lays your `sites.json` over the bundled one.
- Rules apply per command segment.

## [0.3.1] - 2026-11-08
- Windows: retry file reads and renames that collide.

## [0.3.0] - 2026-11-08
- Fixes for block attribution and false positives found in review.

## [0.2.0] - 2026-11-08
- Fixes for strike-tracking gaps found in review.

## [0.1.0] - 2026-11-08
- First release: hooks that stop retrying a blocked site with the same method.
