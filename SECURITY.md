# Security Policy

## Reporting a vulnerability

Please report it privately: open the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/lucas-saldanha-werneck/web-unlock-guard/security/advisories/new). Please do not open a public issue for a
security problem.

## Supported versions

Only the latest release is supported. Fixes go into a new release.

## What web-unlock-guard accesses

- Reads the tool call and result that Claude Code hands to its hooks (the Bash command, the URL or fetch input, the page text that came back) to deny known-bad retries and count blocks per host and method.
- Writes its state file (session ids, hosts, block counts, and hosts that served a Cloudflare challenge, kept up to 30 days) to the plugin data folder, else `~/.claude/state/web-unlock-guard.json`. Creates your rules file `~/.config/web-unlock-guard/rules.json` on first run if it is missing.
- Reads `~/.claude/plugins/installed_plugins.json` to find the web-unlock skill, and that skill's `sites.json` plus `~/.config/web-unlock/sites.json`.
- If the web-unlock skill folder (`skill_dir`, `~/.claude/skills/web-unlock`, or the installed web-unlock plugin) has `lib/detect.mjs`, the hook loads and runs that file inside its own process instead of its bundled detector. Point `skill_dir` only at code you trust.
- Makes no network requests, starts no other programs and reads no secrets. Its own code uses only Node's `fs`, `os`, `path` and `url` modules.
