# Security Policy

## Reporting a vulnerability

Please report it privately: open the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/lucas-saldanha-werneck/web-unlock-guard/security/advisories/new). Please do not open a public issue for a
security problem.

## Supported versions

Only the latest release (0.4.7) is supported. Fixes go into a new release.

## What web-unlock-guard accesses

- Reads the tool call and result that Claude Code hands to its hooks (the Bash command, the URL or fetch input, the page text that came back), only to spot blocked pages and count strikes per host and method.
- Keeps those strike counts in the plugin data folder (or `~/.claude/state`), and reads or creates your rules file at `~/.config/web-unlock-guard/rules.json`. It also reads the `sites.json` of the web-unlock plugin, if you have it.
- Makes no network requests, starts no other programs and reads no secrets. The hooks use only Node's `fs`, `os`, `path` and `url` modules.
