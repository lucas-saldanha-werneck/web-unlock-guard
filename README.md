# web-unlock-guard

A Claude Code plugin with hooks that stop Claude from hammering a blocked website with the same
method. After 2 blocked results on one host and method, the next try with that method is denied
and Claude is told what to switch to.

## Why

When a site answers with a Cloudflare challenge, a 403 or a captcha, Claude tends to retry the
same request with small changes: another user agent, another flag, the same headless browser
again. A rule written in `CLAUDE.md` or a skill doesn't reliably stop that. A hook does, because
it runs outside the model on every tool call.

## Rules

| Rule | Hook | What it does |
|---|---|---|
| R4 | Pre + Post | Reads every web tool result for block signatures (Cloudflare, DataDome, PerimeterX, Kasada, Imperva, Akamai, captcha widgets, 401/403/429/503, empty JS shells). Counts a strike per session, host and method. At 2 strikes, the next call with that method on that host is denied. A clean result resets the count. |
| R3 | Pre | Denies headless browsers (`--headless`, `headless: true`) against a Cloudflare host. |
| R1 | Pre | Denies a default automation browser (`agent-browser` without `--auto-connect`/`--cdp`, plain Playwright, Puppeteer, Selenium) against a Cloudflare host. They set `navigator.webdriver=true` and loop on Turnstile. |
| R2 | Pre | Denies `--remote-debugging-port` without `--user-data-dir`. Chrome 136+ ignores the port on the default profile, silently. |

A host counts as "Cloudflare" when it served a Cloudflare challenge earlier (remembered for 30
days), or when the optional sites registry tags it `cloudflare`.

Methods are: `http` (curl, wget, fetch, WebFetch), `fetch-render` (r.jina.ai, Firecrawl),
`fetch-unlock` (Apify, Bright Data, ScraperAPI...), `browser-automation`, `browser-stealth`,
`browser-real` (your own Chrome via `--auto-connect`, `claude --chrome`, OpenCLI) and
`browser-cloud`.

To insist anyway, put `WEB_UNLOCK_FORCE=1` in the command. The hooks fail open: any internal
error lets the tool call through.

## What Claude sees

After the second blocked `curl`:

```
web-unlock-guard: BLOCKED cloudflare-js-challenge (cloudflare) on blocked.example.com via "http",
strike 2/2. Limit reached: the next try with this method will be denied. Switch to a rendering
fetcher (e.g. r.jina.ai or Firecrawl) or a stealth fetcher.
```

Then, on a third `wget` to the same host:

```
PreToolUse:Bash hook error: web-unlock-guard R4: 2 blocks on blocked.example.com via "http"
(cloudflare-js-challenge). Rule: 2 failures on the same method = stop retrying. Switch to a
rendering fetcher (e.g. r.jina.ai or Firecrawl) or a stealth fetcher, or ask the user.
To insist anyway, prefix the command with WEB_UNLOCK_FORCE=1.
```

## Install

```
/plugin marketplace add lucas-saldanha-werneck/web-unlock-guard
/plugin install web-unlock-guard@web-unlock-guard
```

Requires `node` (18+) on `PATH`. The hooks run on `Bash`, `WebFetch` and context-mode's
`ctx_execute` / `ctx_batch_execute` tools.

## Configuration

All optional. Set them in the plugin's options, or as environment variables.

| Option | Env var | Default | Meaning |
|---|---|---|---|
| `max_strikes` | `WEB_UNLOCK_GUARD_MAX_STRIKES` | `2` | Blocks before a method is denied for a host. |
| `sites_file` | `WEB_UNLOCK_GUARD_SITES` | empty | JSON registry of known hosts (see below). |
| `skill_dir` | `WEB_UNLOCK_GUARD_SKILL_DIR` | empty | Companion skill folder (see Optional requirements). |
| | `WEB_UNLOCK_GUARD_STATE` | `$CLAUDE_PLUGIN_DATA/web-unlock-guard.json`, else `~/.claude/state/web-unlock-guard.json` | Strike counter file. Session entries expire after 24 h. |

### Sites registry

A registry tells the hooks which hosts are behind Cloudflare and which route already worked, so
Claude goes there instead of rediscovering it. See
[`examples/sites.example.json`](examples/sites.example.json):

```json
{
  "hosts": {
    "example-shop.com": {
      "tags": ["cloudflare"],
      "route": "browser-real",
      "how": "agent-browser --auto-connect on your own Chrome profile"
    },
    "shop.example-shop.com": { "alias_of": "example-shop.com" },
    "*.example-jobs.io": { "tags": ["antibot"], "route": "fetch-unlock", "how": "the site's JSON API" }
  }
}
```

A host matches itself, its parent domains and `*.domain` keys. The `route` and `how` are added to
every message about that host.

## Optional requirements

None of these are needed. Without them, all four rules work with the bundled detector and no
registry.

- **A companion web-access skill** (your own, for example one named `web-unlock`). If
  `skill_dir` is set, or `~/.claude/skills/web-unlock/SKILL.md` exists, the hooks use its
  `lib/detect.mjs` (exports `detect`, `inferLayer`, `firstHost`, optional `NEXT_LAYER`) instead
  of the bundled one, and its `sites.json` as the registry when `sites_file` is empty. If its
  detector fails to load, the bundled one is used. If it has `bin/chrome-real.sh`, that script
  is suggested when a browser method is blocked.
- **Scrapling** (`scrapling` CLI). When it's on `PATH`, it's suggested as the next step after
  `http` or `fetch-render` blocks.
- **agent-browser, OpenCLI, Firecrawl, r.jina.ai, Apify** and similar tools are only recognized
  to tell methods apart. Nothing calls them.

## Tests

```
node tests/run.mjs
```

Feeds the sample hook JSON in [`tests/fixtures/`](tests/fixtures) to the hook, one file per rule,
with an empty temporary `HOME`, plus fail-open and companion-skill checks.

## Uninstall

```
/plugin uninstall web-unlock-guard@web-unlock-guard
/plugin marketplace remove web-unlock-guard
```

Then delete the strike file if you like (`~/.claude/state/web-unlock-guard.json` or the plugin
data folder).

## License

MIT. Built with Claude Code
