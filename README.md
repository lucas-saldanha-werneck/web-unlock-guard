# web-unlock-guard

A Claude Code plugin that stops Claude from retrying a blocked website the same way. After 2
blocked results on one host with one method, the next try with that method is denied and Claude
is told what to try instead.

When a site answers with a Cloudflare challenge, a 403 or a captcha, Claude tends to retry the
same request with small changes: another user agent, another flag, the same headless browser
again. A rule in `CLAUDE.md` or a skill doesn't reliably stop that. A hook does, because it runs
outside the model on every tool call.

## What Claude sees

After the second blocked `curl` to the same host, the hook adds this to the tool result:

```
web-unlock-guard: BLOCKED cloudflare-js-challenge (cloudflare) on blocked.example.com via "http",
strike 2/2. Limit reached: the next try with this method will be denied. Switch to a rendering
fetcher (e.g. r.jina.ai or Firecrawl) or a stealth fetcher.
```

If Claude then tries `wget` on the same host, the call is denied and Claude gets:

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

It needs `node` on `PATH` (tested with Node 26). The hooks run on `Bash`, `WebFetch`, and
context-mode's `ctx_execute`, `ctx_execute_file` and `ctx_batch_execute` tools.

## Configuration

Everything is optional. Set the options with `/plugin configure web-unlock-guard@web-unlock-guard`,
or use the environment variables.

| Option | Env var | Default | Meaning |
|---|---|---|---|
| `max_strikes` | `WEB_UNLOCK_GUARD_MAX_STRIKES` | `2` | Blocks on one host and method before that method is denied. |
| `sites_file` | `WEB_UNLOCK_GUARD_SITES` | empty: `~/.config/web-unlock/sites.json` (or `$WEB_UNLOCK_HOME/sites.json`) | Your JSON registry of known hosts (see below). It is laid over the companion skill's bundled `sites.json`, the same way the web-unlock skill reads it: bundled hosts first, then yours; a host in both is your entry, whole. |
| `skill_dir` | `WEB_UNLOCK_GUARD_SKILL_DIR` | empty: `skills/web-unlock` in `$CLAUDE_CONFIG_DIR` or `~/.claude`, else the installed web-unlock plugin | Your own companion skill folder (see Optional extras). |
| `rules_file` | `WEB_UNLOCK_GUARD_RULES` | empty: `~/.config/web-unlock-guard/rules.json` (created on first run) | Your own deny rules and extra tool names (see below). |
| | `WEB_UNLOCK_GUARD_STATE` | `$CLAUDE_PLUGIN_DATA/web-unlock-guard.json`, or `state/web-unlock-guard.json` under `$CLAUDE_CONFIG_DIR` (else `~/.claude`) when that variable isn't set | Strike counter file. A session idle for 24 hours is ignored and dropped. Hooks running in parallel take turns through a `.lock` file next to it. |

Option values live in your `settings.json` (`pluginConfigs`), and the files they point to live in your own
folders, so a plugin update changes neither. Keep your registry and rules file outside the plugin folder.

### Your settings

Your rules file is `~/.config/web-unlock-guard/rules.json` (or the path in `rules_file` /
`WEB_UNLOCK_GUARD_RULES`). The plugin creates it by itself the first time it runs (at session start, or on
the first tool call), from [`hooks/rules.default.json`](hooks/rules.default.json): empty `webish` and `deny`
lists with a short note on each, which behave exactly like having no file. Plugin updates never touch it, and
the plugin never overwrites or changes a rules file that is already there.

### Your own rules file

Rules that only make sense on your machine go in a JSON file instead of a fork of the hook. From
[`examples/rules.example.json`](examples/rules.example.json), which keeps an automation Chrome from stealing
focus:

```json
{
  "webish": [
    {
      "word": "mcporter",
      "layer": "fetch-render"
    },
    "my-scraper-cli"
  ],
  "deny": [
    {
      "name": "no-json-new",
      "pattern": "/json/new\\b",
      "message": "Opening a tab with /json/new brings the automation Chrome to the front. Use {skill_dir}/bin/chrome-real.sh start \"<url>\"."
    },
    {
      "name": "automation-chrome-stays-behind",
      "pattern": "Google Chrome Beta\\\\?\"?\\s*(to\\s+)?activate|activate\\s+application\\s+\\\\?\"Google Chrome Beta|\\bopen\\s+(-[a-zA-Z]+\\s+)*-a\\s+\\\\?[\"\\']?(\\/Applications\\/)?Google Chrome Beta|\\bopen\\s+(-[a-zA-Z]+\\s+)*-b\\s+com\\.google\\.Chrome\\.beta",
      "unless": "\\bopen\\b.*\\s-[a-zA-Z]*g[a-zA-Z]*(\\s|$)",
      "message": "Do not bring the automation Chrome to the front by hand."
    }
  ]
}
```

- `deny`: each rule denies a `PreToolUse` call when one command segment matches `pattern` (a JavaScript
  regular expression) and that same segment does not match `unless`. Segments are split at `;`, `&&`, `||`,
  `|` and new lines (and are the entries of a `ctx_batch_execute` call), so `open -g x; osascript ...` is
  checked as two commands. Optional `flags` (for example `"i"`) apply to both, and `tools` (a regular
  expression on the tool name, such as `"^Bash$"`) limits the rule to some tools. These rules run before the
  built-in ones and on any command the hook sees, web or not.
- Segments whose program only reads, searches or prints text are never denied: `grep`, `egrep`, `fgrep`,
  `rg`, `ag`, `ack`, `git`, `gh`, `echo`, `printf`, `cat`, `less`, `more`, `head`, `tail`, `wc`, `sort`,
  `uniq`, `cut`, `tr`, `sed`, `awk`, `jq`, `diff`, `ls`, `find`, `man`. So `grep -rn '/json/new' .` or a commit
  message that names the pattern passes. In every other program the pattern is matched against the whole
  segment, quoted arguments included: an `osascript -e '...'` or `python -c "..."` that contains it is denied,
  as is a script whose only mention of it is a comment. The split is plain text, so a `;` inside quotes
  also splits. `{skill_dir}` in the message becomes
  the companion skill folder. The message ends with the `WEB_UNLOCK_FORCE=1` hint, and that prefix skips these
  rules too.
- `webish`: extra tool names that make a command count as web work. Each matches as a whole word (`mcp` does
  not match inside `mcporter`). A plain word only lets such commands reach the built-in checks; with a `layer`
  (`http`, `fetch-render`, `fetch-unlock`, `browser-automation`, `browser-cft`, `browser-stealth`,
  `browser-real` or `browser-cloud`), blocked results of that tool count strikes under that method, so R4
  applies to it. An entry with any other layer is ignored, with a warning on the hook's stderr.
- A rule with an invalid regular expression is skipped and the others still apply. A missing or unreadable
  file means no extra rules.

### Sites registry

A registry tells the hooks which hosts are behind Cloudflare and which route already worked, so
Claude goes there instead of finding it again. From
[`examples/sites.example.json`](examples/sites.example.json):

```json
{
  "hosts": {
    "example-shop.com": {
      "tags": ["cloudflare", "logged"],
      "route": "browser-real",
      "how": "agent-browser --auto-connect on your own Chrome profile"
    },
    "shop.example-shop.com": { "alias_of": "example-shop.com" },
    "*.example-jobs.io": {
      "tags": ["antibot"],
      "route": "fetch-unlock",
      "how": "the site's public JSON API at /api/jobs"
    }
  }
}
```

A host matches its own key, its parent domains, and `*.domain` keys (subdomains only). A leading
`www.` is ignored. The `route` and `how` are added to the R1, R3 and R4 messages and to the
strike messages for that host.

## Optional extras

None of these are needed. Without them, all four rules work with the bundled detector and no
registry.

- **A companion skill folder of your own.** Point `skill_dir` at it. If `skill_dir` is empty, the hooks
  use `skills/web-unlock` in `$CLAUDE_CONFIG_DIR` or `~/.claude` (in that order) when it has a `SKILL.md`,
  else the skill of the [web-unlock](https://github.com/lucas-saldanha-werneck/web-unlock) plugin when it is
  installed, found through `plugins/installed_plugins.json` in the same folders, so it follows plugin
  updates. An install for the current project beats a user-scope install, installs for other projects are
  ignored, and among the rest the newest version wins. The companion is looked up only for web commands, or
  when a rule message uses `{skill_dir}`. The hooks look for three
  files in it:
  - `lib/detect.mjs`: replaces the bundled detector. It must export `detect`, `inferLayer` and
    `firstHost`, and may export `NEXT_LAYER`. If it fails to load or lacks an export, the bundled
    detector is used.
  - `sites.json`: the bundled registry. Your registry (`sites_file`, else
    `~/.config/web-unlock/sites.json`) is laid on top of it: same host = your entry wins.
  - `bin/chrome-real.sh`: suggested when a `browser-automation` or `browser-stealth` method is
    blocked.
- **Scrapling.** When the `scrapling` CLI is on `PATH`, it is suggested after an `http` or
  `fetch-render` block.
- **agent-browser, OpenCLI, Firecrawl, r.jina.ai, Apify** and similar tools are only recognized
  to tell methods apart. The plugin never calls them.

## How it works

A `PostToolUse` / `PostToolUseFailure` hook reads each web tool result for block signatures:
Cloudflare, DataDome, PerimeterX, Kasada, Imperva, Akamai, captcha widgets, LinkedIn's authwall,
HTTP 401/403/406/429/451/503 (including the `curl: (22)` line that `curl -f` prints), short
error pages and near-empty JavaScript shells. Captcha and Turnstile widget markers count only on
a thin page (under 600 visible characters of HTML, or under 2000 characters of plain text),
because ordinary pages embed them in forms. Each block counts a strike per session, host and
method. A tool call that succeeds with a clean result resets the count for that method. A failure
with no block signature, such as a DNS error or a timeout, leaves the count as it is.

The host is the first URL in each request. A call can hold several requests: shell commands
joined by `;`, `&&`, `||`, `|` or new lines, or the entries of a `ctx_batch_execute` call.

- Through the r.jina.ai reader (`r.jina.ai/https://site.example/`), strikes count against the
  target site, so one blocked site doesn't use up the reader for every other site.
- A browser command with no URL (`agent-browser snapshot`, `eval`, `click`) counts against the
  host that the same session last opened with that method.
- When one call reaches several hosts, or one host with several methods, its output can't be
  tied to one of them. No strike is counted and no count is reset for that call. The rules
  below still check every host in it before it runs.

A `PreToolUse` hook first applies the deny rules from your rules file, if any, then four rules to every
host and method in the call:

| Rule | What it denies |
|---|---|
| R4 | Any call with a method that already reached `max_strikes` blocks on that host. |
| R3 | Headless browsers (`--headless`, `headless: true`) against a Cloudflare host. |
| R1 | A default automation browser (`agent-browser` without `--auto-connect` or `--cdp`, plain Playwright, Puppeteer, Selenium) against a Cloudflare host. These set `navigator.webdriver=true` and loop on Turnstile. |
| R2 | `--remote-debugging-port` without `--user-data-dir`, on any host, because Chrome 136+ silently ignores the port on the default profile. Commands that contain `agent-browser` are exempt. |

A host counts as Cloudflare when it served a Cloudflare challenge earlier (remembered for 30
days) or when the sites registry tags it `cloudflare`.

The methods are `http` (curl, wget, httpx, requests, fetch, WebFetch), `fetch-render` (r.jina.ai,
Firecrawl, and WebFetch through r.jina.ai), `fetch-unlock` (Apify, Bright Data, ScraperAPI, ZenRows, Scrapfly),
`browser-automation`, `browser-stealth` (Patchright, Camoufox, nodriver, Scrapling),
`browser-real` (your own Chrome via `agent-browser --auto-connect`, `claude --chrome`, OpenCLI)
and `browser-cloud`. A WebFetch call is always `http` or `fetch-render`, whatever tool names
appear in its URL.

To skip every check for one call, put `WEB_UNLOCK_FORCE=1` in the command. The hooks fail open:
bad input or an internal error lets the tool call through.

## Tests

```
node tests/run.mjs
```

This feeds the sample hook JSON in [`tests/fixtures/`](tests/fixtures) to the hook, one file per
rule or case, with an empty temporary home folder. It also checks fail-open behavior, the companion
skill folder and plugin, the user registry, your rules file (deny rules, `unless`, `tools`, bad regexes,
extra web tool names, the option and the default path), the first-run rules file (created when missing,
an existing file byte-identical, overrides respected, no crash on a read-only folder, the seeded file
behaving like no file on every fixture), expiry of old entries, and parallel hooks writing the strike file at
once.

## Uninstall

```
/plugin uninstall web-unlock-guard@web-unlock-guard
/plugin marketplace remove web-unlock-guard
```

Uninstalling deletes the plugin data folder, which holds the strike file. If you ran the hook
outside the plugin system, delete `~/.claude/state/web-unlock-guard.json` yourself.

## Limits

- Tested on macOS with Claude Code 2.1.319 in the terminal. A real `claude -p` session confirmed
  the plugin loads and R2 denies the call with the message above. The strike rules (R4, R3) were
  tested with the sample hook input in `tests/`, not against a live blocked site.
- The test suite runs on Linux, macOS and Windows in GitHub Actions. The plugin was not tried in
  a live Claude Code session on Linux or Windows, or in the desktop app.
- Detection works on text patterns. A block page it doesn't know won't count as a strike, and a
  page that quotes a block signature can count as one.
- A batch or compound command with several hosts never adds strikes. Repeating a blocked request
  inside such a call is caught only when that host already has strikes from single-host calls.

## License

MIT

Built with Claude Code
