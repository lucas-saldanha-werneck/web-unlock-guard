#!/usr/bin/env node
// web-unlock-guard: PreToolUse / PostToolUse / PostToolUseFailure hook.
// Enforces web-scraping rules deterministically, because rules written as prose do not stop
// an agent from retrying the same blocked request over and over.
//
//   Pre  R1: deny a default automation browser (webdriver=true) against a Cloudflare host.
//   Pre  R2: deny --remote-debugging-port without --user-data-dir (recent Chrome ignores it).
//   Pre  R3: deny headless browsers against a Cloudflare host.
//   Pre  R4: deny the next try on the same host + method after N blocks (default 2): switch method.
//   Pre  your own deny rules, from a rules file (rules_file option, else ~/.config/web-unlock-guard/rules.json).
//   Every host in a compound command or batch is checked before it runs.
//   Post   : detect a block signature in the tool output, count a strike per host + method,
//            and remember hosts that served a Cloudflare challenge. A call that reaches several
//            hosts or methods counts nothing, because its output cannot be tied to one of them.
//
// Fails open: any internal error exits 0 with no output. Put WEB_UNLOCK_FORCE=1 in the command
// to skip every check for that call.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOME = os.homedir();
const BASE_WEBISH = /agent-browser|opencli|yt-dlp|curl\s|wget\s|firecrawl|apify|jina\.ai|remote-debugging|connectOverCDP|playwright|puppeteer|selenium|patchright|camoufox|nodriver|scrapling|--headless|https?:\/\//i;
const FORCE = /WEB_(UNLOCK|ACCESS)_FORCE=1/;
const DAY = 24 * 3600 * 1000;

// Plugin options arrive as CLAUDE_PLUGIN_OPTION_<KEY>; plain env vars work for manual installs.
function setting(...names) {
  for (const n of names) { const v = (process.env[n] || '').trim(); if (v) return v; }
  return '';
}
const expand = p => (p ? p.replace(/^~(?=$|[\\/])/, HOME).replace(/\$HOME|\$\{HOME\}/g, HOME) : p);

// Claude's config folders, most specific first: $CLAUDE_CONFIG_DIR, then ~/.claude.
function claudeDirs() {
  const dirs = [expand(setting('CLAUDE_CONFIG_DIR')), path.join(HOME, '.claude')].filter(Boolean).map(d => path.resolve(d));
  return [...new Set(dirs)];
}

// "0.10.0" > "0.9.2"; anything that is not a version sorts first.
function cmpVersion(a, b) {
  const pa = String(a || '').split(/[.+-]/).map(n => parseInt(n, 10) || 0), pb = String(b || '').split(/[.+-]/).map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; }
  return 0;
}
const inside = (dir, root) => { const r = path.relative(path.resolve(root), path.resolve(dir)); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };

// The companion web-unlock skill, when skill_dir is empty: a personal copy in <claude dir>/skills/web-unlock,
// else the web-unlock plugin's skill folder from installed_plugins.json. Among plugin installs, one for the
// current project (projectPath contains cwd) beats a user-scope one; installs for other projects are ignored;
// within a rank the newest version wins.
function findCompanion(cwd) {
  const dirs = claudeDirs();
  for (const d of dirs) {
    const personal = path.join(d, 'skills', 'web-unlock');
    if (fs.existsSync(path.join(personal, 'SKILL.md'))) return personal;
  }
  const found = [];
  for (const d of dirs) {
    const installed = loadJSON(path.join(d, 'plugins', 'installed_plugins.json'));
    const plugins = (installed && installed.plugins) || {};
    for (const [id, entries] of Object.entries(plugins)) {
      if (!id.startsWith('web-unlock@')) continue;
      for (const e of [].concat(entries || [])) {
        if (!e || !e.installPath) continue;
        let rank;
        if (e.projectPath) { if (!cwd || !inside(cwd, e.projectPath)) continue; rank = 2; }
        else if (!e.scope || e.scope === 'user') rank = 1;
        else continue;
        const dir = path.join(e.installPath, 'skills', 'web-unlock');
        if (fs.existsSync(path.join(dir, 'SKILL.md'))) found.push({ dir, rank, version: e.version, updated: e.lastUpdated || '' });
      }
    }
  }
  found.sort((a, b) => b.rank - a.rank || cmpVersion(b.version, a.version) || String(b.updated).localeCompare(String(a.updated)));
  return found.length ? found[0].dir : '';
}

// Cheap part of the settings: paths only, read before anything else.
function rulesPath() {
  return expand(setting('CLAUDE_PLUGIN_OPTION_RULES_FILE', 'WEB_UNLOCK_GUARD_RULES')) || path.join(HOME, '.config', 'web-unlock-guard', 'rules.json');
}

// The rest, resolved only for web commands (or when a rule message needs {skill_dir}).
// Explicit settings beat defaults: sites_file, then an explicitly set skill_dir's sites.json, then the
// web-unlock user folder's sites.json, then the sites.json of a companion found on its own.
function config(cwd) {
  const max = parseInt(setting('CLAUDE_PLUGIN_OPTION_MAX_STRIKES', 'WEB_UNLOCK_GUARD_MAX_STRIKES'), 10);
  const explicitSkill = expand(setting('CLAUDE_PLUGIN_OPTION_SKILL_DIR', 'WEB_UNLOCK_GUARD_SKILL_DIR'));
  let skillDir = explicitSkill || findCompanion(cwd);
  if (skillDir && !fs.existsSync(skillDir)) skillDir = '';
  const skillSites = skillDir && path.join(skillDir, 'sites.json');
  const userSites = path.join(expand(setting('WEB_UNLOCK_HOME')) || path.join(HOME, '.config', 'web-unlock'), 'sites.json');
  let sitesFile = expand(setting('CLAUDE_PLUGIN_OPTION_SITES_FILE', 'WEB_UNLOCK_GUARD_SITES'));
  if (!sitesFile && explicitSkill && skillSites && fs.existsSync(skillSites)) sitesFile = skillSites;
  if (!sitesFile && fs.existsSync(userSites)) sitesFile = userSites;
  if (!sitesFile && skillSites && fs.existsSync(skillSites)) sitesFile = skillSites;
  const dataDir = process.env.CLAUDE_PLUGIN_DATA || path.join(claudeDirs()[0], 'state');
  const stateFile = expand(setting('WEB_UNLOCK_GUARD_STATE')) || path.join(dataDir, 'web-unlock-guard.json');
  return { maxStrikes: max > 0 ? max : 2, skillDir, sitesFile, stateFile };
}

// Your own rules file: { "webish": ["word", ...], "deny": [{ "name", "pattern", "flags", "unless", "tools", "message" }] }.
// "webish" adds tool names that make a command count as web work: a literal word, or
// { "word": "...", "layer": "http|fetch-render|..." } so its blocks count strikes under that method
// (a plain word only lets the call through to the other checks; it has no method of its own).
// Each deny rule blocks a PreToolUse call whose command matches "pattern" (a JavaScript regex) and not
// "unless", tested on each command segment separately (split at ; && || | and new lines); "tools" (a regex on
// the tool name) limits which tools it applies to. Segments whose program only reads or prints text (grep, git,
// echo, sed, ... see TEXT_ONLY) are not checked, so searching for a pattern or a commit message that names
// it is not denied. "{skill_dir}" in the message becomes the companion skill folder. A rule with a bad regex
// is skipped; the others still apply.
const LAYERS = new Set(['http', 'fetch-render', 'fetch-unlock', 'browser-automation', 'browser-cft', 'browser-stealth', 'browser-real', 'browser-cloud']);
function loadRules(file) {
  const raw = file && fs.existsSync(file) ? loadJSON(file) : null;
  const rules = { webish: [], deny: [] };
  if (!raw || typeof raw !== 'object') return rules;
  const re = (src, flags) => { try { return src ? new RegExp(String(src), flags || '') : null; } catch (_) { return undefined; } };
  for (const w of Array.isArray(raw.webish) ? raw.webish : []) {
    const word = typeof w === 'string' ? w : (w && typeof w.word === 'string' ? w.word : '');
    if (!word.trim()) continue;
    const layer = (w && typeof w === 'object' && w.layer) || null;
    if (layer !== null && !LAYERS.has(layer)) {
      process.stderr.write(`web-unlock-guard: rules file ${file}: unknown layer "${layer}" for "${word}", entry ignored (use one of ${[...LAYERS].join(', ')})\n`);
      continue;
    }
    // A whole word: "mcp" does not match inside "mcporter".
    const src = '(?<![A-Za-z0-9_-])' + word.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![A-Za-z0-9_-])';
    rules.webish.push({ src, re: new RegExp(src, 'i'), layer });
  }
  for (const d of Array.isArray(raw.deny) ? raw.deny : []) {
    if (!d || typeof d !== 'object') continue;
    const pattern = re(d.pattern, d.flags), unless = re(d.unless, d.flags), tools = re(d.tools, 'i');
    if (!pattern || unless === undefined || tools === undefined) continue;
    rules.deny.push({ name: String(d.name || 'custom rule'), pattern, unless, tools, message: String(d.message || 'denied by your rules file') });
  }
  return rules;
}

function onPath(bin) {
  for (const d of (process.env.PATH || '').split(path.delimiter)) {
    if (d && fs.existsSync(path.join(d, bin))) return true;
  }
  return false;
}

// Optional companion skill: if it ships lib/detect.mjs, use its detector and layer map.
async function loadDetector(cfg) {
  const local = await import(pathToFileURL(path.join(HERE, 'detect.mjs')).href);
  if (cfg.skillDir) {
    const p = path.join(cfg.skillDir, 'lib', 'detect.mjs');
    if (fs.existsSync(p)) {
      try {
        const m = await import(pathToFileURL(p).href);
        if (typeof m.detect === 'function' && typeof m.inferLayer === 'function' && typeof m.firstHost === 'function') {
          return { detect: m.detect, inferLayer: m.inferLayer, firstHost: m.firstHost, NEXT_LAYER: { ...local.NEXT_LAYER, ...(m.NEXT_LAYER || {}) } };
        }
      } catch (_) { /* fall back to the bundled detector */ }
    }
  }
  return local;
}

// Next-method advice, with tools that are actually installed mentioned first.
function nextAdvice(layer, NEXT_LAYER, cfg) {
  let s = NEXT_LAYER[layer] || 'ask the user';
  if ((layer === 'http' || layer === 'fetch-render') && onPath('scrapling')) {
    s += '; installed here: scrapling (`scrapling extract fetch <url> <file> --solve-cloudflare`)';
  }
  const helper = cfg.skillDir && path.join(cfg.skillDir, 'bin', 'chrome-real.sh');
  if (/^browser-(automation|cft|stealth)$/.test(layer) && helper && fs.existsSync(helper)) {
    s += `; installed here: ${helper}`;
  }
  return s;
}

function cmdText(ti) {
  if (!ti) return '';
  if (typeof ti.command === 'string') return ti.command;
  if (typeof ti.code === 'string') return ti.code;
  if (typeof ti.url === 'string') return ti.url;
  if (Array.isArray(ti.commands)) return ti.commands.map(c => c && c.command).filter(Boolean).join('\n');
  return '';
}
// Split a call into its requests: batch entries, then lines, `;`, `&&`, `||` and `|`.
function segments(ti, cmd) {
  const parts = ti && Array.isArray(ti.commands) ? ti.commands.map(c => c && c.command).filter(c => typeof c === 'string') : [cmd];
  return parts.flatMap(p => p.split(/\n|;|&&|\|\|?/)).map(x => x.trim()).filter(Boolean);
}
function respText(tr) {
  if (tr == null) return '';
  if (typeof tr === 'string') return tr;
  if (Array.isArray(tr)) return tr.map(respText).join('\n');
  if (typeof tr === 'object') return Object.values(tr).map(v => (typeof v === 'string' ? v : (v && typeof v === 'object') ? respText(v) : '')).join('\n');
  return String(tr);
}

// On Windows, reading or replacing a file that another process is renaming at the same moment
// fails for a short time with EPERM, EACCES or EBUSY. Retry those for up to a second.
const TRANSIENT = new Set(['EPERM', 'EACCES', 'EBUSY']);
function retry(fn) {
  const until = Date.now() + 1000;
  for (;;) {
    try { return fn(); } catch (e) {
      if (!TRANSIENT.has(e.code) || Date.now() > until) throw e;
      sleep(5 + Math.random() * 10);
    }
  }
}
function loadJSON(f) { try { return JSON.parse(retry(() => fs.readFileSync(f, 'utf8'))); } catch (_) { return null; } }
// Drop sessions idle for 24 hours and Cloudflare marks older than 30 days. Runs on every load,
// so expired entries never reach a rule.
function prune(s) {
  if (!s || typeof s !== 'object') return {};
  const now = Date.now();
  for (const k of Object.keys(s)) if (k !== '_cloudflare' && s[k] && s[k]._updated && s[k]._updated < now - DAY) delete s[k];
  const cf = s._cloudflare || {};
  for (const h of Object.keys(cf)) if (cf[h] < now - 30 * DAY) delete cf[h];
  return s;
}
const loadState = file => prune(loadJSON(file));
const sleep = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
// Read-modify-write under a lock file, so parallel hooks don't overwrite each other's strikes.
// A lock older than 10 seconds is left over from a killed hook (hooks time out at 5) and is removed.
// If the lock can't be taken in 2 seconds, the update goes ahead without it (fail open).
// The file is written to a temporary name and renamed, so a reader never sees half a file.
function updateState(file, fn) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const lock = file + '.lock';
  const until = Date.now() + 2000;
  let fd = null;
  while (fd === null) {
    try { fd = fs.openSync(lock, 'wx'); } catch (e) {
      if (e.code !== 'EEXIST') break;
      try { if (Date.now() - fs.statSync(lock).mtimeMs > 10000) { fs.unlinkSync(lock); continue; } } catch (_) { continue; }
      if (Date.now() > until) break;
      sleep(10 + Math.random() * 20);
    }
  }
  try {
    const s = loadState(file);
    if (!fn(s)) return;
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(s, null, 1));
    try { retry(() => fs.renameSync(tmp, file)); } catch (e) { try { fs.unlinkSync(tmp); } catch (_) {} throw e; }
  } finally {
    if (fd !== null) { fs.closeSync(fd); try { fs.unlinkSync(lock); } catch (_) {} }
  }
}

// Reader proxies put the target URL in the path (r.jina.ai/https://site/...). Strikes belong to the target.
function targetHost(firstHost, s) {
  const h = firstHost(s);
  if (h !== 'r.jina.ai') return h;
  const m = /r\.jina\.ai\/+((?:https?:\/\/)?[a-z0-9.-]+\.[a-z]{2,}[^\s'"]*)/i.exec(String(s));
  if (!m) return h;
  return firstHost(/^https?:/i.test(m[1]) ? m[1] : 'https://' + m[1]) || h;
}

// Registry lookup: { "hosts": { "example.com": { tags, route, how, alias_of } } }.
// Matches the host, its parent domains, and "*.domain" keys.
function siteInfo(sites, host) {
  if (!host || !sites) return null;
  const hosts = sites.hosts && typeof sites.hosts === 'object' ? sites.hosts : sites;
  const parts = host.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const h = parts.slice(i).join('.');
    let e = hosts[h] || (i > 0 ? hosts['*.' + h] : null);
    if (e && e.alias_of) e = hosts[e.alias_of] || e;
    if (e && typeof e === 'object') return { host: h, ...e };
  }
  return null;
}

// Programs that only read, search or print text: a deny rule never fires on their segments.
const TEXT_ONLY = new Set(['grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'git', 'echo', 'printf', 'cat', 'less', 'more',
  'head', 'tail', 'wc', 'sort', 'uniq', 'cut', 'tr', 'sed', 'awk', 'jq', 'diff', 'ls', 'find', 'gh', 'man']);
// The program a segment runs: the first word after VAR=value, env, sudo, command, exec, nohup, time.
function program(seg) {
  const words = String(seg).trim().replace(/^[({\s]+/, '').split(/\s+/);
  let i = 0;
  while (i < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]) || /^(env|sudo|command|exec|nohup|time|-\S+)$/.test(words[i]))) i++;
  return path.basename(words[i] || '').replace(/^["']|["']$/g, '');
}

const out = o => process.stdout.write(JSON.stringify(o));
const deny = (ev, reason) => out({ hookSpecificOutput: { hookEventName: ev, permissionDecision: 'deny', permissionDecisionReason: reason } });
const FORCE_HINT = 'To insist anyway, prefix the command with WEB_UNLOCK_FORCE=1.';

async function main(hook) {
  const ev = hook.hook_event_name || '';
  const tool = hook.tool_name || '';
  const cmd = cmdText(hook.tool_input);
  const isFetch = /WebFetch/.test(tool);
  if (FORCE.test(cmd)) return;

  // Your rules file is the only thing read before the web check; without one, non-web calls stop here.
  const rules = loadRules(rulesPath());
  if (!rules.deny.length && !rules.webish.length && !BASE_WEBISH.test(cmd) && !isFetch) return;
  let cfg = null;
  const getCfg = () => (cfg = cfg || config(hook.cwd));
  // Your own deny rules run first and on any command, web or not, one segment at a time.
  if (ev === 'PreToolUse' && cmd && rules.deny.length) {
    const segs = isFetch ? [cmd] : segments(hook.tool_input, cmd);
    for (const r of rules.deny) {
      if (r.tools && !r.tools.test(tool)) continue;
      const seg = segs.find(sg => !TEXT_ONLY.has(program(sg)) && r.pattern.test(sg) && !(r.unless && r.unless.test(sg)));
      if (seg !== undefined) {
        const msg = r.message.includes('{skill_dir}') ? r.message.replaceAll('{skill_dir}', getCfg().skillDir || '<web-unlock skill folder>') : r.message;
        return deny(ev, `web-unlock-guard (${r.name}): ${msg} ${FORCE_HINT}`);
      }
    }
  }
  const WEBISH = rules.webish.length ? new RegExp(`${BASE_WEBISH.source}|${rules.webish.map(w => w.src).join('|')}`, 'i') : BASE_WEBISH;
  // The method of a request: the detector's, else the layer of a matching "webish" word from your rules.
  const layerOf = c => inferLayer(c) || (rules.webish.find(w => w.layer && w.re.test(c)) || {}).layer || null;
  if (!WEBISH.test(cmd) && !isFetch) return;
  getCfg();
  const { detect, inferLayer, NEXT_LAYER, firstHost } = await loadDetector(cfg);
  const sites = cfg.sitesFile ? loadJSON(cfg.sitesFile) : null;
  // WebFetch is the http method whatever words its URL contains; through r.jina.ai it is fetch-render.
  const fetchLayer = s => (/r\.jina\.ai/i.test(s) ? 'fetch-render' : 'http');
  const wholeLayer = isFetch ? fetchLayer(cmd) : layerOf(cmd);
  const state = loadState(cfg.stateFile);
  const sid = hook.session_id || 'nosession';
  const sess = state[sid] || {};
  // One target (host + method) per request in the call: each shell segment, line or batch entry.
  const targets = [];
  for (const seg of isFetch ? [cmd] : segments(hook.tool_input, cmd)) {
    const h = targetHost(firstHost, seg);
    if (!h) continue;
    const l = (isFetch ? wholeLayer : layerOf(seg)) || wholeLayer;
    if (!targets.some(t => t.host === h && t.layer === l)) targets.push({ host: h, layer: l });
  }
  const cmdHost = targets.length ? targets[0].host : null;
  if (!targets.length) {
    // Browser follow-ups (snapshot, eval, click) carry no URL: they act on the page the session last opened.
    const isB = /^browser-/.test(wholeLayer || '');
    const h = (isB && sess._last && sess._last[wholeLayer]) ||
      (ev !== 'PreToolUse' ? targetHost(firstHost, respText(hook.tool_response)) : null);
    if (h) targets.push({ host: h, layer: wholeLayer });
  }
  const about = host => {
    const info = siteInfo(sites, host);
    const tagged = !!(info && Array.isArray(info.tags) && info.tags.includes('cloudflare'));
    return {
      cloudflare: tagged || !!(state._cloudflare && state._cloudflare[host]),
      cfWhy: tagged ? 'is tagged [cloudflare] in the sites registry' : 'served a Cloudflare challenge earlier',
      known: info && info.route ? ` Known working route for ${info.host}: ${info.route}${info.how ? ' (' + info.how + ')' : ''}.` : '',
    };
  };

  if (ev === 'PreToolUse') {
    // R2 applies to any host.
    if (/--remote-debugging-port(=|\s)/.test(cmd) && !/--user-data-dir/.test(cmd) && !/agent-browser/.test(cmd)) {
      return deny(ev, 'web-unlock-guard R2: Chrome 136+ silently ignores --remote-debugging-port on the default profile (no port, no DevToolsActivePort). Add --user-data-dir=<a dedicated automation profile folder>. Do not copy cookies from your real profile into it. ' + FORCE_HINT);
    }
    // Every host in the call is checked, not only the first one.
    for (const { host, layer } of targets) {
      const { cloudflare, cfWhy, known } = about(host);
      if (cloudflare) {
        const isAutomationDefault = layer === 'browser-automation' || layer === 'browser-cft';
        if (!isFetch && /--headless|headless\s*[:=]\s*(true|True)\b/.test(cmd)) {
          return deny(ev, `web-unlock-guard R3: ${host} ${cfWhy}. Headless browsers do not pass Cloudflare (software WebGL, navigator.webdriver=true). Use a headed real browser, or an unlocker service.${known} ${FORCE_HINT}`);
        }
        if (isAutomationDefault && /\bagent-browser\b|\bplaywright\b|\bpuppeteer\b|\bselenium\b/.test(cmd)) {
          return deny(ev, `web-unlock-guard R1: ${host} ${cfWhy}. A default automation browser sets navigator.webdriver=true, which loops on the Turnstile challenge. Use ${nextAdvice(layer, NEXT_LAYER, cfg)}.${known} ${FORCE_HINT}`);
        }
      }
      // R4: N blocks on the same host + method = switch method.
      const st = layer && sess[host] && sess[host][layer];
      if (st && st.count >= cfg.maxStrikes) {
        return deny(ev, `web-unlock-guard R4: ${st.count} blocks on ${host} via "${layer}" (${st.reasons.join(', ')}). Rule: ${cfg.maxStrikes} failures on the same method = stop retrying. Switch to ${nextAdvice(layer, NEXT_LAYER, cfg)}, or ask the user.${known} ${FORCE_HINT}`);
      }
    }
    return;
  }

  if (ev === 'PostToolUse' || ev === 'PostToolUseFailure') {
    // With several hosts or methods in one call, the output can't be tied to one of them:
    // count nothing rather than charge the wrong host.
    if (targets.length !== 1) return;
    const { host, layer } = targets[0];
    if (!host || !layer) return;
    const { known } = about(host);
    const isBrowser = /^browser-/.test(layer);
    const text = respText(hook.tool_response) + '\n' + respText(hook.error || '');
    const r = detect(text) || {};
    // Only a tool call that succeeded with output resets the count; a failure we can't classify
    // (DNS error, timeout) is neither a strike nor a success.
    const success = !r.blocked && ev === 'PostToolUse' && text.trim() !== '';
    const remember = isBrowser && !!cmdHost;
    if (!r.blocked && !success && !remember) return;
    let st = null;
    updateState(cfg.stateFile, s => {
      const ss = (s[sid] = s[sid] || {});
      let changed = false;
      if (remember && (!ss._last || ss._last[layer] !== host)) { (ss._last = ss._last || {})[layer] = host; changed = true; }
      if (r.blocked) {
        if (r.vendor === 'cloudflare') (s._cloudflare = s._cloudflare || {})[host] = Date.now();
        ss[host] = ss[host] || {};
        st = (ss[host][layer] = ss[host][layer] || { count: 0, reasons: [] });
        st.count += 1; st.last = Date.now();
        if (!st.reasons.includes(r.reason)) st.reasons.push(r.reason);
        changed = true;
      } else if (success && ss[host] && ss[host][layer]) { delete ss[host][layer]; changed = true; }
      if (changed) ss._updated = Date.now();
      return changed;
    });
    if (r.blocked && st) {
      const next = nextAdvice(layer, NEXT_LAYER, cfg);
      const msg = `web-unlock-guard: BLOCKED ${r.reason} (${r.vendor}) on ${host} via "${layer}", strike ${st.count}/${cfg.maxStrikes}.` +
        (st.count >= cfg.maxStrikes ? ` Limit reached: the next try with this method will be denied. Switch to ${next}.` : ` One more failure here and you must switch to ${next}.`) + known;
      return out({ hookSpecificOutput: { hookEventName: ev, additionalContext: msg }, systemMessage: msg });
    }
  }
}

let input = '';
const timer = setTimeout(() => process.exit(0), 4000);
process.stdin.setEncoding('utf8');
process.stdin.on('data', c => (input += c));
process.stdin.on('end', async () => {
  clearTimeout(timer);
  try { await main(JSON.parse(input)); } catch (_) { /* fail open */ }
  // No process.exit() here: let stdout drain (pipe writes can be async on macOS).
});
