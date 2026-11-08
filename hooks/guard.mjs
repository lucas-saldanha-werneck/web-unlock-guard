#!/usr/bin/env node
// web-unlock-guard: PreToolUse / PostToolUse / PostToolUseFailure hook.
// Enforces web-scraping rules deterministically, because rules written as prose do not stop
// an agent from retrying the same blocked request over and over.
//
//   Pre  R1: deny a default automation browser (webdriver=true) against a Cloudflare host.
//   Pre  R2: deny --remote-debugging-port without --user-data-dir (recent Chrome ignores it).
//   Pre  R3: deny headless browsers against a Cloudflare host.
//   Pre  R4: deny the next try on the same host + method after N blocks (default 2): switch method.
//   Post   : detect a block signature in the tool output, count a strike per host + method,
//            and remember hosts that served a Cloudflare challenge.
//
// Fails open: any internal error exits 0 with no output. Put WEB_UNLOCK_FORCE=1 in the command
// to skip every check for that call.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOME = os.homedir();
const WEBISH = /agent-browser|opencli|yt-dlp|curl\s|wget\s|firecrawl|apify|jina\.ai|remote-debugging|connectOverCDP|playwright|puppeteer|selenium|patchright|camoufox|nodriver|scrapling|--headless|https?:\/\//i;
const FORCE = /WEB_(UNLOCK|ACCESS)_FORCE=1/;
const DAY = 24 * 3600 * 1000;

// Plugin options arrive as CLAUDE_PLUGIN_OPTION_<KEY>; plain env vars work for manual installs.
function setting(...names) {
  for (const n of names) { const v = (process.env[n] || '').trim(); if (v) return v; }
  return '';
}
const expand = p => (p ? p.replace(/^~(?=$|\/)/, HOME).replace(/\$HOME|\$\{HOME\}/g, HOME) : p);

function config() {
  const max = parseInt(setting('CLAUDE_PLUGIN_OPTION_MAX_STRIKES', 'WEB_UNLOCK_GUARD_MAX_STRIKES'), 10);
  let skillDir = expand(setting('CLAUDE_PLUGIN_OPTION_SKILL_DIR', 'WEB_UNLOCK_GUARD_SKILL_DIR'));
  if (!skillDir) {
    const guess = path.join(HOME, '.claude', 'skills', 'web-unlock');
    if (fs.existsSync(path.join(guess, 'SKILL.md'))) skillDir = guess;
  }
  if (skillDir && !fs.existsSync(skillDir)) skillDir = '';
  let sitesFile = expand(setting('CLAUDE_PLUGIN_OPTION_SITES_FILE', 'WEB_UNLOCK_GUARD_SITES'));
  if (!sitesFile && skillDir && fs.existsSync(path.join(skillDir, 'sites.json'))) sitesFile = path.join(skillDir, 'sites.json');
  const dataDir = process.env.CLAUDE_PLUGIN_DATA || path.join(HOME, '.claude', 'state');
  const stateFile = expand(setting('WEB_UNLOCK_GUARD_STATE')) || path.join(dataDir, 'web-unlock-guard.json');
  return { maxStrikes: max > 0 ? max : 2, skillDir, sitesFile, stateFile };
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
function respText(tr) {
  if (tr == null) return '';
  if (typeof tr === 'string') return tr;
  if (Array.isArray(tr)) return tr.map(respText).join('\n');
  if (typeof tr === 'object') return Object.values(tr).map(v => (typeof v === 'string' ? v : (v && typeof v === 'object') ? respText(v) : '')).join('\n');
  return String(tr);
}

function loadJSON(f) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (_) { return null; } }
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
    fs.renameSync(tmp, file);
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

const out = o => process.stdout.write(JSON.stringify(o));
const deny = (ev, reason) => out({ hookSpecificOutput: { hookEventName: ev, permissionDecision: 'deny', permissionDecisionReason: reason } });
const FORCE_HINT = 'To insist anyway, prefix the command with WEB_UNLOCK_FORCE=1.';

async function main(hook) {
  const ev = hook.hook_event_name || '';
  const tool = hook.tool_name || '';
  const cmd = cmdText(hook.tool_input);
  const isFetch = /WebFetch/.test(tool);
  if (!WEBISH.test(cmd) && !isFetch) return;
  if (FORCE.test(cmd)) return;

  const cfg = config();
  const { detect, inferLayer, NEXT_LAYER, firstHost } = await loadDetector(cfg);
  const sites = cfg.sitesFile ? loadJSON(cfg.sitesFile) : null;
  const layer = inferLayer(cmd) || (isFetch ? 'http' : null);
  const state = loadState(cfg.stateFile);
  const sid = hook.session_id || 'nosession';
  const sess = state[sid] || {};
  // Browser follow-ups (snapshot, eval, click) carry no URL: they act on the page the session last opened.
  const isBrowser = /^browser-/.test(layer || '');
  const cmdHost = targetHost(firstHost, cmd);
  const host = cmdHost ||
    (isBrowser && sess._last && sess._last[layer]) ||
    (ev !== 'PreToolUse' ? targetHost(firstHost, respText(hook.tool_response)) : null);
  const info = siteInfo(sites, host);
  const seenCf = host && state._cloudflare && state._cloudflare[host];
  const cloudflare = (info && Array.isArray(info.tags) && info.tags.includes('cloudflare')) || !!seenCf;
  const cfWhy = info && Array.isArray(info.tags) && info.tags.includes('cloudflare') ? 'is tagged [cloudflare] in the sites registry' : 'served a Cloudflare challenge earlier';
  const known = info && info.route ? ` Known working route for ${info.host}: ${info.route}${info.how ? ' (' + info.how + ')' : ''}.` : '';

  if (ev === 'PreToolUse') {
    // R2 applies to any host.
    if (/--remote-debugging-port(=|\s)/.test(cmd) && !/--user-data-dir/.test(cmd) && !/agent-browser/.test(cmd)) {
      return deny(ev, 'web-unlock-guard R2: Chrome 136+ silently ignores --remote-debugging-port on the default profile (no port, no DevToolsActivePort). Add --user-data-dir=<a dedicated automation profile folder>. Do not copy cookies from your real profile into it. ' + FORCE_HINT);
    }
    if (host && cloudflare) {
      const isAutomationDefault = layer === 'browser-automation' || layer === 'browser-cft';
      if (/--headless|headless\s*[:=]\s*(true|True)\b/.test(cmd)) {
        return deny(ev, `web-unlock-guard R3: ${host} ${cfWhy}. Headless browsers do not pass Cloudflare (software WebGL, navigator.webdriver=true). Use a headed real browser, or an unlocker service.${known} ${FORCE_HINT}`);
      }
      if (isAutomationDefault && /\bagent-browser\b|\bplaywright\b|\bpuppeteer\b|\bselenium\b/.test(cmd)) {
        return deny(ev, `web-unlock-guard R1: ${host} ${cfWhy}. A default automation browser sets navigator.webdriver=true, which loops on the Turnstile challenge. Use ${nextAdvice(layer, NEXT_LAYER, cfg)}.${known} ${FORCE_HINT}`);
      }
    }
    // R4: N blocks on the same host + method = switch method.
    if (host && layer) {
      const st = sess[host] && sess[host][layer];
      if (st && st.count >= cfg.maxStrikes) {
        return deny(ev, `web-unlock-guard R4: ${st.count} blocks on ${host} via "${layer}" (${st.reasons.join(', ')}). Rule: ${cfg.maxStrikes} failures on the same method = stop retrying. Switch to ${nextAdvice(layer, NEXT_LAYER, cfg)}, or ask the user.${known} ${FORCE_HINT}`);
      }
    }
    return;
  }

  if (ev === 'PostToolUse' || ev === 'PostToolUseFailure') {
    if (!host || !layer) return;
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
