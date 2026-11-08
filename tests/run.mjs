#!/usr/bin/env node
// Feeds the sample hook JSON in tests/fixtures/ to hooks/guard.mjs and checks the result.
// Run: node tests/run.mjs
// Each fixture runs with an empty temporary HOME and state file, so nothing on this machine
// (a companion skill, a sites registry, earlier strikes) changes the result.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const GUARD = path.join(ROOT, 'hooks', 'guard.mjs');
let pass = 0, fail = 0;

function sandbox(extraEnv = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wug-'));
  // os.homedir() reads USERPROFILE on Windows and HOME elsewhere, so set both.
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, WEB_UNLOCK_GUARD_STATE: path.join(home, 'state.json') };
  for (const [k, v] of Object.entries(extraEnv)) env[k] = v.replaceAll('${ROOT}', ROOT).replaceAll('${HOME}', home);
  return { home, env };
}

function run(env, stdin) {
  const r = spawnSync(process.execPath, [GUARD], { input: stdin, env, encoding: 'utf8', timeout: 10000 });
  let parsed = null;
  try { parsed = r.stdout ? JSON.parse(r.stdout) : null; } catch (_) {}
  return { code: r.status, stdout: r.stdout, parsed };
}

function check(label, res, expect, contains) {
  const hso = res.parsed && res.parsed.hookSpecificOutput;
  let got = 'silent';
  if (hso && hso.permissionDecision === 'deny') got = 'deny';
  else if (hso && hso.additionalContext) got = 'context';
  else if (res.stdout) got = 'other';
  const text = hso ? (hso.permissionDecisionReason || hso.additionalContext || '') : '';
  const ok = res.code === 0 && got === expect && (!contains || text.includes(contains));
  if (ok) pass++; else fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  -> ${got}${text ? ': ' + text.slice(0, 110) : ''}`);
  if (!ok) console.log(`      expected ${expect}${contains ? ' containing "' + contains + '"' : ''}, exit ${res.code}, stdout ${JSON.stringify(res.stdout).slice(0, 300)}`);
}

// 1. Fixtures
for (const f of fs.readdirSync(path.join(ROOT, 'tests', 'fixtures')).filter(f => f.endsWith('.json')).sort()) {
  const fx = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', f), 'utf8'));
  const { env } = sandbox(fx.env || {});
  console.log(`\n# ${f}: ${fx.description}`);
  fx.steps.forEach((s, i) => check(`step ${i + 1} ${s.event.hook_event_name}`, run(env, JSON.stringify(s.event)), s.expect, s.contains));
}

// 2. Fail open on bad input
console.log('\n# fail-open');
{
  const { env } = sandbox();
  check('invalid JSON on stdin', run(env, '{not json'), 'silent');
  check('empty stdin', run(env, ''), 'silent');
  const { env: env2 } = sandbox({ WEB_UNLOCK_GUARD_SITES: '${HOME}/missing.json', WEB_UNLOCK_GUARD_SKILL_DIR: '${HOME}/no-such-skill' });
  check('missing registry and skill folder still enforce R2', run(env2, JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'chrome --remote-debugging-port=9333 https://example.org' } })), 'deny', 'R2');
}

// 3. Optional companion skill: its detector and sites.json are used when present
console.log('\n# companion skill');
{
  const { home, env } = sandbox();
  const skill = path.join(home, '.claude', 'skills', 'web-unlock');
  fs.mkdirSync(path.join(skill, 'lib'), { recursive: true });
  fs.writeFileSync(path.join(skill, 'SKILL.md'), '---\nname: web-unlock\n---\n');
  fs.writeFileSync(path.join(skill, 'sites.json'), JSON.stringify({ hosts: { 'walled.example.com': { tags: ['antibot'], route: 'site-api', how: 'GET /api/v1/items' } } }));
  fs.writeFileSync(path.join(skill, 'lib', 'detect.mjs'), `
export const detect = t => /CUSTOM-WALL/.test(t) ? { blocked: true, reason: 'custom-wall', vendor: 'custom' } : { blocked: false };
export const inferLayer = c => /\\bcurl\\b/.test(c) ? 'http' : null;
export const firstHost = s => { const m = /https?:\\/\\/([a-z0-9.-]+)/i.exec(s || ''); return m ? m[1] : null; };
export const NEXT_LAYER = { http: 'the custom next step' };
`);
  const post = { hook_event_name: 'PostToolUse', session_id: 's-skill', tool_name: 'Bash', tool_input: { command: 'curl -s https://walled.example.com/' }, tool_response: { stdout: 'CUSTOM-WALL' } };
  check('skill detector + registry route found in ~/.claude/skills/web-unlock', run(env, JSON.stringify(post)), 'context', 'the custom next step');
  check('registry route shown', run(env, JSON.stringify(post)), 'context', 'Known working route for walled.example.com: site-api');
  const broken = sandbox({ WEB_UNLOCK_GUARD_SKILL_DIR: '${HOME}/broken' });
  fs.mkdirSync(path.join(broken.home, 'broken', 'lib'), { recursive: true });
  fs.writeFileSync(path.join(broken.home, 'broken', 'lib', 'detect.mjs'), 'export const detect = ;');
  const post2 = { ...post, tool_response: { stdout: '<title>Just a moment...</title>' } };
  check('broken skill detector falls back to the bundled one', run(broken.env, JSON.stringify(post2)), 'context', 'cloudflare');
}

// 4. Expired state is ignored before any rule runs, even on a call that writes nothing
console.log('\n# expiry on read');
{
  const { env } = sandbox();
  const old = Date.now() - 3 * 24 * 3600 * 1000;
  fs.writeFileSync(env.WEB_UNLOCK_GUARD_STATE, JSON.stringify({
    _cloudflare: { 'cf-old.example.com': Date.now() - 40 * 24 * 3600 * 1000 },
    's-exp': { _updated: old, 'stale.example.com': { http: { count: 2, reasons: ['http-blocked-status'], last: old } } },
  }));
  const pre = c => JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's-exp', tool_name: 'Bash', tool_input: { command: c } });
  check('strikes older than 24 hours do not deny', run(env, pre('curl -s https://stale.example.com/')), 'silent');
  check('Cloudflare mark older than 30 days does not deny', run(env, pre('agent-browser open https://cf-old.example.com/')), 'silent');
}

// 5. Parallel hooks do not lose each other's strikes
console.log('\n# concurrent writes');
{
  const { env } = sandbox();
  const N = 12;
  const runAsync = stdin => new Promise(res => {
    const p = spawn(process.execPath, [GUARD], { env });
    p.on('close', res);
    p.stdin.end(stdin);
  });
  await Promise.all(Array.from({ length: N }, (_, i) => runAsync(JSON.stringify({
    hook_event_name: 'PostToolUse', session_id: 's-par', tool_name: 'Bash',
    tool_input: { command: `curl -s https://${i % 2 ? 'same' : 'h' + i}.example.com/` },
    tool_response: { stdout: 'HTTP/1.1 403 Forbidden' } }))));
  let st = {};
  try { st = JSON.parse(fs.readFileSync(env.WEB_UNLOCK_GUARD_STATE, 'utf8')); } catch (_) {}
  const s = st['s-par'] || {};
  const hosts = Array.from({ length: N / 2 }, (_, i) => `h${i * 2}.example.com`).filter(h => s[h] && s[h].http).length;
  const same = s['same.example.com'] && s['same.example.com'].http ? s['same.example.com'].http.count : 0;
  const ok = hosts === N / 2 && same === N / 2;
  if (ok) pass++; else fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${N} parallel blocked results all counted  -> ${hosts}/${N / 2} distinct hosts kept, same-host count ${same}/${N / 2}`);
  // A lock left by a killed hook is removed instead of blocking every later write
  const { env: env2 } = sandbox();
  const lock = env2.WEB_UNLOCK_GUARD_STATE + '.lock';
  fs.writeFileSync(lock, '');
  const t = new Date(Date.now() - 60000); fs.utimesSync(lock, t, t);
  check('stale lock file is cleared', run(env2, JSON.stringify({ hook_event_name: 'PostToolUse', session_id: 's-lock', tool_name: 'Bash',
    tool_input: { command: 'curl -s https://lock.example.com/' }, tool_response: { stdout: 'HTTP/1.1 429' } })), 'context', 'strike 1/2');
  const left = fs.existsSync(lock);
  if (!left) pass++; else fail++;
  console.log(`${!left ? 'PASS' : 'FAIL'}  lock file removed after the write`);
}

// 6. ctx_execute_file: the request lives in `code` (required by its schema); `path` is a data file
console.log('\n# ctx_execute_file');
{
  const { env } = sandbox();
  const ev = { hook_event_name: 'PostToolUse', session_id: 's-ctxf', tool_name: 'mcp__plugin_context-mode_context-mode__ctx_execute_file',
    tool_input: { path: 'urls.txt', language: 'shell', code: 'curl -s https://ctxf.example.com/' }, tool_response: 'HTTP/1.1 403 Forbidden' };
  check('request in code is inspected', run(env, JSON.stringify(ev)), 'context', 'ctxf.example.com');
}

// 7. Your own rules file: deny rules and extra web tool names
console.log('\n# rules file');
{
  const rules = {
    webish: [{ word: 'mcporter', layer: 'fetch-render' }, 'some-watched-cli'],
    deny: [
      { name: 'no-json-new', pattern: '/json/new\\b', message: 'use {skill_dir}/bin/chrome-real.sh start "<url>"' },
      { name: 'no-front', pattern: 'activate application "Chrome Beta"|open (-\\w+ )*-a "?Chrome Beta', unless: 'open -\\w*g', message: 'keep it behind' },
      { name: 'bash-only', pattern: 'only-in-bash', tools: '^Bash$', message: 'bash rule' },
      { name: 'broken', pattern: '(', message: 'never used' },
    ],
  };
  const pre = (c, tool = 'Bash') => JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's-rules', tool_name: tool, tool_input: { command: c } });
  // Default location: ~/.config/web-unlock-guard/rules.json
  const { home, env } = sandbox();
  fs.mkdirSync(path.join(home, '.config', 'web-unlock-guard'), { recursive: true });
  fs.writeFileSync(path.join(home, '.config', 'web-unlock-guard', 'rules.json'), JSON.stringify(rules));
  check('deny rule from ~/.config/web-unlock-guard/rules.json', run(env, pre('curl -s -X PUT "http://127.0.0.1:9223/json/new?https://a.example"')), 'deny', 'no-json-new');
  check('deny rule applies to non-web commands too', run(env, pre('osascript -e \'tell application "Chrome Beta" to activate\'; activate application "Chrome Beta"')), 'deny', 'keep it behind');
  check('"unless" lets the background form through', run(env, pre('open -g -a "Chrome Beta" https://a.example')), 'silent');
  check('"tools" limits a rule to matching tools', run(env, pre('only-in-bash', 'mcp__x__ctx_execute')), 'silent');
  check('"tools" rule still fires on its tool', run(env, pre('only-in-bash')), 'deny', 'bash rule');
  check('a rule with a bad regex is skipped, the others apply', run(env, pre('echo (')), 'silent');
  check('WEB_UNLOCK_FORCE=1 skips your rules too', run(env, pre('WEB_UNLOCK_FORCE=1 curl http://127.0.0.1:9223/json/new')), 'silent');
  // Extra webish word: an mcporter call with a URL-less body gets strikes only when watched
  const post = { hook_event_name: 'PostToolUse', session_id: 's-rules', tool_name: 'Bash',
    tool_input: { command: 'mcporter call fetch.page site.example.com' }, tool_response: { stdout: '<title>Just a moment...</title> https://site.example.com/' } };
  check('"webish" word with a layer counts strikes for that tool', run(env, JSON.stringify(post)), 'context', 'via "fetch-render"');
  check('its next call on that host after the limit is denied (R4)', (run(env, JSON.stringify(post)), run(env, pre('mcporter call fetch.page https://site.example.com/'))), 'deny', 'R4');
  const plain = sandbox();
  check('without the word the same call is ignored', run(plain.env, JSON.stringify(post)), 'silent');
  // {skill_dir} is filled with the companion folder
  const sk = path.join(home, '.claude', 'skills', 'web-unlock');
  fs.mkdirSync(sk, { recursive: true }); fs.writeFileSync(path.join(sk, 'SKILL.md'), '---\nname: web-unlock\n---\n');
  check('{skill_dir} in the message becomes the companion folder', run(env, pre('curl http://127.0.0.1:9223/json/new')), 'deny', `${sk}/bin/chrome-real.sh`);
  // Option / env var path wins; a missing or broken file is ignored
  const other = sandbox({ WEB_UNLOCK_GUARD_RULES: '${HOME}/my-rules.json' });
  fs.writeFileSync(path.join(other.home, 'my-rules.json'), JSON.stringify({ deny: [{ name: 'from-option', pattern: 'forbidden-word', message: 'no' }] }));
  check('rules_file option (CLAUDE_PLUGIN_OPTION_RULES_FILE / WEB_UNLOCK_GUARD_RULES) is read', run(other.env, pre('echo forbidden-word')), 'deny', 'from-option');
  const viaOpt = sandbox({ CLAUDE_PLUGIN_OPTION_RULES_FILE: '${HOME}/my-rules.json' });
  fs.writeFileSync(path.join(viaOpt.home, 'my-rules.json'), JSON.stringify({ deny: [{ name: 'plugin-opt', pattern: 'forbidden-word', message: 'no' }] }));
  check('plugin option form works', run(viaOpt.env, pre('echo forbidden-word')), 'deny', 'plugin-opt');
  const bad = sandbox({ WEB_UNLOCK_GUARD_RULES: '${HOME}/bad.json' });
  fs.writeFileSync(path.join(bad.home, 'bad.json'), '{not json');
  check('broken rules file: built-in rules still work', run(bad.env, pre('chrome --remote-debugging-port=9333 https://example.org')), 'deny', 'R2');
}

// 8. Companion discovery: the web-unlock plugin and the web-unlock user folder
console.log('\n# companion plugin and user registry');
{
  const { home, env } = sandbox();
  const install = path.join(home, '.claude', 'plugins', 'cache', 'mk', 'web-unlock', '0.2.0');
  const skill = path.join(install, 'skills', 'web-unlock');
  fs.mkdirSync(path.join(skill, 'lib'), { recursive: true });
  fs.writeFileSync(path.join(skill, 'SKILL.md'), '---\nname: web-unlock\n---\n');
  fs.writeFileSync(path.join(skill, 'sites.json'), JSON.stringify({ hosts: { 'walled.example.com': { route: 'bundled-route' } } }));
  fs.writeFileSync(path.join(skill, 'lib', 'detect.mjs'), `
export const detect = t => /PLUGIN-WALL/.test(t) ? { blocked: true, reason: 'plugin-wall', vendor: 'custom' } : { blocked: false };
export const inferLayer = c => /\\bcurl\\b/.test(c) ? 'http' : null;
export const firstHost = s => { const m = /https?:\\/\\/([a-z0-9.-]+)/i.exec(s || ''); return m ? m[1] : null; };
`);
  fs.writeFileSync(path.join(home, '.claude', 'plugins', 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins: { 'web-unlock@mk': [{ scope: 'user', installPath: install, version: '0.2.0' }] } }));
  const post = { hook_event_name: 'PostToolUse', session_id: 's-comp', tool_name: 'Bash', tool_input: { command: 'curl -s https://walled.example.com/' }, tool_response: { stdout: 'PLUGIN-WALL' } };
  check('installed web-unlock plugin is used as the companion skill', run(env, JSON.stringify(post)), 'context', 'plugin-wall');
  check('its bundled sites.json is the fallback registry', run(env, JSON.stringify({ ...post, session_id: 's-comp2' })), 'context', 'bundled-route');
  fs.mkdirSync(path.join(home, '.config', 'web-unlock'), { recursive: true });
  fs.writeFileSync(path.join(home, '.config', 'web-unlock', 'sites.json'), JSON.stringify({ hosts: { 'walled.example.com': { route: 'user-route' } } }));
  check('~/.config/web-unlock/sites.json wins over the skill registry', run(env, JSON.stringify({ ...post, session_id: 's-comp3' })), 'context', 'user-route');
  const wh = sandbox({ WEB_UNLOCK_HOME: '${HOME}/wu' });
  fs.mkdirSync(path.join(wh.home, 'wu'), { recursive: true });
  fs.writeFileSync(path.join(wh.home, 'wu', 'sites.json'), JSON.stringify({ hosts: { 'cf.example.com': { tags: ['cloudflare'] } } }));
  check('WEB_UNLOCK_HOME moves the user registry', run(wh.env, JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's-wh', tool_name: 'Bash', tool_input: { command: 'agent-browser open https://cf.example.com/' } })), 'deny', 'R1');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
