#!/usr/bin/env node
// Feeds the sample hook JSON in tests/fixtures/ to hooks/guard.mjs and checks the result.
// Run: node tests/run.mjs
// Each fixture runs with an empty temporary HOME and state file, so nothing on this machine
// (a companion skill, a sites registry, earlier strikes) changes the result.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

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
  check('WEB_UNLOCK_FORCE=1 does not skip your rules', run(env, pre('WEB_UNLOCK_FORCE=1 curl http://127.0.0.1:9223/json/new')), 'deny', 'no-json-new');
  check('WEB_UNLOCK_FORCE=1 does not skip your rules on a non-web command', run(env, pre('WEB_UNLOCK_FORCE=1 osascript -e x; activate application "Chrome Beta"')), 'deny', 'keep it behind');
  {
    const r = run(env, pre('curl http://127.0.0.1:9223/json/new'));
    const t = r.stdout || '';
    const ok = t.includes('no-json-new') && !/FORCE/.test(t);
    if (ok) pass++; else fail++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  your rule's refusal does not mention the FORCE bypass${ok ? '' : '  ' + t.slice(0, 300)}`);
  }
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
  fs.writeFileSync(path.join(other.home, 'my-rules.json'), JSON.stringify({ deny: [{ name: 'from-option', pattern: 'forbidden-tool', message: 'no' }] }));
  check('rules_file option (CLAUDE_PLUGIN_OPTION_RULES_FILE / WEB_UNLOCK_GUARD_RULES) is read', run(other.env, pre('forbidden-tool --now')), 'deny', 'from-option');
  const viaOpt = sandbox({ CLAUDE_PLUGIN_OPTION_RULES_FILE: '${HOME}/my-rules.json' });
  fs.writeFileSync(path.join(viaOpt.home, 'my-rules.json'), JSON.stringify({ deny: [{ name: 'plugin-opt', pattern: 'forbidden-tool', message: 'no' }] }));
  check('plugin option form works', run(viaOpt.env, pre('forbidden-tool --now')), 'deny', 'plugin-opt');
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

// 9. Review fixes
console.log('\n# review fixes');
{
  const J = '/json/' + 'new';
  const ex = JSON.parse(fs.readFileSync(path.join(ROOT, 'examples', 'rules.example.json'), 'utf8'));
  const pre = (c, sid = 's-rv') => JSON.stringify({ hook_event_name: 'PreToolUse', session_id: sid, tool_name: 'Bash', tool_input: { command: c }, cwd: '/tmp' });
  const withRules = (rules, extra = {}) => {
    const sb = sandbox(extra);
    fs.mkdirSync(path.join(sb.home, '.config', 'web-unlock-guard'), { recursive: true });
    fs.writeFileSync(path.join(sb.home, '.config', 'web-unlock-guard', 'rules.json'), JSON.stringify(rules));
    return sb;
  };
  const { env } = withRules(ex);
  // 1: "unless" is checked on the same segment as the pattern
  check('unless in another segment does not excuse the match', run(env, pre(`open -g ~/x.txt; osascript -e 'activate application "Google Chrome Beta"'`)), 'deny', 'automation-chrome-stays-behind');
  // 4: -g anywhere in the open command
  check('open -a "Google Chrome Beta" -g <url> is allowed', run(env, pre('open -a "Google Chrome Beta" -g https://a.example')), 'silent');
  check('open -n -a "Google Chrome Beta" is denied', run(env, pre('open -n -a "Google Chrome Beta" https://a.example')), 'deny', 'automation-chrome-stays-behind');
  // 5: escaped quotes, as an osascript call inside double quotes is written
  check('escaped-quote osascript form is denied', run(env, pre('osascript -e "tell application \\"Google Chrome Beta\\" to activate"')), 'deny', 'automation-chrome-stays-behind');
  // 6: searching for a pattern or naming it in a commit message is not denied; running it is
  check(`grep for ${J} is not denied`, run(env, pre(`grep -rn '${J}' hooks/`)), 'silent');
  check('a commit message that names it is not denied', run(env, pre(`git commit -m "deny ${J} in rules"`)), 'silent');
  check(`curl to ${J} after a grep is still denied`, run(env, pre(`grep -q x f && curl -s "http://127.0.0.1:9223${J}?https://a.example"`)), 'deny', 'no-json-new');
  // 9: webish words match whole words only; unknown layers are rejected
  const w = withRules({ webish: [{ word: 'mcp', layer: 'http' }, { word: 'oddtool', layer: 'not-a-layer' }] });
  const post = c => JSON.stringify({ hook_event_name: 'PostToolUse', session_id: 's-w', tool_name: 'Bash', tool_input: { command: c }, tool_response: { stdout: '<title>Just a moment...</title> https://w.example.com/' } });
  check('"mcp" does not match inside "mcporter"', run(w.env, post('mcporter call x w.example.com')), 'silent');
  check('"mcp" as a word still counts', run(w.env, post('mcp get w.example.com')), 'context', 'via "http"');
  const bad = spawnSync(process.execPath, [GUARD], { input: post('oddtool get w.example.com'), env: w.env, encoding: 'utf8' });
  const okBad = bad.status === 0 && !bad.stdout && /unknown layer "not-a-layer"/.test(bad.stderr);
  if (okBad) pass++; else fail++;
  console.log(`${okBad ? 'PASS' : 'FAIL'}  unknown layer: entry ignored with a warning on stderr  -> ${JSON.stringify(bad.stderr).slice(0, 100)}`);
  // 3: no rules file and a non-web command: nothing else is read (a broken skill dir would not matter anyway),
  // and with a rules file the companion is resolved only for {skill_dir}
  // A preloaded module logs every file the hook checks or reads.
  const lz = withRules({ deny: [{ name: 'other', pattern: 'never-matches-this', message: 'no skill dir here' }] });
  const preload = path.join(lz.home, 'trace.mjs'), log = path.join(lz.home, 'trace.log');
  fs.writeFileSync(preload, `import fs from 'node:fs';
const log = ${JSON.stringify(log)};
for (const k of ['existsSync', 'readFileSync', 'statSync']) { const f = fs[k]; fs[k] = function (p, ...a) { try { fs.appendFileSync(log, String(p) + '\\n'); } catch (_) {} return f.call(this, p, ...a); }; }`);
  const tr = spawnSync(process.execPath, ['--import', pathToFileURL(preload).href, GUARD], { input: pre('ls -la'), env: lz.env, encoding: 'utf8' });
  const seen = fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '';
  const okLazy = tr.status === 0 && !tr.stdout && !/installed_plugins|skills[\\/]web-unlock|sites\.json/.test(seen) && /rules\.json/.test(seen);
  if (okLazy) pass++; else fail++;
  console.log(`${okLazy ? 'PASS' : 'FAIL'}  non-web command: only the rules file is read (no companion or registry lookup)  -> ${seen.split('\n').filter(Boolean).map(x => path.basename(x)).join(',').slice(0, 160)}`);
}
{
  // 2: an explicitly set skill_dir's sites.json is the bundled layer; ~/.config/web-unlock/sites.json lies on top
  const { home, env } = sandbox({ WEB_UNLOCK_GUARD_SKILL_DIR: '${HOME}/myskill' });
  fs.mkdirSync(path.join(home, 'myskill'), { recursive: true });
  fs.writeFileSync(path.join(home, 'myskill', 'sites.json'), JSON.stringify({ hosts: { 'pick.example.com': { route: 'explicit-skill-route' }, 'only-skill.example.com': { route: 'explicit-skill-route' } } }));
  fs.mkdirSync(path.join(home, '.config', 'web-unlock'), { recursive: true });
  fs.writeFileSync(path.join(home, '.config', 'web-unlock', 'sites.json'), JSON.stringify({ hosts: { 'pick.example.com': { route: 'default-route' } } }));
  const post = { hook_event_name: 'PostToolUse', session_id: 's-pick', tool_name: 'Bash', tool_input: { command: 'curl -s https://pick.example.com/' }, tool_response: { stdout: 'HTTP/1.1 403 Forbidden' } };
  check('same host in the skill_dir registry and yours: yours wins', run(env, JSON.stringify(post)), 'context', 'default-route');
  const post2 = { ...post, session_id: 's-pick2', tool_input: { command: 'curl -s https://only-skill.example.com/' } };
  check('a host only in the skill_dir registry is still used', run(env, JSON.stringify(post2)), 'context', 'explicit-skill-route');
}
{
  // 7: CLAUDE_CONFIG_DIR first, then ~/.claude, for the companion and for the state folder
  const { home, env } = sandbox({ CLAUDE_CONFIG_DIR: '${HOME}/cc' });
  delete env.WEB_UNLOCK_GUARD_STATE;
  const sk = path.join(home, '.claude', 'skills', 'web-unlock');
  fs.mkdirSync(sk, { recursive: true }); fs.writeFileSync(path.join(sk, 'SKILL.md'), '---\nname: web-unlock\n---\n');
  fs.writeFileSync(path.join(sk, 'sites.json'), JSON.stringify({ hosts: { 'cc.example.com': { route: 'home-claude-route' } } }));
  const post = { hook_event_name: 'PostToolUse', session_id: 's-cc', tool_name: 'Bash', tool_input: { command: 'curl -s https://cc.example.com/' }, tool_response: { stdout: 'HTTP/1.1 403 Forbidden' } };
  check('companion in ~/.claude is still found when CLAUDE_CONFIG_DIR is set', run(env, JSON.stringify(post)), 'context', 'home-claude-route');
  const st = fs.existsSync(path.join(home, 'cc', 'state', 'web-unlock-guard.json'));
  if (st) pass++; else fail++;
  console.log(`${st ? 'PASS' : 'FAIL'}  state file goes under CLAUDE_CONFIG_DIR when it is set`);
}
{
  // 8: plugin installs: other projects are ignored, a matching project beats user scope, newest version wins
  const { home, env } = sandbox();
  const mk = (ver, route) => {
    const inst = path.join(home, 'cache', 'web-unlock', ver);
    fs.mkdirSync(path.join(inst, 'skills', 'web-unlock'), { recursive: true });
    fs.writeFileSync(path.join(inst, 'skills', 'web-unlock', 'SKILL.md'), '---\nname: web-unlock\n---\n');
    fs.writeFileSync(path.join(inst, 'skills', 'web-unlock', 'sites.json'), JSON.stringify({ hosts: { 'v.example.com': { route } } }));
    return inst;
  };
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true });
  const write = entries => { fs.mkdirSync(path.join(home, '.claude', 'plugins'), { recursive: true });
    fs.writeFileSync(path.join(home, '.claude', 'plugins', 'installed_plugins.json'), JSON.stringify({ version: 2, plugins: { 'web-unlock@mk': entries } })); };
  write([
    { scope: 'project', projectPath: path.join(home, 'other'), installPath: mk('0.9.0', 'other-project'), version: '0.9.0' },
    { scope: 'user', installPath: mk('0.2.0', 'user-0.2.0'), version: '0.2.0' },
    { scope: 'user', installPath: mk('0.10.0', 'user-0.10.0'), version: '0.10.0' },
  ]);
  const post = (sid, cwd) => JSON.stringify({ hook_event_name: 'PostToolUse', session_id: sid, cwd, tool_name: 'Bash', tool_input: { command: 'curl -s https://v.example.com/' }, tool_response: { stdout: 'HTTP/1.1 403 Forbidden' } });
  check('user scope, newest version (0.10.0 over 0.2.0), other project ignored', run(env, post('s-v1', home)), 'context', 'user-0.10.0');
  write([
    { scope: 'user', installPath: mk('0.10.0', 'user-0.10.0'), version: '0.10.0' },
    { scope: 'project', projectPath: proj, installPath: mk('0.3.0', 'this-project'), version: '0.3.0' },
  ]);
  check('install for the current project beats user scope', run(env, post('s-v2', path.join(proj, 'sub'))), 'context', 'this-project');
}

// 9b. Registry overlay, read the same way as the web-unlock skill: the companion's bundled sites.json first,
// then yours (~/.config/web-unlock/sites.json) on top; same host = your whole entry.
console.log('\n# registry overlay');
{
  const { home, env } = sandbox();
  const skill = path.join(home, '.claude', 'skills', 'web-unlock');
  fs.mkdirSync(skill, { recursive: true });
  fs.writeFileSync(path.join(skill, 'SKILL.md'), '# web-unlock\n');
  const bundled = { hosts: { 'b-only.example.com': { route: 'bundled-route' }, 'both.example.com': { route: 'bundled-route', how: 'bundled-how' } } };
  fs.writeFileSync(path.join(skill, 'sites.json'), JSON.stringify(bundled));
  fs.mkdirSync(path.join(home, '.config', 'web-unlock'), { recursive: true });
  const mine = path.join(home, '.config', 'web-unlock', 'sites.json');
  fs.writeFileSync(mine, JSON.stringify({ _doc: 'x', hosts: { 'u-only.example.com': { route: 'user-route' }, 'both.example.com': { route: 'user-route' } } }));
  let n = 0;
  const blocked = host => JSON.stringify({ hook_event_name: 'PostToolUse', session_id: `s-ov-${n++}`, tool_name: 'Bash', tool_input: { command: `curl -s https://${host}/` }, tool_response: { stdout: 'HTTP/1.1 403 Forbidden' } });
  check('overlay: a host only in your registry is used', run(env, blocked('u-only.example.com')), 'context', 'user-route');
  check('overlay: a host only in the bundled registry is used', run(env, blocked('b-only.example.com')), 'context', 'bundled-route');
  const both = run(env, blocked('both.example.com'));
  check('overlay: same host in both -> your entry wins', both, 'context', 'user-route');
  const t = (both.parsed && both.parsed.hookSpecificOutput && both.parsed.hookSpecificOutput.additionalContext) || '';
  const whole = !t.includes('bundled-how');
  if (whole) pass++; else fail++;
  console.log(`${whole ? 'PASS' : 'FAIL'}  overlay: your entry replaces the bundled one whole (no bundled fields mixed in)`);
  // a seeded (empty) registry: a host the next skill version adds to the bundled file reaches you
  fs.writeFileSync(mine, JSON.stringify({ _doc: 'x', hosts: {} }));
  fs.writeFileSync(path.join(skill, 'sites.json'), JSON.stringify({ hosts: { 'new-in-update.example.com': { route: 'update-route' } } }));
  check('overlay: a bundled update reaches a seeded (empty) registry', run(env, blocked('new-in-update.example.com')), 'context', 'update-route');
  // an old full copy of the bundled registry still works: it overrides every host it lists
  fs.writeFileSync(mine, JSON.stringify({ hosts: { 'new-in-update.example.com': { route: 'copy-route' } } }));
  check('overlay: a full copy still works and wins for the hosts it lists', run(env, blocked('new-in-update.example.com')), 'context', 'copy-route');
}

// 10. First run: the rules file is created where the guard reads it, never overwritten, never a crash
console.log('\n# first-run seed');
{
  const DEFAULT = fs.readFileSync(path.join(ROOT, 'hooks', 'rules.default.json'));
  const ok = (label, cond, extra) => { if (cond) pass++; else fail++; console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${cond ? '' : '  ' + (extra || '')}`); };
  const start = JSON.stringify({ hook_event_name: 'SessionStart', source: 'startup', session_id: 's-seed' });
  const pre = cmd => JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's-seed', tool_name: 'Bash', tool_input: { command: cmd } });

  const { home, env } = sandbox();
  const def = path.join(home, '.config', 'web-unlock-guard', 'rules.json');
  let r = run(env, start);
  ok('SessionStart, no rules file -> created from rules.default.json, silent, exit 0',
    r.code === 0 && r.stdout === '' && fs.existsSync(def) && fs.readFileSync(def).equals(DEFAULT), `exit ${r.code} stdout ${r.stdout}`);
  const seeded = JSON.parse(fs.readFileSync(def, 'utf8'));
  ok('seeded file has empty webish and deny lists', Array.isArray(seeded.webish) && !seeded.webish.length && Array.isArray(seeded.deny) && !seeded.deny.length);

  const mine = '{"deny":[{"name":"mine","pattern":"\\\\bforbidden-tool\\\\b","message":"no"}]}\n';
  fs.writeFileSync(def, mine);
  r = run(env, start);
  ok('existing rules file is byte-identical after SessionStart', r.code === 0 && r.stdout === '' && fs.readFileSync(def, 'utf8') === mine);
  check('and its rule still applies', run(env, pre('forbidden-tool --go')), 'deny', 'mine');
  ok('existing rules file is byte-identical after a tool call', fs.readFileSync(def, 'utf8') === mine);

  const { home: h2, env: env2 } = sandbox();
  run(env2, pre('ls'));
  ok('first tool call also creates a missing rules file', fs.existsSync(path.join(h2, '.config', 'web-unlock-guard', 'rules.json')));

  const { home: h3, env: env3 } = sandbox({ WEB_UNLOCK_GUARD_RULES: '${HOME}/elsewhere/my-rules.json' });
  run(env3, start);
  ok('WEB_UNLOCK_GUARD_RULES is respected (created there, nothing under ~/.config)',
    fs.existsSync(path.join(h3, 'elsewhere', 'my-rules.json')) && !fs.existsSync(path.join(h3, '.config')));
  const { home: h4, env: env4 } = sandbox({ CLAUDE_PLUGIN_OPTION_RULES_FILE: '${HOME}/opt/rules.json' });
  run(env4, start);
  ok('the rules_file plugin option is respected', fs.existsSync(path.join(h4, 'opt', 'rules.json')) && !fs.existsSync(path.join(h4, '.config')));

  const { home: h5 } = sandbox();
  fs.writeFileSync(path.join(h5, 'afile'), 'x');
  const { env: env5 } = sandbox({ WEB_UNLOCK_GUARD_RULES: path.join(h5, 'afile', 'rules.json') });
  r = run(env5, start);
  ok('rules folder that cannot be created (under a file) -> exit 0, silent', r.code === 0 && r.stdout === '', `exit ${r.code} stdout ${r.stdout}`);
  check('and the guard still enforces R2', run(env5, pre('chrome --remote-debugging-port=9333 https://example.org')), 'deny', 'R2');

  const { home: h7, env: env7 } = sandbox({ WEB_UNLOCK_GUARD_RULES: 'rel/rules.json' });
  const r7 = spawnSync(process.execPath, [GUARD], { input: start, env: env7, cwd: h7, encoding: 'utf8', timeout: 10000 });
  ok('relative rules_file is not seeded into the current folder', r7.status === 0 && r7.stdout === '' && !fs.existsSync(path.join(h7, 'rel')));

  // A write that fails half-way (disk full) leaves no file behind, so the next run seeds it whole.
  {
    const { home: h8, env: env8 } = sandbox();
    const failWrite = "data:text/javascript,import fs from 'node:fs'; fs.writeSync = () => { throw Object.assign(new Error('no space'), { code: 'ENOSPC' }); };";
    const r8 = spawnSync(process.execPath, ['--import', failWrite, GUARD], { input: start, env: env8, encoding: 'utf8', timeout: 10000 });
    const f8 = path.join(h8, '.config', 'web-unlock-guard', 'rules.json');
    ok('failed write -> exit 0 and no empty rules file left behind', r8.status === 0 && !fs.existsSync(f8), `exit ${r8.status} ${r8.stderr}`);
    run(env8, start);
    ok('and the next run seeds the whole file', fs.existsSync(f8) && fs.readFileSync(f8).equals(DEFAULT));
  }

  const { home: h6 } = sandbox();
  const ro = path.join(h6, 'ro');
  fs.mkdirSync(ro); fs.chmodSync(ro, 0o555);
  let writable = true;
  try { fs.accessSync(ro, fs.constants.W_OK); } catch (_) { writable = false; }
  if (process.platform === 'win32' || writable) ok('read-only folder check skipped (Windows or root)', true);
  else {
    const { env: env6 } = sandbox({ WEB_UNLOCK_GUARD_RULES: path.join(ro, 'sub', 'rules.json') });
    r = run(env6, start);
    ok('read-only parent folder -> exit 0, silent, nothing written', r.code === 0 && r.stdout === '' && !fs.existsSync(path.join(ro, 'sub')));
  }
  fs.chmodSync(ro, 0o755);

  // The seeded file behaves exactly like no file: every fixture step gives the same output with the seeded
  // rules file as with a rules path that can never exist.
  let same = 0;
  const diff = [];
  for (const f of fs.readdirSync(path.join(ROOT, 'tests', 'fixtures')).filter(f => f.endsWith('.json')).sort()) {
    const fx = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', f), 'utf8'));
    if (fx.env && (fx.env.WEB_UNLOCK_GUARD_RULES || fx.env.CLAUDE_PLUGIN_OPTION_RULES_FILE)) continue;
    const { home: hn, env: envNone } = sandbox(fx.env || {});
    fs.writeFileSync(path.join(hn, 'afile'), 'x');
    envNone.WEB_UNLOCK_GUARD_RULES = path.join(hn, 'afile', 'rules.json');
    const { home: hs, env: envSeeded } = sandbox(fx.env || {});
    run(envSeeded, start);
    if (!fs.existsSync(path.join(hs, '.config', 'web-unlock-guard', 'rules.json'))) { diff.push(`${f}: not seeded`); continue; }
    for (const [i, st] of fx.steps.entries()) {
      const a = (run(envNone, JSON.stringify(st.event)).stdout || '').replaceAll(JSON.stringify(hn).slice(1, -1), 'H').replaceAll(hn, 'H');
      const b = (run(envSeeded, JSON.stringify(st.event)).stdout || '').replaceAll(JSON.stringify(hs).slice(1, -1), 'H').replaceAll(hs, 'H');
      if (a === b) same++; else diff.push(`${f} step ${i + 1}: ${a.slice(0, 120)} | ${b.slice(0, 120)}`);
    }
  }
  ok(`seeded rules file behaves like no file (${same} fixture steps identical)`, !diff.length && same > 0, diff.join('; '));

  const hooks = JSON.parse(fs.readFileSync(path.join(ROOT, 'hooks', 'hooks.json'), 'utf8')).hooks;
  const ss = hooks.SessionStart && hooks.SessionStart[0].hooks[0];
  ok('hooks.json runs guard.mjs with node at SessionStart', !!ss && ss.command === 'node' && ss.args[0] === '${CLAUDE_PLUGIN_ROOT}/hooks/guard.mjs');
}

// 11. Audit round 2 (WUG-01 .. WUG-10)
console.log('\n# audit round 2');
{
  const yes = (label, cond, extra) => { if (cond) pass++; else fail++; console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${cond ? '' : '  ' + (extra || '')}`); };
  const ev = (event, tool, input, extra = {}) => JSON.stringify({ hook_event_name: event, session_id: extra.sid || 's-a2', tool_name: tool, tool_input: input, ...extra.more });
  const bash = (event, command, more, sid) => ev(event, 'Bash', { command }, { more, sid });
  const CF = '<html><head><title>Just a moment...</title></head><body></body></html>';

  // WUG-01: MCP fetch tools are watched (hooks.json matcher) and count strikes
  const hooks = JSON.parse(fs.readFileSync(path.join(ROOT, 'hooks', 'hooks.json'), 'utf8')).hooks;
  for (const name of ['mcp__plugin_context-mode_context-mode__ctx_fetch_and_index', 'mcp__ScraplingServer__make_request', 'mcp__ScraplingServer__browser_fetch_once']) {
    const all = ['PreToolUse', 'PostToolUse', 'PostToolUseFailure'].every(e => new RegExp(`^(?:${hooks[e][0].matcher})$`).test(name));
    yes(`hooks.json matcher covers ${name} on every tool event`, all);
  }
  {
    const { env } = sandbox();
    check('ctx_fetch_and_index block counts a strike via "http"', run(env, ev('PostToolUse', 'mcp__plugin_context-mode_context-mode__ctx_fetch_and_index',
      { url: 'https://cf.example.com/page', source: 'x' }, { more: { tool_response: CF } })), 'context', 'on cf.example.com via "http", strike 1/2');
    check('ctx_fetch_and_index "requests" form is read too', run(env, ev('PostToolUse', 'mcp__plugin_context-mode_context-mode__ctx_fetch_and_index',
      { requests: [{ url: 'https://cf2.example.com/' }] }, { more: { tool_response: CF } })), 'context', 'on cf2.example.com');
    check('Scrapling MCP block counts a strike via "browser-stealth"', run(env, ev('PostToolUse', 'mcp__ScraplingServer__make_request',
      { url: 'https://sc.example.com/' }, { more: { tool_response: CF } })), 'context', 'on sc.example.com via "browser-stealth"');
  }

  // WUG-02: WEB_UNLOCK_FORCE=1 counts only as a real prefix of a command, not anywhere in the text
  {
    const { env } = sandbox();
    check('FORCE in a trailing comment does not skip R2', run(env, bash('PreToolUse', 'chrome --remote-debugging-port=9333 https://e.example.org # WEB_UNLOCK_FORCE=1')), 'deny', 'R2');
    check('FORCE in an echoed string does not skip R2', run(env, bash('PreToolUse', 'echo "WEB_UNLOCK_FORCE=1"; chrome --remote-debugging-port=9333 https://e.example.org')), 'deny', 'R2');
    check('FORCE as a command prefix still skips', run(env, bash('PreToolUse', 'WEB_UNLOCK_FORCE=1 chrome --remote-debugging-port=9333 https://e.example.org')), 'silent');
    check('FORCE after another assignment still skips', run(env, bash('PreToolUse', 'A=1 WEB_UNLOCK_FORCE=1 chrome --remote-debugging-port=9333 https://e.example.org')), 'silent');
  }

  // WUG-02 (owner decision b): no refusal of R1-R4 hints at the FORCE bypass
  {
    const { env } = sandbox();
    const noHint = (label, res, rule) => {
      const t = res.stdout || '';
      const ok = res.code === 0 && t.includes(rule) && !/FORCE/.test(t);
      if (ok) pass++; else fail++;
      console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + t.slice(0, 300)}`);
    };
    noHint('R2 refusal has no FORCE hint', run(env, bash('PreToolUse', 'chrome --remote-debugging-port=9333 https://e.example.org')), 'R2');
    for (let i = 0; i < 2; i++) run(env, bash('PostToolUse', 'curl -s https://hint.example.com/', { tool_response: { stdout: CF } }, 's-hint'));
    noHint('R3 refusal has no FORCE hint', run(env, bash('PreToolUse', 'chromium --headless https://hint.example.com/', undefined, 's-hint')), 'R3');
    noHint('R1 refusal has no FORCE hint', run(env, bash('PreToolUse', 'agent-browser open https://hint.example.com/', undefined, 's-hint')), 'R1');
    noHint('R4 refusal has no FORCE hint', run(env, bash('PreToolUse', 'wget -q https://hint.example.com/', undefined, 's-hint')), 'R4');
    check('FORCE prefix still skips R4', run(env, bash('PreToolUse', 'WEB_UNLOCK_FORCE=1 wget -q https://hint.example.com/', undefined, 's-hint')), 'silent');
  }

  // WUG-03: tool names inside a URL do not change the method
  {
    const { env } = sandbox();
    check('curl to a URL that names playwright stays "http"', run(env, bash('PostToolUse', 'curl -s https://github.com/microsoft/playwright', { tool_response: { stdout: CF } })), 'context', 'via "http"');
    check('curl to a URL that names apify stays "http"', run(env, bash('PostToolUse', 'curl -s https://apify.example.com/apify/crawlee', { tool_response: { stdout: CF } }, 's-a2b')), 'context', 'via "http"');
    check('curl through r.jina.ai is still "fetch-render"', run(env, bash('PostToolUse', 'curl -s https://r.jina.ai/https://j.example.com/', { tool_response: { stdout: CF } }, 's-a2c')), 'context', 'via "fetch-render"');
  }

  // WUG-04: user@host URLs count against the real host
  {
    const { env } = sandbox();
    check('https://a@b counts against b', run(env, bash('PostToolUse', 'curl -s https://a.example.com@b.example.com/', { tool_response: { stdout: CF } })), 'context', 'on b.example.com');
  }

  // WUG-05: every URL of a segment is checked
  {
    const { env } = sandbox();
    for (let i = 0; i < 2; i++) run(env, bash('PostToolUse', 'curl -s https://blk.example.com/', { tool_response: { stdout: CF } }));
    check('second URL in one curl segment is checked by R4', run(env, bash('PreToolUse', 'curl -s https://ok.example.com/ https://blk.example.com/')), 'deny', 'R4: 2 blocks on blk.example.com');
  }

  // WUG-06: find -exec, awk system(), git -c alias and gh alias/api are not exempt from your deny rules
  {
    const sb = sandbox();
    fs.mkdirSync(path.join(sb.home, '.config', 'web-unlock-guard'), { recursive: true });
    fs.writeFileSync(path.join(sb.home, '.config', 'web-unlock-guard', 'rules.json'), JSON.stringify({ deny: [{ name: 'no-json-new', pattern: '/json/new\\b', message: 'no' }] }));
    const J = 'http://127.0.0.1:9223/json/' + 'new';
    check('find -exec curl is checked', run(sb.env, bash('PreToolUse', `find . -name x -exec curl -s ${J} \\;`)), 'deny', 'no-json-new');
    check('awk system() is checked', run(sb.env, bash('PreToolUse', `awk 'BEGIN{system("curl -s ${J}")}'`)), 'deny', 'no-json-new');
    check('git -c alias with ! is checked', run(sb.env, bash('PreToolUse', `git -c alias.x='!curl -s ${J}' x`)), 'deny', 'no-json-new');
    check('gh alias set --shell is checked', run(sb.env, bash('PreToolUse', `gh alias set --shell x 'curl -s ${J}'`)), 'deny', 'no-json-new');
    check('plain find that prints the pattern stays exempt', run(sb.env, bash('PreToolUse', 'find . -name "json/new"')), 'silent');
    check('git commit message stays exempt', run(sb.env, bash('PreToolUse', 'git commit -m "deny /json/new"')), 'silent');
  }

  // WUG-07: R2 looks at the Chrome segment only
  {
    const { env } = sandbox();
    check('agent-browser in another segment does not excuse R2', run(env, bash('PreToolUse', 'chrome --remote-debugging-port=9222 https://e.example.org; agent-browser open https://x.example.org')), 'deny', 'R2');
    check('--user-data-dir in another segment does not excuse R2', run(env, bash('PreToolUse', 'echo --user-data-dir; chrome --remote-debugging-port=9222 https://e.example.org')), 'deny', 'R2');
    check('a backslash-continued launch with --user-data-dir passes', run(env, bash('PreToolUse', 'chrome \\\n  --remote-debugging-port=9222 \\\n  --user-data-dir=/tmp/p https://e.example.org')), 'silent');
  }

  // WUG-08: no lock in 2 s = the update is skipped, not written without the lock
  {
    const { env } = sandbox();
    const lock = env.WEB_UNLOCK_GUARD_STATE + '.lock';
    fs.writeFileSync(lock, '');
    const res = run(env, bash('PostToolUse', 'curl -s https://locked.example.com/', { tool_response: { stdout: 'HTTP/1.1 429' } }));
    const st = fs.existsSync(env.WEB_UNLOCK_GUARD_STATE) ? fs.readFileSync(env.WEB_UNLOCK_GUARD_STATE, 'utf8') : '';
    yes('held lock: nothing written, no strike reported', res.code === 0 && !res.stdout && !st.includes('locked.example.com'), `stdout ${res.stdout} state ${st}`);
    fs.unlinkSync(lock);
  }

  // WUG-09: auth answers from an API are not anti-bot blocks
  {
    const { env } = sandbox();
    check('401 with a JSON body is not a strike', run(env, bash('PostToolUse', 'curl -si https://api.example.com/v1/me', { tool_response: { stdout: 'HTTP/2 401\ncontent-type: application/json\n\n{"message":"Bad credentials"}' } })), 'silent');
    check('403 with a JSON body is not a strike', run(env, bash('PostToolUse', 'curl -si https://api.example.com/v1/me', { tool_response: { stdout: 'HTTP/1.1 403 Forbidden\ncontent-type: application/json\n\n{"message":"Resource not accessible by token"}' } })), 'silent');
    check('curl -f 401 is not a strike', run(env, bash('PostToolUseFailure', 'curl -sf https://api.example.com/v1/me', { error: 'Exit code 22\ncurl: (22) The requested URL returned error: 401' })), 'silent');
    check('a bare 403 page still counts', run(env, bash('PostToolUse', 'curl -si https://www2.example.com/', { tool_response: { stdout: 'HTTP/1.1 403 Forbidden' } })), 'context', 'strike 1/2');
  }

  // WUG-10: no host in the command = the response's links are not charged
  {
    const { env } = sandbox();
    check('URL in a variable: a link in the response is not charged', run(env, bash('PostToolUse', 'curl -s "$URL"', { tool_response: { stdout: CF + ' https://www.cloudflare.com/5xx-error-landing' } })), 'silent');
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
