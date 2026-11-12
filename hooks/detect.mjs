// Generic block detector, layer inference and escalation map. No dependencies.
// A companion skill can replace these by shipping its own lib/detect.mjs with the same exports.

// Strong signatures: anti-bot challenge pages and WAF block pages.
// The word "captcha" in prose does not count; only widget markers do.
const STRONG = [
  // Cloudflare
  [/cf-mitigated:\s*challenge/i, 'cloudflare-challenge', 'cloudflare'],
  [/Performing security verification/i, 'cloudflare-turnstile', 'cloudflare'],
  [/__cf_chl_|cf_chl_opt/i, 'cloudflare-challenge', 'cloudflare'],
  [/<title>\s*Just a moment\.\.\.\s*<\/title>|(^|\n)\s*Just a moment\.\.\.\s*($|\n)|(^|\n)Title:\s*Just a moment\.\.\.\s*($|\n)/i, 'cloudflare-js-challenge', 'cloudflare'],
  // Verification page a site serves behind Cloudflare (Indeed through r.jina.ai, 2026-11-09)
  [/Additional Verification Required[\s\S]{0,400}Ray ID for this request|Ray ID for this request[\s\S]{0,400}Waiting for [\w.-]+ to respond/i, 'cloudflare-verification-page', 'cloudflare'],
  [/Attention Required!\s*\|\s*Cloudflare|Sorry, you have been blocked/i, 'cloudflare-waf-block', 'cloudflare'],
  [/Enable JavaScript and cookies to continue/i, 'cloudflare-js-challenge', 'cloudflare'],
  // Other anti-bot vendors
  [/captcha-delivery\.com/i, 'datadome', 'datadome'],
  [/_pxAppId|px-captcha/i, 'perimeterx', 'perimeterx'],
  [/\bKPSDK\b/, 'kasada', 'kasada'],
  [/_Incapsula_Resource|Incapsula incident ID/i, 'incapsula', 'imperva'],
  [/Access Denied.{0,200}Reference #[0-9a-f.]+/is, 'akamai-block', 'akamai'],
  // Login walls
  [/linkedin\.com\/authwall|\bauthwall\b/i, 'authwall', 'linkedin'],
  // Reader proxies that return the target's error as a page
  [/Warning:\s*Target URL returned error\s*(4\d\d|5\d\d)/i, 'reader-target-error', 'reader'],
  // Generic denial as a title or heading
  [/<title>\s*Access Denied\s*<\/title>|<h1[^>]*>\s*Access Denied\s*<\/h1>/i, 'access-denied', 'generic'],
];
// Blocking HTTP statuses, from curl -i headers or the error line curl -f prints (no body). 401 is an
// authentication answer, never an anti-bot block, so it is not listed.
const STATUS = /(^|\n)HTTP\/[0-9.]+\s+(403|406|429|451|503)\b|curl: \(22\) The requested URL returned error:?\s*(403|406|429|451|503)\b/i;
// An API's own answer: a JSON content type or a JSON body. A 401/403 from it is a token problem, not a block.
const API_ANSWER = /(^|\n)content-type:\s*application\/([\w.+-]*\+)?json\b|(^|\n)\s*[{[]\s*"/i;
const AUTH_STATUS = /(^|\n)HTTP\/[0-9.]+\s+(401|403)\b/i;
// Widget markers: ordinary pages embed these too (a contact form with Turnstile or reCAPTCHA,
// Cloudflare's bot script). They count only on a thin page: under 600 visible characters of
// HTML, or under 2000 characters of plain text such as a browser snapshot.
const WIDGET = [
  [/Verify you are human|Widget containing a Cloudflare security challenge/i, 'cloudflare-turnstile', 'cloudflare'],
  [/challenges\.cloudflare\.com|\/cdn-cgi\/challenge-platform\/|cf-turnstile/i, 'cloudflare-challenge', 'cloudflare'],
  [/g-recaptcha|recaptcha\/api\.js|hcaptcha\.com\/1\/api\.js/i, 'captcha-widget', 'captcha'],
];
// Short error pages: only counted when the whole output is small, so docs prose does not trigger it.
const SHORT_PAGE = /Too Many Requests|Rate limit exceeded|\bForbidden\b|Access Denied|Request blocked|try again later|Service Unavailable/i;

function visibleText(t) {
  return t.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>|<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#\d+;|&[a-z]+;/gi, ' ')
    .replace(/\s+/g, ' ').trim();
}

export function detect(text) {
  const t = String(text || '');
  const vis = /<[a-z!/][^>]*>/i.test(t) ? visibleText(t) : null;
  for (const [re, reason, vendor] of STRONG) {
    const m = re.exec(t) || (vis && re.exec(vis));
    if (m) return { blocked: true, reason, vendor, match: m[0].slice(0, 80).replace(/\s+/g, ' ') };
  }
  // No anti-bot signature and an API's JSON answer to a 401/403: a bad token, not a block.
  if (AUTH_STATUS.test(t) && API_ANSWER.test(t)) return { blocked: false, reason: null, vendor: null, match: null };
  {
    const m = STATUS.exec(t);
    if (m) return { blocked: true, reason: 'http-blocked-status', vendor: 'http', match: m[0].trim().slice(0, 80) };
  }
  const thin = vis !== null ? vis.length < 600 : t.length < 2000;
  if (thin) {
    for (const [re, reason, vendor] of WIDGET) {
      const m = re.exec(t) || (vis && re.exec(vis));
      if (m) return { blocked: true, reason, vendor, match: m[0].slice(0, 80).replace(/\s+/g, ' ') };
    }
  }
  // Shell page: lots of HTML, almost no visible text (a JS-rendered block or login page).
  if (vis !== null && t.length > 10000 && vis.length < 600) {
    return { blocked: true, reason: 'shell-page', vendor: 'structural', match: `${t.length} bytes of HTML, ${vis.length} visible chars` };
  }
  if (t.length < 2000) {
    const m = SHORT_PAGE.exec(t);
    if (m) return { blocked: true, reason: 'short-error-page', vendor: 'http', match: m[0] };
  }
  return { blocked: false, reason: null, vendor: null, match: null };
}

// Which "method" (layer) a command uses. Strikes are counted per host + layer.
// The program the command runs decides first; tool names are then looked for in the text with its URLs
// removed, so a URL such as github.com/microsoft/playwright does not change the method. Reader and unlocker
// services are recognized by the host they are called on.
const URL_RE = /https?:\/\/[^\s'"<>`]+/gi;
const READER_HOST = /(^|\.)(r\.jina\.ai|api\.firecrawl\.dev)$/;
const UNLOCK_HOST = /(^|\.)(api\.apify\.com|brightdata\.com|scrapfly\.io|scraperapi\.com|zenrows\.com)$/;
const HTTP_PROGRAMS = new Set(['curl', 'wget', 'http', 'https', 'httpx', 'xh', 'curlie']);
function leadProgram(c) {
  const words = c.trim().replace(/^[({\s]+/, '').split(/\s+/);
  let i = 0;
  while (i < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]) || /^(env|sudo|command|exec|nohup|time|-\S+)$/.test(words[i]))) i++;
  return (words[i] || '').replace(/^["']|["']$/g, '').split(/[\\/]/).pop();
}
function urlHosts(c) {
  return (c.match(URL_RE) || []).map(u => { try { return new URL(u).hostname.toLowerCase(); } catch (_) { return ''; } }).filter(Boolean);
}
function serviceLayer(c) {
  const hosts = urlHosts(c);
  if (hosts.some(h => READER_HOST.test(h)) || /(^|[\s'"])r\.jina\.ai\//.test(c)) return 'fetch-render';
  if (hosts.some(h => UNLOCK_HOST.test(h))) return 'fetch-unlock';
  return null;
}
export function inferLayer(cmd) {
  const c = String(cmd || '');
  if (HTTP_PROGRAMS.has(leadProgram(c))) return serviceLayer(c) || 'http';
  const t = c.replace(URL_RE, ' ');
  if (/\bagent-browser\b/.test(t)) {
    if (/--auto-connect|--cdp\b/.test(t)) return 'browser-real';
    if (/--provider\b/.test(t)) return 'browser-cloud';
    return 'browser-automation';
  }
  if (/connectOverCDP|claude\s+--chrome|\bopencli\b/.test(t)) return 'browser-real';
  if (/\bpatchright\b|\bcamoufox\b|\bnodriver\b|\bzendriver\b|\bscrapling\b/.test(t)) return 'browser-stealth';
  if (/\bplaywright\b|\bpuppeteer\b|\bselenium\b|--headless|--remote-debugging-port/.test(t)) return 'browser-automation';
  if (/\bfirecrawl\b/.test(t)) return 'fetch-render';
  if (/\bapify\b|\bbrightdata\b|\bscrapfly\b|\bscraperapi\b|\bzenrows\b/.test(t)) return 'fetch-unlock';
  const svc = serviceLayer(c);
  if (svc) return svc;
  if (/\bcurl\b|\bwget\b|\bhttpx?\b|curl_cffi|urllib|requests\.get|fetch\(/.test(t)) return 'http';
  return null;
}

export const NEXT_LAYER = {
  'http': 'a rendering fetcher (e.g. r.jina.ai or Firecrawl) or a stealth fetcher',
  'fetch-render': 'an unlocker service, a site-specific API or scraper, or a real headed browser',
  'fetch-unlock': 'a real headed browser on your own Chrome profile',
  'browser-automation': 'a real headed browser (agent-browser --auto-connect, claude --chrome, or Chrome started with its own --user-data-dir)',
  'browser-stealth': 'a real headed browser or a cloud browser',
  'browser-real': 'the user: a captcha or login needs a human once, then the session persists',
  'browser-cloud': 'the user, or the site\'s internal API (record the request and replay it)',
};

// The first web host in a text. Every "http(s)://" starts a candidate (so a URL nested in another one's
// query string is seen too); the host is read with the URL parser, so user@host gives the real host.
// Local addresses and hosts without a top-level domain are skipped.
export function firstHost(s) {
  const str = String(s || '');
  const re = /https?:\/\//gi;
  let m;
  while ((m = re.exec(str))) {
    const cand = /^[^\s'"<>`]+/.exec(str.slice(m.index));
    if (!cand) continue;
    let h = '';
    try { h = new URL(cand[0]).hostname.toLowerCase(); } catch (_) { continue; }
    h = h.replace(/\.$/, '');
    if (!/\.(xn--[a-z0-9-]+|[a-z]{2,})$/.test(h) || /^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(h)) continue;
    return h.replace(/^www\./, '');
  }
  return null;
}
