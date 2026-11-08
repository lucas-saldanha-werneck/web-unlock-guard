// Generic block detector, layer inference and escalation map. No dependencies.
// A companion skill can replace these by shipping its own lib/detect.mjs with the same exports.

// Strong signatures: anti-bot challenge pages and WAF block pages.
// The word "captcha" in prose does not count; only widget markers do.
const STRONG = [
  // Cloudflare
  [/cf-mitigated:\s*challenge/i, 'cloudflare-challenge', 'cloudflare'],
  [/Performing security verification|Verify you are human|Widget containing a Cloudflare security challenge/i, 'cloudflare-turnstile', 'cloudflare'],
  [/challenges\.cloudflare\.com|\/cdn-cgi\/challenge-platform\/|__cf_chl_|cf-turnstile|cf_chl_opt/i, 'cloudflare-challenge', 'cloudflare'],
  [/<title>\s*Just a moment\.\.\.\s*<\/title>|(^|\n)\s*Just a moment\.\.\.\s*($|\n)/i, 'cloudflare-js-challenge', 'cloudflare'],
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
  // Captcha widgets
  [/g-recaptcha|recaptcha\/api\.js|hcaptcha\.com\/1\/api\.js/i, 'captcha-widget', 'captcha'],
  // Generic denial as a title or heading
  [/<title>\s*Access Denied\s*<\/title>|<h1[^>]*>\s*Access Denied\s*<\/h1>/i, 'access-denied', 'generic'],
  [/(^|\n)HTTP\/[0-9.]+\s+(401|403|406|429|451|503)\b/i, 'http-blocked-status', 'http'],
  // curl -f prints the status as an error line and no body
  [/curl: \(22\) The requested URL returned error:?\s*(401|403|406|429|451|503)\b/i, 'http-blocked-status', 'http'],
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
export function inferLayer(cmd) {
  const c = String(cmd || '');
  if (/\bagent-browser\b/.test(c)) {
    if (/--auto-connect|--cdp\b/.test(c)) return 'browser-real';
    if (/--provider\b/.test(c)) return 'browser-cloud';
    return 'browser-automation';
  }
  if (/connectOverCDP|claude\s+--chrome|\bopencli\b/.test(c)) return 'browser-real';
  if (/\bpatchright\b|\bcamoufox\b|\bnodriver\b|\bzendriver\b|\bscrapling\b/.test(c)) return 'browser-stealth';
  if (/\bplaywright\b|\bpuppeteer\b|\bselenium\b|--headless|--remote-debugging-port/.test(c)) return 'browser-automation';
  if (/\bfirecrawl\b|r\.jina\.ai/.test(c)) return 'fetch-render';
  if (/api\.apify\.com|\bapify\b|brightdata|scrapfly|scraperapi|zenrows/.test(c)) return 'fetch-unlock';
  if (/\bcurl\b|\bwget\b|\bhttpx?\b|curl_cffi|urllib|requests\.get|fetch\(/.test(c)) return 'http';
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

export function firstHost(s) {
  const m = /https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/i.exec(String(s || ''));
  if (!m) return null;
  const h = m[1].toLowerCase();
  if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(h)) return null;
  return h.replace(/^www\./, '');
}
