const { app } = require('@azure/functions');
const https = require('https');
const http = require('http');

/**
 * Technology Detection + CVE Matching
 * Detects web technologies via headers, cookies, HTML patterns, and path probes.
 */

// CVE lookup map — empty for v1, will be populated later
const KNOWN_CVES = {};

// --- Signature Definitions ---

const HEADER_SIGNATURES = {
  server: [
    { name: 'Apache', category: 'Web Server', regex: /Apache\/([\d.]+)/i, versionGroup: 1 },
    { name: 'Apache', category: 'Web Server', regex: /^Apache$/i },
    { name: 'nginx', category: 'Web Server', regex: /nginx\/([\d.]+)/i, versionGroup: 1 },
    { name: 'nginx', category: 'Web Server', regex: /^nginx$/i },
    { name: 'Cloudflare', category: 'CDN', regex: /cloudflare/i },
    { name: 'Microsoft IIS', category: 'Web Server', regex: /IIS\/([\d.]+)/i, versionGroup: 1 },
    { name: 'Microsoft IIS', category: 'Web Server', regex: /Microsoft-IIS/i },
    { name: 'LiteSpeed', category: 'Web Server', regex: /litespeed/i },
    { name: 'OpenResty', category: 'Web Server', regex: /openresty/i },
  ],
  'x-powered-by': [
    { name: 'PHP', category: 'Language', regex: /PHP\/([\d.]+)/i, versionGroup: 1 },
    { name: 'PHP', category: 'Language', regex: /PHP/i },
    { name: 'ASP.NET', category: 'Framework', regex: /ASP\.NET/i },
    { name: 'Express', category: 'Framework', regex: /Express/i },
    { name: 'Next.js', category: 'Framework', regex: /Next\.js/i },
  ],
  'x-generator': [
    { name: 'WordPress', category: 'CMS', regex: /WordPress/i },
    { name: 'Joomla', category: 'CMS', regex: /Joomla/i },
    { name: 'Drupal', category: 'CMS', regex: /Drupal/i },
  ],
  'x-aspnet-version': [
    { name: 'ASP.NET', category: 'Framework', regex: /([\d.]+)/, versionGroup: 1 },
  ],
};

const COOKIE_SIGNATURES = [
  { pattern: /PHPSESSID/i, name: 'PHP', category: 'Language' },
  { pattern: /JSESSIONID/i, name: 'Java', category: 'Language' },
  { pattern: /ASP\.NET_SessionId/i, name: 'ASP.NET', category: 'Framework' },
  { pattern: /wp-settings/i, name: 'WordPress', category: 'CMS' },
  { pattern: /__cfduid|__cf_bm/i, name: 'Cloudflare', category: 'CDN' },
];

const HTML_PATTERNS = [
  { regex: /<meta\s+name=["']generator["']\s+content=["']WordPress\s*(\d[\d.]*)?/i, name: 'WordPress', category: 'CMS', versionGroup: 1 },
  { regex: /<meta\s+name=["']generator["']\s+content=["']Joomla/i, name: 'Joomla', category: 'CMS' },
  { regex: /<meta\s+name=["']generator["']\s+content=["']Drupal/i, name: 'Drupal', category: 'CMS' },
  { regex: /jquery[/.\-]?([\d.]+)(?:\.min)?\.js/i, name: 'jQuery', category: 'JavaScript Library', versionGroup: 1 },
  { regex: /bootstrap[/.\-]?([\d.]+)/i, name: 'Bootstrap', category: 'CSS Framework', versionGroup: 1 },
  { regex: /react[/.\-]?(?:dom)?[/.\-]?([\d.]+)/i, name: 'React', category: 'JavaScript Library', versionGroup: 1 },
  { regex: /vue[/.\-]?([\d.]+)/i, name: 'Vue.js', category: 'JavaScript Library', versionGroup: 1 },
  { regex: /angular[/.\-]?([\d.]+)/i, name: 'Angular', category: 'Framework', versionGroup: 1 },
  { regex: /wp-content|wp-includes/i, name: 'WordPress', category: 'CMS' },
  { regex: /next\.js|__NEXT_DATA__/i, name: 'Next.js', category: 'Framework' },
];

const PATH_PROBES = [
  { path: '/wp-login.php', name: 'WordPress', category: 'CMS', successCodes: [200, 302] },
  { path: '/wp-json', name: 'WordPress', category: 'CMS', successCodes: [200] },
  { path: '/administrator', name: 'Joomla', category: 'CMS', successCodes: [200, 302] },
  { path: '/user/login', name: 'Drupal', category: 'CMS', successCodes: [200, 302] },
];

// --- Helpers ---

/**
 * Clean a domain string: strip protocol, paths, ports, whitespace
 */
function cleanDomain(input) {
  if (!input || typeof input !== 'string') return '';
  return input
    .trim()
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .split(':')[0]
    .trim()
    .toLowerCase();
}

/**
 * Fetch a URL with timeout and redirect following, return { headers, body, statusCode }
 */
function fetchUrl(url, timeoutMs = 8000, method = 'GET', maxBodyBytes = 200 * 1024) {
  return new Promise((resolve, reject) => {
    const proto = url.startsWith('https') ? https : http;
    const options = {
      method,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; InventiveHQ-TechDetect/1.0)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
      },
      timeout: timeoutMs,
      // Follow redirects manually up to 5 hops
    };

    let redirectCount = 0;
    const maxRedirects = 5;

    function doRequest(requestUrl) {
      const reqProto = requestUrl.startsWith('https') ? https : http;
      const req = reqProto.request(requestUrl, options, (res) => {
        // Follow redirects
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirectCount < maxRedirects) {
          redirectCount++;
          let location = res.headers.location;
          if (location.startsWith('/')) {
            const parsed = new URL(requestUrl);
            location = `${parsed.protocol}//${parsed.host}${location}`;
          }
          res.resume(); // drain response
          doRequest(location);
          return;
        }

        const chunks = [];
        let totalBytes = 0;

        res.on('data', (chunk) => {
          if (totalBytes < maxBodyBytes) {
            chunks.push(chunk);
            totalBytes += chunk.length;
          }
        });

        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: method === 'HEAD' ? '' : Buffer.concat(chunks).toString('utf-8').slice(0, maxBodyBytes),
          });
        });

        res.on('error', reject);
      });

      req.setTimeout(timeoutMs, () => {
        req.destroy();
        reject(new Error(`Request timeout after ${timeoutMs}ms`));
      });

      req.on('error', reject);
      req.end();
    }

    doRequest(url);
  });
}

/**
 * HEAD request to a path, return status code or null on error
 */
async function headProbe(domain, path, timeoutMs = 3000) {
  const url = `https://${domain}${path}`;
  try {
    const result = await fetchUrl(url, timeoutMs, 'HEAD');
    return result.statusCode;
  } catch {
    return null;
  }
}

/**
 * Look up CVEs for a technology + version
 */
function lookupCves(name, version) {
  if (!version) return [];
  const key = `${name.toLowerCase()}@${version}`;
  return KNOWN_CVES[key] || [];
}

// --- Detection Methods ---

/**
 * Detect technologies from response headers
 */
function detectFromHeaders(headers) {
  const results = [];
  if (!headers) return results;

  for (const [headerName, signatures] of Object.entries(HEADER_SIGNATURES)) {
    const headerValue = headers[headerName];
    if (!headerValue) continue;

    for (const sig of signatures) {
      const match = headerValue.match(sig.regex);
      if (match) {
        const version = sig.versionGroup ? (match[sig.versionGroup] || null) : null;
        results.push({
          name: sig.name,
          version,
          category: sig.category,
          source: 'header',
          cves: lookupCves(sig.name, version),
        });
        break; // first match per header per tech name is enough
      }
    }
  }

  return results;
}

/**
 * Detect technologies from Set-Cookie header
 */
function detectFromCookies(headers) {
  const results = [];
  if (!headers) return results;

  const setCookie = headers['set-cookie'];
  if (!setCookie) return results;

  // set-cookie can be a string or array
  const cookieStr = Array.isArray(setCookie) ? setCookie.join('; ') : setCookie;

  for (const sig of COOKIE_SIGNATURES) {
    if (sig.pattern.test(cookieStr)) {
      results.push({
        name: sig.name,
        version: null,
        category: sig.category,
        source: 'cookie',
        cves: [],
      });
    }
  }

  return results;
}

/**
 * Detect technologies from HTML body
 */
function detectFromHtml(body) {
  const results = [];
  if (!body) return results;

  for (const pattern of HTML_PATTERNS) {
    const match = body.match(pattern.regex);
    if (match) {
      const version = pattern.versionGroup ? (match[pattern.versionGroup] || null) : null;
      results.push({
        name: pattern.name,
        version: version || null,
        category: pattern.category,
        source: 'html',
        cves: lookupCves(pattern.name, version),
      });
    }
  }

  return results;
}

/**
 * Detect technologies via path probes (HEAD requests in parallel)
 */
async function detectFromPathProbes(domain) {
  const results = [];

  const probeResults = await Promise.allSettled(
    PATH_PROBES.map(async (probe) => {
      const statusCode = await headProbe(domain, probe.path);
      return { ...probe, statusCode };
    })
  );

  for (const result of probeResults) {
    if (result.status !== 'fulfilled') continue;
    const { name, category, successCodes, statusCode } = result.value;
    if (statusCode !== null && successCodes.includes(statusCode)) {
      results.push({
        name,
        version: null,
        category,
        source: 'path-probe',
        cves: [],
      });
    }
  }

  return results;
}

/**
 * Deduplicate technologies by name, preferring entries with versions
 */
function deduplicateTechnologies(techs) {
  const map = new Map();

  for (const tech of techs) {
    const key = tech.name.toLowerCase();
    const existing = map.get(key);

    if (!existing) {
      map.set(key, tech);
    } else {
      // Prefer the entry with a version
      if (!existing.version && tech.version) {
        map.set(key, tech);
      }
    }
  }

  return Array.from(map.values());
}

// --- Main Handler ---

app.http('tech-detect', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle preflight
    if (request.method === 'OPTIONS') {
      return { status: 204, headers: corsHeaders };
    }

    try {
      const body = await request.json();
      const domain = cleanDomain(body.domain);

      if (!domain) {
        return {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'A valid domain is required' }),
        };
      }

      context.log(`Tech detection for: ${domain}`);

      let allDetections = [];

      // Step 1: Fetch the page (headers + HTML body)
      let pageHeaders = null;
      let pageBody = '';

      try {
        const response = await fetchUrl(`https://${domain}`, 8000, 'GET');
        pageHeaders = response.headers;
        pageBody = response.body;
      } catch (err) {
        context.warn(`Primary fetch failed for ${domain}: ${err.message}`);
        // Try HTTP fallback
        try {
          const response = await fetchUrl(`http://${domain}`, 8000, 'GET');
          pageHeaders = response.headers;
          pageBody = response.body;
        } catch (err2) {
          context.warn(`HTTP fallback also failed for ${domain}: ${err2.message}`);
        }
      }

      // Step 2: Detect from headers
      try {
        const headerTechs = detectFromHeaders(pageHeaders);
        allDetections.push(...headerTechs);
      } catch (err) {
        context.warn(`Header detection error: ${err.message}`);
      }

      // Step 3: Detect from cookies
      try {
        const cookieTechs = detectFromCookies(pageHeaders);
        allDetections.push(...cookieTechs);
      } catch (err) {
        context.warn(`Cookie detection error: ${err.message}`);
      }

      // Step 4: Detect from HTML
      try {
        const htmlTechs = detectFromHtml(pageBody);
        allDetections.push(...htmlTechs);
      } catch (err) {
        context.warn(`HTML detection error: ${err.message}`);
      }

      // Step 5: Path probes (parallel HEAD requests)
      try {
        const probeTechs = await detectFromPathProbes(domain);
        allDetections.push(...probeTechs);
      } catch (err) {
        context.warn(`Path probe error: ${err.message}`);
      }

      // Deduplicate
      const technologies = deduplicateTechnologies(allDetections);

      return {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain,
          timestamp: new Date().toISOString(),
          technologies,
        }, null, 2),
      };

    } catch (error) {
      context.error('Tech detection error:', error);

      return {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          error: 'Technology detection failed',
          message: error.message,
        }),
      };
    }
  },
});
