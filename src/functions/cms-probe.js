const { app } = require('@azure/functions');
const https = require('https');
const http = require('http');

/**
 * CMS & Sensitive Path Probe
 * Scans a domain for exposed CMS admin panels, debug files, environment leaks,
 * and other sensitive paths that attackers commonly exploit.
 */

const PROBES = [
  // WordPress
  // allow403: true means a 403 is evidence the path exists (login/admin pages).
  // By default 403 is ignored — WAFs like Cloudflare return 403 for any blocked path.
  { path: '/wp-login.php', cms: 'WordPress', risk: 'medium', description: 'WordPress login page is publicly accessible', method: 'HEAD', allow403: true },
  { path: '/xmlrpc.php', cms: 'WordPress', risk: 'high', description: 'XML-RPC enabled — potential brute-force and DDoS vector', method: 'HEAD' },
  { path: '/wp-json/wp/v2/users', cms: 'WordPress', risk: 'high', description: 'WordPress user enumeration endpoint is accessible', method: 'GET', checkBody: true },
  { path: '/readme.html', cms: 'WordPress', risk: 'medium', description: 'WordPress readme.html exposes version information', method: 'HEAD' },
  { path: '/wp-content/debug.log', cms: 'WordPress', risk: 'critical', description: 'WordPress debug log is publicly accessible — may contain sensitive data', method: 'HEAD' },

  // Joomla
  { path: '/administrator', cms: 'Joomla', risk: 'medium', description: 'Joomla admin panel is publicly accessible', method: 'HEAD', allow403: true },
  { path: '/configuration.php.bak', cms: 'Joomla', risk: 'critical', description: 'Joomla configuration backup file may contain database credentials', method: 'HEAD' },

  // Drupal
  { path: '/user/login', cms: 'Drupal', risk: 'low', description: 'Drupal login page is publicly accessible', method: 'HEAD', allow403: true },
  { path: '/CHANGELOG.txt', cms: 'Drupal', risk: 'medium', description: 'Drupal changelog exposes version information', method: 'HEAD' },

  // Generic — never treat 403 as found (WAF false positives)
  { path: '/.env', cms: null, risk: 'critical', description: 'Environment file exposed — may contain API keys, database credentials, secrets', method: 'HEAD' },
  { path: '/.git/HEAD', cms: null, risk: 'critical', description: 'Git repository exposed — source code and history accessible', method: 'GET', checkBody: true, bodyPattern: /^ref:/ },
  { path: '/server-status', cms: null, risk: 'high', description: 'Apache server-status page exposed — reveals active connections and URLs', method: 'HEAD' },
  { path: '/phpinfo.php', cms: null, risk: 'critical', description: 'phpinfo() page exposed — reveals full server configuration', method: 'HEAD' },
  { path: '/robots.txt', cms: null, risk: 'info', description: 'robots.txt found', method: 'GET', checkBody: true },
  { path: '/sitemap.xml', cms: null, risk: 'info', description: 'Sitemap found', method: 'HEAD' },
  { path: '/.well-known/security.txt', cms: null, risk: 'info', description: 'security.txt found — security contact information available', positive: true, method: 'HEAD' },
];

const RECOMMENDATIONS = {
  '/wp-login.php': 'Restrict login page access to known IPs or add two-factor authentication.',
  '/xmlrpc.php': 'Disable XML-RPC if not needed, or restrict access via .htaccess or WAF rules.',
  '/wp-json/wp/v2/users': 'Disable the REST API users endpoint or require authentication.',
  '/readme.html': 'Delete readme.html from the WordPress root directory.',
  '/wp-content/debug.log': 'Delete debug.log immediately and disable WP_DEBUG_LOG in production.',
  '/administrator': 'Restrict admin panel access to known IPs.',
  '/configuration.php.bak': 'Delete configuration backup file immediately. Rotate database credentials.',
  '/user/login': 'Consider restricting login page access or adding rate limiting.',
  '/CHANGELOG.txt': 'Delete CHANGELOG.txt to prevent version disclosure.',
  '/.env': 'Remove .env from web root immediately. Rotate all exposed credentials.',
  '/.git/HEAD': 'Block access to .git directory via web server configuration. Rotate any exposed secrets.',
  '/server-status': 'Disable mod_status or restrict to localhost only.',
  '/phpinfo.php': 'Delete phpinfo.php immediately — it reveals your entire server configuration.',
  '/robots.txt': 'Review robots.txt for unintentionally disclosed sensitive paths.',
  '/sitemap.xml': 'Review sitemap for any pages that should not be publicly indexed.',
  '/.well-known/security.txt': 'Good practice — security.txt helps researchers report vulnerabilities responsibly.',
};

const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SENSITIVE_ROBOTS_PATTERNS = [
  /admin/i, /backup/i, /\.env/i, /config/i, /secret/i, /private/i,
  /database/i, /dump/i, /\.sql/i, /\.bak/i, /\.log/i, /cgi-bin/i,
  /\.git/i, /\.svn/i, /\.htaccess/i, /phpmyadmin/i, /cpanel/i,
  /wp-admin/i, /server-status/i, /server-info/i,
];

function cleanDomain(input) {
  if (!input) return null;
  let domain = String(input).trim();
  // Remove protocol
  domain = domain.replace(/^https?:\/\//i, '');
  // Remove path, query, fragment
  domain = domain.split('/')[0];
  // Remove port
  domain = domain.split(':')[0];
  // Remove trailing dots
  domain = domain.replace(/\.+$/, '');
  return domain || null;
}

function fetchUrl(url, method, timeout) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const lib = parsedUrl.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: method,
      timeout: timeout,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; InventiveHQ-SecurityScanner/1.0)',
        'Accept': '*/*',
      },
      rejectUnauthorized: false,
    };

    const req = lib.request(options, (res) => {
      if (method === 'HEAD') {
        resolve({ status: res.statusCode, body: null, headers: res.headers });
        res.resume();
        return;
      }
      const chunks = [];
      let size = 0;
      const maxSize = 256 * 1024; // 256KB limit
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size <= maxSize) chunks.push(chunk);
      });
      res.on('end', () => {
        resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8'), headers: res.headers });
      });
      res.on('error', reject);
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

function parseRobotsDisallow(body) {
  if (!body) return [];
  const sensitive = [];
  const lines = body.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.toLowerCase().startsWith('disallow:')) continue;
    const path = trimmed.substring(9).trim();
    if (!path) continue;
    for (const pattern of SENSITIVE_ROBOTS_PATTERNS) {
      if (pattern.test(path)) {
        sensitive.push(path);
        break;
      }
    }
  }
  return [...new Set(sensitive)];
}

async function runProbe(domain, probe) {
  const url = `https://${domain}${probe.path}`;
  try {
    const result = await fetchUrl(url, probe.method, 3000);
    const { status, body } = result;

    // For HEAD probes: 200 = found
    if (!probe.checkBody) {
      if (status === 200) {
        return { found: true, status, probe };
      }
      if (status === 403 && probe.allow403) {
        return { found: true, status, probe, blocked: true };
      }
      return { found: false, status, probe };
    }

    // GET probes with body checks
    if (status !== 200) {
      return { found: false, status, probe };
    }

    // /wp-json/wp/v2/users — check for JSON array
    if (probe.path === '/wp-json/wp/v2/users') {
      try {
        const parsed = JSON.parse(body);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return { found: true, status, probe };
        }
      } catch {
        // Not valid JSON — not a real user enumeration endpoint
      }
      return { found: false, status, probe };
    }

    // /.git/HEAD — check for ref: pattern
    if (probe.bodyPattern) {
      if (probe.bodyPattern.test(body)) {
        return { found: true, status, probe };
      }
      return { found: false, status, probe };
    }

    // /robots.txt — always "found" at 200, parse for sensitive paths
    if (probe.path === '/robots.txt') {
      const sensitiveDisallow = parseRobotsDisallow(body);
      return { found: true, status, probe, robotsDisallow: sensitiveDisallow };
    }

    // Default for other GET+checkBody probes
    return { found: true, status, probe };
  } catch {
    return { found: false, status: null, probe, error: true };
  }
}

async function handler(request, context) {
  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  // Preflight
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
        jsonBody: { error: 'Missing or invalid domain parameter' },
      };
    }

    const startTime = Date.now();

    // Run all probes in parallel
    const results = await Promise.allSettled(
      PROBES.map((probe) => runProbe(domain, probe))
    );

    const findings = [];
    let robotsDisallow = [];
    let hasSecurityTxt = false;
    const cmsVotes = {};

    for (const result of results) {
      if (result.status !== 'fulfilled') continue;
      const { found, status, probe, blocked, robotsDisallow: rd } = result.value;

      if (!found) continue;

      // Track robots.txt sensitive disallow paths
      if (probe.path === '/robots.txt' && rd) {
        robotsDisallow = rd;
      }

      // Track security.txt
      if (probe.path === '/.well-known/security.txt' && probe.positive) {
        hasSecurityTxt = true;
      }

      // Track CMS detections
      if (probe.cms) {
        cmsVotes[probe.cms] = (cmsVotes[probe.cms] || 0) + 1;
      }

      findings.push({
        path: probe.path,
        status: status,
        found: true,
        risk: probe.risk,
        cms: probe.cms,
        description: blocked
          ? `${probe.description} (blocked with 403 but path exists)`
          : probe.description,
        recommendation: RECOMMENDATIONS[probe.path] || 'Review and restrict access to this resource.',
        ...(probe.positive ? { positive: true } : {}),
      });
    }

    // Sort findings by risk severity (critical first)
    findings.sort((a, b) => (RISK_ORDER[a.risk] ?? 99) - (RISK_ORDER[b.risk] ?? 99));

    // Determine detected CMS (most votes wins)
    let detectedCms = null;
    let maxVotes = 0;
    for (const [cms, votes] of Object.entries(cmsVotes)) {
      if (votes > maxVotes) {
        maxVotes = votes;
        detectedCms = cms;
      }
    }

    // Build summary counts
    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    for (const f of findings) {
      summary[f.risk] = (summary[f.risk] || 0) + 1;
      summary.total++;
    }

    const scanDuration = parseFloat(((Date.now() - startTime) / 1000).toFixed(2));

    return {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      jsonBody: {
        domain,
        timestamp: new Date().toISOString(),
        scanDuration,
        cms: detectedCms,
        findings,
        summary,
        robotsDisallow,
        hasSecurityTxt,
      },
    };
  } catch (err) {
    return {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      jsonBody: { error: 'Internal server error', message: err.message },
    };
  }
}

app.http('cms-probe', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler,
});
