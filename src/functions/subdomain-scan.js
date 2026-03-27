const { app } = require('@azure/functions');
const { checkTLS, calculateGrade } = require('../lib/ssl-utils');
const { analyzeHeaders } = require('../lib/headers-scoring');

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const MAX_SUBDOMAINS = 10;
const SUBDOMAIN_TIMEOUT_MS = 8000;
const FETCH_TIMEOUT_MS = 5000;

function cleanDomain(input) {
  let d = String(input).trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '');
  d = d.split('/')[0];
  d = d.split(':')[0];
  return d;
}

function timeoutPromise(ms, label) {
  return new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`Timeout after ${ms}ms for ${label}`)), ms)
  );
}

async function scanSubdomain(subdomain) {
  const issues = [];
  let sslGrade = null;
  let sslScore = 0;
  let headersGrade = null;
  let headersScore = 0;

  // SSL check
  try {
    const tlsResult = await checkTLS(subdomain, 443, { timeout: FETCH_TIMEOUT_MS });
    const grade = calculateGrade(tlsResult);
    sslGrade = grade.grade;
    sslScore = grade.score;
    if (grade.issues && grade.issues.length > 0) {
      issues.push(...grade.issues);
    }
  } catch (err) {
    issues.push(`SSL check failed: ${err.message}`);
  }

  // Headers check
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(`https://${subdomain}`, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const rawHeaders = {};
    for (const [key, value] of response.headers.entries()) {
      rawHeaders[key.toLowerCase()] = value;
    }

    const headerAnalysis = analyzeHeaders(rawHeaders, true);
    headersGrade = headerAnalysis.grade;
    headersScore = headerAnalysis.score;
    if (headerAnalysis.missingCritical && headerAnalysis.missingCritical.length > 0) {
      issues.push(...headerAnalysis.missingCritical.map((h) => `Missing: ${h}`));
    }
  } catch (err) {
    issues.push(`Headers check failed: ${err.message}`);
  }

  return {
    subdomain,
    sslGrade,
    sslScore,
    headersGrade,
    headersScore,
    issues,
  };
}

async function handler(request, context) {
  if (request.method === 'OPTIONS') {
    return { status: 204, headers: CORS_HEADERS };
  }

  try {
    const body = await request.json();
    const { domain, subdomains } = body || {};

    if (!domain || typeof domain !== 'string') {
      return {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: 'domain is required and must be a string' },
      };
    }

    if (!Array.isArray(subdomains)) {
      return {
        status: 400,
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
        jsonBody: { error: 'subdomains must be an array' },
      };
    }

    const cleanedDomain = cleanDomain(domain);

    // Validate and cap subdomains
    const validSubdomains = subdomains
      .map((s) => String(s).trim().toLowerCase())
      .filter((s) => s.endsWith(`.${cleanedDomain}`))
      .slice(0, MAX_SUBDOMAINS);

    // Scan all subdomains in parallel with per-subdomain timeout
    const promises = validSubdomains.map((subdomain) =>
      Promise.race([
        scanSubdomain(subdomain),
        timeoutPromise(SUBDOMAIN_TIMEOUT_MS, subdomain),
      ])
    );

    const settled = await Promise.allSettled(promises);

    const results = settled.map((result, i) => {
      if (result.status === 'fulfilled') {
        return result.value;
      }
      return {
        subdomain: validSubdomains[i],
        sslGrade: null,
        sslScore: 0,
        headersGrade: null,
        headersScore: 0,
        issues: [`Scan failed: ${result.reason?.message || 'Unknown error'}`],
      };
    });

    return {
      status: 200,
      headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      jsonBody: { results },
    };
  } catch (err) {
    return {
      status: 500,
      headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      jsonBody: { error: 'Internal server error', message: err.message },
    };
  }
}

app.http('subdomain-scan', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler,
});
