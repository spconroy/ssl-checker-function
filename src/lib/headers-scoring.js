/**
 * Security headers scoring — ported from lib/security-headers-scoring.ts
 * Used by subdomain-scan to grade headers without the inventivehq.com runtime.
 */

function analyzeCSP(headers) {
  const value = headers['content-security-policy'] || headers['content-security-policy-report-only'] || null;
  if (!value) {
    return { name: 'Content-Security-Policy', score: 0, status: 'fail', severity: 'critical', value: null, recommendation: 'Add a Content-Security-Policy header to prevent XSS and code injection attacks.' };
  }
  const hasUnsafeInline = value.includes("'unsafe-inline'");
  const hasUnsafeEval = value.includes("'unsafe-eval'");
  const hasNonces = /nonce-[a-zA-Z0-9+/=]+/.test(value);
  const hasHashes = /sha(256|384|512)-[a-zA-Z0-9+/=]+/.test(value);

  if (hasUnsafeInline && hasUnsafeEval) {
    return { name: 'Content-Security-Policy', score: 40, status: 'warn', severity: 'high', value, recommendation: 'Remove unsafe-inline and unsafe-eval directives from your CSP.' };
  }
  if (hasUnsafeInline) {
    return { name: 'Content-Security-Policy', score: 60, status: 'warn', severity: 'medium', value, recommendation: 'Remove unsafe-inline from your CSP. Use nonces or hashes instead.' };
  }
  if (hasNonces || hasHashes) {
    return { name: 'Content-Security-Policy', score: 95, status: 'pass', severity: 'low', value, recommendation: 'CSP is well configured with nonces/hashes.' };
  }
  return { name: 'Content-Security-Policy', score: 75, status: 'pass', severity: 'low', value, recommendation: 'Consider adding nonces or hashes for stricter CSP.' };
}

function analyzeHSTS(headers, isHttps) {
  const value = headers['strict-transport-security'] || null;
  if (!isHttps) {
    return { name: 'Strict-Transport-Security', score: 0, status: 'info', severity: 'info', value: null, recommendation: 'HSTS only applies to HTTPS sites.' };
  }
  if (!value) {
    return { name: 'Strict-Transport-Security', score: 0, status: 'fail', severity: 'high', value: null, recommendation: 'Add HSTS header with max-age of at least 31536000 (1 year).' };
  }
  let score = 50;
  const maxAgeMatch = value.match(/max-age=(\d+)/);
  if (maxAgeMatch && parseInt(maxAgeMatch[1]) >= 31536000) { score += 10; }
  if (/includesubdomains/i.test(value)) { score += 10; }
  if (/preload/i.test(value)) { score += 10; }
  const status = score >= 70 ? 'pass' : 'warn';
  return { name: 'Strict-Transport-Security', score: Math.min(score, 100), status, severity: status === 'pass' ? 'low' : 'medium', value, recommendation: score < 80 ? 'Add includeSubDomains and preload directives to your HSTS header.' : 'HSTS is well configured.' };
}

function analyzeXFrameOptions(headers) {
  const value = headers['x-frame-options'] || null;
  if (!value) {
    return { name: 'X-Frame-Options', score: 0, status: 'fail', severity: 'high', value: null, recommendation: 'Add X-Frame-Options header set to DENY or SAMEORIGIN to prevent clickjacking.' };
  }
  if (/allow-from/i.test(value)) {
    return { name: 'X-Frame-Options', score: 60, status: 'warn', severity: 'medium', value, recommendation: 'ALLOW-FROM is deprecated. Use CSP frame-ancestors instead.' };
  }
  return { name: 'X-Frame-Options', score: 100, status: 'pass', severity: 'low', value, recommendation: 'X-Frame-Options is properly configured.' };
}

function analyzeXContentTypeOptions(headers) {
  const value = headers['x-content-type-options'] || null;
  if (!value || value.toLowerCase() !== 'nosniff') {
    return { name: 'X-Content-Type-Options', score: 0, status: 'fail', severity: 'medium', value, recommendation: 'Set X-Content-Type-Options to "nosniff" to prevent MIME-type sniffing.' };
  }
  return { name: 'X-Content-Type-Options', score: 100, status: 'pass', severity: 'low', value, recommendation: 'X-Content-Type-Options is properly configured.' };
}

function analyzeReferrerPolicy(headers) {
  const value = headers['referrer-policy'] || null;
  if (!value) {
    return { name: 'Referrer-Policy', score: 0, status: 'warn', severity: 'medium', value: null, recommendation: 'Add a Referrer-Policy header to control referrer information leakage.' };
  }
  const strict = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
  if (strict.includes(value.toLowerCase())) {
    return { name: 'Referrer-Policy', score: 100, status: 'pass', severity: 'low', value, recommendation: 'Referrer-Policy is well configured.' };
  }
  return { name: 'Referrer-Policy', score: 50, status: 'warn', severity: 'medium', value, recommendation: 'Consider a stricter referrer policy like strict-origin-when-cross-origin.' };
}

function analyzePermissionsPolicy(headers) {
  const value = headers['permissions-policy'] || headers['feature-policy'] || null;
  if (!value) {
    return { name: 'Permissions-Policy', score: 0, status: 'warn', severity: 'low', value: null, recommendation: 'Add a Permissions-Policy header to restrict browser features.' };
  }
  return { name: 'Permissions-Policy', score: 100, status: 'pass', severity: 'low', value, recommendation: 'Permissions-Policy is configured.' };
}

function analyzeCOOP(headers) {
  const value = headers['cross-origin-opener-policy'] || null;
  if (!value) {
    return { name: 'Cross-Origin-Opener-Policy', score: 0, status: 'warn', severity: 'low', value: null, recommendation: 'Add Cross-Origin-Opener-Policy header for cross-origin isolation.' };
  }
  if (value.includes('same-origin')) {
    return { name: 'Cross-Origin-Opener-Policy', score: 100, status: 'pass', severity: 'low', value, recommendation: 'COOP is properly configured.' };
  }
  return { name: 'Cross-Origin-Opener-Policy', score: 50, status: 'warn', severity: 'low', value, recommendation: 'Consider setting COOP to same-origin for full isolation.' };
}

function analyzeCOEP(headers) {
  const value = headers['cross-origin-embedder-policy'] || null;
  if (!value) {
    return { name: 'Cross-Origin-Embedder-Policy', score: 0, status: 'warn', severity: 'low', value: null, recommendation: 'Add Cross-Origin-Embedder-Policy header.' };
  }
  return { name: 'Cross-Origin-Embedder-Policy', score: 100, status: 'pass', severity: 'low', value, recommendation: 'COEP is configured.' };
}

function analyzeCORP(headers) {
  const value = headers['cross-origin-resource-policy'] || null;
  if (!value) {
    return { name: 'Cross-Origin-Resource-Policy', score: 0, status: 'warn', severity: 'low', value: null, recommendation: 'Add Cross-Origin-Resource-Policy header.' };
  }
  return { name: 'Cross-Origin-Resource-Policy', score: 100, status: 'pass', severity: 'low', value, recommendation: 'CORP is configured.' };
}

const WEIGHTS = {
  csp: 0.25,
  hsts: 0.20,
  xFrameOptions: 0.15,
  xContentTypeOptions: 0.10,
  referrerPolicy: 0.10,
  permissionsPolicy: 0.05,
  coop: 0.05,
  coep: 0.05,
  corp: 0.03,
};

function calculateHeadersGrade(score) {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 75) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

/**
 * Analyze HTTP response headers and produce a security score.
 * @param {Record<string, string>} rawHeaders - lowercase header name → value
 * @param {boolean} isHttps - whether the site was accessed over HTTPS
 * @returns {{ score: number, grade: string, headers: object, missingCritical: string[], techStack: string[] }}
 */
function analyzeHeaders(rawHeaders, isHttps = true) {
  const headers = {
    csp: analyzeCSP(rawHeaders),
    hsts: analyzeHSTS(rawHeaders, isHttps),
    xFrameOptions: analyzeXFrameOptions(rawHeaders),
    xContentTypeOptions: analyzeXContentTypeOptions(rawHeaders),
    referrerPolicy: analyzeReferrerPolicy(rawHeaders),
    permissionsPolicy: analyzePermissionsPolicy(rawHeaders),
    coop: analyzeCOOP(rawHeaders),
    coep: analyzeCOEP(rawHeaders),
    corp: analyzeCORP(rawHeaders),
  };

  let totalScore = 0;
  let totalWeight = 0;
  for (const [key, analysis] of Object.entries(headers)) {
    const weight = WEIGHTS[key] || 0;
    if (weight > 0 && analysis.severity !== 'info') {
      totalScore += analysis.score * weight;
      totalWeight += weight;
    }
  }

  const score = Math.round(totalWeight > 0 ? totalScore / totalWeight : 0);

  const missingCritical = Object.values(headers)
    .filter(h => h.status === 'fail' && (h.severity === 'critical' || h.severity === 'high'))
    .map(h => h.name);

  const techStack = [];
  if (rawHeaders['server']) techStack.push(rawHeaders['server']);
  if (rawHeaders['x-powered-by']) techStack.push(rawHeaders['x-powered-by']);
  if (rawHeaders['x-generator']) techStack.push(rawHeaders['x-generator']);

  return { score, grade: calculateHeadersGrade(score), headers, missingCritical, techStack };
}

module.exports = { analyzeHeaders, calculateHeadersGrade };
