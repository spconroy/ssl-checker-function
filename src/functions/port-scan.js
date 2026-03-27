const { app } = require('@azure/functions');
const net = require('net');
const dns = require('dns');

const PORT_INFO = {
  21:    { service: 'FTP', risk: 'critical', description: 'File Transfer Protocol — plaintext credentials' },
  22:    { service: 'SSH', risk: 'high', description: 'Secure Shell — should be restricted to known IPs' },
  23:    { service: 'Telnet', risk: 'critical', description: 'Telnet — plaintext protocol, never use publicly' },
  25:    { service: 'SMTP', risk: 'medium', description: 'Mail Transfer — expected for mail servers' },
  53:    { service: 'DNS', risk: 'medium', description: 'Domain Name System — check for open resolver' },
  80:    { service: 'HTTP', risk: 'info', description: 'Hypertext Transfer Protocol — standard web traffic' },
  110:   { service: 'POP3', risk: 'high', description: 'Post Office Protocol — plaintext email retrieval' },
  143:   { service: 'IMAP', risk: 'high', description: 'Internet Message Access — plaintext email access' },
  443:   { service: 'HTTPS', risk: 'info', description: 'HTTPS — encrypted web traffic' },
  445:   { service: 'SMB', risk: 'critical', description: 'Server Message Block — frequent ransomware vector' },
  1433:  { service: 'MSSQL', risk: 'critical', description: 'Microsoft SQL Server — database should never be public' },
  3306:  { service: 'MySQL', risk: 'critical', description: 'MySQL — database should never be public' },
  3389:  { service: 'RDP', risk: 'critical', description: 'Remote Desktop — primary target for brute force attacks' },
  5432:  { service: 'PostgreSQL', risk: 'critical', description: 'PostgreSQL — database should never be public' },
  5900:  { service: 'VNC', risk: 'critical', description: 'Virtual Network Computing — remote desktop, often unencrypted' },
  6379:  { service: 'Redis', risk: 'critical', description: 'Redis — in-memory database, often has no authentication' },
  8080:  { service: 'HTTP-Alt', risk: 'low', description: 'Alternative HTTP — may expose development/admin interfaces' },
  8443:  { service: 'HTTPS-Alt', risk: 'low', description: 'Alternative HTTPS — may expose admin interfaces' },
  9200:  { service: 'Elasticsearch', risk: 'critical', description: 'Elasticsearch — search engine, often has no auth' },
  27017: { service: 'MongoDB', risk: 'critical', description: 'MongoDB — database should never be public' },
};

const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
  1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
];

const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function scanPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    socket.on('connect', () => {
      socket.destroy();
      resolve({ port, status: 'open' });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ port, status: 'filtered' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({ port, status: err.code === 'ECONNREFUSED' ? 'closed' : 'filtered' });
    });

    socket.connect(port, host);
  });
}

function cleanDomain(input) {
  if (!input || typeof input !== 'string') return null;
  let domain = input.trim().toLowerCase();
  // Strip protocol
  domain = domain.replace(/^https?:\/\//, '');
  // Strip path, query, fragment
  domain = domain.split(/[/?#]/)[0];
  // Strip port
  domain = domain.split(':')[0];
  // Strip trailing dot
  domain = domain.replace(/\.$/, '');
  if (!domain || domain.length === 0) return null;
  return domain;
}

function getPortInfo(port) {
  if (PORT_INFO[port]) return PORT_INFO[port];
  return { service: `Port ${port}`, risk: 'info', description: `Unknown service on port ${port}` };
}

async function handler(request, context) {
  // CORS headers
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
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        jsonBody: { error: 'A valid domain is required.' },
      };
    }

    // Determine ports to scan
    let ports = DEFAULT_PORTS;
    if (Array.isArray(body.ports) && body.ports.length > 0) {
      ports = [...new Set(body.ports.map(Number).filter((p) => p > 0 && p <= 65535))];
      if (ports.length === 0) {
        return {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          jsonBody: { error: 'No valid port numbers provided. Ports must be between 1 and 65535.' },
        };
      }
    }

    // Resolve domain to IP — try system DNS first, then DoH fallback
    let ip;
    try {
      const addresses = await dns.promises.resolve4(domain);
      ip = addresses[0];
    } catch {
      // Fallback: resolve via Cloudflare DNS-over-HTTPS
      try {
        const dohRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
          headers: { Accept: 'application/dns-json' },
        });
        if (dohRes.ok) {
          const dohData = await dohRes.json();
          const aRecord = (dohData.Answer || []).find((r) => r.type === 1);
          if (aRecord) ip = aRecord.data;
        }
      } catch { /* ignore */ }
    }

    if (!ip) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        jsonBody: { error: `Could not resolve IP address for "${domain}"` },
      };
    }

    // Scan all ports in parallel
    const startTime = Date.now();
    const results = await Promise.allSettled(ports.map((port) => scanPort(ip, port)));
    const scanDuration = parseFloat(((Date.now() - startTime) / 1000).toFixed(2));

    // Build result set
    const allResults = results.map((r) => {
      const result = r.status === 'fulfilled' ? r.value : { port: 0, status: 'filtered' };
      const info = getPortInfo(result.port);
      return {
        port: result.port,
        service: info.service,
        risk: info.risk,
        description: info.description,
        status: result.status,
      };
    });

    // Sort allResults by port number
    allResults.sort((a, b) => a.port - b.port);

    // Open ports sorted by risk (critical first), then port number
    const openPorts = allResults
      .filter((r) => r.status === 'open')
      .sort((a, b) => {
        const riskDiff = (RISK_ORDER[a.risk] ?? 99) - (RISK_ORDER[b.risk] ?? 99);
        if (riskDiff !== 0) return riskDiff;
        return a.port - b.port;
      });

    // Summary counts
    const summary = {
      open: allResults.filter((r) => r.status === 'open').length,
      closed: allResults.filter((r) => r.status === 'closed').length,
      filtered: allResults.filter((r) => r.status === 'filtered').length,
    };

    return {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      jsonBody: {
        domain,
        ip,
        timestamp: new Date().toISOString(),
        scanDuration,
        summary,
        openPorts,
        allResults,
      },
    };
  } catch (err) {
    return {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      jsonBody: { error: `Scan failed: ${err.message}` },
    };
  }
}

app.http('port-scan', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler,
});
