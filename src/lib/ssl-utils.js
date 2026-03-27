const tls = require('tls');
const crypto = require('crypto');

// Protocols to test (in order of preference)
const PROTOCOLS_TO_TEST = [
  { name: 'TLSv1.3', minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' },
  { name: 'TLSv1.2', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' },
  { name: 'TLSv1.1', minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1' },
  { name: 'TLSv1.0', minVersion: 'TLSv1', maxVersion: 'TLSv1' },
];

// Common cipher suites to check
const CIPHER_CATEGORIES = {
  strong: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
  ],
  acceptable: [
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-SHA384',
    'ECDHE-RSA-AES256-SHA384',
  ],
  weak: [
    'ECDHE-RSA-AES128-SHA',
    'AES256-GCM-SHA384',
    'AES128-GCM-SHA256',
    'AES256-SHA256',
    'AES128-SHA256',
  ],
  insecure: [
    'DES-CBC3-SHA',
    'RC4-SHA',
    'RC4-MD5',
    'DES-CBC-SHA',
    'EXP-DES-CBC-SHA',
    'NULL-SHA',
    'NULL-MD5',
  ],
};

/**
 * Connect to a host and get certificate/cipher info
 */
function checkTLS(hostname, port = 443, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 10000;

    const socketOptions = {
      host: hostname,
      port: port,
      servername: hostname, // SNI
      rejectUnauthorized: false, // We want to inspect even invalid certs
      ...options.tlsOptions,
    };

    const socket = tls.connect(socketOptions, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        const authError = socket.authorizationError;

        const result = {
          connected: true,
          authorized,
          authorizationError: authError || null,
          protocol,
          cipher: cipher ? {
            name: cipher.name,
            standardName: cipher.standardName,
            version: cipher.version,
          } : null,
          certificate: cert ? parseCertificate(cert) : null,
          chain: cert ? parseCertificateChain(cert) : [],
        };

        socket.end();
        resolve(result);
      } catch (err) {
        socket.end();
        reject(err);
      }
    });

    socket.setTimeout(timeout);

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`Connection timeout after ${timeout}ms`));
    });

    socket.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Convert DER-encoded certificate to PEM format
 */
function derToPem(derBuffer) {
  if (!derBuffer) return null;
  const base64 = derBuffer.toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}

/**
 * Parse certificate object into clean format
 */
function parseCertificate(cert) {
  if (!cert || !cert.subject) return null;

  return {
    subject: {
      CN: cert.subject.CN,
      O: cert.subject.O,
      OU: cert.subject.OU,
      C: cert.subject.C,
      ST: cert.subject.ST,
      L: cert.subject.L,
    },
    issuer: {
      CN: cert.issuer.CN,
      O: cert.issuer.O,
      OU: cert.issuer.OU,
      C: cert.issuer.C,
    },
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    serialNumber: cert.serialNumber,
    fingerprint: cert.fingerprint,
    fingerprint256: cert.fingerprint256,
    fingerprint512: cert.fingerprint512,
    subjectAltNames: parseSubjectAltNames(cert.subjectaltname),
    keyUsage: cert.ext_key_usage || [],
    bits: cert.bits,
    publicKey: cert.pubkey ? {
      type: cert.asn1Curve || 'RSA',
      size: cert.bits,
    } : null,
    signatureAlgorithm: cert.signatureAlgorithm,
    isCA: cert.ca || false,
    pem: derToPem(cert.raw),
  };
}

/**
 * Parse Subject Alternative Names
 */
function parseSubjectAltNames(sanString) {
  if (!sanString) return [];

  return sanString.split(', ').map(san => {
    const [type, value] = san.split(':');
    return { type, value };
  });
}

/**
 * Parse certificate chain
 */
function parseCertificateChain(cert) {
  const chain = [];
  let current = cert;
  const seen = new Set();

  while (current && current.subject) {
    const fingerprint = current.fingerprint256 || current.fingerprint;

    if (seen.has(fingerprint)) break;
    seen.add(fingerprint);

    chain.push({
      subject: current.subject.CN || current.subject.O,
      issuer: current.issuer.CN || current.issuer.O,
      validFrom: current.valid_from,
      validTo: current.valid_to,
      fingerprint256: current.fingerprint256,
      isCA: current.ca || false,
    });

    current = current.issuerCertificate;

    if (current && current.subject && current.issuer &&
        current.subject.CN === current.issuer.CN) {
      chain.push({
        subject: current.subject.CN || current.subject.O,
        issuer: current.issuer.CN || current.issuer.O,
        validFrom: current.valid_from,
        validTo: current.valid_to,
        fingerprint256: current.fingerprint256,
        isCA: true,
        isRoot: true,
      });
      break;
    }
  }

  return chain;
}

/**
 * Test which protocols are supported
 */
async function testProtocols(hostname, port = 443) {
  const results = {};

  for (const proto of PROTOCOLS_TO_TEST) {
    try {
      const result = await checkTLS(hostname, port, {
        tlsOptions: {
          minVersion: proto.minVersion,
          maxVersion: proto.maxVersion,
        },
        timeout: 5000,
      });
      results[proto.name] = {
        supported: true,
        cipher: result.cipher?.name,
      };
    } catch (err) {
      results[proto.name] = {
        supported: false,
        error: err.message,
      };
    }
  }

  return results;
}

/**
 * Calculate security grade based on findings
 */
function calculateGrade(result) {
  let score = 100;
  const issues = [];

  if (!result.authorized) {
    score -= 40;
    issues.push({ severity: 'critical', message: `Certificate not trusted: ${result.authorizationError}` });
  }

  if (result.certificate) {
    const validTo = new Date(result.certificate.validTo);
    const now = new Date();
    const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

    if (daysUntilExpiry < 0) {
      score -= 50;
      issues.push({ severity: 'critical', message: 'Certificate has expired' });
    } else if (daysUntilExpiry < 7) {
      score -= 20;
      issues.push({ severity: 'high', message: `Certificate expires in ${daysUntilExpiry} days` });
    } else if (daysUntilExpiry < 30) {
      score -= 10;
      issues.push({ severity: 'medium', message: `Certificate expires in ${daysUntilExpiry} days` });
    }

    if (result.certificate.bits && result.certificate.bits > 512 && result.certificate.bits < 2048) {
      score -= 20;
      issues.push({ severity: 'high', message: `Weak RSA key size: ${result.certificate.bits} bits` });
    }
  }

  if (result.protocols) {
    if (result.protocols['TLSv1.0']?.supported) {
      score -= 15;
      issues.push({ severity: 'medium', message: 'TLS 1.0 is supported (deprecated)' });
    }
    if (result.protocols['TLSv1.1']?.supported) {
      score -= 10;
      issues.push({ severity: 'medium', message: 'TLS 1.1 is supported (deprecated)' });
    }
    if (!result.protocols['TLSv1.2']?.supported && !result.protocols['TLSv1.3']?.supported) {
      score -= 30;
      issues.push({ severity: 'critical', message: 'Neither TLS 1.2 nor TLS 1.3 supported' });
    }
    if (result.protocols['TLSv1.3']?.supported) {
      score += 5;
    }
  }

  let grade;
  if (score >= 95) grade = 'A+';
  else if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';
  else grade = 'F';

  return { grade, score: Math.max(0, Math.min(100, score)), issues };
}

module.exports = {
  checkTLS,
  parseCertificate,
  parseCertificateChain,
  parseSubjectAltNames,
  derToPem,
  testProtocols,
  calculateGrade,
  PROTOCOLS_TO_TEST,
  CIPHER_CATEGORIES,
};
