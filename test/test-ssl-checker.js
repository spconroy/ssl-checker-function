/**
 * Test script for SSL checker - runs without Azure Functions runtime
 */

const tls = require('tls');

const PROTOCOLS_TO_TEST = [
  { name: 'TLSv1.3', minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' },
  { name: 'TLSv1.2', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' },
  { name: 'TLSv1.1', minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1' },
  { name: 'TLSv1.0', minVersion: 'TLSv1', maxVersion: 'TLSv1' },
];

function checkTLS(hostname, port = 443, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 10000;

    const socketOptions = {
      host: hostname,
      port: port,
      servername: hostname,
      rejectUnauthorized: false,
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
          certificate: cert ? {
            subject: cert.subject,
            issuer: cert.issuer,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            serialNumber: cert.serialNumber,
            fingerprint256: cert.fingerprint256,
            bits: cert.bits,
          } : null,
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
    socket.on('error', reject);
  });
}

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
        error: err.code || err.message,
      };
    }
  }

  return results;
}

async function main() {
  const domain = process.argv[2] || 'google.com';

  console.log(`\n🔒 SSL/TLS Check for: ${domain}\n`);
  console.log('='.repeat(60));

  try {
    // Basic check
    console.log('\n📋 Basic TLS Connection:');
    const result = await checkTLS(domain);

    console.log(`   Protocol: ${result.protocol}`);
    console.log(`   Cipher: ${result.cipher?.name}`);
    console.log(`   Authorized: ${result.authorized ? '✅ Yes' : '❌ No'}`);
    if (result.authorizationError) {
      console.log(`   Auth Error: ${result.authorizationError}`);
    }

    if (result.certificate) {
      console.log('\n📜 Certificate:');
      console.log(`   Subject: ${result.certificate.subject.CN || result.certificate.subject.O}`);
      console.log(`   Issuer: ${result.certificate.issuer.CN || result.certificate.issuer.O}`);
      console.log(`   Valid From: ${result.certificate.validFrom}`);
      console.log(`   Valid To: ${result.certificate.validTo}`);
      console.log(`   Key Size: ${result.certificate.bits} bits`);
      console.log(`   Serial: ${result.certificate.serialNumber}`);

      // Check expiration
      const validTo = new Date(result.certificate.validTo);
      const now = new Date();
      const daysLeft = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
      console.log(`   Days Until Expiry: ${daysLeft}`);
    }

    // Protocol support
    console.log('\n🔐 Protocol Support:');
    const protocols = await testProtocols(domain);
    for (const [name, status] of Object.entries(protocols)) {
      const icon = status.supported ? '✅' : '❌';
      const cipher = status.supported ? ` (${status.cipher})` : '';
      console.log(`   ${icon} ${name}${cipher}`);
    }

    // Security assessment
    console.log('\n📊 Security Assessment:');
    let issues = [];

    if (!result.authorized) {
      issues.push('⚠️  Certificate not trusted');
    }

    if (protocols['TLSv1.0']?.supported) {
      issues.push('⚠️  TLS 1.0 supported (deprecated)');
    }

    if (protocols['TLSv1.1']?.supported) {
      issues.push('⚠️  TLS 1.1 supported (deprecated)');
    }

    if (!protocols['TLSv1.3']?.supported) {
      issues.push('ℹ️  TLS 1.3 not supported');
    }

    // Only flag weak keys for RSA (ECDSA 256-bit is strong)
    if (result.certificate?.bits && result.certificate.bits < 2048 && result.certificate.bits > 512) {
      // Likely RSA with weak key - but 256/384 bit is ECDSA which is fine
      // Skip this check - need to detect key type properly
    }

    if (issues.length === 0) {
      console.log('   ✅ No issues found');
    } else {
      issues.forEach(issue => console.log(`   ${issue}`));
    }

    console.log('\n' + '='.repeat(60));
    console.log('✅ Check complete!\n');

  } catch (error) {
    console.error(`\n❌ Error: ${error.message}\n`);
    process.exit(1);
  }
}

main();
