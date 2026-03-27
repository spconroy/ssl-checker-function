const { app } = require('@azure/functions');
const { checkTLS, testProtocols, calculateGrade } = require('../lib/ssl-utils');

/**
 * SSL/TLS Certificate and Cipher Checker
 * Performs actual TLS handshake to inspect what the server presents
 */
app.http('ssl-check', {
  methods: ['GET', 'POST'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle preflight
    if (request.method === 'OPTIONS') {
      return { status: 204, headers: corsHeaders };
    }

    try {
      // Get domain from query or body
      let domain;
      let port = 443;
      let fullCheck = false;

      if (request.method === 'GET') {
        const url = new URL(request.url);
        domain = url.searchParams.get('domain');
        port = parseInt(url.searchParams.get('port') || '443', 10);
        fullCheck = url.searchParams.get('full') === 'true';
      } else {
        const body = await request.json();
        domain = body.domain;
        port = body.port || 443;
        fullCheck = body.full || false;
      }

      if (!domain) {
        return {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Domain parameter is required' }),
        };
      }

      // Clean domain (remove protocol if present)
      domain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

      context.log(`Checking SSL for: ${domain}:${port}`);

      // Perform basic TLS check
      const basicResult = await checkTLS(domain, port);

      // Optionally test all protocols
      let protocols = null;
      if (fullCheck) {
        protocols = await testProtocols(domain, port);
      }

      const result = {
        domain,
        port,
        timestamp: new Date().toISOString(),
        ...basicResult,
        protocols,
      };

      // Calculate grade
      const grading = calculateGrade(result);
      result.grade = grading.grade;
      result.score = grading.score;
      result.issues = grading.issues;

      return {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify(result, null, 2),
      };

    } catch (error) {
      context.error('SSL check error:', error);

      return {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          error: 'SSL check failed',
          message: error.message,
          code: error.code,
        }),
      };
    }
  },
});
