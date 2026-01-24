# SSL Checker Azure Function

Azure Function for SSL/TLS certificate and cipher inspection. Performs actual TLS handshakes to inspect what servers present - works around Cloudflare Workers limitations.

## Features

- **Certificate Inspection**: Full certificate chain, validity, fingerprints
- **Cipher Analysis**: Negotiated cipher suite and strength
- **Protocol Testing**: TLS 1.0, 1.1, 1.2, 1.3 support detection
- **Security Grading**: A+ to F grade based on configuration
- **CORS Enabled**: Ready for browser-based API calls

## Quick Test (No Azure Required)

```bash
# Install dependencies
npm install

# Test against any domain
node test/test-ssl-checker.js google.com
node test/test-ssl-checker.js expired.badssl.com
node test/test-ssl-checker.js self-signed.badssl.com
```

## Local Development

```bash
# Install Azure Functions Core Tools
npm install -g azure-functions-core-tools@4

# Install dependencies
npm install

# Start local server
npm start
# or
func start

# Test the endpoint
curl "http://localhost:7071/api/ssl-check?domain=google.com"
curl "http://localhost:7071/api/ssl-check?domain=google.com&full=true"
```

## API Usage

### Basic Check
```
GET /api/ssl-check?domain=example.com
```

### Full Check (includes protocol testing)
```
GET /api/ssl-check?domain=example.com&full=true
```

### POST Request
```bash
curl -X POST https://your-function.azurewebsites.net/api/ssl-check \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "port": 443, "full": true}'
```

## Response Format

```json
{
  "domain": "google.com",
  "port": 443,
  "timestamp": "2024-01-24T12:00:00.000Z",
  "connected": true,
  "authorized": true,
  "protocol": "TLSv1.3",
  "cipher": {
    "name": "TLS_AES_256_GCM_SHA384",
    "standardName": "TLS_AES_256_GCM_SHA384",
    "version": "TLSv1.3"
  },
  "certificate": {
    "subject": { "CN": "*.google.com", "O": "Google LLC" },
    "issuer": { "CN": "GTS CA 1C3", "O": "Google Trust Services LLC" },
    "validFrom": "Jan 01 00:00:00 2024 GMT",
    "validTo": "Apr 01 00:00:00 2024 GMT",
    "serialNumber": "...",
    "fingerprint256": "...",
    "bits": 256,
    "subjectAltNames": [
      { "type": "DNS", "value": "*.google.com" },
      { "type": "DNS", "value": "google.com" }
    ]
  },
  "chain": [
    { "subject": "*.google.com", "issuer": "GTS CA 1C3", "isCA": false },
    { "subject": "GTS CA 1C3", "issuer": "GTS Root R1", "isCA": true },
    { "subject": "GTS Root R1", "issuer": "GTS Root R1", "isCA": true, "isRoot": true }
  ],
  "protocols": {
    "TLSv1.3": { "supported": true, "cipher": "TLS_AES_256_GCM_SHA384" },
    "TLSv1.2": { "supported": true, "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256" },
    "TLSv1.1": { "supported": false },
    "TLSv1.0": { "supported": false }
  },
  "grade": "A+",
  "score": 100,
  "issues": []
}
```

## Deployment to Azure

### Using Azure CLI

```bash
# Login to Azure
az login

# Create resource group
az group create --name ssl-checker-rg --location eastus

# Create storage account (required for Functions)
az storage account create \
  --name sslcheckerstorage \
  --location eastus \
  --resource-group ssl-checker-rg \
  --sku Standard_LRS

# Create Function App
az functionapp create \
  --resource-group ssl-checker-rg \
  --consumption-plan-location eastus \
  --runtime node \
  --runtime-version 18 \
  --functions-version 4 \
  --name ssl-checker-func \
  --storage-account sslcheckerstorage

# Deploy
func azure functionapp publish ssl-checker-func
```

### Using VS Code

1. Install Azure Functions extension
2. Sign in to Azure
3. Right-click on project → Deploy to Function App
4. Follow prompts

## Integration with InventiveHQ

Add this to your Next.js tool:

```typescript
const SSL_CHECKER_URL = 'https://ssl-checker-func.azurewebsites.net/api/ssl-check';

async function checkSSL(domain: string, full = false) {
  const response = await fetch(
    `${SSL_CHECKER_URL}?domain=${encodeURIComponent(domain)}&full=${full}`
  );
  return response.json();
}
```

## Security Grading Criteria

| Grade | Score | Criteria |
|-------|-------|----------|
| A+ | 95-100 | TLS 1.3, strong ciphers, valid cert, no issues |
| A | 90-94 | TLS 1.2+, valid cert, minor issues |
| B | 80-89 | Some deprecated protocols or weak config |
| C | 70-79 | Multiple issues, but functional |
| D | 60-69 | Significant security concerns |
| F | <60 | Critical issues (expired cert, only weak protocols) |

## Cost

Azure Functions Consumption Plan:
- **1 million free executions/month**
- ~$0.20 per additional million
- Essentially free for typical usage
