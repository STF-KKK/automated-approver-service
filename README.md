# Institutional Vault Automated Approver Service - Reference Implementation

## Overview

The Automated Approver Service is a lightweight approval server designed for testing MPC Policy Authority (MPA) wallet approval workflows. It provides cryptographic approval signing capabilities for transaction intents including transfers, smart contract calls, and contract deployments.

## Features

- ✅ **Intent Approval**: Automatically approves and signs transaction intents
- 🔐 **Cryptographic Signing**: ECDSA P-256 signature generation
- 🔒 **TLS Support**: Optional TLS with Ed25519 certificates
- 📦 **Multiple Operation Types**: Supports transfer, contract call, contract deployment and raw transaction intents
- ☁️ **AWS Integration**: Secrets Manager integration

### Components

1. **Approval Server** (`approval-service/`): Core Go service that handles approval requests
2. **Infrastructure** (`infra/`): AWS CDK stacks and Helm charts for deployment
3. **Configuration** (`cue.mod/`): CUE schemas for configuration validation

## Prerequisites

- Go 1.23 or higher
- Docker (optional, for containerized deployment)

## Installation

### Local Development

2. **Install Go dependencies**
   ```bash
   go mod download
   ```

3. **Generate cryptographic keys**
   
   Generate a private key for signing (see [schema.cue](cue.mod/approval-service/schema.cue) for helper links):
   - Private key: https://go.dev/play/p/hvTalsJgu2T
   - TLS key seed: https://go.dev/play/p/t7OAtd0-ilL

4. **Configure the service**
   
   Create your local configuration:
   ```bash
   cp infra/config/config_local.cue infra/config/config_local.cue.local
   ```
   
   Edit `config_local.cue.local` and add your generated keys:
   ```cue
   {
       port: 9294
       private_key: "<your-base64-encoded-private-key>"
       tls_private_key_seed: "<your-base64-encoded-seed>"
       secret_manager: "local"
   }
   ```


The service will start on `http://localhost:9294`.

## Configuration

### Local Configuration

For local development, configure via `infra/config/config_local.cue`:

- `port`: Server port (default: 9294)
- `private_key`: Base64-encoded ASN.1 DER private key for signing
- `tls_private_key_seed`: Base64-encoded 32-byte seed for TLS certificate
- `secret_manager`: Use `"local"` for local development

### Production Configuration

For production, use AWS Secrets Manager:

Required secrets:
- `sandbox-approval-tls-private-key`: TLS private key
- `sandbox-approval-key-seed`: TLS certificate seed
- `sandbox-approval-tls-public-key`: TLS public key (auto-generated)
- `sandbox-approval-signature-verification-key`: Signature verification key (auto-generated)

## API Endpoints

### POST /confirm

Approves and signs a transaction intent.

**Request:**
```json
{
  "EnrichedIntent": "<base64-encoded-intent-bytes>",
  "MPASignature": "<base64-encoded-signature-bytes>"
}
```

**Response:**
```json
{
  "Confirmed": true,
  "Signature": "<base64-encoded-signature-bytes>"
}
```

### GET /public-key

Returns the server's public key for signature verification.

**Response:**
```json
{
  "public_key": "<65-byte-uncompressed-public-key>"
}
```

## Deployment

### Docker

Build and run the container:
```bash
docker build -f approval-service/Dockerfile -t approval-service:latest .
docker run -p 9294:9294 \
  -v $(pwd)/infra/config:/config \
  approval-service:latest \
  --configFile=/config/config_local.cue
```

### Running the service

```bash
go build -o approval-svc ./approval-service && ./approval-svc  --configFile=./infra/config/config_local.cue
```

## Security Considerations

⚠️ **IMPORTANT**: This service is designed for **sandbox/testing environments only**.

- The service automatically approves **all** valid requests
- Secrets are logged to stdout for debugging purposes
- Do **NOT** use in production with real assets
