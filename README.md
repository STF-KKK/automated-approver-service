# Institutional Vault Automated Approver Service - Reference Implementation

## Overview

The Automated Approver Service is a lightweight approval server designed for testing MPC Policy Authority (MPA) approval workflows. It provides cryptographic approval signing capabilities for transaction intents.

## Features

- ✅ **Intent Approval**: Automatically approves and signs transaction intents
- 🔐 **Cryptographic Signing**: ECDSA P-256 signature generation
- 🔒 **TLS Support**: Optional TLS with Ed25519 certificates
- 📦 **Multiple Operation Types**: Supports transfer, contract call, contract deployment and raw transaction intents
- ☁️ **AWS Integration**: Secrets Manager integration

### Components

1. **Approval Server** (`approval-service/`): Core Go service that handles approval requests
2. **Infrastructure** (`infra/`): Service configuration files
3. **Configuration** (`cue.mod/`): CUE schemas for configuration validation

## Prerequisites

- Go 1.23 or higher
- Docker (optional, for containerized deployment)


## Configuration

For local development, configure via `infra/config/config_local.cue`:

- `port`: Server port (default: 9294)
- `private_key`: Base64-encoded ASN.1 DER private key for signing https://go.dev/play/p/hvTalsJgu2T
- `tls_private_key_seed`: Base64-encoded 32-byte seed for TLS certificate https://go.dev/play/p/t7OAtd0-ilL
- `secret_manager`: Use `"local"` for local development 

Otherwise, use AWS Secrets Manager:

Required secrets names:
- `sandbox-approval-tls-private-key`: TLS private key
- `sandbox-approval-key-seed`: TLS certificate seed
- `sandbox-approval-tls-public-key`: TLS public key (auto-generated)
- `sandbox-approval-signature-verification-key`: Signature verification key (auto-generated)


## Deployment

Build and run the container:
```bash
docker build -f approval-service/Dockerfile -t approval-service:latest .
docker run -p 9294:9294 \
  -v $(pwd)/infra/config:/config \
  approval-service:latest \
  --configFile=/config/config_local.cue
```

The service will start on `http://localhost:9294`.

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

## Security Considerations

⚠️ **IMPORTANT**: This service is designed for **sandbox/testing environments only**.
- The service automatically approves **all** valid requests
- Secrets are logged to stdout for debugging purposes
