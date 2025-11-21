# E2EE Documentation

## Project Overview
This project implements an End-to-End Encrypted (E2EE) microservices architecture for secure prompt handling. It consists of a **Vault Service** that stores and encrypts prompts, E2EE service and a **Prompt Response Service** that decrypts and processes them. A shared library handles the cryptographic operations using AES-256-GCM and RSA.

## Architecture
The workflow ensures that sensitive prompts are encrypted at rest and in transit, and are only accessible to the intended recipient service.

For a detailed sequence diagram and workflow description, see [WORK_FLOW.md](WORK_FLOW.md).

## Prerequisites
- **Node.js**: v14 or higher.
- **OpenSSL**: Required for generating RSA key pairs.

## Setup
1. Clone the repository.
2. Install dependencies:
   ```bash
   npm install
   ```

## Key Generation
The services require RSA key pairs for encryption (Receiver) and signing (Sender).

1. **Create a `keys` directory**:
   ```bash
   mkdir keys
   ```

2. **Generate Receiver's Encryption Keys (for Prompt Response Service)**:
   ```bash
   # Private Key
   openssl genpkey -algorithm RSA -out keys/prompt_response_enc_private.key -pkeyopt rsa_keygen_bits:2048
   
   # Public Key
   openssl rsa -pubout -in keys/prompt_response_enc_private.key -out keys/prompt_response_enc_public.key
   ```

3. **Generate Sender's Signing Keys (for Vault Service)**:
   ```bash
   # Private Key
   openssl genpkey -algorithm RSA -out keys/prompt_vault_sign_private.key -pkeyopt rsa_keygen_bits:2048
   
   # Public Key
   openssl rsa -pubout -in keys/prompt_vault_sign_private.key -out keys/prompt_vault_sign_public.key
   ```

## Usage Guide

### 1. Vault Service (Generate Envelope)
The Vault Service retrieves a prompt and wraps it in an encrypted envelope.

**Command:**
```bash
node services/vault_service/vault.js envelope \
  --id "1" \
  --secret "my_secret_key" \
  --receiver-key "keys/prompt_response_enc_public.key" \
  --sender-key "keys/prompt_vault_sign_private.key"
```
*Note: You can pass the file paths directly to `--receiver-key` and `--sender-key`.*

**Output:**
A JSON object containing the `envelope`.

### 2. Prompt Response Service (Decrypt Envelope)
The Prompt Response Service decrypts the envelope to access the plaintext prompt.

**Step 1:** Save the `envelope` object from the Vault Service output to a file (e.g., `envelope.json`).

**Step 2:** Run the service:
```bash
node services/prompt_response_service/response.js \
  --file "envelope.json" \
  --receiver-key "keys/prompt_response_enc_private.key" \
  --sender-key "keys/prompt_vault_sign_public.key"
```

## Testing
To verify the entire flow locally:

1. **Generate an envelope**:
   ```bash
   node services/vault_service/vault.js envelope --id "1" --secret "my_secret_key" --receiver-key "keys/prompt_response_enc_public.key" --sender-key "keys/prompt_vault_sign_private.key" > output.json
   ```

2. **Extract the envelope** (Manual step or using `jq` if available):
   Copy the `envelope` object from `output.json` into a new file `envelope_only.json`.

3. **Decrypt**:
   ```bash
   node services/prompt_response_service/response.js --file "envelope_only.json" --receiver-key "keys/prompt_response_enc_private.key" --sender-key "keys/prompt_vault_sign_public.key"
   ```
   You should see the decrypted prompt printed to the console.
