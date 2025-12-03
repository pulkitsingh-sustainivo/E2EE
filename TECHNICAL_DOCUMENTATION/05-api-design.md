# 05. API Design Specification

## 1. API Overview

The E2EE system exposes RESTful APIs following OpenAPI 3.0 specification. All APIs use HTTPS, JSON request/response format, and standard HTTP status codes.

## 2. API Design Principles

### 2.1 RESTful Design
- Resource-based URLs
- HTTP verbs for actions (GET, POST, PUT, DELETE)
- Stateless requests
- Consistent response formats

### 2.2 Versioning
- URL-based versioning: `/api/v1/...`
- Backward compatibility maintained
- Deprecation notices in headers

### 2.3 Authentication
- JWT tokens for user authentication
- API keys for service-to-service communication
- Bearer token authentication

### 2.4 Error Handling
- Consistent error response format
- Appropriate HTTP status codes
- Detailed error messages (in development)
- Sanitized error messages (in production)

## 3. Base URL Structure

```
Production:  https://api.e2ee.example.com/v1
Staging:     https://api-staging.e2ee.example.com/v1
Development: http://localhost:3000/v1
```

## 4. Common Response Formats

### 4.1 Success Response

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "meta": {
    "timestamp": "2025-03-12T14:30:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### 4.2 Error Response

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input parameters",
    "details": [
      {
        "field": "promptId",
        "message": "promptId is required"
      }
    ]
  },
  "meta": {
    "timestamp": "2025-03-12T14:30:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### 4.3 Pagination Response

```json
{
  "success": true,
  "data": [
    // Array of items
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "totalPages": 5,
    "hasNext": true,
    "hasPrev": false
  },
  "meta": {
    "timestamp": "2025-03-12T14:30:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

## 5. Vault Service APIs

### 5.1 Create Prompt

**Endpoint**: `POST /api/v1/prompts`

**Description**: Create a new prompt in the vault.

**Authentication**: Required (JWT or API Key)

**Request Body**:
```json
{
  "promptText": "What is the capital of France?",
  "secret": "my_secret_key",
  "metadata": {
    "category": "geography",
    "priority": "high"
  }
}
```

**Response**: `201 Created`
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "promptText": "What is the capital of France?",
    "status": "active",
    "version": 1,
    "createdAt": "2025-03-12T14:30:00Z",
    "updatedAt": "2025-03-12T14:30:00Z"
  },
  "meta": {
    "timestamp": "2025-03-12T14:30:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Error Responses**:
- `400 Bad Request`: Validation error
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `500 Internal Server Error`: Server error

### 5.2 Get Prompt

**Endpoint**: `GET /api/v1/prompts/{id}`

**Description**: Retrieve a prompt by ID.

**Authentication**: Required

**Path Parameters**:
- `id` (UUID, required): Prompt identifier

**Query Parameters**:
- `includeEnvelopes` (boolean, optional): Include associated envelopes

**Response**: `200 OK`
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "promptText": "What is the capital of France?",
    "status": "active",
    "version": 1,
    "createdAt": "2025-03-12T14:30:00Z",
    "updatedAt": "2025-03-12T14:30:00Z",
    "envelopes": [] // if includeEnvelopes=true
  },
  "meta": {
    "timestamp": "2025-03-12T14:30:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Error Responses**:
- `404 Not Found`: Prompt not found
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions

### 5.3 List Prompts

**Endpoint**: `GET /api/v1/prompts`

**Description**: List prompts with pagination and filtering.

**Authentication**: Required

**Query Parameters**:
- `page` (integer, optional, default: 1): Page number
- `limit` (integer, optional, default: 20, max: 100): Items per page
- `status` (string, optional): Filter by status
- `search` (string, optional): Search in prompt text
- `sortBy` (string, optional, default: "createdAt"): Sort field
- `sortOrder` (string, optional, default: "desc"): Sort order (asc/desc)

**Response**: `200 OK`
```json
{
  "success": true,
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "promptText": "What is the capital of France?",
      "status": "active",
      "createdAt": "2025-03-12T14:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "totalPages": 5,
    "hasNext": true,
    "hasPrev": false
  },
  "meta": {
    "timestamp": "2025-03-12T14:30:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### 5.4 Generate Envelope

**Endpoint**: `POST /api/v1/envelopes`

**Description**: Generate an encrypted envelope for a prompt.

**Authentication**: Required

**Request Body**:
```json
{
  "promptId": "550e8400-e29b-41d4-a716-446655440000",
  "secret": "my_secret_key",
  "receiverPublicKeyId": "prompt_response_enc_public",
  "expiresAt": "2025-03-19T14:30:00Z",
  "metadata": {
    "priority": "high"
  }
}
```

**Response**: `201 Created`
```json
{
  "success": true,
  "data": {
    "envelope": {
      "id": "660e8400-e29b-41d4-a716-446655440000",
      "encryptedData": "base64-encoded-encrypted-data",
      "encryptedKey": "base64-encoded-encrypted-key",
      "signature": "base64-encoded-signature",
      "iv": "base64-encoded-iv",
      "authTag": "base64-encoded-auth-tag",
      "algorithm": "AES-256-GCM",
      "keyAlgorithm": "RSA-OAEP",
      "signatureAlgorithm": "RSA-PSS",
      "receiverPublicKeyId": "prompt_response_enc_public",
      "senderPrivateKeyId": "prompt_vault_sign_private",
      "expiresAt": "2025-03-19T14:30:00Z",
      "status": "pending",
      "createdAt": "2025-03-12T14:30:00Z"
    }
  },
  "meta": {
    "timestamp": "2025-03-12T14:30:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Error Responses**:
- `400 Bad Request`: Invalid input or prompt not found
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `500 Internal Server Error`: Encryption failed

### 5.5 Get Envelope

**Endpoint**: `GET /api/v1/envelopes/{id}`

**Description**: Retrieve envelope metadata (not encrypted data).

**Authentication**: Required

**Path Parameters**:
- `id` (UUID, required): Envelope identifier

**Response**: `200 OK`
```json
{
  "success": true,
  "data": {
    "id": "660e8400-e29b-41d4-a716-446655440000",
    "promptId": "550e8400-e29b-41d4-a716-446655440000",
    "algorithm": "AES-256-GCM",
    "keyAlgorithm": "RSA-OAEP",
    "signatureAlgorithm": "RSA-PSS",
    "receiverPublicKeyId": "prompt_response_enc_public",
    "senderPrivateKeyId": "prompt_vault_sign_private",
    "expiresAt": "2025-03-19T14:30:00Z",
    "status": "pending",
    "createdAt": "2025-03-12T14:30:00Z"
  },
  "meta": {
    "timestamp": "2025-03-12T14:30:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

## 6. Prompt Response Service APIs

### 6.1 Decrypt Envelope

**Endpoint**: `POST /api/v1/envelopes/decrypt`

**Description**: Decrypt an envelope and retrieve the plaintext prompt.

**Authentication**: Required

**Request Body**:
```json
{
  "envelope": {
    "id": "660e8400-e29b-41d4-a716-446655440000",
    "encryptedData": "base64-encoded-encrypted-data",
    "encryptedKey": "base64-encoded-encrypted-key",
    "signature": "base64-encoded-signature",
    "iv": "base64-encoded-iv",
    "authTag": "base64-encoded-auth-tag",
    "algorithm": "AES-256-GCM",
    "keyAlgorithm": "RSA-OAEP",
    "signatureAlgorithm": "RSA-PSS",
    "receiverPublicKeyId": "prompt_response_enc_public",
    "senderPrivateKeyId": "prompt_vault_sign_private"
  },
  "receiverPrivateKeyId": "prompt_response_enc_private",
  "senderPublicKeyId": "prompt_vault_sign_public"
}
```

**Response**: `200 OK`
```json
{
  "success": true,
  "data": {
    "prompt": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "promptText": "What is the capital of France?",
      "metadata": {
        "category": "geography",
        "priority": "high"
      }
    },
    "decryption": {
      "envelopeId": "660e8400-e29b-41d4-a716-446655440000",
      "decryptedAt": "2025-03-12T14:35:00Z",
      "signatureVerified": true,
      "decryptionSuccessful": true
    }
  },
  "meta": {
    "timestamp": "2025-03-12T14:35:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Error Responses**:
- `400 Bad Request`: Invalid envelope format
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Signature verification failed
- `404 Not Found`: Envelope not found
- `422 Unprocessable Entity`: Decryption failed
- `500 Internal Server Error`: Server error

### 6.2 Process Prompt

**Endpoint**: `POST /api/v1/prompts/process`

**Description**: Process a decrypted prompt and generate a response.

**Authentication**: Required

**Request Body**:
```json
{
  "promptId": "550e8400-e29b-41d4-a716-446655440000",
  "promptText": "What is the capital of France?",
  "options": {
    "format": "json",
    "includeMetadata": true
  }
}
```

**Response**: `200 OK`
```json
{
  "success": true,
  "data": {
    "response": {
      "id": "770e8400-e29b-41d4-a716-446655440000",
      "promptId": "550e8400-e29b-41d4-a716-446655440000",
      "result": "The capital of France is Paris.",
      "metadata": {
        "processingTime": 45,
        "model": "gpt-4"
      },
      "createdAt": "2025-03-12T14:40:00Z"
    }
  },
  "meta": {
    "timestamp": "2025-03-12T14:40:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

## 7. Common APIs

### 7.1 Health Check

**Endpoint**: `GET /api/v1/health`

**Description**: Service health check endpoint.

**Authentication**: Not required

**Response**: `200 OK`
```json
{
  "status": "healthy",
  "service": "vault-service",
  "version": "1.0.0",
  "timestamp": "2025-03-12T14:30:00Z",
  "checks": {
    "database": "connected",
    "redis": "connected",
    "keyVault": "connected"
  }
}
```

### 7.2 Metrics

**Endpoint**: `GET /api/v1/metrics`

**Description**: Service metrics (Prometheus format).

**Authentication**: Required (API Key only)

**Response**: `200 OK`
```
# Prometheus metrics format
http_requests_total{method="POST",endpoint="/envelopes",status="201"} 150
http_request_duration_seconds{method="POST",endpoint="/envelopes",quantile="0.95"} 0.085
```

## 8. HTTP Status Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Successful GET, PUT, PATCH |
| 201 | Created | Successful POST (resource created) |
| 204 | No Content | Successful DELETE |
| 400 | Bad Request | Invalid request format |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource conflict |
| 422 | Unprocessable Entity | Validation failed |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service temporarily unavailable |

## 9. Rate Limiting

### 9.1 Rate Limit Headers

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1647091200
```

### 9.2 Rate Limit Policies

- **Default**: 1000 requests per hour per API key
- **Envelope Generation**: 100 requests per hour per user
- **Decryption**: 500 requests per hour per user
- **Admin APIs**: 10000 requests per hour

## 10. Request/Response Headers

### 10.1 Required Headers

```
Authorization: Bearer <token>
Content-Type: application/json
Accept: application/json
```

### 10.2 Optional Headers

```
X-Request-ID: <uuid> (for request tracing)
X-Client-Version: 1.0.0
X-Platform: web
```

### 10.3 Response Headers

```
Content-Type: application/json
X-Request-ID: <uuid>
X-Response-Time: 45ms
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
```

## 11. Webhooks (Future)

### 11.1 Webhook Events

- `envelope.created`
- `envelope.decrypted`
- `prompt.processed`
- `error.occurred`

### 11.2 Webhook Payload

```json
{
  "event": "envelope.created",
  "timestamp": "2025-03-12T14:30:00Z",
  "data": {
    "envelopeId": "660e8400-e29b-41d4-a716-446655440000",
    "promptId": "550e8400-e29b-41d4-a716-446655440000"
  },
  "signature": "webhook-signature"
}
```

## 12. API Testing

### 12.1 Test Endpoints

- Health check endpoint for smoke tests
- Mock endpoints for integration tests
- Test data cleanup endpoints

### 12.2 Postman Collection

- Complete API collection
- Environment variables
- Pre-request scripts
- Test assertions

