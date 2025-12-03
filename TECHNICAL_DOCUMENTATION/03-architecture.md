# 03. System Architecture

## 1. Architecture Overview

### 1.1 High-Level Architecture

The E2EE system follows a **microservices architecture** pattern with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Applications                      │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        │ HTTPS/TLS
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
┌───────────────┐              ┌──────────────────┐
│  Vault Service │              │ Prompt Response  │
│   (NestJS)     │              │   Service        │
│                │              │   (NestJS)       │
└───────┬────────┘              └────────┬─────────┘
        │                               │
        │                               │
        ▼                               ▼
┌──────────────────────────────────────────────────┐
│         Shared Crypto Library (NPM Package)      │
│  - AES-256-GCM Encryption                        │
│  - RSA Encryption/Signing                        │
│  - Key Management                                │
└──────────────────────────────────────────────────┘
        │                               │
        ▼                               ▼
┌───────────────┐              ┌──────────────────┐
│  PostgreSQL   │              │     Redis        │
│   Database    │              │     Cache        │
└───────────────┘              └──────────────────┘
```

### 1.2 Architecture Patterns

#### Microservices Pattern
- **Independent Services**: Each service can be developed, deployed, and scaled independently
- **Service Communication**: RESTful APIs over HTTPS
- **Service Discovery**: Environment-based configuration or service mesh

#### Layered Architecture (within each service)
```
┌─────────────────────────────────────┐
│      Presentation Layer (Controllers)│
├─────────────────────────────────────┤
│      Application Layer (Services)   │
├─────────────────────────────────────┤
│      Domain Layer (Entities/Models) │
├─────────────────────────────────────┤
│      Infrastructure Layer (DB, Cache)│
└─────────────────────────────────────┘
```

#### Repository Pattern
- Abstract data access logic
- Enable easy testing and database switching
- Centralize query logic

#### Strategy Pattern (Cryptography)
- Pluggable encryption algorithms
- Easy algorithm upgrades
- Algorithm-specific implementations

## 2. Service Architecture

### 2.1 Vault Service Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Vault Service                       │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │   Envelope   │  │    Prompt    │  │   Key    │ │
│  │  Controller  │  │  Controller  │  │Controller│ │
│  └──────┬───────┘  └──────┬───────┘  └────┬─────┘ │
│         │                 │                │        │
│  ┌──────▼─────────────────▼────────────────▼─────┐ │
│  │            Vault Service Layer                 │ │
│  │  - Envelope Generation                         │ │
│  │  - Prompt Management                           │ │
│  │  - Key Management                              │ │
│  └──────┬─────────────────────────────────────────┘ │
│         │                                            │
│  ┌──────▼─────────────────────────────────────────┐ │
│  │         Crypto Service (Shared Library)         │ │
│  │  - AES Encryption                              │ │
│  │  - RSA Encryption                              │ │
│  │  - Digital Signatures                          │ │
│  └──────┬─────────────────────────────────────────┘ │
│         │                                            │
│  ┌──────▼─────────────────────────────────────────┐ │
│  │         Repository Layer                        │ │
│  │  - Prompt Repository                           │ │
│  │  - Envelope Repository                         │ │
│  └──────┬─────────────────────────────────────────┘ │
│         │                                            │
│  ┌──────▼─────────────────────────────────────────┐ │
│  │         Infrastructure Layer                    │ │
│  │  - PostgreSQL (via TypeORM)                    │ │
│  │  - Redis Cache                                 │ │
│  │  - Key Vault Integration                       │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

### 2.2 Prompt Response Service Architecture

```
┌─────────────────────────────────────────────────────┐
│            Prompt Response Service                   │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────┐  ┌──────────────┐                │
│  │   Envelope   │  │   Response   │                │
│  │  Controller  │  │  Controller  │                │
│  └──────┬───────┘  └──────┬───────┘                │
│         │                 │                         │
│  ┌──────▼─────────────────▼───────────────────────┐ │
│  │         Response Service Layer                  │ │
│  │  - Envelope Decryption                          │ │
│  │  - Signature Verification                      │ │
│  │  - Prompt Processing                           │ │
│  └──────┬─────────────────────────────────────────┘ │
│         │                                            │
│  ┌──────▼─────────────────────────────────────────┐ │
│  │         Crypto Service (Shared Library)         │ │
│  │  - AES Decryption                              │ │
│  │  - RSA Decryption                              │ │
│  │  - Signature Verification                      │ │
│  └──────┬─────────────────────────────────────────┘ │
│         │                                            │
│  ┌──────▼─────────────────────────────────────────┐ │
│  │         Infrastructure Layer                    │ │
│  │  - Redis Cache                                 │ │
│  │  - Key Vault Integration                       │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## 3. Data Flow Architecture

### 3.1 Envelope Generation Flow

```
1. Client Request
   │
   ▼
2. Vault Controller (Validation)
   │
   ▼
3. Prompt Repository (Fetch Prompt by ID)
   │
   ▼
4. Crypto Service
   ├─► Generate AES-256 Key
   ├─► Encrypt Prompt (AES-256-GCM)
   ├─► Encrypt AES Key (RSA-2048)
   └─► Generate Signature (RSA-2048)
   │
   ▼
5. Envelope Assembly
   │
   ▼
6. Response to Client
```

### 3.2 Envelope Decryption Flow

```
1. Client Request (Envelope)
   │
   ▼
2. Response Controller (Validation)
   │
   ▼
3. Crypto Service
   ├─► Verify Signature (RSA-2048)
   ├─► Decrypt AES Key (RSA-2048)
   └─► Decrypt Prompt (AES-256-GCM)
   │
   ▼
4. Prompt Processing Service
   │
   ▼
5. Response Generation
   │
   ▼
6. Response to Client
```

## 4. Security Architecture

### 4.1 Security Layers

```
┌─────────────────────────────────────────┐
│  Layer 1: Network Security (TLS 1.3)   │
├─────────────────────────────────────────┤
│  Layer 2: Authentication (JWT/API Keys) │
├─────────────────────────────────────────┤
│  Layer 3: Authorization (RBAC)          │
├─────────────────────────────────────────┤
│  Layer 4: Input Validation              │
├─────────────────────────────────────────┤
│  Layer 5: Application Encryption         │
├─────────────────────────────────────────┤
│  Layer 6: Database Encryption            │
└─────────────────────────────────────────┘
```

### 4.2 Key Management Architecture

```
┌─────────────────────────────────────────┐
│      Key Management Service              │
│  (AWS KMS / HashiCorp Vault / Azure)    │
└───────────────┬─────────────────────────┘
                │
        ┌───────┴───────┐
        │               │
        ▼               ▼
┌──────────────┐  ┌──────────────┐
│ Vault Service│  │Response Service│
│  Key Access  │  │  Key Access   │
└──────────────┘  └──────────────┘
```

## 5. Deployment Architecture

### 5.1 Container Architecture

```
┌─────────────────────────────────────────────────┐
│              Docker Compose / Kubernetes         │
├─────────────────────────────────────────────────┤
│                                                  │
│  ┌──────────────┐      ┌──────────────┐         │
│  │ Vault Service│      │Response Service│       │
│  │  Container   │      │   Container   │        │
│  └──────┬───────┘      └──────┬───────┘         │
│         │                     │                 │
│  ┌──────▼─────────────────────▼───────┐         │
│  │      Shared Network                │         │
│  └──────┬─────────────────────┬───────┘         │
│         │                     │                 │
│  ┌──────▼──────┐      ┌───────▼──────┐         │
│  │ PostgreSQL  │      │    Redis     │         │
│  │  Container  │      │   Container  │         │
│  └─────────────┘      └──────────────┘         │
└─────────────────────────────────────────────────┘
```

### 5.2 Production Deployment

```
                    ┌─────────────┐
                    │ Load Balancer│
                    └──────┬───────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Vault Service│  │ Vault Service│  │ Vault Service│
│  Instance 1  │  │  Instance 2  │  │  Instance N  │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                  │
       └─────────────────┼──────────────────┘
                        │
                ┌───────▼────────┐
                │  PostgreSQL     │
                │  (Primary +    │
                │   Replicas)     │
                └─────────────────┘
```

## 6. Communication Patterns

### 6.1 Synchronous Communication
- **REST APIs**: Primary communication method
- **HTTP/HTTPS**: Transport protocol
- **JSON**: Data format

### 6.2 Asynchronous Communication (Future)
- **Message Queue**: RabbitMQ or AWS SQS
- **Event-Driven**: For audit logging and notifications
- **Pub/Sub**: For service coordination

## 7. Caching Strategy

### 7.1 Cache Layers

```
┌─────────────────────────────────────┐
│  Application Cache (In-Memory)      │
│  - Frequently accessed prompts      │
│  - TTL: 5 minutes                   │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Redis Cache (Distributed)          │
│  - Envelope metadata                │
│  - Key cache                        │
│  - TTL: 15 minutes                  │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Database (PostgreSQL)               │
│  - Persistent storage                │
└─────────────────────────────────────┘
```

### 7.2 Cache Invalidation
- **Time-based**: TTL expiration
- **Event-based**: Invalidate on updates
- **Manual**: Admin-triggered invalidation

## 8. Error Handling Architecture

### 8.1 Error Hierarchy

```
BaseException
├── ValidationException
├── AuthenticationException
├── AuthorizationException
├── CryptographyException
│   ├── EncryptionException
│   ├── DecryptionException
│   └── SignatureException
├── DatabaseException
└── ServiceException
```

### 8.2 Error Response Format

```json
{
  "error": {
    "code": "ENCRYPTION_FAILED",
    "message": "Failed to encrypt data",
    "details": {},
    "timestamp": "2025-03-12T14:30:00Z",
    "requestId": "uuid-v4"
  }
}
```

## 9. Monitoring Architecture

### 9.1 Observability Stack

```
┌─────────────────────────────────────────┐
│         Application Services             │
│  (Vault Service, Response Service)      │
└──────┬──────────────────────┬───────────┘
       │                      │
       ▼                      ▼
┌──────────────┐      ┌──────────────┐
│  Prometheus  │      │   Logging    │
│  (Metrics)   │      │   (ELK/Cloud)│
└──────┬───────┘      └──────────────┘
       │
       ▼
┌──────────────┐
│   Grafana    │
│ (Dashboards) │
└──────────────┘
```

### 9.2 Key Metrics
- **Performance**: Response time, throughput
- **Errors**: Error rate, error types
- **Security**: Failed authentication, signature verification failures
- **Resources**: CPU, memory, database connections

## 10. Scalability Considerations

### 10.1 Horizontal Scaling
- Stateless service design
- Load balancer distribution
- Database connection pooling
- Distributed caching

### 10.2 Vertical Scaling
- Resource limits per container
- Auto-scaling based on metrics
- Database read replicas

## 11. Disaster Recovery

### 11.1 Backup Strategy
- **Database**: Daily automated backups
- **Keys**: Secure backup in key vault
- **Configuration**: Version-controlled

### 11.2 Recovery Procedures
- **RTO (Recovery Time Objective)**: 1 hour
- **RPO (Recovery Point Objective)**: 24 hours
- **Failover**: Automated database failover

## 12. Technology Decisions

### 12.1 Framework: NestJS
**Rationale**:
- Built-in dependency injection
- Modular architecture
- TypeScript support
- Excellent documentation
- Large ecosystem

### 12.2 Database: PostgreSQL
**Rationale**:
- ACID compliance
- JSON support
- Excellent performance
- Strong security features
- Mature ecosystem

### 12.3 Cache: Redis
**Rationale**:
- High performance
- Distributed caching
- Pub/sub support
- Persistence options

### 12.4 Cryptography: Node.js crypto
**Rationale**:
- Built-in module
- NIST-approved algorithms
- Well-tested
- No external dependencies

