# 04. Database Schema Design

## 1. Schema Overview

The database schema is designed to support the E2EE system with a focus on security, performance, and auditability. All tables include audit fields (created_at, updated_at, deleted_at) for tracking changes.

## 2. Database Technology

- **Primary Database**: PostgreSQL 14+
- **Cache**: Redis 7+
- **ORM**: TypeORM (NestJS integration)

## 3. Core Tables

### 3.1 Prompts Table

Stores the original prompts that need to be encrypted and transmitted.

```sql
CREATE TABLE prompts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prompt_text TEXT NOT NULL,
    prompt_metadata JSONB,
    secret_hash VARCHAR(255) NOT NULL, -- SHA-256 hash of secret
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(255),
    updated_by VARCHAR(255)
);

-- Indexes
CREATE INDEX idx_prompts_status ON prompts(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_prompts_created_at ON prompts(created_at DESC);
CREATE INDEX idx_prompts_secret_hash ON prompts(secret_hash);
CREATE INDEX idx_prompts_deleted_at ON prompts(deleted_at) WHERE deleted_at IS NULL;

-- Full-text search index
CREATE INDEX idx_prompts_text_search ON prompts USING gin(to_tsvector('english', prompt_text));
```

**Field Descriptions**:
- `id`: Unique identifier (UUID v4)
- `prompt_text`: The actual prompt content (encrypted at application level if needed)
- `prompt_metadata`: Additional metadata (JSON format)
- `secret_hash`: Hash of the secret key for lookup
- `status`: Prompt status (active, archived, deleted)
- `version`: Version number for optimistic locking
- `created_at`, `updated_at`, `deleted_at`: Audit timestamps
- `created_by`, `updated_by`: User/service identifiers

### 3.2 Envelopes Table

Stores generated encrypted envelopes with their metadata.

```sql
CREATE TABLE envelopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prompt_id UUID NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    encrypted_data TEXT NOT NULL, -- Base64 encoded encrypted prompt
    encrypted_key TEXT NOT NULL, -- Base64 encoded RSA-encrypted AES key
    signature TEXT NOT NULL, -- Base64 encoded digital signature
    iv TEXT NOT NULL, -- Base64 encoded initialization vector
    auth_tag TEXT NOT NULL, -- Base64 encoded GCM authentication tag
    algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
    key_algorithm VARCHAR(50) NOT NULL DEFAULT 'RSA-OAEP',
    signature_algorithm VARCHAR(50) NOT NULL DEFAULT 'RSA-PSS',
    receiver_public_key_id VARCHAR(255), -- Identifier for receiver's public key
    sender_private_key_id VARCHAR(255), -- Identifier for sender's private key
    metadata JSONB,
    expires_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Indexes
CREATE INDEX idx_envelopes_prompt_id ON envelopes(prompt_id);
CREATE INDEX idx_envelopes_status ON envelopes(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_envelopes_created_at ON envelopes(created_at DESC);
CREATE INDEX idx_envelopes_expires_at ON envelopes(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_envelopes_deleted_at ON envelopes(deleted_at) WHERE deleted_at IS NULL;
```

**Field Descriptions**:
- `id`: Unique envelope identifier
- `prompt_id`: Foreign key to prompts table
- `encrypted_data`: AES-encrypted prompt (Base64)
- `encrypted_key`: RSA-encrypted AES key (Base64)
- `signature`: Digital signature (Base64)
- `iv`: Initialization vector for GCM (Base64)
- `auth_tag`: GCM authentication tag (Base64)
- `algorithm`: Encryption algorithm identifier
- `key_algorithm`: Key encryption algorithm
- `signature_algorithm`: Signature algorithm
- `receiver_public_key_id`: Key identifier for receiver
- `sender_private_key_id`: Key identifier for sender
- `metadata`: Additional envelope metadata
- `expires_at`: Optional expiration timestamp
- `status`: Envelope status (pending, delivered, decrypted, expired)

### 3.3 Envelope Decryptions Table

Tracks all decryption operations for audit purposes.

```sql
CREATE TABLE envelope_decryptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    envelope_id UUID NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
    decrypted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    signature_verified BOOLEAN NOT NULL,
    decryption_successful BOOLEAN NOT NULL,
    error_message TEXT,
    decrypted_by VARCHAR(255) NOT NULL, -- Service/user identifier
    ip_address INET,
    user_agent TEXT,
    metadata JSONB
);

-- Indexes
CREATE INDEX idx_decryptions_envelope_id ON envelope_decryptions(envelope_id);
CREATE INDEX idx_decryptions_decrypted_at ON envelope_decryptions(decrypted_at DESC);
CREATE INDEX idx_decryptions_success ON envelope_decryptions(decryption_successful, signature_verified);
CREATE INDEX idx_decryptions_decrypted_by ON envelope_decryptions(decrypted_by);
```

**Field Descriptions**:
- `id`: Unique decryption record identifier
- `envelope_id`: Foreign key to envelopes table
- `decrypted_at`: Timestamp of decryption
- `signature_verified`: Whether signature was verified
- `decryption_successful`: Whether decryption succeeded
- `error_message`: Error details if decryption failed
- `decrypted_by`: Service or user that performed decryption
- `ip_address`: Client IP address
- `user_agent`: Client user agent
- `metadata`: Additional decryption metadata

### 3.4 Cryptographic Keys Table

Stores metadata about cryptographic keys (not the keys themselves).

```sql
CREATE TABLE cryptographic_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id VARCHAR(255) UNIQUE NOT NULL, -- Human-readable key identifier
    key_type VARCHAR(50) NOT NULL, -- 'encryption', 'signing'
    key_algorithm VARCHAR(50) NOT NULL, -- 'RSA-2048', 'RSA-4096'
    key_usage VARCHAR(50) NOT NULL, -- 'sender', 'receiver'
    service_name VARCHAR(100) NOT NULL, -- 'vault', 'response'
    key_storage_location VARCHAR(255) NOT NULL, -- Path or vault identifier
    public_key_hash VARCHAR(255), -- SHA-256 hash of public key
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'rotated', 'revoked'
    rotated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_keys_key_id ON cryptographic_keys(key_id);
CREATE INDEX idx_keys_service_name ON cryptographic_keys(service_name);
CREATE INDEX idx_keys_status ON cryptographic_keys(status);
CREATE INDEX idx_keys_key_type ON cryptographic_keys(key_type, key_usage);
```

**Field Descriptions**:
- `id`: Unique key record identifier
- `key_id`: Human-readable key identifier
- `key_type`: Type of key (encryption or signing)
- `key_algorithm`: Algorithm and key size
- `key_usage`: Whether key is for sender or receiver
- `service_name`: Service that uses this key
- `key_storage_location`: Where the key is stored (path or vault ID)
- `public_key_hash`: Hash of public key for verification
- `status`: Key status
- `rotated_at`: When key was rotated
- `expires_at`: Key expiration date

### 3.5 Audit Logs Table

Comprehensive audit trail for all security-sensitive operations.

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL, -- 'encryption', 'decryption', 'key_access', etc.
    service_name VARCHAR(100) NOT NULL,
    user_id VARCHAR(255),
    resource_type VARCHAR(100), -- 'prompt', 'envelope', 'key'
    resource_id UUID,
    action VARCHAR(100) NOT NULL, -- 'create', 'read', 'update', 'delete'
    success BOOLEAN NOT NULL,
    error_message TEXT,
    ip_address INET,
    user_agent TEXT,
    request_id UUID, -- Correlation ID for request tracing
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_service_name ON audit_logs(service_name);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_request_id ON audit_logs(request_id);
CREATE INDEX idx_audit_user_id ON audit_logs(user_id);

-- Partitioning by month for performance (PostgreSQL 10+)
-- CREATE TABLE audit_logs_2025_03 PARTITION OF audit_logs
--     FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
```

**Field Descriptions**:
- `id`: Unique audit log identifier
- `event_type`: Type of event being logged
- `service_name`: Service that generated the log
- `user_id`: User or service identifier
- `resource_type`: Type of resource affected
- `resource_id`: ID of affected resource
- `action`: Action performed
- `success`: Whether action succeeded
- `error_message`: Error details if failed
- `ip_address`: Client IP address
- `user_agent`: Client user agent
- `request_id`: Request correlation ID
- `metadata`: Additional event metadata
- `created_at`: Event timestamp

## 4. TypeORM Entity Definitions

### 4.1 Prompt Entity

```typescript
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  OneToMany,
  Index,
} from 'typeorm';
import { Envelope } from './envelope.entity';

@Entity('prompts')
@Index(['status', 'deletedAt'])
@Index(['createdAt'])
export class Prompt {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text' })
  promptText: string;

  @Column({ type: 'jsonb', nullable: true })
  promptMetadata: Record<string, any>;

  @Column({ type: 'varchar', length: 255 })
  @Index()
  secretHash: string;

  @Column({ type: 'varchar', length: 50, default: 'active' })
  status: string;

  @Column({ type: 'int', default: 1 })
  version: number;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updatedAt: Date;

  @DeleteDateColumn({ type: 'timestamptz', nullable: true })
  deletedAt: Date;

  @Column({ type: 'varchar', length: 255, nullable: true })
  createdBy: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  updatedBy: string;

  @OneToMany(() => Envelope, (envelope) => envelope.prompt)
  envelopes: Envelope[];
}
```

### 4.2 Envelope Entity

```typescript
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Prompt } from './prompt.entity';

@Entity('envelopes')
@Index(['promptId'])
@Index(['status', 'deletedAt'])
@Index(['createdAt'])
export class Envelope {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  @Index()
  promptId: string;

  @ManyToOne(() => Prompt, (prompt) => prompt.envelopes)
  @JoinColumn({ name: 'promptId' })
  prompt: Prompt;

  @Column({ type: 'text' })
  encryptedData: string;

  @Column({ type: 'text' })
  encryptedKey: string;

  @Column({ type: 'text' })
  signature: string;

  @Column({ type: 'text' })
  iv: string;

  @Column({ type: 'text' })
  authTag: string;

  @Column({ type: 'varchar', length: 50, default: 'AES-256-GCM' })
  algorithm: string;

  @Column({ type: 'varchar', length: 50, default: 'RSA-OAEP' })
  keyAlgorithm: string;

  @Column({ type: 'varchar', length: 50, default: 'RSA-PSS' })
  signatureAlgorithm: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  receiverPublicKeyId: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  senderPrivateKeyId: string;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any>;

  @Column({ type: 'timestamptz', nullable: true })
  @Index()
  expiresAt: Date;

  @Column({ type: 'varchar', length: 50, default: 'pending' })
  status: string;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updatedAt: Date;

  @DeleteDateColumn({ type: 'timestamptz', nullable: true })
  deletedAt: Date;
}
```

## 5. Redis Cache Schema

### 5.1 Cache Key Patterns

```
# Prompt cache
prompt:{id} -> JSON serialized prompt object
TTL: 300 seconds (5 minutes)

# Envelope cache
envelope:{id} -> JSON serialized envelope metadata (without encrypted data)
TTL: 900 seconds (15 minutes)

# Key cache
key:{keyId} -> Public key (if safe to cache)
TTL: 3600 seconds (1 hour)

# Rate limiting
ratelimit:{service}:{identifier}:{window} -> Request count
TTL: Window duration
```

### 5.2 Cache Structure Examples

```typescript
// Prompt cache
{
  id: "uuid",
  promptText: "encrypted or hashed",
  status: "active",
  createdAt: "ISO timestamp"
}

// Envelope metadata cache
{
  id: "uuid",
  promptId: "uuid",
  status: "pending",
  expiresAt: "ISO timestamp",
  createdAt: "ISO timestamp"
}
```

## 6. Database Migrations

### 6.1 Migration Strategy

- Use TypeORM migrations for schema versioning
- All migrations are reversible
- Test migrations on staging before production
- Backup database before migrations

### 6.2 Sample Migration File

```typescript
import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitialSchema1234567890 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE prompts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        -- ... other columns
      );
    `);
    // ... other tables
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS prompts CASCADE;`);
    // ... other drops
  }
}
```

## 7. Data Retention Policies

### 7.1 Retention Periods

- **Prompts**: 7 years (compliance requirement)
- **Envelopes**: 1 year after expiration
- **Decryption Logs**: 7 years
- **Audit Logs**: 7 years (partitioned by month)
- **Key Metadata**: Indefinite (for historical reference)

### 7.2 Archival Strategy

- Move old data to archive tables
- Compress archived data
- Store archives in cold storage
- Maintain indexes for archived data queries

## 8. Backup and Recovery

### 8.1 Backup Strategy

- **Full Backups**: Daily at 2 AM UTC
- **Incremental Backups**: Every 6 hours
- **Transaction Logs**: Continuous archiving
- **Retention**: 30 days for full backups, 7 days for incremental

### 8.2 Recovery Procedures

- Point-in-time recovery capability
- Tested recovery procedures
- Documented RTO and RPO
- Automated backup verification

## 9. Performance Optimization

### 9.1 Indexing Strategy

- Index all foreign keys
- Index frequently queried columns
- Composite indexes for common query patterns
- Partial indexes for filtered queries

### 9.2 Query Optimization

- Use prepared statements
- Implement connection pooling
- Optimize N+1 queries
- Use database query analyzers

### 9.3 Partitioning

- Partition audit_logs by month
- Consider partitioning large tables by date
- Use PostgreSQL native partitioning

