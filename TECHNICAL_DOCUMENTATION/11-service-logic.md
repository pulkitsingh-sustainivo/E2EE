# 11. Service Logic & Business Rules

## 1. Vault Service Logic

### 1.1 Prompt Management

#### Create Prompt Logic

```typescript
// prompts/prompts.service.ts
import { Injectable, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Prompt } from './entities/prompt.entity';
import { CreatePromptDto } from './dto/create-prompt.dto';
import { createHash } from 'crypto';

@Injectable()
export class PromptsService {
  constructor(
    @InjectRepository(Prompt)
    private promptRepository: Repository<Prompt>,
  ) {}

  async create(createPromptDto: CreatePromptDto, userId: string): Promise<Prompt> {
    const { promptText, secret, metadata } = createPromptDto;

    // Hash the secret for storage
    const secretHash = this.hashSecret(secret);

    // Check if prompt with same secret hash exists
    const existingPrompt = await this.promptRepository.findOne({
      where: { secretHash, deletedAt: null },
    });

    if (existingPrompt) {
      throw new ConflictException('Prompt with this secret already exists');
    }

    // Create prompt entity
    const prompt = this.promptRepository.create({
      promptText,
      secretHash,
      promptMetadata: metadata,
      status: 'active',
      version: 1,
      createdBy: userId,
    });

    return await this.promptRepository.save(prompt);
  }

  private hashSecret(secret: string): string {
    return createHash('sha256').update(secret).digest('hex');
  }
}
```

#### Retrieve Prompt Logic

```typescript
async findOne(id: string, includeEnvelopes = false): Promise<Prompt> {
  const relations = includeEnvelopes ? ['envelopes'] : [];
  
  const prompt = await this.promptRepository.findOne({
    where: { id, deletedAt: null },
    relations,
  });

  if (!prompt) {
    throw new NotFoundException(`Prompt with ID ${id} not found`);
  }

  return prompt;
}
```

#### List Prompts Logic

```typescript
async findAll(query: QueryPromptDto): Promise<PaginatedResponse<Prompt>> {
  const { page = 1, limit = 20, status, search, sortBy = 'createdAt', sortOrder = 'desc' } = query;

  const queryBuilder = this.promptRepository
    .createQueryBuilder('prompt')
    .where('prompt.deletedAt IS NULL');

  // Filter by status
  if (status) {
    queryBuilder.andWhere('prompt.status = :status', { status });
  }

  // Search in prompt text
  if (search) {
    queryBuilder.andWhere(
      'prompt.promptText ILIKE :search',
      { search: `%${search}%` },
    );
  }

  // Sorting
  queryBuilder.orderBy(`prompt.${sortBy}`, sortOrder.toUpperCase() as 'ASC' | 'DESC');

  // Pagination
  const skip = (page - 1) * limit;
  queryBuilder.skip(skip).take(limit);

  const [items, total] = await queryBuilder.getManyAndCount();

  return {
    data: items,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasNext: page * limit < total,
      hasPrev: page > 1,
    },
  };
}
```

### 1.2 Envelope Generation Logic

```typescript
// envelopes/envelopes.service.ts
import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Envelope } from './entities/envelope.entity';
import { CreateEnvelopeDto } from './dto/create-envelope.dto';
import { CryptoService } from '../crypto/crypto.service';
import { PromptsService } from '../prompts/prompts.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class EnvelopesService {
  constructor(
    @InjectRepository(Envelope)
    private envelopeRepository: Repository<Envelope>,
    private cryptoService: CryptoService,
    private promptsService: PromptsService,
    private auditService: AuditService,
  ) {}

  async generateEnvelope(
    createEnvelopeDto: CreateEnvelopeDto,
    userId: string,
  ): Promise<Envelope> {
    const { promptId, secret, receiverPublicKeyId, expiresAt, metadata } = createEnvelopeDto;

    // Step 1: Verify prompt exists and secret is correct
    const prompt = await this.promptsService.findOne(promptId);
    const secretHash = this.hashSecret(secret);
    
    if (prompt.secretHash !== secretHash) {
      throw new BadRequestException('Invalid secret for prompt');
    }

    // Step 2: Check if prompt is active
    if (prompt.status !== 'active') {
      throw new BadRequestException(`Prompt is ${prompt.status}`);
    }

    // Step 3: Validate expiration date
    if (expiresAt && new Date(expiresAt) <= new Date()) {
      throw new BadRequestException('Expiration date must be in the future');
    }

    // Step 4: Generate encrypted envelope
    const envelopeData = await this.cryptoService.encryptAndSign({
      data: prompt.promptText,
      receiverPublicKeyId,
      senderPrivateKeyId: 'prompt_vault_sign_private',
      metadata: {
        promptId,
        ...metadata,
      },
    });

    // Step 5: Create envelope entity
    const envelope = this.envelopeRepository.create({
      promptId: prompt.id,
      ...envelopeData,
      receiverPublicKeyId,
      senderPrivateKeyId: 'prompt_vault_sign_private',
      expiresAt: expiresAt ? new Date(expiresAt) : null,
      status: 'pending',
      metadata,
    });

    const savedEnvelope = await this.envelopeRepository.save(envelope);

    // Step 6: Audit log
    await this.auditService.log({
      eventType: 'envelope_created',
      serviceName: 'vault-service',
      userId,
      resourceType: 'envelope',
      resourceId: savedEnvelope.id,
      action: 'create',
      success: true,
      metadata: { promptId },
    });

    return savedEnvelope;
  }

  private hashSecret(secret: string): string {
    return createHash('sha256').update(secret).digest('hex');
  }
}
```

## 2. Prompt Response Service Logic

### 2.1 Envelope Decryption Logic

```typescript
// envelopes/envelopes.service.ts (Prompt Response Service)
import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { EnvelopeDecryptorService } from '@e2ee/crypto-lib';
import { DecryptEnvelopeDto } from './dto/decrypt-envelope.dto';
import { AuditService } from '../audit/audit.service';
import { EnvelopeDecryption } from './entities/envelope-decryption.entity';

@Injectable()
export class EnvelopesService {
  constructor(
    private envelopeDecryptor: EnvelopeDecryptorService,
    private auditService: AuditService,
    @InjectRepository(EnvelopeDecryption)
    private decryptionRepository: Repository<EnvelopeDecryption>,
  ) {}

  async decryptEnvelope(
    decryptEnvelopeDto: DecryptEnvelopeDto,
    userId: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<{ prompt: string; decryption: EnvelopeDecryption }> {
    const { envelope, receiverPrivateKeyId, senderPublicKeyId } = decryptEnvelopeDto;

    let decryptionRecord: EnvelopeDecryption;
    let decryptedPrompt: string;

    try {
      // Step 1: Validate envelope structure
      this.validateEnvelope(envelope);

      // Step 2: Check expiration
      if (envelope.expiresAt && new Date(envelope.expiresAt) < new Date()) {
        throw new BadRequestException('Envelope has expired');
      }

      // Step 3: Decrypt envelope
      decryptedPrompt = await this.envelopeDecryptor.decryptEnvelope({
        envelope,
        receiverPrivateKeyPath: this.getKeyPath(receiverPrivateKeyId),
        senderPublicKeyPath: this.getKeyPath(senderPublicKeyId),
      });

      // Step 4: Create decryption record
      decryptionRecord = this.decryptionRepository.create({
        envelopeId: envelope.id,
        decryptedAt: new Date(),
        signatureVerified: true,
        decryptionSuccessful: true,
        decryptedBy: userId,
        ipAddress,
        userAgent,
      });

      await this.decryptionRepository.save(decryptionRecord);

      // Step 5: Audit log
      await this.auditService.log({
        eventType: 'envelope_decrypted',
        serviceName: 'prompt-response-service',
        userId,
        resourceType: 'envelope',
        resourceId: envelope.id,
        action: 'decrypt',
        success: true,
        ipAddress,
        userAgent,
      });

      return {
        prompt: decryptedPrompt,
        decryption: decryptionRecord,
      };
    } catch (error) {
      // Log failed decryption
      decryptionRecord = this.decryptionRepository.create({
        envelopeId: envelope.id,
        decryptedAt: new Date(),
        signatureVerified: error.message.includes('signature') ? false : null,
        decryptionSuccessful: false,
        errorMessage: error.message,
        decryptedBy: userId,
        ipAddress,
        userAgent,
      });

      await this.decryptionRepository.save(decryptionRecord);

      // Audit log failure
      await this.auditService.log({
        eventType: 'envelope_decryption_failed',
        serviceName: 'prompt-response-service',
        userId,
        resourceType: 'envelope',
        resourceId: envelope.id,
        action: 'decrypt',
        success: false,
        errorMessage: error.message,
        ipAddress,
        userAgent,
      });

      throw error;
    }
  }

  private validateEnvelope(envelope: any): void {
    const requiredFields = [
      'encryptedData',
      'encryptedKey',
      'signature',
      'iv',
      'authTag',
      'algorithm',
      'keyAlgorithm',
      'signatureAlgorithm',
    ];

    for (const field of requiredFields) {
      if (!envelope[field]) {
        throw new BadRequestException(`Missing required field: ${field}`);
      }
    }

    // Validate algorithm compatibility
    if (envelope.algorithm !== 'AES-256-GCM') {
      throw new BadRequestException(`Unsupported algorithm: ${envelope.algorithm}`);
    }

    if (envelope.keyAlgorithm !== 'RSA-OAEP') {
      throw new BadRequestException(`Unsupported key algorithm: ${envelope.keyAlgorithm}`);
    }
  }

  private getKeyPath(keyId: string): string {
    // Map key ID to file path
    const keyMap: Record<string, string> = {
      'prompt_response_enc_private': process.env.PROMPT_RESPONSE_ENC_PRIVATE_KEY_PATH,
      'prompt_vault_sign_public': process.env.PROMPT_VAULT_SIGN_PUBLIC_KEY_PATH,
    };

    const path = keyMap[keyId];
    if (!path) {
      throw new BadRequestException(`Unknown key ID: ${keyId}`);
    }

    return path;
  }
}
```

### 2.2 Prompt Processing Logic

```typescript
// prompts/prompts.service.ts (Prompt Response Service)
import { Injectable } from '@nestjs/common';
import { ProcessPromptDto } from './dto/process-prompt.dto';
import { PromptProcessor } from './processors/prompt-processor.interface';

@Injectable()
export class PromptsService {
  constructor(
    private promptProcessor: PromptProcessor,
  ) {}

  async processPrompt(processPromptDto: ProcessPromptDto): Promise<any> {
    const { promptId, promptText, options } = processPromptDto;

    // Step 1: Validate prompt text
    if (!promptText || promptText.trim().length === 0) {
      throw new BadRequestException('Prompt text is required');
    }

    // Step 2: Process prompt using processor
    const result = await this.promptProcessor.process({
      promptText,
      options: options || {},
    });

    // Step 3: Format response
    return {
      id: require('uuid').v4(),
      promptId,
      result: result.response,
      metadata: {
        processingTime: result.processingTime,
        model: result.model,
        ...result.metadata,
      },
      createdAt: new Date(),
    };
  }
}
```

#### Prompt Processor Interface

```typescript
// prompts/processors/prompt-processor.interface.ts
export interface ProcessOptions {
  format?: 'json' | 'text';
  includeMetadata?: boolean;
  [key: string]: any;
}

export interface ProcessResult {
  response: string;
  processingTime: number;
  model?: string;
  metadata?: Record<string, any>;
}

export interface PromptProcessor {
  process(prompt: { promptText: string; options: ProcessOptions }): Promise<ProcessResult>;
}
```

#### Default Prompt Processor

```typescript
// prompts/processors/default-prompt-processor.ts
import { Injectable } from '@nestjs/common';
import { PromptProcessor, ProcessResult } from './prompt-processor.interface';

@Injectable()
export class DefaultPromptProcessor implements PromptProcessor {
  async process(prompt: { promptText: string; options: any }): Promise<ProcessResult> {
    const startTime = Date.now();

    // Simple echo processor (replace with actual AI/LLM integration)
    const response = `Processed: ${prompt.promptText}`;

    const processingTime = Date.now() - startTime;

    return {
      response,
      processingTime,
      model: 'default',
      metadata: {
        inputLength: prompt.promptText.length,
        outputLength: response.length,
      },
    };
  }
}
```

## 3. Business Rules

### 3.1 Prompt Rules

1. **Uniqueness**: Prompts with the same secret hash cannot be created
2. **Status**: Only active prompts can be used to generate envelopes
3. **Versioning**: Each update increments version number
4. **Soft Delete**: Prompts are soft-deleted, not permanently removed

### 3.2 Envelope Rules

1. **Expiration**: Envelopes can have expiration dates
2. **Status Flow**: pending → delivered → decrypted → expired
3. **One-Time Use**: Envelopes can be marked as one-time use (optional)
4. **Secret Validation**: Secret must match prompt's secret hash

### 3.3 Decryption Rules

1. **Signature Verification**: Must verify signature before decryption
2. **Expiration Check**: Expired envelopes cannot be decrypted
3. **Audit Trail**: All decryption attempts are logged
4. **Error Handling**: Failed decryptions are logged with error details

## 4. Error Handling

### 4.1 Custom Exceptions

```typescript
// common/exceptions/business-exceptions.ts
export class PromptNotFoundException extends NotFoundException {
  constructor(promptId: string) {
    super(`Prompt with ID ${promptId} not found`);
  }
}

export class InvalidSecretException extends BadRequestException {
  constructor() {
    super('Invalid secret for prompt');
  }
}

export class EnvelopeExpiredException extends BadRequestException {
  constructor() {
    super('Envelope has expired');
  }
}

export class SignatureVerificationFailedException extends UnauthorizedException {
  constructor() {
    super('Signature verification failed: envelope may have been tampered with');
  }
}
```

### 4.2 Global Exception Filter

```typescript
// common/filters/all-exceptions.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const message =
      exception instanceof HttpException
        ? exception.getResponse()
        : 'Internal server error';

    const errorResponse = {
      success: false,
      error: {
        code: this.getErrorCode(exception),
        message: typeof message === 'string' ? message : (message as any).message,
        details: typeof message === 'object' ? (message as any).details : undefined,
      },
      meta: {
        timestamp: new Date().toISOString(),
        path: request.url,
        requestId: request.headers['x-request-id'] || require('uuid').v4(),
      },
    };

    // Don't log 4xx errors in production
    if (status >= 500) {
      console.error('Internal server error:', exception);
    }

    response.status(status).json(errorResponse);
  }

  private getErrorCode(exception: unknown): string {
    if (exception instanceof HttpException) {
      const response = exception.getResponse();
      return typeof response === 'object' && (response as any).error
        ? (response as any).error
        : 'HTTP_EXCEPTION';
    }
    return 'INTERNAL_SERVER_ERROR';
  }
}
```

## 5. Caching Strategy

### 5.1 Prompt Caching

```typescript
// prompts/prompts.service.ts
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable } from '@nestjs/common';
import { Cache } from 'cache-manager';

@Injectable()
export class PromptsService {
  constructor(
    @InjectRepository(Prompt)
    private promptRepository: Repository<Prompt>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async findOne(id: string): Promise<Prompt> {
    // Check cache first
    const cacheKey = `prompt:${id}`;
    const cached = await this.cacheManager.get<Prompt>(cacheKey);
    
    if (cached) {
      return cached;
    }

    // Fetch from database
    const prompt = await this.promptRepository.findOne({
      where: { id, deletedAt: null },
    });

    if (!prompt) {
      throw new NotFoundException(`Prompt with ID ${id} not found`);
    }

    // Cache for 5 minutes
    await this.cacheManager.set(cacheKey, prompt, 300);

    return prompt;
  }

  async invalidateCache(id: string): Promise<void> {
    await this.cacheManager.del(`prompt:${id}`);
  }
}
```

## 6. Transaction Management

### 6.1 Database Transactions

```typescript
// envelopes/envelopes.service.ts
import { DataSource } from 'typeorm';

@Injectable()
export class EnvelopesService {
  constructor(
    private dataSource: DataSource,
    // ... other dependencies
  ) {}

  async generateEnvelopeWithTransaction(dto: CreateEnvelopeDto): Promise<Envelope> {
    return await this.dataSource.transaction(async (manager) => {
      // All operations within transaction
      const prompt = await manager.findOne(Prompt, { where: { id: dto.promptId } });
      
      const envelope = manager.create(Envelope, {
        // ... envelope data
      });

      const savedEnvelope = await manager.save(Envelope, envelope);

      await manager.save(AuditLog, {
        // ... audit log
      });

      return savedEnvelope;
    });
  }
}
```

## 7. Validation Logic

### 7.1 Custom Validators

```typescript
// common/validators/is-secret-strong.validator.ts
import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
} from 'class-validator';

export function IsSecretStrong(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isSecretStrong',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          if (typeof value !== 'string') {
            return false;
          }

          // At least 8 characters, contains uppercase, lowercase, number, special char
          const minLength = value.length >= 8;
          const hasUpperCase = /[A-Z]/.test(value);
          const hasLowerCase = /[a-z]/.test(value);
          const hasNumber = /[0-9]/.test(value);
          const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(value);

          return minLength && hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} must be at least 8 characters and contain uppercase, lowercase, number, and special character`;
        },
      },
    });
  };
}
```

