# 06. NestJS Project Structure

## 1. Monorepo Structure

The project uses a monorepo structure with shared libraries and independent services:

```
e2ee-project/
├── packages/
│   ├── crypto-lib/              # Shared cryptographic library
│   │   ├── src/
│   │   │   ├── aes/
│   │   │   ├── rsa/
│   │   │   ├── signatures/
│   │   │   └── index.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── common/                  # Shared utilities
│       ├── src/
│       │   ├── decorators/
│       │   ├── filters/
│       │   ├── guards/
│       │   ├── interceptors/
│       │   └── pipes/
│       └── package.json
├── services/
│   ├── vault-service/          # Vault Service
│   │   ├── src/
│   │   ├── test/
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── prompt-response-service/ # Prompt Response Service
│       ├── src/
│       ├── test/
│       ├── package.json
│       └── tsconfig.json
├── docker/
│   ├── Dockerfile.vault
│   ├── Dockerfile.response
│   └── docker-compose.yml
├── scripts/
│   ├── generate-keys.sh
│   ├── migrate.sh
│   └── seed.sh
├── .github/
│   └── workflows/
│       └── ci.yml
├── package.json                 # Root package.json (workspace)
├── tsconfig.base.json
├── .eslintrc.js
├── .prettierrc
└── README.md
```

## 2. Vault Service Structure

```
vault-service/
├── src/
│   ├── main.ts                  # Application entry point
│   ├── app.module.ts            # Root module
│   ├── config/                  # Configuration
│   │   ├── config.module.ts
│   │   ├── config.service.ts
│   │   ├── database.config.ts
│   │   ├── redis.config.ts
│   │   └── security.config.ts
│   ├── common/                  # Service-specific common code
│   │   ├── decorators/
│   │   │   ├── public.decorator.ts
│   │   │   └── roles.decorator.ts
│   │   ├── filters/
│   │   │   ├── http-exception.filter.ts
│   │   │   └── all-exceptions.filter.ts
│   │   ├── guards/
│   │   │   ├── jwt-auth.guard.ts
│   │   │   ├── api-key.guard.ts
│   │   │   └── roles.guard.ts
│   │   ├── interceptors/
│   │   │   ├── logging.interceptor.ts
│   │   │   ├── transform.interceptor.ts
│   │   │   └── timeout.interceptor.ts
│   │   ├── pipes/
│   │   │   ├── validation.pipe.ts
│   │   │   └── parse-uuid.pipe.ts
│   │   └── middleware/
│   │       ├── logger.middleware.ts
│   │       └── request-id.middleware.ts
│   ├── prompts/                 # Prompt module
│   │   ├── prompts.module.ts
│   │   ├── prompts.controller.ts
│   │   ├── prompts.service.ts
│   │   ├── entities/
│   │   │   └── prompt.entity.ts
│   │   ├── dto/
│   │   │   ├── create-prompt.dto.ts
│   │   │   ├── update-prompt.dto.ts
│   │   │   └── query-prompt.dto.ts
│   │   ├── repositories/
│   │   │   └── prompts.repository.ts
│   │   └── prompts.controller.spec.ts
│   ├── envelopes/               # Envelope module
│   │   ├── envelopes.module.ts
│   │   ├── envelopes.controller.ts
│   │   ├── envelopes.service.ts
│   │   ├── entities/
│   │   │   └── envelope.entity.ts
│   │   ├── dto/
│   │   │   ├── create-envelope.dto.ts
│   │   │   └── query-envelope.dto.ts
│   │   ├── repositories/
│   │   │   └── envelopes.repository.ts
│   │   └── envelopes.controller.spec.ts
│   ├── crypto/                  # Crypto module (wraps shared lib)
│   │   ├── crypto.module.ts
│   │   ├── crypto.service.ts
│   │   ├── key-management.service.ts
│   │   └── crypto.service.spec.ts
│   ├── audit/                   # Audit logging module
│   │   ├── audit.module.ts
│   │   ├── audit.service.ts
│   │   ├── entities/
│   │   │   └── audit-log.entity.ts
│   │   └── audit.service.spec.ts
│   ├── health/                  # Health check module
│   │   ├── health.module.ts
│   │   ├── health.controller.ts
│   │   └── health.service.ts
│   └── database/                # Database configuration
│       ├── database.module.ts
│       ├── migrations/
│       └── seeds/
├── test/
│   ├── e2e/
│   │   ├── prompts.e2e-spec.ts
│   │   └── envelopes.e2e-spec.ts
│   ├── fixtures/
│   └── jest-e2e.json
├── .env.example
├── .env
├── package.json
├── tsconfig.json
├── nest-cli.json
└── README.md
```

## 3. Prompt Response Service Structure

```
prompt-response-service/
├── src/
│   ├── main.ts
│   ├── app.module.ts
│   ├── config/
│   │   ├── config.module.ts
│   │   ├── config.service.ts
│   │   ├── redis.config.ts
│   │   └── security.config.ts
│   ├── common/                  # Similar to vault-service
│   │   ├── decorators/
│   │   ├── filters/
│   │   ├── guards/
│   │   ├── interceptors/
│   │   └── pipes/
│   ├── envelopes/               # Envelope decryption module
│   │   ├── envelopes.module.ts
│   │   ├── envelopes.controller.ts
│   │   ├── envelopes.service.ts
│   │   ├── dto/
│   │   │   └── decrypt-envelope.dto.ts
│   │   └── envelopes.controller.spec.ts
│   ├── prompts/                 # Prompt processing module
│   │   ├── prompts.module.ts
│   │   ├── prompts.controller.ts
│   │   ├── prompts.service.ts
│   │   ├── processors/
│   │   │   ├── prompt-processor.interface.ts
│   │   │   └── default-prompt-processor.ts
│   │   └── dto/
│   │       └── process-prompt.dto.ts
│   ├── crypto/                  # Crypto module
│   │   ├── crypto.module.ts
│   │   ├── crypto.service.ts
│   │   └── key-management.service.ts
│   ├── audit/
│   │   ├── audit.module.ts
│   │   └── audit.service.ts
│   └── health/
│       ├── health.module.ts
│       └── health.controller.ts
├── test/
│   ├── e2e/
│   └── fixtures/
├── package.json
├── tsconfig.json
└── nest-cli.json
```

## 4. Shared Crypto Library Structure

```
packages/crypto-lib/
├── src/
│   ├── index.ts                 # Public API
│   ├── aes/
│   │   ├── aes-encryption.service.ts
│   │   ├── aes-decryption.service.ts
│   │   └── aes.types.ts
│   ├── rsa/
│   │   ├── rsa-encryption.service.ts
│   │   ├── rsa-decryption.service.ts
│   │   └── rsa.types.ts
│   ├── signatures/
│   │   ├── signature.service.ts
│   │   ├── signature-verification.service.ts
│   │   └── signature.types.ts
│   ├── keys/
│   │   ├── key-loader.service.ts
│   │   ├── key-validator.service.ts
│   │   └── key.types.ts
│   ├── envelope/
│   │   ├── envelope-builder.service.ts
│   │   ├── envelope-decryptor.service.ts
│   │   └── envelope.types.ts
│   └── errors/
│       ├── crypto-error.ts
│       ├── encryption-error.ts
│       └── decryption-error.ts
├── test/
│   ├── unit/
│   └── integration/
├── package.json
├── tsconfig.json
└── README.md
```

## 5. Module Organization Principles

### 5.1 Feature-Based Modules
Each feature is a self-contained module with:
- Controller (handles HTTP requests)
- Service (business logic)
- Entities (database models)
- DTOs (data transfer objects)
- Repository (data access)
- Tests

### 5.2 Module Dependencies
```
AppModule
├── ConfigModule (global)
├── DatabaseModule (global)
├── RedisModule (global)
├── PromptsModule
│   ├── CryptoModule
│   └── AuditModule
├── EnvelopesModule
│   ├── PromptsModule
│   ├── CryptoModule
│   └── AuditModule
├── HealthModule
└── CommonModule (global)
```

## 6. Key Files Explained

### 6.1 main.ts

```typescript
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Global prefix
  app.setGlobalPrefix('api/v1');

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Global exception filter
  app.useGlobalFilters(new AllExceptionsFilter());

  // Global interceptors
  app.useGlobalInterceptors(new LoggingInterceptor());

  // Swagger documentation
  const config = new DocumentBuilder()
    .setTitle('Vault Service API')
    .setDescription('E2EE Vault Service API Documentation')
    .setVersion('1.0')
    .addBearerAuth()
    .addApiKey({ type: 'apiKey', name: 'X-API-Key', in: 'header' })
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  // CORS
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
    credentials: true,
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`Application is running on: http://localhost:${port}`);
}

bootstrap();
```

### 6.2 app.module.ts

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PromptsModule } from './prompts/prompts.module';
import { EnvelopesModule } from './envelopes/envelopes.module';
import { CryptoModule } from './crypto/crypto.module';
import { AuditModule } from './audit/audit.module';
import { HealthModule } from './health/health.module';
import { DatabaseModule } from './database/database.module';
import { RedisModule } from './config/redis.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
    }),
    DatabaseModule,
    RedisModule,
    PromptsModule,
    EnvelopesModule,
    CryptoModule,
    AuditModule,
    HealthModule,
  ],
})
export class AppModule {}
```

### 6.3 Example Controller

```typescript
import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { EnvelopesService } from './envelopes.service';
import { CreateEnvelopeDto } from './dto/create-envelope.dto';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { ApiKeyGuard } from '../common/guards/api-key.guard';

@ApiTags('envelopes')
@Controller('envelopes')
@UseGuards(JwtAuthGuard, ApiKeyGuard)
@ApiBearerAuth()
export class EnvelopesController {
  constructor(private readonly envelopesService: EnvelopesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Generate encrypted envelope' })
  @ApiResponse({ status: 201, description: 'Envelope created successfully' })
  @ApiResponse({ status: 400, description: 'Bad request' })
  async create(@Body() createEnvelopeDto: CreateEnvelopeDto) {
    return this.envelopesService.generateEnvelope(createEnvelopeDto);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get envelope by ID' })
  @ApiResponse({ status: 200, description: 'Envelope found' })
  @ApiResponse({ status: 404, description: 'Envelope not found' })
  async findOne(@Param('id') id: string) {
    return this.envelopesService.findOne(id);
  }
}
```

### 6.4 Example Service

```typescript
import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Envelope } from './entities/envelope.entity';
import { CreateEnvelopeDto } from './dto/create-envelope.dto';
import { CryptoService } from '../crypto/crypto.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class EnvelopesService {
  constructor(
    @InjectRepository(Envelope)
    private envelopeRepository: Repository<Envelope>,
    private cryptoService: CryptoService,
    private auditService: AuditService,
  ) {}

  async generateEnvelope(createEnvelopeDto: CreateEnvelopeDto): Promise<Envelope> {
    const { promptId, secret, receiverPublicKeyId, expiresAt } = createEnvelopeDto;

    // Fetch prompt
    const prompt = await this.findPromptById(promptId);

    // Generate envelope using crypto service
    const envelopeData = await this.cryptoService.encryptAndSign({
      data: prompt.promptText,
      receiverPublicKeyId,
      senderPrivateKeyId: 'prompt_vault_sign_private',
      metadata: { promptId },
    });

    // Create envelope entity
    const envelope = this.envelopeRepository.create({
      promptId,
      ...envelopeData,
      expiresAt,
      status: 'pending',
    });

    const savedEnvelope = await this.envelopeRepository.save(envelope);

    // Audit log
    await this.auditService.log({
      eventType: 'envelope_created',
      resourceType: 'envelope',
      resourceId: savedEnvelope.id,
      action: 'create',
      success: true,
    });

    return savedEnvelope;
  }

  async findOne(id: string): Promise<Envelope> {
    const envelope = await this.envelopeRepository.findOne({
      where: { id, deletedAt: null },
    });

    if (!envelope) {
      throw new NotFoundException(`Envelope with ID ${id} not found`);
    }

    return envelope;
  }

  private async findPromptById(id: string) {
    // Implementation to fetch prompt
    // This would be in a prompts service
    return null;
  }
}
```

## 7. Configuration Management

### 7.1 Config Module Structure

```typescript
// config/config.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { ConfigService } from './config.service';
import databaseConfig from './database.config';
import redisConfig from './redis.config';
import securityConfig from './security.config';

@Module({
  imports: [
    NestConfigModule.forRoot({
      load: [databaseConfig, redisConfig, securityConfig],
      isGlobal: true,
    }),
  ],
  providers: [ConfigService],
  exports: [ConfigService],
})
export class ConfigModule {}
```

### 7.2 Environment Variables

```bash
# .env.example
NODE_ENV=development
PORT=3000

# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres
DATABASE_NAME=e2ee_vault

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Security
JWT_SECRET=your-jwt-secret
JWT_EXPIRES_IN=1h
API_KEY_HEADER=X-API-Key

# Keys
RECEIVER_PUBLIC_KEY_PATH=./keys/prompt_response_enc_public.key
SENDER_PRIVATE_KEY_PATH=./keys/prompt_vault_sign_private.key

# Logging
LOG_LEVEL=info
```

## 8. Testing Structure

### 8.1 Unit Tests
- One test file per service/controller
- Mock all dependencies
- Test business logic in isolation

### 8.2 Integration Tests
- Test module integration
- Use test database
- Test database operations

### 8.3 E2E Tests
- Test complete request/response cycle
- Use test containers for databases
- Test API endpoints

## 9. Build Configuration

### 9.1 tsconfig.json

```json
{
  "compilerOptions": {
    "module": "commonjs",
    "declaration": true,
    "removeComments": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "allowSyntheticDefaultImports": true,
    "target": "ES2021",
    "sourceMap": true,
    "outDir": "./dist",
    "baseUrl": "./",
    "incremental": true,
    "skipLibCheck": true,
    "strictNullChecks": true,
    "noImplicitAny": true,
    "strictBindCallApply": true,
    "forceConsistentCasingInFileNames": true,
    "noFallthroughCasesInSwitch": true,
    "paths": {
      "@/*": ["src/*"],
      "@common/*": ["src/common/*"],
      "@crypto-lib/*": ["../../packages/crypto-lib/src/*"]
    }
  }
}
```

### 9.2 nest-cli.json

```json
{
  "collection": "@nestjs/schematics",
  "sourceRoot": "src",
  "compilerOptions": {
    "deleteOutDir": true,
    "webpack": false,
    "tsConfigPath": "tsconfig.json"
  }
}
```

## 10. Best Practices

### 10.1 Code Organization
- One feature per module
- Shared code in common directory
- DTOs for all data transfer
- Entities for database models

### 10.2 Dependency Injection
- Use constructor injection
- Avoid circular dependencies
- Use interfaces for abstractions

### 10.3 Error Handling
- Custom exception classes
- Global exception filter
- Consistent error responses

### 10.4 Validation
- DTOs with class-validator
- Global validation pipe
- Custom validators for complex rules

