# 08. Security Implementation

## 1. Security Overview

The E2EE system implements multiple layers of security to protect data at rest, in transit, and during processing. This document outlines all security measures and their implementation.

## 2. Authentication & Authorization

### 2.1 JWT Authentication

#### Implementation

```typescript
// auth/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    if (!payload.sub || !payload.email) {
      throw new UnauthorizedException('Invalid token payload');
    }

    return {
      userId: payload.sub,
      email: payload.email,
      roles: payload.roles || [],
    };
  }
}
```

#### JWT Guard

```typescript
// common/guards/jwt-auth.guard.ts
import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Reflector } from '@nestjs/core';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    return super.canActivate(context);
  }
}
```

### 2.2 API Key Authentication

#### Implementation

```typescript
// auth/api-key.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { HeaderAPIKeyStrategy } from 'passport-headerapikey';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class ApiKeyStrategy extends PassportStrategy(HeaderAPIKeyStrategy, 'api-key') {
  constructor(private configService: ConfigService) {
    super(
      { header: 'X-API-Key', prefix: '' },
      true,
      async (apiKey: string, done: any) => {
        return this.validate(apiKey, done);
      },
    );
  }

  async validate(apiKey: string, done: (error: Error, data?: any) => void) {
    // Validate API key from database or config
    const validKey = await this.validateApiKey(apiKey);
    
    if (!validKey) {
      return done(new UnauthorizedException('Invalid API key'), null);
    }

    return done(null, { apiKey, service: validKey.service });
  }

  private async validateApiKey(apiKey: string): Promise<any> {
    // Implementation: Check against database or key store
    // Hash comparison for security
    return null;
  }
}
```

### 2.3 Role-Based Access Control (RBAC)

#### Roles Decorator

```typescript
// common/decorators/roles.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
```

#### Roles Guard

```typescript
// common/guards/roles.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}
```

#### Usage

```typescript
@Controller('prompts')
@UseGuards(JwtAuthGuard, RolesGuard)
export class PromptsController {
  @Post()
  @Roles('admin', 'vault-service')
  create(@Body() createPromptDto: CreatePromptDto) {
    // Only admin and vault-service can create prompts
  }
}
```

## 3. Input Validation & Sanitization

### 3.1 DTO Validation

```typescript
// prompts/dto/create-prompt.dto.ts
import { IsString, IsNotEmpty, IsOptional, IsObject, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreatePromptDto {
  @ApiProperty({ description: 'Prompt text', maxLength: 10000 })
  @IsString()
  @IsNotEmpty()
  @MaxLength(10000)
  promptText: string;

  @ApiProperty({ description: 'Secret key for prompt access', required: false })
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  secret: string;

  @ApiProperty({ description: 'Additional metadata', required: false })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}
```

### 3.2 Global Validation Pipe

```typescript
// main.ts
app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true, // Strip properties not in DTO
    forbidNonWhitelisted: true, // Throw error for unknown properties
    transform: true, // Auto-transform to DTO instances
    transformOptions: {
      enableImplicitConversion: true,
    },
    disableErrorMessages: process.env.NODE_ENV === 'production',
  }),
);
```

### 3.3 Custom Validators

```typescript
// common/validators/is-uuid.validator.ts
import { registerDecorator, ValidationOptions, ValidationArguments } from 'class-validator';
import { validate as uuidValidate } from 'uuid';

export function IsUUID(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isUUID',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          return typeof value === 'string' && uuidValidate(value);
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} must be a valid UUID`;
        },
      },
    });
  };
}
```

## 4. Security Headers

### 4.1 Helmet Configuration

```typescript
// main.ts
import helmet from 'helmet';

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'no-referrer' },
  }),
);
```

## 5. Rate Limiting

### 5.1 Throttler Configuration

```typescript
// app.module.ts
import { ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [
    ThrottlerModule.forRoot({
      ttl: 60, // Time window in seconds
      limit: 100, // Max requests per window
      storage: new ThrottlerStorageRedisService(redisClient),
    }),
  ],
})
export class AppModule {}
```

### 5.2 Rate Limit Guards

```typescript
// common/guards/throttle.guard.ts
import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  protected getTracker(req: Record<string, any>): string {
    // Use API key or user ID for tracking
    return req.headers['x-api-key'] || req.user?.userId || req.ip;
  }
}
```

### 5.3 Rate Limit Decorators

```typescript
// Usage
@Controller('envelopes')
@UseGuards(CustomThrottlerGuard)
export class EnvelopesController {
  @Post()
  @Throttle(10, 60) // 10 requests per 60 seconds
  create(@Body() createEnvelopeDto: CreateEnvelopeDto) {
    // ...
  }
}
```

## 6. Encryption at Rest

### 6.1 Database Encryption

```typescript
// config/database.config.ts
import { TypeOrmModuleOptions } from '@nestjs/typeorm';

export default (): TypeOrmModuleOptions => ({
  type: 'postgres',
  host: process.env.DATABASE_HOST,
  port: parseInt(process.env.DATABASE_PORT, 10),
  username: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE_NAME,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: true,
    ca: process.env.DATABASE_CA_CERT,
  } : false,
  // Enable encryption at rest (PostgreSQL TDE or application-level)
  extra: {
    encrypt: true,
  },
});
```

### 6.2 Sensitive Data Encryption

```typescript
// common/services/encryption.service.ts
import { Injectable } from '@nestjs/common';
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';

@Injectable()
export class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32;
  private readonly ivLength = 16;

  async encryptSensitiveData(data: string, password: string): Promise<string> {
    const salt = randomBytes(16);
    const key = (await promisify(scrypt)(password, salt, this.keyLength)) as Buffer;
    const iv = randomBytes(this.ivLength);
    
    const cipher = createCipheriv(this.algorithm, key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return `${salt.toString('hex')}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  async decryptSensitiveData(encryptedData: string, password: string): Promise<string> {
    const [saltHex, ivHex, authTagHex, encrypted] = encryptedData.split(':');
    
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const key = (await promisify(scrypt)(password, salt, this.keyLength)) as Buffer;
    
    const decipher = createDecipheriv(this.algorithm, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}
```

## 7. Transport Security (TLS)

### 7.1 HTTPS Configuration

```typescript
// main.ts
import * as fs from 'fs';
import * as https from 'https';

async function bootstrap() {
  const httpsOptions = process.env.NODE_ENV === 'production' ? {
    key: fs.readFileSync(process.env.SSL_KEY_PATH),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH),
    ca: fs.readFileSync(process.env.SSL_CA_PATH),
  } : undefined;

  const app = await NestFactory.create(AppModule, {
    httpsOptions,
  });

  // ...
}
```

### 7.2 TLS Version Enforcement

```typescript
// Ensure TLS 1.2 or higher
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
process.env.NODE_OPTIONS = '--tls-min-v1.2';
```

## 8. Secret Management

### 8.1 Environment Variables

```typescript
// config/config.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';

@Injectable()
export class ConfigService {
  constructor(private configService: NestConfigService) {}

  get jwtSecret(): string {
    const secret = this.configService.get<string>('JWT_SECRET');
    if (!secret) {
      throw new Error('JWT_SECRET is not defined');
    }
    return secret;
  }

  get databasePassword(): string {
    return this.configService.get<string>('DATABASE_PASSWORD') || '';
  }
}
```

### 8.2 Key Vault Integration

```typescript
// crypto/key-vault.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
// Example: AWS KMS, HashiCorp Vault, Azure Key Vault

@Injectable()
export class KeyVaultService {
  constructor(private configService: ConfigService) {}

  async getKey(keyId: string): Promise<Buffer> {
    // Implementation depends on key vault provider
    // Example: AWS KMS
    // const kms = new AWS.KMS();
    // const result = await kms.getPublicKey({ KeyId: keyId }).promise();
    // return Buffer.from(result.PublicKey);
    
    // For now, read from file system
    const keyPath = this.configService.get<string>(`${keyId}_PATH`);
    return require('fs').readFileSync(keyPath);
  }

  async rotateKey(keyId: string): Promise<void> {
    // Key rotation logic
  }
}
```

## 9. Audit Logging

### 9.1 Audit Service

```typescript
// audit/audit.service.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from './entities/audit-log.entity';

@Injectable()
export class AuditService {
  constructor(
    @InjectRepository(AuditLog)
    private auditLogRepository: Repository<AuditLog>,
  ) {}

  async log(event: {
    eventType: string;
    serviceName: string;
    userId?: string;
    resourceType?: string;
    resourceId?: string;
    action: string;
    success: boolean;
    errorMessage?: string;
    ipAddress?: string;
    userAgent?: string;
    requestId?: string;
    metadata?: Record<string, any>;
  }): Promise<void> {
    const auditLog = this.auditLogRepository.create({
      ...event,
      createdAt: new Date(),
    });

    await this.auditLogRepository.save(auditLog);
  }
}
```

### 9.2 Audit Interceptor

```typescript
// common/interceptors/audit.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { AuditService } from '../../audit/audit.service';

@Injectable()
export class AuditInterceptor implements NestInterceptor {
  constructor(private auditService: AuditService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, user, ip, headers } = request;
    const requestId = request.headers['x-request-id'] || require('uuid').v4();

    return next.handle().pipe(
      tap({
        next: (data) => {
          this.auditService.log({
            eventType: 'api_request',
            serviceName: 'vault-service',
            userId: user?.userId,
            action: method,
            success: true,
            ipAddress: ip,
            userAgent: headers['user-agent'],
            requestId,
            metadata: { url, method },
          });
        },
        error: (error) => {
          this.auditService.log({
            eventType: 'api_request',
            serviceName: 'vault-service',
            userId: user?.userId,
            action: method,
            success: false,
            errorMessage: error.message,
            ipAddress: ip,
            userAgent: headers['user-agent'],
            requestId,
            metadata: { url, method },
          });
        },
      }),
    );
  }
}
```

## 10. SQL Injection Prevention

### 10.1 TypeORM Parameterized Queries

```typescript
// TypeORM automatically uses parameterized queries
const prompt = await this.promptRepository.findOne({
  where: { id: promptId }, // Safe: parameterized
});

// For raw queries, use parameters
await this.promptRepository.query(
  'SELECT * FROM prompts WHERE id = $1',
  [promptId], // Safe: parameterized
);
```

## 11. XSS Prevention

### 11.1 Input Sanitization

```typescript
// common/pipes/sanitize.pipe.ts
import { PipeTransform, Injectable, ArgumentMetadata } from '@nestjs/common';
import * as sanitizeHtml from 'sanitize-html';

@Injectable()
export class SanitizePipe implements PipeTransform {
  transform(value: any, metadata: ArgumentMetadata) {
    if (typeof value === 'string') {
      return sanitizeHtml(value, {
        allowedTags: [],
        allowedAttributes: {},
      });
    }
    
    if (typeof value === 'object' && value !== null) {
      return this.sanitizeObject(value);
    }
    
    return value;
  }

  private sanitizeObject(obj: any): any {
    // Recursively sanitize object properties
    // Implementation...
  }
}
```

## 12. CORS Configuration

```typescript
// main.ts
app.enableCors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || [],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
  maxAge: 86400, // 24 hours
});
```

## 13. Security Best Practices Checklist

- [ ] All endpoints require authentication (except health checks)
- [ ] JWT tokens have expiration
- [ ] API keys are hashed in database
- [ ] All inputs are validated
- [ ] SQL injection prevented (parameterized queries)
- [ ] XSS prevented (input sanitization)
- [ ] CSRF protection enabled
- [ ] Security headers configured (Helmet)
- [ ] Rate limiting enabled
- [ ] Audit logging for all sensitive operations
- [ ] Secrets stored securely (not in code)
- [ ] TLS/HTTPS enforced in production
- [ ] Database connections encrypted
- [ ] Error messages don't leak sensitive information
- [ ] Dependencies regularly updated
- [ ] Security audits performed regularly

