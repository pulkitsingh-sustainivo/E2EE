# 09. Swagger API Documentation

## 1. Swagger Overview

Swagger (OpenAPI 3.0) documentation is automatically generated from NestJS decorators and DTOs, providing interactive API documentation and testing capabilities.

## 2. Swagger Setup

### 2.1 Installation

```bash
npm install @nestjs/swagger swagger-ui-express
```

### 2.2 Main Configuration

```typescript
// main.ts
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder()
    .setTitle('E2EE Vault Service API')
    .setDescription('End-to-End Encrypted Vault Service API Documentation')
    .setVersion('1.0.0')
    .addTag('prompts', 'Prompt management operations')
    .addTag('envelopes', 'Envelope encryption and management')
    .addTag('health', 'Health check endpoints')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'JWT',
        description: 'Enter JWT token',
        in: 'header',
      },
      'JWT-auth', // This name here is important for matching up with @ApiBearerAuth() in your controller!
    )
    .addApiKey(
      {
        type: 'apiKey',
        name: 'X-API-Key',
        in: 'header',
        description: 'API Key for service-to-service authentication',
      },
      'api-key', // This name here is important for matching up with @ApiKey() in your controller!
    )
    .addServer('https://api.e2ee.example.com/v1', 'Production')
    .addServer('https://api-staging.e2ee.example.com/v1', 'Staging')
    .addServer('http://localhost:3000/v1', 'Development')
    .setContact('Support', 'https://support.e2ee.example.com', 'support@e2ee.example.com')
    .setLicense('MIT', 'https://opensource.org/licenses/MIT')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true, // Persist auth across page refreshes
      tagsSorter: 'alpha',
      operationsSorter: 'alpha',
    },
    customSiteTitle: 'E2EE API Documentation',
    customfavIcon: '/favicon.ico',
    customCss: '.swagger-ui .topbar { display: none }',
  });

  await app.listen(3000);
}
bootstrap();
```

## 3. Controller Documentation

### 3.1 Basic Controller Setup

```typescript
// prompts/prompts.controller.ts
import { Controller, Get, Post, Body, Param } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
  ApiBearerAuth,
  ApiKeyAuth,
} from '@nestjs/swagger';
import { PromptsService } from './prompts.service';
import { CreatePromptDto } from './dto/create-prompt.dto';
import { PromptResponseDto } from './dto/prompt-response.dto';

@ApiTags('prompts')
@Controller('prompts')
@ApiBearerAuth('JWT-auth')
@ApiKeyAuth('api-key')
export class PromptsController {
  constructor(private readonly promptsService: PromptsService) {}

  @Post()
  @ApiOperation({
    summary: 'Create a new prompt',
    description: 'Creates a new prompt in the vault with the provided text and metadata.',
  })
  @ApiResponse({
    status: 201,
    description: 'Prompt created successfully',
    type: PromptResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - validation error',
    schema: {
      example: {
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid input parameters',
          details: [
            {
              field: 'promptText',
              message: 'promptText should not be empty',
            },
          ],
        },
      },
    },
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - invalid or missing token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - insufficient permissions',
  })
  async create(@Body() createPromptDto: CreatePromptDto): Promise<PromptResponseDto> {
    return this.promptsService.create(createPromptDto);
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Get prompt by ID',
    description: 'Retrieves a prompt by its unique identifier.',
  })
  @ApiParam({
    name: 'id',
    type: String,
    description: 'Prompt UUID',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @ApiQuery({
    name: 'includeEnvelopes',
    required: false,
    type: Boolean,
    description: 'Include associated envelopes',
  })
  @ApiResponse({
    status: 200,
    description: 'Prompt found',
    type: PromptResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'Prompt not found',
  })
  async findOne(
    @Param('id') id: string,
    @Query('includeEnvelopes') includeEnvelopes?: boolean,
  ): Promise<PromptResponseDto> {
    return this.promptsService.findOne(id, includeEnvelopes);
  }
}
```

## 4. DTO Documentation

### 4.1 Create Prompt DTO

```typescript
// prompts/dto/create-prompt.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsOptional, IsObject, MaxLength, MinLength } from 'class-validator';

export class CreatePromptDto {
  @ApiProperty({
    description: 'The prompt text content',
    example: 'What is the capital of France?',
    maxLength: 10000,
    minLength: 1,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(10000)
  @MinLength(1)
  promptText: string;

  @ApiProperty({
    description: 'Secret key for prompt access',
    example: 'my_secret_key',
    maxLength: 255,
    minLength: 8,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  @MinLength(8)
  secret: string;

  @ApiPropertyOptional({
    description: 'Additional metadata for the prompt',
    example: {
      category: 'geography',
      priority: 'high',
      tags: ['france', 'capital'],
    },
    type: 'object',
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}
```

### 4.2 Response DTOs

```typescript
// prompts/dto/prompt-response.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PromptResponseDto {
  @ApiProperty({
    description: 'Prompt unique identifier',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  id: string;

  @ApiProperty({
    description: 'Prompt text content',
    example: 'What is the capital of France?',
  })
  promptText: string;

  @ApiProperty({
    description: 'Prompt status',
    example: 'active',
    enum: ['active', 'archived', 'deleted'],
  })
  status: string;

  @ApiProperty({
    description: 'Prompt version number',
    example: 1,
  })
  version: number;

  @ApiPropertyOptional({
    description: 'Additional metadata',
    example: {
      category: 'geography',
      priority: 'high',
    },
  })
  metadata?: Record<string, any>;

  @ApiProperty({
    description: 'Creation timestamp',
    example: '2025-03-12T14:30:00Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Last update timestamp',
    example: '2025-03-12T14:30:00Z',
  })
  updatedAt: Date;
}
```

### 4.3 Envelope DTOs

```typescript
// envelopes/dto/create-envelope.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsUUID, IsString, IsOptional, IsDateString } from 'class-validator';

export class CreateEnvelopeDto {
  @ApiProperty({
    description: 'Prompt ID to encrypt',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @IsUUID()
  promptId: string;

  @ApiProperty({
    description: 'Secret key for prompt access',
    example: 'my_secret_key',
  })
  @IsString()
  secret: string;

  @ApiProperty({
    description: 'Receiver public key identifier',
    example: 'prompt_response_enc_public',
  })
  @IsString()
  receiverPublicKeyId: string;

  @ApiPropertyOptional({
    description: 'Envelope expiration date',
    example: '2025-03-19T14:30:00Z',
  })
  @IsOptional()
  @IsDateString()
  expiresAt?: string;

  @ApiPropertyOptional({
    description: 'Additional envelope metadata',
    example: {
      priority: 'high',
      source: 'api',
    },
  })
  @IsOptional()
  metadata?: Record<string, any>;
}
```

```typescript
// envelopes/dto/envelope-response.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class EnvelopeResponseDto {
  @ApiProperty({
    description: 'Envelope unique identifier',
    example: '660e8400-e29b-41d4-a716-446655440000',
  })
  id: string;

  @ApiProperty({
    description: 'Associated prompt ID',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  promptId: string;

  @ApiProperty({
    description: 'Base64-encoded encrypted data',
    example: 'aGVsbG8gd29ybGQ=',
  })
  encryptedData: string;

  @ApiProperty({
    description: 'Base64-encoded encrypted AES key',
    example: 'YWJjZGVmZ2hpams=',
  })
  encryptedKey: string;

  @ApiProperty({
    description: 'Base64-encoded digital signature',
    example: 'c2lnbmF0dXJlMTIz',
  })
  signature: string;

  @ApiProperty({
    description: 'Base64-encoded initialization vector',
    example: 'aXZ2YWx1ZTEyMw==',
  })
  iv: string;

  @ApiProperty({
    description: 'Base64-encoded GCM authentication tag',
    example: 'YXV0aHRhZzEyMw==',
  })
  authTag: string;

  @ApiProperty({
    description: 'Encryption algorithm',
    example: 'AES-256-GCM',
    enum: ['AES-256-GCM'],
  })
  algorithm: string;

  @ApiProperty({
    description: 'Key encryption algorithm',
    example: 'RSA-OAEP',
    enum: ['RSA-OAEP'],
  })
  keyAlgorithm: string;

  @ApiProperty({
    description: 'Signature algorithm',
    example: 'RSA-PSS',
    enum: ['RSA-PSS', 'RSA-PKCS1-v1_5'],
  })
  signatureAlgorithm: string;

  @ApiProperty({
    description: 'Envelope status',
    example: 'pending',
    enum: ['pending', 'delivered', 'decrypted', 'expired'],
  })
  status: string;

  @ApiPropertyOptional({
    description: 'Envelope expiration date',
    example: '2025-03-19T14:30:00Z',
  })
  expiresAt?: Date;

  @ApiProperty({
    description: 'Creation timestamp',
    example: '2025-03-12T14:30:00Z',
  })
  createdAt: Date;
}
```

## 5. Error Response Documentation

### 5.1 Error DTOs

```typescript
// common/dto/error-response.dto.ts
import { ApiProperty } from '@nestjs/swagger';

export class ErrorDetailDto {
  @ApiProperty({
    description: 'Field name with error',
    example: 'promptText',
  })
  field: string;

  @ApiProperty({
    description: 'Error message',
    example: 'promptText should not be empty',
  })
  message: string;
}

export class ErrorResponseDto {
  @ApiProperty({
    description: 'Success flag',
    example: false,
  })
  success: boolean;

  @ApiProperty({
    description: 'Error information',
    type: 'object',
    properties: {
      code: {
        type: 'string',
        example: 'VALIDATION_ERROR',
      },
      message: {
        type: 'string',
        example: 'Invalid input parameters',
      },
      details: {
        type: 'array',
        items: {
          $ref: '#/components/schemas/ErrorDetailDto',
        },
      },
    },
  })
  error: {
    code: string;
    message: string;
    details?: ErrorDetailDto[];
  };

  @ApiProperty({
    description: 'Response metadata',
    type: 'object',
    properties: {
      timestamp: {
        type: 'string',
        example: '2025-03-12T14:30:00Z',
      },
      requestId: {
        type: 'string',
        example: '550e8400-e29b-41d4-a716-446655440000',
      },
    },
  })
  meta: {
    timestamp: string;
    requestId: string;
  };
}
```

## 6. Pagination Documentation

### 6.1 Pagination DTOs

```typescript
// common/dto/pagination.dto.ts
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsInt, Min, Max, IsOptional } from 'class-validator';

export class PaginationQueryDto {
  @ApiPropertyOptional({
    description: 'Page number',
    example: 1,
    minimum: 1,
    default: 1,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiPropertyOptional({
    description: 'Items per page',
    example: 20,
    minimum: 1,
    maximum: 100,
    default: 20,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 20;
}

export class PaginationMetaDto {
  @ApiProperty({ example: 1 })
  page: number;

  @ApiProperty({ example: 20 })
  limit: number;

  @ApiProperty({ example: 100 })
  total: number;

  @ApiProperty({ example: 5 })
  totalPages: number;

  @ApiProperty({ example: true })
  hasNext: boolean;

  @ApiProperty({ example: false })
  hasPrev: boolean;
}
```

## 7. Advanced Swagger Features

### 7.1 File Upload Documentation

```typescript
// If file uploads are needed
@Post('upload')
@UseInterceptors(FileInterceptor('file'))
@ApiConsumes('multipart/form-data')
@ApiBody({
  schema: {
    type: 'object',
    properties: {
      file: {
        type: 'string',
        format: 'binary',
      },
    },
  },
})
async uploadFile(@UploadedFile() file: Express.Multer.File) {
  // ...
}
```

### 7.2 Custom Examples

```typescript
@ApiProperty({
  description: 'Prompt text',
  example: 'What is the capital of France?',
  examples: {
    geography: {
      value: 'What is the capital of France?',
      summary: 'Geography question',
    },
    history: {
      value: 'When did World War II end?',
      summary: 'History question',
    },
  },
})
promptText: string;
```

### 7.3 Enum Documentation

```typescript
export enum PromptStatus {
  ACTIVE = 'active',
  ARCHIVED = 'archived',
  DELETED = 'deleted',
}

@ApiProperty({
  description: 'Prompt status',
  enum: PromptStatus,
  enumName: 'PromptStatus',
  example: PromptStatus.ACTIVE,
})
status: PromptStatus;
```

## 8. Swagger UI Customization

### 8.1 Custom CSS

```typescript
SwaggerModule.setup('api/docs', app, document, {
  customCss: `
    .swagger-ui .topbar { display: none }
    .swagger-ui .info { margin: 50px 0 }
    .swagger-ui .scheme-container { background: #fafafa; padding: 20px }
  `,
  customSiteTitle: 'E2EE API Documentation',
  customfavIcon: '/favicon.ico',
});
```

### 8.2 Custom JavaScript

```typescript
SwaggerModule.setup('api/docs', app, document, {
  customJs: '/swagger-custom.js',
});
```

## 9. Swagger in Different Environments

### 9.1 Environment-Based Configuration

```typescript
// main.ts
if (process.env.NODE_ENV !== 'production') {
  const config = new DocumentBuilder()
    .setTitle('E2EE API')
    .setDescription('API Documentation')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);
}
```

### 9.2 Password Protection (Optional)

```typescript
// For production Swagger UI protection
app.use('/api/docs', (req, res, next) => {
  const auth = { login: 'admin', password: 'swagger-secret' };
  const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
  const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');

  if (login && password && login === auth.login && password === auth.password) {
    return next();
  }

  res.set('WWW-Authenticate', 'Basic realm="Swagger"');
  res.status(401).send('Authentication required');
});
```

## 10. API Documentation Best Practices

### 10.1 Documentation Checklist

- [ ] All endpoints documented with @ApiOperation
- [ ] All DTOs have @ApiProperty decorators
- [ ] Request/response examples provided
- [ ] Error responses documented
- [ ] Authentication requirements specified
- [ ] Query parameters documented
- [ ] Path parameters documented
- [ ] Response types specified
- [ ] Tags used for grouping
- [ ] Descriptions are clear and concise

### 10.2 Documentation Standards

- Use clear, concise descriptions
- Provide realistic examples
- Document all possible status codes
- Include validation rules in descriptions
- Group related endpoints with tags
- Use consistent naming conventions
- Keep examples up to date

## 11. Accessing Swagger UI

### 11.1 URLs

- **Development**: `http://localhost:3000/api/docs`
- **Staging**: `https://api-staging.e2ee.example.com/api/docs`
- **Production**: `https://api.e2ee.example.com/api/docs` (if enabled)

### 11.2 Using Swagger UI

1. Navigate to the Swagger UI URL
2. Click "Authorize" button
3. Enter JWT token or API key
4. Explore available endpoints
5. Test endpoints directly from the UI
6. View request/response schemas

## 12. OpenAPI Specification Export

### 12.1 Export JSON

```typescript
// Export OpenAPI JSON
import { writeFileSync } from 'fs';

const document = SwaggerModule.createDocument(app, config);
writeFileSync('./openapi.json', JSON.stringify(document, null, 2));
```

### 12.2 Export YAML

```bash
# Convert JSON to YAML
npm install -g js-yaml
js-yaml openapi.json > openapi.yaml
```

