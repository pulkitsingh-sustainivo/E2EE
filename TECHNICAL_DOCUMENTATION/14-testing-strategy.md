# 14. Testing Strategy

## 1. Testing Overview

Comprehensive testing strategy covering unit, integration, E2E, and security tests to ensure system reliability and security.

## 2. Testing Pyramid

```
        ┌─────────┐
        │   E2E   │  (Few, critical paths)
        │  Tests  │
        ├─────────┤
       │Integration│  (Service integration)
       │   Tests   │
       ├───────────┤
      │    Unit     │  (Many, isolated components)
      │    Tests    │
      └────────────┘
```

## 3. Unit Testing

### 3.1 Setup

```typescript
// test/jest.config.ts
export default {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: 'src',
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  collectCoverageFrom: [
    '**/*.(t|j)s',
    '!**/*.spec.ts',
    '!**/node_modules/**',
    '!**/dist/**',
  ],
  coverageDirectory: '../coverage',
  testEnvironment: 'node',
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/$1',
    '^@e2ee/crypto-lib$': '<rootDir>/../../packages/crypto-lib/src',
  },
};
```

### 3.2 Example Unit Test - Service

```typescript
// prompts/prompts.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PromptsService } from './prompts.service';
import { Prompt } from './entities/prompt.entity';
import { NotFoundException } from '@nestjs/common';

describe('PromptsService', () => {
  let service: PromptsService;
  let repository: Repository<Prompt>;

  const mockRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
    createQueryBuilder: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PromptsService,
        {
          provide: getRepositoryToken(Prompt),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<PromptsService>(PromptsService);
    repository = module.get<Repository<Prompt>>(getRepositoryToken(Prompt));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('findOne', () => {
    it('should return a prompt', async () => {
      const promptId = '550e8400-e29b-41d4-a716-446655440000';
      const mockPrompt: Prompt = {
        id: promptId,
        promptText: 'Test prompt',
        status: 'active',
        version: 1,
        secretHash: 'hash',
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
      } as Prompt;

      mockRepository.findOne.mockResolvedValue(mockPrompt);

      const result = await service.findOne(promptId);

      expect(result).toEqual(mockPrompt);
      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { id: promptId, deletedAt: null },
        relations: [],
      });
    });

    it('should throw NotFoundException when prompt not found', async () => {
      const promptId = '550e8400-e29b-41d4-a716-446655440000';
      mockRepository.findOne.mockResolvedValue(null);

      await expect(service.findOne(promptId)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('create', () => {
    it('should create a prompt', async () => {
      const createDto = {
        promptText: 'Test prompt',
        secret: 'my_secret',
      };
      const mockPrompt: Prompt = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        ...createDto,
        status: 'active',
        version: 1,
        secretHash: 'hashed_secret',
        createdAt: new Date(),
        updatedAt: new Date(),
      } as Prompt;

      mockRepository.findOne.mockResolvedValue(null);
      mockRepository.create.mockReturnValue(mockPrompt);
      mockRepository.save.mockResolvedValue(mockPrompt);

      const result = await service.create(createDto, 'user-id');

      expect(result).toEqual(mockPrompt);
      expect(mockRepository.create).toHaveBeenCalled();
      expect(mockRepository.save).toHaveBeenCalled();
    });
  });
});
```

### 3.3 Example Unit Test - Controller

```typescript
// prompts/prompts.controller.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { PromptsController } from './prompts.controller';
import { PromptsService } from './prompts.service';
import { CreatePromptDto } from './dto/create-prompt.dto';

describe('PromptsController', () => {
  let controller: PromptsController;
  let service: PromptsService;

  const mockService = {
    create: jest.fn(),
    findOne: jest.fn(),
    findAll: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [PromptsController],
      providers: [
        {
          provide: PromptsService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<PromptsController>(PromptsController);
    service = module.get<PromptsService>(PromptsService);
  });

  it('should create a prompt', async () => {
    const createDto: CreatePromptDto = {
      promptText: 'Test prompt',
      secret: 'my_secret',
    };
    const expectedResult = {
      id: '550e8400-e29b-41d4-a716-446655440000',
      ...createDto,
    };

    mockService.create.mockResolvedValue(expectedResult);

    const result = await controller.create(createDto);

    expect(result).toEqual(expectedResult);
    expect(mockService.create).toHaveBeenCalledWith(createDto, undefined);
  });
});
```

## 4. Integration Testing

### 4.1 Setup

```typescript
// test/test-setup.ts
import { Test } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AppModule } from '../src/app.module';

export async function createTestApp() {
  const module = await Test.createTestingModule({
    imports: [
      AppModule,
      TypeOrmModule.forRoot({
        type: 'postgres',
        host: process.env.TEST_DATABASE_HOST || 'localhost',
        port: parseInt(process.env.TEST_DATABASE_PORT || '5432', 10),
        username: process.env.TEST_DATABASE_USER || 'postgres',
        password: process.env.TEST_DATABASE_PASSWORD || 'postgres',
        database: process.env.TEST_DATABASE_NAME || 'e2ee_test',
        synchronize: false,
        dropSchema: false,
        entities: [__dirname + '/../src/**/*.entity.ts'],
      }),
    ],
  }).compile();

  const app = module.createNestApplication();
  await app.init();

  return { app, module };
}

export async function closeTestApp(app: any) {
  const dataSource = app.get(DataSource);
  await dataSource.destroy();
  await app.close();
}
```

### 4.2 Example Integration Test

```typescript
// test/integration/prompts.integration.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';
import { DataSource } from 'typeorm';

describe('Prompts Integration (e2e)', () => {
  let app: INestApplication;
  let dataSource: DataSource;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    dataSource = app.get(DataSource);
  });

  afterAll(async () => {
    await dataSource.destroy();
    await app.close();
  });

  beforeEach(async () => {
    // Clean database before each test
    await dataSource.query('TRUNCATE TABLE prompts CASCADE');
  });

  describe('/prompts (POST)', () => {
    it('should create a prompt', () => {
      return request(app.getHttpServer())
        .post('/api/v1/prompts')
        .set('Authorization', 'Bearer test-token')
        .send({
          promptText: 'What is the capital of France?',
          secret: 'my_secret_key',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body.success).toBe(true);
          expect(res.body.data.promptText).toBe('What is the capital of France?');
          expect(res.body.data.id).toBeDefined();
        });
    });

    it('should return 400 for invalid input', () => {
      return request(app.getHttpServer())
        .post('/api/v1/prompts')
        .set('Authorization', 'Bearer test-token')
        .send({
          promptText: '', // Invalid: empty
          secret: 'my_secret_key',
        })
        .expect(400);
    });
  });

  describe('/prompts/:id (GET)', () => {
    it('should return a prompt', async () => {
      // Create a prompt first
      const createResponse = await request(app.getHttpServer())
        .post('/api/v1/prompts')
        .set('Authorization', 'Bearer test-token')
        .send({
          promptText: 'Test prompt',
          secret: 'my_secret_key',
        });

      const promptId = createResponse.body.data.id;

      // Get the prompt
      return request(app.getHttpServer())
        .get(`/api/v1/prompts/${promptId}`)
        .set('Authorization', 'Bearer test-token')
        .expect(200)
        .expect((res) => {
          expect(res.body.success).toBe(true);
          expect(res.body.data.id).toBe(promptId);
        });
    });

    it('should return 404 for non-existent prompt', () => {
      return request(app.getHttpServer())
        .get('/api/v1/prompts/550e8400-e29b-41d4-a716-446655440000')
        .set('Authorization', 'Bearer test-token')
        .expect(404);
    });
  });
});
```

## 5. E2E Testing

### 5.1 E2E Test Configuration

```typescript
// test/jest-e2e.json
{
  "moduleFileExtensions": ["js", "json", "ts"],
  "rootDir": ".",
  "testEnvironment": "node",
  "testRegex": ".e2e-spec.ts$",
  "transform": {
    "^.+\\.(t|j)s$": "ts-jest"
  },
  "setupFilesAfterEnv": ["<rootDir>/test/setup-e2e.ts"]
}
```

### 5.2 Complete Flow E2E Test

```typescript
// test/e2e/envelope-flow.e2e-spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';

describe('Envelope Flow E2E', () => {
  let app: INestApplication;
  let promptId: string;
  let envelopeId: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('should complete full envelope flow', async () => {
    // Step 1: Create a prompt
    const createPromptResponse = await request(app.getHttpServer())
      .post('/api/v1/prompts')
      .set('Authorization', 'Bearer test-token')
      .send({
        promptText: 'What is the capital of France?',
        secret: 'my_secret_key',
      })
      .expect(201);

    promptId = createPromptResponse.body.data.id;
    expect(promptId).toBeDefined();

    // Step 2: Generate envelope
    const createEnvelopeResponse = await request(app.getHttpServer())
      .post('/api/v1/envelopes')
      .set('Authorization', 'Bearer test-token')
      .send({
        promptId,
        secret: 'my_secret_key',
        receiverPublicKeyId: 'prompt_response_enc_public',
      })
      .expect(201);

    envelopeId = createEnvelopeResponse.body.data.envelope.id;
    expect(envelopeId).toBeDefined();
    expect(createEnvelopeResponse.body.data.envelope.encryptedData).toBeDefined();
    expect(createEnvelopeResponse.body.data.envelope.signature).toBeDefined();

    // Step 3: Decrypt envelope (simulated in response service)
    // This would be tested in prompt-response-service tests
  });
});
```

## 6. Cryptographic Testing

### 6.1 Crypto Library Tests

```typescript
// packages/crypto-lib/src/aes/aes-encryption.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { AESEncryptionService } from './aes-encryption.service';
import { AESDecryptionService } from './aes-decryption.service';

describe('AES Encryption/Decryption', () => {
  let encryptionService: AESEncryptionService;
  let decryptionService: AESDecryptionService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AESEncryptionService, AESDecryptionService],
    }).compile();

    encryptionService = module.get<AESEncryptionService>(AESEncryptionService);
    decryptionService = module.get<AESDecryptionService>(AESDecryptionService);
  });

  it('should encrypt and decrypt data correctly', () => {
    const plaintext = 'Hello, World!';
    const key = encryptionService.generateKey();

    const encrypted = encryptionService.encrypt(plaintext, key);
    const decrypted = decryptionService.decrypt(
      encrypted.encryptedData,
      key,
      encrypted.iv,
      encrypted.authTag,
    );

    expect(decrypted.decryptedData.toString('utf8')).toBe(plaintext);
  });

  it('should fail with wrong key', () => {
    const plaintext = 'Hello, World!';
    const key = encryptionService.generateKey();
    const wrongKey = encryptionService.generateKey();

    const encrypted = encryptionService.encrypt(plaintext, key);

    expect(() => {
      decryptionService.decrypt(
        encrypted.encryptedData,
        wrongKey,
        encrypted.iv,
        encrypted.authTag,
      );
    }).toThrow();
  });

  it('should fail with tampered data', () => {
    const plaintext = 'Hello, World!';
    const key = encryptionService.generateKey();

    const encrypted = encryptionService.encrypt(plaintext, key);
    const tamperedData = Buffer.from(encrypted.encryptedData);
    tamperedData[0] = tamperedData[0] ^ 0xFF; // Tamper with data

    expect(() => {
      decryptionService.decrypt(
        tamperedData,
        key,
        encrypted.iv,
        encrypted.authTag,
      );
    }).toThrow();
  });
});
```

## 7. Security Testing

### 7.1 Security Test Cases

```typescript
// test/security/security.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';

describe('Security Tests', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Authentication', () => {
    it('should reject requests without token', () => {
      return request(app.getHttpServer())
        .post('/api/v1/prompts')
        .send({ promptText: 'test', secret: 'test' })
        .expect(401);
    });

    it('should reject requests with invalid token', () => {
      return request(app.getHttpServer())
        .post('/api/v1/prompts')
        .set('Authorization', 'Bearer invalid-token')
        .send({ promptText: 'test', secret: 'test' })
        .expect(401);
    });
  });

  describe('Input Validation', () => {
    it('should reject SQL injection attempts', () => {
      return request(app.getHttpServer())
        .post('/api/v1/prompts')
        .set('Authorization', 'Bearer test-token')
        .send({
          promptText: "'; DROP TABLE prompts; --",
          secret: 'test',
        })
        .expect(400);
    });

    it('should reject XSS attempts', () => {
      return request(app.getHttpServer())
        .post('/api/v1/prompts')
        .set('Authorization', 'Bearer test-token')
        .send({
          promptText: '<script>alert("xss")</script>',
          secret: 'test',
        })
        .expect(201); // Should sanitize, not reject
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits', async () => {
      const requests = Array(110).fill(null).map(() =>
        request(app.getHttpServer())
          .post('/api/v1/prompts')
          .set('Authorization', 'Bearer test-token')
          .send({ promptText: 'test', secret: 'test' })
      );

      const responses = await Promise.all(requests);
      const rateLimited = responses.filter(r => r.status === 429);
      expect(rateLimited.length).toBeGreaterThan(0);
    });
  });
});
```

## 8. Performance Testing

### 8.1 Load Testing Setup

```typescript
// test/performance/load-test.ts
import { performance } from 'perf_hooks';
import * as request from 'supertest';
import { INestApplication } from '@nestjs/common';

export async function loadTest(
  app: INestApplication,
  endpoint: string,
  iterations: number,
) {
  const times: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await request(app.getHttpServer())
      .post(endpoint)
      .set('Authorization', 'Bearer test-token')
      .send({ promptText: `Test ${i}`, secret: 'test' });
    const end = performance.now();
    times.push(end - start);
  }

  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);
  const p95 = times.sort((a, b) => a - b)[Math.floor(times.length * 0.95)];

  return { avg, min, max, p95 };
}
```

## 9. Test Coverage

### 9.1 Coverage Configuration

```json
// package.json
{
  "scripts": {
    "test:cov": "jest --coverage",
    "test:cov:watch": "jest --coverage --watch"
  },
  "jest": {
    "coverageThreshold": {
      "global": {
        "branches": 80,
        "functions": 80,
        "lines": 80,
        "statements": 80
      }
    }
  }
}
```

### 9.2 Coverage Report

```bash
# Generate coverage report
npm run test:cov

# View HTML report
open coverage/index.html
```

## 10. Test Data Management

### 10.1 Fixtures

```typescript
// test/fixtures/prompts.fixture.ts
export const promptFixtures = {
  valid: {
    promptText: 'What is the capital of France?',
    secret: 'my_secret_key',
    metadata: {
      category: 'geography',
    },
  },
  invalid: {
    promptText: '',
    secret: 'short',
  },
};
```

### 10.2 Test Database

```typescript
// test/helpers/test-database.helper.ts
import { DataSource } from 'typeorm';

export async function seedTestDatabase(dataSource: DataSource) {
  // Seed test data
  await dataSource.query(`
    INSERT INTO prompts (id, prompt_text, secret_hash, status, version)
    VALUES 
      ('550e8400-e29b-41d4-a716-446655440000', 'Test prompt 1', 'hash1', 'active', 1),
      ('660e8400-e29b-41d4-a716-446655440001', 'Test prompt 2', 'hash2', 'active', 1);
  `);
}

export async function cleanupTestDatabase(dataSource: DataSource) {
  await dataSource.query('TRUNCATE TABLE prompts, envelopes, audit_logs CASCADE');
}
```

## 11. Continuous Testing

### 11.1 Pre-commit Hooks

```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged",
      "pre-push": "npm test"
    }
  },
  "lint-staged": {
    "*.ts": [
      "eslint --fix",
      "prettier --write"
    ]
  }
}
```

### 11.2 CI/CD Integration

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm ci
      - run: npm run build
      - run: npm test
      - run: npm run test:e2e
      - uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
```

## 12. Test Best Practices

1. **Test Isolation**: Each test should be independent
2. **Clear Test Names**: Describe what is being tested
3. **Arrange-Act-Assert**: Follow AAA pattern
4. **Mock External Dependencies**: Don't test external services
5. **Test Edge Cases**: Include boundary conditions
6. **Maintain Test Coverage**: Aim for 80%+ coverage
7. **Fast Tests**: Unit tests should be fast
8. **Reliable Tests**: Tests should be deterministic
9. **Clean Test Data**: Clean up after tests
10. **Document Complex Tests**: Explain why tests exist

