# 07. Packages & Dependencies

## 1. Package Management Strategy

### 1.1 Monorepo Package Management
- **Tool**: npm workspaces or yarn workspaces
- **Versioning**: Semantic versioning (SemVer)
- **Lock Files**: package-lock.json committed to repository

### 1.2 Dependency Categories
- **Production Dependencies**: Required at runtime
- **Development Dependencies**: Required only during development
- **Peer Dependencies**: Expected to be provided by the consumer
- **Optional Dependencies**: Nice to have but not required

## 2. Root Package.json (Workspace)

```json
{
  "name": "e2ee-workspace",
  "version": "1.0.0",
  "private": true,
  "workspaces": [
    "packages/*",
    "services/*"
  ],
  "scripts": {
    "build": "npm run build --workspaces",
    "test": "npm run test --workspaces",
    "lint": "npm run lint --workspaces",
    "format": "prettier --write \"**/*.{ts,js,json,md}\""
  },
  "devDependencies": {
    "@types/node": "^20.10.0",
    "prettier": "^3.1.0",
    "typescript": "^5.3.0"
  }
}
```

## 3. Vault Service Dependencies

### 3.1 Production Dependencies

```json
{
  "dependencies": {
    "@nestjs/common": "^10.2.10",
    "@nestjs/core": "^10.2.10",
    "@nestjs/platform-express": "^10.2.10",
    "@nestjs/config": "^3.1.1",
    "@nestjs/typeorm": "^10.0.1",
    "@nestjs/swagger": "^7.1.16",
    "@nestjs/jwt": "^10.2.0",
    "@nestjs/passport": "^10.0.2",
    "@nestjs/throttler": "^5.0.1",
    "@nestjs/terminus": "^10.1.1",
    "@nestjs/cache-manager": "^2.1.1",
    "typeorm": "^0.3.17",
    "pg": "^8.11.3",
    "cache-manager": "^5.2.4",
    "cache-manager-redis-store": "^3.0.1",
    "redis": "^4.6.11",
    "passport": "^0.7.0",
    "passport-jwt": "^4.0.1",
    "passport-api-key": "^2.0.0",
    "class-validator": "^0.14.0",
    "class-transformer": "^0.5.1",
    "bcrypt": "^5.1.1",
    "helmet": "^7.1.0",
    "compression": "^1.7.4",
    "winston": "^3.11.0",
    "nest-winston": "^1.9.4",
    "uuid": "^9.0.1",
    "reflect-metadata": "^0.1.13",
    "rxjs": "^7.8.1",
    "@e2ee/crypto-lib": "workspace:*"
  }
}
```

### 3.2 Development Dependencies

```json
{
  "devDependencies": {
    "@nestjs/cli": "^10.2.1",
    "@nestjs/schematics": "^10.0.3",
    "@nestjs/testing": "^10.2.10",
    "@types/express": "^4.17.21",
    "@types/node": "^20.10.0",
    "@types/jest": "^29.5.8",
    "@types/passport-jwt": "^4.0.0",
    "@types/passport-api-key": "^1.0.0",
    "@types/bcrypt": "^5.0.2",
    "@types/uuid": "^9.0.7",
    "@typescript-eslint/eslint-plugin": "^6.13.1",
    "@typescript-eslint/parser": "^6.13.1",
    "eslint": "^8.54.0",
    "eslint-config-prettier": "^9.0.0",
    "eslint-plugin-prettier": "^5.0.1",
    "prettier": "^3.1.0",
    "jest": "^29.7.0",
    "@types/jest": "^29.5.8",
    "ts-jest": "^29.1.1",
    "ts-node": "^10.9.1",
    "ts-loader": "^9.5.1",
    "typescript": "^5.3.0",
    "supertest": "^6.3.3",
    "@types/supertest": "^6.0.2",
    "testcontainers": "^10.7.1"
  }
}
```

## 4. Prompt Response Service Dependencies

Similar to Vault Service, with minor differences:

```json
{
  "dependencies": {
    "@nestjs/common": "^10.2.10",
    "@nestjs/core": "^10.2.10",
    "@nestjs/platform-express": "^10.2.10",
    "@nestjs/config": "^3.1.1",
    "@nestjs/swagger": "^7.1.16",
    "@nestjs/jwt": "^10.2.0",
    "@nestjs/passport": "^10.0.2",
    "@nestjs/throttler": "^5.0.1",
    "@nestjs/terminus": "^10.1.1",
    "@nestjs/cache-manager": "^2.1.1",
    "cache-manager": "^5.2.4",
    "cache-manager-redis-store": "^3.0.1",
    "redis": "^4.6.11",
    "passport": "^0.7.0",
    "passport-jwt": "^4.0.1",
    "passport-api-key": "^2.0.0",
    "class-validator": "^0.14.0",
    "class-transformer": "^0.5.1",
    "helmet": "^7.1.0",
    "compression": "^1.7.4",
    "winston": "^3.11.0",
    "nest-winston": "^1.9.4",
    "uuid": "^9.0.1",
    "reflect-metadata": "^0.1.13",
    "rxjs": "^7.8.1",
    "@e2ee/crypto-lib": "workspace:*"
  }
}
```

## 5. Shared Crypto Library Dependencies

```json
{
  "name": "@e2ee/crypto-lib",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "dependencies": {
    "crypto": "^1.0.0" // Node.js built-in
  },
  "devDependencies": {
    "@types/node": "^20.10.0",
    "typescript": "^5.3.0",
    "jest": "^29.7.0",
    "ts-jest": "^29.1.1"
  },
  "peerDependencies": {
    "typescript": ">=5.0.0"
  }
}
```

## 6. Package Descriptions

### 6.1 Core NestJS Packages

#### @nestjs/common
- **Purpose**: Core NestJS functionality (decorators, pipes, guards, interceptors)
- **Version**: ^10.2.10
- **Usage**: Used throughout the application

#### @nestjs/core
- **Purpose**: NestJS application core
- **Version**: ^10.2.10
- **Usage**: Application bootstrap and dependency injection

#### @nestjs/platform-express
- **Purpose**: Express adapter for NestJS
- **Version**: ^10.2.10
- **Usage**: HTTP server implementation

#### @nestjs/config
- **Purpose**: Configuration management
- **Version**: ^3.1.1
- **Usage**: Environment variables and configuration files

#### @nestjs/typeorm
- **Purpose**: TypeORM integration for NestJS
- **Version**: ^10.0.1
- **Usage**: Database access and ORM functionality

#### @nestjs/swagger
- **Purpose**: OpenAPI/Swagger documentation
- **Version**: ^7.1.16
- **Usage**: API documentation generation

### 6.2 Security Packages

#### @nestjs/jwt
- **Purpose**: JWT token handling
- **Version**: ^10.2.0
- **Usage**: Authentication token generation and validation

#### @nestjs/passport
- **Purpose**: Passport.js integration
- **Version**: ^10.0.2
- **Usage**: Authentication strategies

#### passport-jwt
- **Purpose**: JWT authentication strategy
- **Version**: ^4.0.1
- **Usage**: JWT token validation

#### passport-api-key
- **Purpose**: API key authentication strategy
- **Version**: ^2.0.0
- **Usage**: Service-to-service authentication

#### bcrypt
- **Purpose**: Password hashing
- **Version**: ^5.1.1
- **Usage**: Hashing secrets and passwords

#### helmet
- **Purpose**: Security headers
- **Version**: ^7.1.0
- **Usage**: HTTP security headers middleware

### 6.3 Database & Cache Packages

#### typeorm
- **Purpose**: TypeScript ORM
- **Version**: ^0.3.17
- **Usage**: Database operations and migrations

#### pg
- **Purpose**: PostgreSQL client
- **Version**: ^8.11.3
- **Usage**: Database driver

#### cache-manager
- **Purpose**: Cache abstraction
- **Version**: ^5.2.4
- **Usage**: Caching layer

#### cache-manager-redis-store
- **Purpose**: Redis store for cache-manager
- **Version**: ^3.0.1
- **Usage**: Redis caching implementation

#### redis
- **Purpose**: Redis client
- **Version**: ^4.6.11
- **Usage**: Direct Redis operations

### 6.4 Validation & Transformation

#### class-validator
- **Purpose**: Decorator-based validation
- **Version**: ^0.14.0
- **Usage**: DTO validation

#### class-transformer
- **Purpose**: Object transformation
- **Version**: ^0.5.1
- **Usage**: DTO transformation and serialization

### 6.5 Rate Limiting

#### @nestjs/throttler
- **Purpose**: Rate limiting
- **Version**: ^5.0.1
- **Usage**: API rate limiting

### 6.6 Health Checks

#### @nestjs/terminus
- **Purpose**: Health check endpoints
- **Version**: ^10.1.1
- **Usage**: Service health monitoring

### 6.7 Logging

#### winston
- **Purpose**: Logging library
- **Version**: ^3.11.0
- **Usage**: Application logging

#### nest-winston
- **Purpose**: Winston integration for NestJS
- **Version**: ^1.9.4
- **Usage**: NestJS logger wrapper

### 6.8 Utilities

#### uuid
- **Purpose**: UUID generation
- **Version**: ^9.0.1
- **Usage**: Unique identifier generation

#### compression
- **Purpose**: Response compression
- **Version**: ^1.7.4
- **Usage**: Gzip compression middleware

#### rxjs
- **Purpose**: Reactive programming
- **Version**: ^7.8.1
- **Usage**: Observable streams (used by NestJS)

## 7. Development Tools

### 7.1 Testing

#### jest
- **Purpose**: Testing framework
- **Version**: ^29.7.0
- **Usage**: Unit and integration tests

#### ts-jest
- **Purpose**: TypeScript support for Jest
- **Version**: ^29.1.1
- **Usage**: TypeScript test compilation

#### supertest
- **Purpose**: HTTP assertion library
- **Version**: ^6.3.3
- **Usage**: E2E API testing

#### testcontainers
- **Purpose**: Docker containers for testing
- **Version**: ^10.7.1
- **Usage**: Integration tests with real databases

### 7.2 Code Quality

#### eslint
- **Purpose**: JavaScript/TypeScript linter
- **Version**: ^8.54.0
- **Usage**: Code linting

#### prettier
- **Purpose**: Code formatter
- **Version**: ^3.1.0
- **Usage**: Code formatting

#### typescript
- **Purpose**: TypeScript compiler
- **Version**: ^5.3.0
- **Usage**: TypeScript compilation

## 8. Version Pinning Strategy

### 8.1 Major Versions
- Pin major versions for stability
- Use `^` for minor and patch updates
- Example: `"@nestjs/common": "^10.2.10"`

### 8.2 Critical Security Packages
- Pin exact versions for security-sensitive packages
- Example: `"helmet": "7.1.0"`

### 8.3 Node.js Built-in Modules
- Use Node.js built-in modules when possible
- Example: `crypto` module for cryptography

## 9. Dependency Update Strategy

### 9.1 Regular Updates
- **Weekly**: Check for security updates
- **Monthly**: Review and update minor versions
- **Quarterly**: Review major version updates

### 9.2 Security Updates
- **Immediate**: Apply critical security patches
- **Within 24 hours**: Apply high-severity patches
- **Within 1 week**: Apply medium-severity patches

### 9.3 Update Process
1. Check for updates: `npm outdated`
2. Review changelogs
3. Update in development environment
4. Run tests
5. Update in staging
6. Deploy to production

## 10. Package Installation Commands

### 10.1 Install All Dependencies
```bash
# Root workspace
npm install

# Specific service
cd services/vault-service
npm install
```

### 10.2 Install Production Dependencies Only
```bash
npm install --production
```

### 10.3 Update Dependencies
```bash
# Update all
npm update

# Update specific package
npm update @nestjs/common

# Update to latest (may break)
npm install @nestjs/common@latest
```

## 11. Security Considerations

### 11.1 Vulnerability Scanning
- Use `npm audit` regularly
- Integrate Snyk or Dependabot
- Review security advisories

### 11.2 Trusted Sources
- Only install from npm registry
- Verify package integrity
- Use package-lock.json

### 11.3 Minimal Dependencies
- Only include necessary packages
- Remove unused dependencies
- Audit dependencies regularly

## 12. Workspace Dependencies

### 12.1 Internal Packages
```json
{
  "dependencies": {
    "@e2ee/crypto-lib": "workspace:*"
  }
}
```

### 12.2 Workspace Protocol
- `workspace:*`: Use workspace version
- `workspace:^`: Use compatible workspace version
- `workspace:~`: Use patch-compatible workspace version

## 13. Package.json Scripts

### 13.1 Common Scripts
```json
{
  "scripts": {
    "build": "nest build",
    "start": "nest start",
    "start:dev": "nest start --watch",
    "start:debug": "nest start --debug --watch",
    "start:prod": "node dist/main",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:cov": "jest --coverage",
    "test:debug": "node --inspect-brk -r tsconfig-paths/register -r ts-node/register node_modules/.bin/jest --runInBand",
    "test:e2e": "jest --config ./test/jest-e2e.json",
    "lint": "eslint \"{src,apps,libs,test}/**/*.ts\" --fix",
    "format": "prettier --write \"src/**/*.ts\" \"test/**/*.ts\"",
    "migration:generate": "typeorm migration:generate",
    "migration:run": "typeorm migration:run",
    "migration:revert": "typeorm migration:revert"
  }
}
```

## 14. Dependency Resolution

### 14.1 Peer Dependencies
- Explicitly install peer dependencies
- Check peer dependency warnings
- Resolve version conflicts

### 14.2 Optional Dependencies
- Handle missing optional dependencies gracefully
- Document optional dependency usage
- Provide fallback implementations

### 14.3 Bundled Dependencies
- Avoid bundling when possible
- Use external dependencies
- Document bundled dependencies

