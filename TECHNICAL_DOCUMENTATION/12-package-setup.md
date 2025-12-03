# 12. Package Setup & Installation Guide

## 1. Prerequisites

### 1.1 System Requirements

- **Node.js**: v18.0.0 or higher (LTS version recommended)
- **npm**: v9.0.0 or higher (comes with Node.js)
- **PostgreSQL**: v14.0 or higher
- **Redis**: v7.0 or higher
- **OpenSSL**: For generating RSA key pairs
- **Git**: For version control

### 1.2 Verify Installation

```bash
# Check Node.js version
node --version
# Should output: v18.x.x or higher

# Check npm version
npm --version
# Should output: 9.x.x or higher

# Check PostgreSQL version
psql --version
# Should output: psql (PostgreSQL) 14.x or higher

# Check Redis version
redis-server --version
# Should output: Redis server v=7.x.x

# Check OpenSSL version
openssl version
# Should output: OpenSSL 1.1.1 or higher
```

## 2. Project Setup

### 2.1 Clone Repository

```bash
git clone <repository-url>
cd e2ee-project
```

### 2.2 Install Root Dependencies

```bash
# Install all workspace dependencies
npm install
```

This will install dependencies for:
- Root workspace
- All packages (crypto-lib, common)
- All services (vault-service, prompt-response-service)

### 2.3 Build Shared Packages

```bash
# Build crypto-lib package
cd packages/crypto-lib
npm run build
cd ../..

# Build common package (if applicable)
cd packages/common
npm run build
cd ../..
```

## 3. Environment Configuration

### 3.1 Create Environment Files

```bash
# Vault Service
cd services/vault-service
cp .env.example .env

# Prompt Response Service
cd ../prompt-response-service
cp .env.example .env
```

### 3.2 Configure Environment Variables

#### Vault Service (.env)

```bash
# Application
NODE_ENV=development
PORT=3000
APP_NAME=vault-service

# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=postgres
DATABASE_PASSWORD=your_password
DATABASE_NAME=e2ee_vault

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Security
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=1h
API_KEY_HEADER=X-API-Key

# Keys
RECEIVER_PUBLIC_KEY_PATH=./keys/prompt_response_enc_public.key
SENDER_PRIVATE_KEY_PATH=./keys/prompt_vault_sign_private.key

# Logging
LOG_LEVEL=info

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
```

#### Prompt Response Service (.env)

```bash
# Application
NODE_ENV=development
PORT=3001
APP_NAME=prompt-response-service

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Security
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=1h
API_KEY_HEADER=X-API-Key

# Keys
RECEIVER_PRIVATE_KEY_PATH=./keys/prompt_response_enc_private.key
SENDER_PUBLIC_KEY_PATH=./keys/prompt_vault_sign_public.key

# Logging
LOG_LEVEL=info

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
```

## 4. Database Setup

### 4.1 Create PostgreSQL Database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE e2ee_vault;

# Create user (optional)
CREATE USER e2ee_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE e2ee_vault TO e2ee_user;

# Exit psql
\q
```

### 4.2 Run Migrations

```bash
# Vault Service
cd services/vault-service
npm run migration:run

# Or using TypeORM CLI
npx typeorm migration:run -d src/database/data-source.ts
```

## 5. Redis Setup

### 5.1 Install Redis

#### macOS (using Homebrew)
```bash
brew install redis
brew services start redis
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install redis-server
sudo systemctl start redis
sudo systemctl enable redis
```

#### Windows
Download and install from: https://github.com/microsoftarchive/redis/releases

### 5.2 Verify Redis

```bash
# Test Redis connection
redis-cli ping
# Should output: PONG
```

## 6. Key Generation

### 6.1 Create Keys Directory

```bash
mkdir keys
cd keys
```

### 6.2 Generate Receiver's Encryption Keys

```bash
# Private Key (for Prompt Response Service)
openssl genpkey -algorithm RSA -out prompt_response_enc_private.key -pkeyopt rsa_keygen_bits:2048

# Public Key
openssl rsa -pubout -in prompt_response_enc_private.key -out prompt_response_enc_public.key

# Set permissions (Linux/macOS)
chmod 600 prompt_response_enc_private.key
chmod 644 prompt_response_enc_public.key
```

### 6.3 Generate Sender's Signing Keys

```bash
# Private Key (for Vault Service)
openssl genpkey -algorithm RSA -out prompt_vault_sign_private.key -pkeyopt rsa_keygen_bits:2048

# Public Key
openssl rsa -pubout -in prompt_vault_sign_private.key -out prompt_vault_sign_public.key

# Set permissions (Linux/macOS)
chmod 600 prompt_vault_sign_private.key
chmod 644 prompt_vault_sign_public.key
```

### 6.4 Verify Keys

```bash
# Verify private key
openssl rsa -in prompt_response_enc_private.key -check -noout
# Should output: RSA key ok

# Verify public key
openssl rsa -pubin -in prompt_response_enc_public.key -text -noout
```

## 7. Service Installation

### 7.1 Vault Service Setup

```bash
cd services/vault-service

# Install dependencies (if not done at root)
npm install

# Build the project
npm run build

# Run migrations
npm run migration:run

# Start in development mode
npm run start:dev
```

### 7.2 Prompt Response Service Setup

```bash
cd services/prompt-response-service

# Install dependencies (if not done at root)
npm install

# Build the project
npm run build

# Start in development mode
npm run start:dev
```

## 8. Development Tools Setup

### 8.1 Install Development Dependencies

```bash
# Global development tools (optional)
npm install -g @nestjs/cli
npm install -g typescript
npm install -g ts-node
```

### 8.2 Configure VS Code (Optional)

Create `.vscode/settings.json`:

```json
{
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "typescript.tsdk": "node_modules/typescript/lib",
  "typescript.enablePromptUseWorkspaceTsdk": true
}
```

### 8.3 Install VS Code Extensions

Recommended extensions:
- ESLint
- Prettier
- TypeScript and JavaScript Language Features
- NestJS Files
- Docker
- PostgreSQL

## 9. Docker Setup (Optional)

### 9.1 Install Docker

- **macOS**: Download from https://www.docker.com/products/docker-desktop
- **Windows**: Download from https://www.docker.com/products/docker-desktop
- **Linux**: Follow distribution-specific instructions

### 9.2 Docker Compose Setup

```bash
# Start all services (PostgreSQL, Redis)
docker-compose up -d

# Check services
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## 10. Testing Setup

### 10.1 Run Tests

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
```

### 10.2 Test Database Setup

```bash
# Create test database
psql -U postgres
CREATE DATABASE e2ee_vault_test;
\q
```

Update test configuration to use test database.

## 11. Verification Steps

### 11.1 Health Checks

```bash
# Vault Service
curl http://localhost:3000/api/v1/health

# Prompt Response Service
curl http://localhost:3001/api/v1/health
```

### 11.2 Swagger Documentation

- Vault Service: http://localhost:3000/api/docs
- Prompt Response Service: http://localhost:3001/api/docs

### 11.3 Test API Endpoints

```bash
# Create a prompt
curl -X POST http://localhost:3000/api/v1/prompts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "promptText": "What is the capital of France?",
    "secret": "my_secret_key"
  }'
```

## 12. Troubleshooting

### 12.1 Common Issues

#### Port Already in Use
```bash
# Find process using port
lsof -i :3000  # macOS/Linux
netstat -ano | findstr :3000  # Windows

# Kill process
kill -9 <PID>  # macOS/Linux
taskkill /PID <PID> /F  # Windows
```

#### Database Connection Error
- Verify PostgreSQL is running
- Check database credentials in .env
- Verify database exists
- Check firewall settings

#### Redis Connection Error
- Verify Redis is running: `redis-cli ping`
- Check Redis host and port in .env
- Verify Redis password (if set)

#### Key File Not Found
- Verify key files exist in `keys/` directory
- Check key paths in .env files
- Verify file permissions

#### Module Not Found
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

### 12.2 Logs

```bash
# View application logs
tail -f logs/application.log

# View error logs
tail -f logs/error.log
```

## 13. Production Setup

### 13.1 Production Environment Variables

- Use secure secret management (AWS Secrets Manager, HashiCorp Vault)
- Enable SSL/TLS
- Use strong passwords
- Enable database encryption
- Configure proper CORS origins
- Set up monitoring and logging

### 13.2 Build for Production

```bash
# Build all services
npm run build

# Start in production mode
NODE_ENV=production npm run start:prod
```

## 14. CI/CD Setup

### 14.1 GitHub Actions Example

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm ci
      - run: npm run build
      - run: npm test
```

## 15. Package Update Strategy

### 15.1 Check for Updates

```bash
# Check outdated packages
npm outdated

# Update packages (minor and patch)
npm update

# Update specific package
npm install package-name@latest
```

### 15.2 Security Audits

```bash
# Run security audit
npm audit

# Fix vulnerabilities
npm audit fix

# Fix with breaking changes
npm audit fix --force
```

