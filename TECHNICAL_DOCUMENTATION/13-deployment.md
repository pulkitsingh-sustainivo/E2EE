# 13. Deployment Guide

## 1. Deployment Overview

This guide covers deployment strategies for the E2EE microservices architecture, including containerization, orchestration, and cloud deployment options.

## 2. Deployment Architecture

### 2.1 Production Architecture

```
┌─────────────────────────────────────────────────┐
│              Load Balancer / API Gateway         │
│            (Nginx / AWS ALB / Cloudflare)        │
└───────────────┬─────────────────────────────────┘
                │
    ┌───────────┴───────────┐
    │                       │
    ▼                       ▼
┌─────────────┐      ┌──────────────────┐
│ Vault       │      │ Prompt Response  │
│ Service     │      │ Service           │
│ (3 instances)│      │ (3 instances)      │
└──────┬──────┘      └────────┬──────────┘
       │                      │
       └──────────┬───────────┘
                  │
    ┌─────────────┴─────────────┐
    │                            │
    ▼                            ▼
┌─────────────┐          ┌─────────────┐
│ PostgreSQL  │          │    Redis     │
│ (Primary +  │          │    Cluster    │
│  Replicas)   │          │               │
└─────────────┘          └─────────────┘
```

## 3. Containerization

### 3.1 Dockerfile - Vault Service

```dockerfile
# services/vault-service/Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY packages/ ./packages/
COPY services/vault-service/package*.json ./services/vault-service/

# Install dependencies
RUN npm ci --workspace=services/vault-service

# Copy source code
COPY services/vault-service/ ./services/vault-service/
COPY packages/ ./packages/

# Build application
RUN npm run build --workspace=services/vault-service

# Production stage
FROM node:18-alpine

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nestjs -u 1001

# Copy package files
COPY package*.json ./
COPY packages/ ./packages/
COPY services/vault-service/package*.json ./services/vault-service/

# Install production dependencies only
RUN npm ci --workspace=services/vault-service --only=production && \
    npm cache clean --force

# Copy built application
COPY --from=builder --chown=nestjs:nodejs /app/services/vault-service/dist ./dist
COPY --from=builder --chown=nestjs:nodejs /app/packages ./packages

# Copy keys directory (if needed, or use secrets management)
# COPY --chown=nestjs:nodejs keys/ ./keys

USER nestjs

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/v1/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start application
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main"]
```

### 3.2 Dockerfile - Prompt Response Service

Similar structure to Vault Service, change:
- Port: 3001
- Service path: `services/prompt-response-service`

### 3.3 Docker Compose for Development

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:14-alpine
    container_name: e2ee-postgres
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: e2ee_vault
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: e2ee-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  vault-service:
    build:
      context: .
      dockerfile: services/vault-service/Dockerfile
    container_name: e2ee-vault-service
    environment:
      NODE_ENV: production
      PORT: 3000
      DATABASE_HOST: postgres
      DATABASE_PORT: 5432
      DATABASE_USER: postgres
      DATABASE_PASSWORD: postgres
      DATABASE_NAME: e2ee_vault
      REDIS_HOST: redis
      REDIS_PORT: 6379
    ports:
      - "3000:3000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped

  prompt-response-service:
    build:
      context: .
      dockerfile: services/prompt-response-service/Dockerfile
    container_name: e2ee-prompt-response-service
    environment:
      NODE_ENV: production
      PORT: 3001
      REDIS_HOST: redis
      REDIS_PORT: 6379
    ports:
      - "3001:3001"
    depends_on:
      redis:
        condition: service_healthy
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

## 4. Kubernetes Deployment

### 4.1 Namespace

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: e2ee
```

### 4.2 ConfigMap

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: e2ee-config
  namespace: e2ee
data:
  NODE_ENV: "production"
  DATABASE_HOST: "postgres-service"
  DATABASE_PORT: "5432"
  REDIS_HOST: "redis-service"
  REDIS_PORT: "6379"
```

### 4.3 Secrets

```yaml
# k8s/secrets.yaml (base64 encoded)
apiVersion: v1
kind: Secret
metadata:
  name: e2ee-secrets
  namespace: e2ee
type: Opaque
data:
  DATABASE_PASSWORD: <base64-encoded-password>
  JWT_SECRET: <base64-encoded-jwt-secret>
  REDIS_PASSWORD: <base64-encoded-redis-password>
```

### 4.4 Deployment - Vault Service

```yaml
# k8s/vault-service-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-service
  namespace: e2ee
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vault-service
  template:
    metadata:
      labels:
        app: vault-service
    spec:
      containers:
      - name: vault-service
        image: your-registry/vault-service:latest
        ports:
        - containerPort: 3000
        env:
        - name: DATABASE_HOST
          valueFrom:
            configMapKeyRef:
              name: e2ee-config
              key: DATABASE_HOST
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: e2ee-secrets
              key: DATABASE_PASSWORD
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 5
```

### 4.5 Service

```yaml
# k8s/vault-service-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: vault-service
  namespace: e2ee
spec:
  selector:
    app: vault-service
  ports:
  - port: 80
    targetPort: 3000
  type: LoadBalancer
```

### 4.6 Horizontal Pod Autoscaler

```yaml
# k8s/vault-service-hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: vault-service-hpa
  namespace: e2ee
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: vault-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## 5. Cloud Deployment Options

### 5.1 AWS Deployment

#### ECS Task Definition

```json
{
  "family": "vault-service",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "vault-service",
      "image": "your-account.dkr.ecr.region.amazonaws.com/vault-service:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "DATABASE_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:database-password"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:3000/api/v1/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/vault-service",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### 5.2 Azure Deployment

#### Azure Container Instances

```bash
# Create resource group
az group create --name e2ee-rg --location eastus

# Deploy container
az container create \
  --resource-group e2ee-rg \
  --name vault-service \
  --image your-registry/vault-service:latest \
  --cpu 1 \
  --memory 1 \
  --registry-login-server your-registry.azurecr.io \
  --registry-username your-username \
  --registry-password your-password \
  --dns-name-label vault-service \
  --ports 3000 \
  --environment-variables \
    NODE_ENV=production \
    DATABASE_HOST=your-database-host
```

### 5.3 Google Cloud Deployment

#### Cloud Run

```bash
# Deploy to Cloud Run
gcloud run deploy vault-service \
  --image gcr.io/your-project/vault-service:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 1 \
  --max-instances 10 \
  --set-env-vars NODE_ENV=production
```

## 6. Database Deployment

### 6.1 PostgreSQL Deployment

#### AWS RDS

```bash
# Create RDS instance
aws rds create-db-instance \
  --db-instance-identifier e2ee-postgres \
  --db-instance-class db.t3.medium \
  --engine postgres \
  --engine-version 14.9 \
  --master-username postgres \
  --master-user-password YourPassword123 \
  --allocated-storage 100 \
  --storage-encrypted \
  --backup-retention-period 7 \
  --multi-az
```

#### Azure Database for PostgreSQL

```bash
# Create Azure Database
az postgres server create \
  --resource-group e2ee-rg \
  --name e2ee-postgres \
  --location eastus \
  --admin-user postgres \
  --admin-password YourPassword123 \
  --sku-name GP_Gen5_2 \
  --version 14 \
  --storage-size 51200 \
  --ssl-enforcement Enabled
```

### 6.2 Redis Deployment

#### AWS ElastiCache

```bash
# Create ElastiCache cluster
aws elasticache create-cache-cluster \
  --cache-cluster-id e2ee-redis \
  --cache-node-type cache.t3.medium \
  --engine redis \
  --num-cache-nodes 1 \
  --engine-version 7.0
```

## 7. CI/CD Pipeline

### 7.1 GitHub Actions Workflow

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Run tests
        run: npm test

      - name: Build Docker image
        run: docker build -t vault-service:latest -f services/vault-service/Dockerfile .

      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: Push Docker image
        run: |
          docker tag vault-service:latest ${{ secrets.DOCKER_USERNAME }}/vault-service:${{ github.sha }}
          docker push ${{ secrets.DOCKER_USERNAME }}/vault-service:${{ github.sha }}
          docker tag vault-service:latest ${{ secrets.DOCKER_USERNAME }}/vault-service:latest
          docker push ${{ secrets.DOCKER_USERNAME }}/vault-service:latest

      - name: Deploy to Kubernetes
        uses: azure/k8s-deploy@v3
        with:
          manifests: k8s/
          images: ${{ secrets.DOCKER_USERNAME }}/vault-service:${{ github.sha }}
```

## 8. Blue-Green Deployment

### 8.1 Strategy

1. Deploy new version to "green" environment
2. Run health checks
3. Switch traffic from "blue" to "green"
4. Monitor "green" environment
5. Keep "blue" as rollback option

### 8.2 Kubernetes Implementation

```yaml
# Use Istio or similar for traffic splitting
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: vault-service
spec:
  hosts:
  - vault-service
  http:
  - match:
    - headers:
        version:
          exact: "v2"
    route:
    - destination:
        host: vault-service
        subset: v2
  - route:
    - destination:
        host: vault-service
        subset: v1
      weight: 90
    - destination:
        host: vault-service
        subset: v2
      weight: 10
```

## 9. Rollback Procedures

### 9.1 Kubernetes Rollback

```bash
# Rollback deployment
kubectl rollout undo deployment/vault-service -n e2ee

# Check rollout status
kubectl rollout status deployment/vault-service -n e2ee

# View rollout history
kubectl rollout history deployment/vault-service -n e2ee
```

### 9.2 Docker Compose Rollback

```bash
# Stop current containers
docker-compose down

# Checkout previous version
git checkout <previous-commit>

# Rebuild and start
docker-compose up -d --build
```

## 10. Monitoring Deployment

### 10.1 Health Check Endpoints

- `/api/v1/health`: Basic health check
- `/api/v1/health/live`: Liveness probe
- `/api/v1/health/ready`: Readiness probe

### 10.2 Deployment Verification

```bash
# Check service status
curl https://api.e2ee.example.com/api/v1/health

# Check metrics
curl https://api.e2ee.example.com/api/v1/metrics

# Verify endpoints
curl -X POST https://api.e2ee.example.com/api/v1/prompts \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"promptText": "test", "secret": "test"}'
```

## 11. Security Considerations

### 11.1 Secrets Management

- Use Kubernetes Secrets or external secret management
- Never commit secrets to repository
- Rotate secrets regularly
- Use least privilege principle

### 11.2 Network Security

- Use TLS/SSL for all communications
- Implement network policies
- Use private subnets for databases
- Enable firewall rules

### 11.3 Image Security

- Scan images for vulnerabilities
- Use minimal base images
- Keep images updated
- Sign images cryptographically

## 12. Disaster Recovery

### 12.1 Backup Strategy

- Database backups: Daily automated backups
- Key backups: Secure backup in key vault
- Configuration backups: Version controlled

### 12.2 Recovery Procedures

- **RTO**: 1 hour
- **RPO**: 24 hours
- Automated failover for database
- Manual failover for application services

## 13. Performance Optimization

### 13.1 Resource Limits

- Set appropriate CPU and memory limits
- Monitor resource usage
- Scale based on metrics

### 13.2 Caching

- Enable Redis caching
- Use CDN for static assets
- Implement application-level caching

## 14. Deployment Checklist

- [ ] All tests passing
- [ ] Security scan completed
- [ ] Database migrations tested
- [ ] Environment variables configured
- [ ] Secrets properly managed
- [ ] Health checks configured
- [ ] Monitoring enabled
- [ ] Logging configured
- [ ] Backup strategy in place
- [ ] Rollback plan documented
- [ ] Documentation updated
- [ ] Team notified

