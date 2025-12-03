# 15. Monitoring & Logging

## 1. Monitoring Overview

Comprehensive monitoring and logging strategy for observability, performance tracking, and troubleshooting.

## 2. Logging Strategy

### 2.1 Winston Configuration

```typescript
// common/logger/winston.config.ts
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';
import * as DailyRotateFile from 'winston-daily-rotate-file';

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json(),
);

const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, context, ...meta }) => {
    return `${timestamp} [${context}] ${level}: ${message} ${
      Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''
    }`;
  }),
);

export const winstonConfig = WinstonModule.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: process.env.APP_NAME || 'vault-service' },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: consoleFormat,
    }),

    // Error log file
    new DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxSize: '20m',
      maxFiles: '14d',
      format: logFormat,
    }),

    // Combined log file
    new DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
      format: logFormat,
    }),

    // Audit log file
    new DailyRotateFile({
      filename: 'logs/audit-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'audit',
      maxSize: '20m',
      maxFiles: '90d', // Keep audit logs for 90 days
      format: logFormat,
    }),
  ],

  exceptionHandlers: [
    new DailyRotateFile({
      filename: 'logs/exceptions-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
    }),
  ],

  rejectionHandlers: [
    new DailyRotateFile({
      filename: 'logs/rejections-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
    }),
  ],
});
```

### 2.2 Structured Logging

```typescript
// common/interceptors/logging.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, body, query, params } = request;
    const requestId = request.headers['x-request-id'] || require('uuid').v4();
    const startTime = Date.now();

    // Log request
    this.logger.log({
      event: 'request_started',
      method,
      url,
      requestId,
      body: this.sanitizeBody(body),
      query,
      params,
      ip: request.ip,
      userAgent: request.headers['user-agent'],
    });

    return next.handle().pipe(
      tap({
        next: (data) => {
          const duration = Date.now() - startTime;
          this.logger.log({
            event: 'request_completed',
            method,
            url,
            requestId,
            statusCode: context.switchToHttp().getResponse().statusCode,
            duration,
          });
        },
        error: (error) => {
          const duration = Date.now() - startTime;
          this.logger.error({
            event: 'request_failed',
            method,
            url,
            requestId,
            error: error.message,
            stack: error.stack,
            duration,
          });
        },
      }),
    );
  }

  private sanitizeBody(body: any): any {
    if (!body) return body;
    const sanitized = { ...body };
    // Remove sensitive fields
    if (sanitized.secret) {
      sanitized.secret = '***REDACTED***';
    }
    if (sanitized.password) {
      sanitized.password = '***REDACTED***';
    }
    return sanitized;
  }
}
```

## 3. Metrics Collection

### 3.1 Prometheus Metrics

```typescript
// common/metrics/prometheus.service.ts
import { Injectable } from '@nestjs/common';
import { Counter, Histogram, Gauge, Registry } from 'prom-client';

@Injectable()
export class PrometheusService {
  private readonly registry: Registry;

  // HTTP Metrics
  public readonly httpRequestDuration: Histogram<string>;
  public readonly httpRequestTotal: Counter<string>;
  public readonly httpRequestErrors: Counter<string>;

  // Business Metrics
  public readonly envelopesCreated: Counter<string>;
  public readonly envelopesDecrypted: Counter<string>;
  public readonly encryptionDuration: Histogram<string>;
  public readonly decryptionDuration: Histogram<string>;

  // System Metrics
  public readonly activeConnections: Gauge<string>;
  public readonly databaseConnections: Gauge<string>;

  constructor() {
    this.registry = new Registry();

    // HTTP Metrics
    this.httpRequestDuration = new Histogram({
      name: 'http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route', 'status'],
      buckets: [0.1, 0.5, 1, 2, 5],
      registers: [this.registry],
    });

    this.httpRequestTotal = new Counter({
      name: 'http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status'],
      registers: [this.registry],
    });

    this.httpRequestErrors = new Counter({
      name: 'http_request_errors_total',
      help: 'Total number of HTTP request errors',
      labelNames: ['method', 'route', 'status'],
      registers: [this.registry],
    });

    // Business Metrics
    this.envelopesCreated = new Counter({
      name: 'envelopes_created_total',
      help: 'Total number of envelopes created',
      labelNames: ['status'],
      registers: [this.registry],
    });

    this.envelopesDecrypted = new Counter({
      name: 'envelopes_decrypted_total',
      help: 'Total number of envelopes decrypted',
      labelNames: ['success'],
      registers: [this.registry],
    });

    this.encryptionDuration = new Histogram({
      name: 'encryption_duration_seconds',
      help: 'Duration of encryption operations in seconds',
      labelNames: ['algorithm'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1],
      registers: [this.registry],
    });

    this.decryptionDuration = new Histogram({
      name: 'decryption_duration_seconds',
      help: 'Duration of decryption operations in seconds',
      labelNames: ['algorithm'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1],
      registers: [this.registry],
    });

    // System Metrics
    this.activeConnections = new Gauge({
      name: 'active_connections',
      help: 'Number of active connections',
      registers: [this.registry],
    });

    this.databaseConnections = new Gauge({
      name: 'database_connections',
      help: 'Number of database connections',
      registers: [this.registry],
    });
  }

  getMetrics(): Promise<string> {
    return this.registry.metrics();
  }

  getRegistry(): Registry {
    return this.registry;
  }
}
```

### 3.2 Metrics Endpoint

```typescript
// metrics/metrics.controller.ts
import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { PrometheusService } from '../common/metrics/prometheus.service';

@ApiTags('metrics')
@Controller('metrics')
export class MetricsController {
  constructor(private prometheusService: PrometheusService) {}

  @Get()
  @ApiOperation({ summary: 'Get Prometheus metrics' })
  async getMetrics() {
    const metrics = await this.prometheusService.getMetrics();
    return metrics;
  }
}
```

## 4. Health Checks

### 4.1 Health Check Module

```typescript
// health/health.controller.ts
import { Controller, Get } from '@nestjs/common';
import {
  HealthCheckService,
  HealthCheck,
  TypeOrmHealthIndicator,
  MemoryHealthIndicator,
  DiskHealthIndicator,
} from '@nestjs/terminus';
import { ApiTags, ApiOperation } from '@nestjs/swagger';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
    private memory: MemoryHealthIndicator,
    private disk: DiskHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  @ApiOperation({ summary: 'Health check endpoint' })
  check() {
    return this.health.check([
      () => this.db.pingCheck('database'),
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),
      () => this.memory.checkRSS('memory_rss', 300 * 1024 * 1024),
      () =>
        this.disk.checkStorage('storage', {
          path: '/',
          thresholdPercent: 0.9,
        }),
    ]);
  }

  @Get('live')
  @ApiOperation({ summary: 'Liveness probe' })
  liveness() {
    return { status: 'ok' };
  }

  @Get('ready')
  @HealthCheck()
  @ApiOperation({ summary: 'Readiness probe' })
  readiness() {
    return this.health.check([
      () => this.db.pingCheck('database'),
    ]);
  }
}
```

## 5. Distributed Tracing

### 5.1 OpenTelemetry Setup

```typescript
// common/tracing/tracing.config.ts
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';

export function initTracing() {
  const sdk = new NodeSDK({
    resource: new Resource({
      [SemanticResourceAttributes.SERVICE_NAME]: process.env.APP_NAME || 'vault-service',
      [SemanticResourceAttributes.SERVICE_VERSION]: process.env.APP_VERSION || '1.0.0',
    }),
    traceExporter: new JaegerExporter({
      endpoint: process.env.JAEGER_ENDPOINT || 'http://localhost:14268/api/traces',
    }),
    instrumentations: [getNodeAutoInstrumentations()],
  });

  sdk.start();
  console.log('Tracing initialized');

  process.on('SIGTERM', () => {
    sdk.shutdown()
      .then(() => console.log('Tracing terminated'))
      .catch((error) => console.log('Error terminating tracing', error))
      .finally(() => process.exit(0));
  });
}
```

## 6. Error Tracking

### 6.1 Sentry Integration

```typescript
// main.ts
import * as Sentry from '@sentry/node';
import { ProfilingIntegration } from '@sentry/profiling-node';

if (process.env.NODE_ENV === 'production') {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV,
    integrations: [
      new ProfilingIntegration(),
    ],
    tracesSampleRate: 1.0,
    profilesSampleRate: 1.0,
  });
}
```

### 6.2 Exception Filter with Sentry

```typescript
// common/filters/sentry-exception.filter.ts
import { ExceptionFilter, Catch, ArgumentsHost } from '@nestjs/common';
import { AllExceptionsFilter } from './all-exceptions.filter';
import * as Sentry from '@sentry/node';

@Catch()
export class SentryExceptionFilter extends AllExceptionsFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    if (process.env.NODE_ENV === 'production') {
      Sentry.captureException(exception);
    }
    return super.catch(exception, host);
  }
}
```

## 7. Alerting

### 7.1 Alert Rules (Prometheus)

```yaml
# monitoring/alerts.yml
groups:
  - name: e2ee_alerts
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: rate(http_request_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors per second"

      - alert: HighResponseTime
        expr: histogram_quantile(0.95, http_request_duration_seconds_bucket) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High response time"
          description: "95th percentile response time is {{ $value }} seconds"

      - alert: DatabaseConnectionFailure
        expr: up{job="postgres"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database connection failed"
          description: "Cannot connect to PostgreSQL database"

      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes / 1024 / 1024 > 500
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value }} MB"

      - alert: EncryptionFailure
        expr: rate(encryption_errors_total[5m]) > 0.01
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Encryption failures detected"
          description: "Encryption error rate is {{ $value }} per second"
```

## 8. Dashboards

### 8.1 Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "E2EE System Dashboard",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(http_request_errors_total[5m])"
          }
        ]
      },
      {
        "title": "Response Time (95th percentile)",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, http_request_duration_seconds_bucket)"
          }
        ]
      },
      {
        "title": "Envelopes Created",
        "targets": [
          {
            "expr": "rate(envelopes_created_total[5m])"
          }
        ]
      },
      {
        "title": "Envelopes Decrypted",
        "targets": [
          {
            "expr": "rate(envelopes_decrypted_total[5m])"
          }
        ]
      },
      {
        "title": "Encryption Duration",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, encryption_duration_seconds_bucket)"
          }
        ]
      },
      {
        "title": "Database Connections",
        "targets": [
          {
            "expr": "database_connections"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "targets": [
          {
            "expr": "process_resident_memory_bytes"
          }
        ]
      }
    ]
  }
}
```

## 9. Log Aggregation

### 9.1 ELK Stack Integration

```typescript
// common/logger/elk.config.ts
import { createLogger, format, transports } from 'winston';
import { ElasticsearchTransport } from 'winston-elasticsearch';

export const elkLogger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.json(),
  ),
  transports: [
    new ElasticsearchTransport({
      level: 'info',
      clientOpts: {
        node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
      },
      index: 'e2ee-logs',
      indexTemplate: {
        index_patterns: ['e2ee-logs-*'],
        settings: {
          number_of_shards: 1,
          number_of_replicas: 1,
        },
      },
    }),
  ],
});
```

## 10. Monitoring Best Practices

1. **Comprehensive Logging**: Log all important events
2. **Structured Logs**: Use JSON format for easy parsing
3. **Log Levels**: Use appropriate log levels (debug, info, warn, error)
4. **Sensitive Data**: Never log secrets, passwords, or keys
5. **Context**: Include request IDs, user IDs, timestamps
6. **Metrics**: Track business and technical metrics
7. **Alerts**: Set up actionable alerts
8. **Dashboards**: Create visual dashboards for key metrics
9. **Retention**: Define log and metric retention policies
10. **Performance**: Ensure monitoring doesn't impact performance

## 11. Monitoring Checklist

- [ ] Application logs configured
- [ ] Error tracking integrated (Sentry)
- [ ] Metrics collection setup (Prometheus)
- [ ] Health check endpoints configured
- [ ] Distributed tracing enabled
- [ ] Alerting rules defined
- [ ] Dashboards created
- [ ] Log aggregation configured
- [ ] Performance monitoring enabled
- [ ] Security monitoring in place
- [ ] Backup and retention policies defined

