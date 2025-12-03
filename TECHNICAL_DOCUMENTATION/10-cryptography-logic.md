# 10. Cryptography Logic & Implementation

## 1. Cryptographic Overview

The E2EE system uses a hybrid encryption approach combining:
- **AES-256-GCM**: Symmetric encryption for data (fast, secure)
- **RSA-2048**: Asymmetric encryption for key exchange and digital signatures
- **SHA-256**: Hashing for integrity verification

## 2. Encryption Flow

### 2.1 Envelope Generation Process

```
1. Input: Plaintext Prompt
   │
   ▼
2. Generate Random AES-256 Key (32 bytes)
   │
   ▼
3. Generate Random IV (12 bytes for GCM)
   │
   ▼
4. Encrypt Prompt with AES-256-GCM
   ├─► Encrypted Data
   └─► Authentication Tag
   │
   ▼
5. Encrypt AES Key with RSA-OAEP (Receiver's Public Key)
   └─► Encrypted Key
   │
   ▼
6. Create Envelope Payload
   ├─► Encrypted Data
   ├─► Encrypted Key
   ├─► IV
   └─► Auth Tag
   │
   ▼
7. Generate Digital Signature (RSA-PSS, Sender's Private Key)
   └─► Signature
   │
   ▼
8. Assemble Final Envelope
   ├─► Encrypted Data
   ├─► Encrypted Key
   ├─► IV
   ├─► Auth Tag
   ├─► Signature
   └─► Metadata
```

## 3. AES-256-GCM Implementation

### 3.1 Encryption Service

```typescript
// packages/crypto-lib/src/aes/aes-encryption.service.ts
import { Injectable } from '@nestjs/common';
import { createCipheriv, randomBytes } from 'crypto';

export interface AESEncryptionResult {
  encryptedData: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

@Injectable()
export class AESEncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32; // 256 bits
  private readonly ivLength = 12; // 96 bits for GCM

  /**
   * Encrypts data using AES-256-GCM
   * @param data Plaintext data to encrypt
   * @param key AES key (32 bytes)
   * @returns Encrypted data, IV, and authentication tag
   */
  encrypt(data: string | Buffer, key: Buffer): AESEncryptionResult {
    if (key.length !== this.keyLength) {
      throw new Error(`Key must be ${this.keyLength} bytes (256 bits)`);
    }

    // Generate random IV
    const iv = randomBytes(this.ivLength);

    // Create cipher
    const cipher = createCipheriv(this.algorithm, key, iv);

    // Encrypt data
    const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    let encrypted = cipher.update(dataBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    // Get authentication tag
    const authTag = cipher.getAuthTag();

    return {
      encryptedData: encrypted,
      iv,
      authTag,
    };
  }

  /**
   * Generates a random AES-256 key
   * @returns 32-byte random key
   */
  generateKey(): Buffer {
    return randomBytes(this.keyLength);
  }
}
```

### 3.2 Decryption Service

```typescript
// packages/crypto-lib/src/aes/aes-decryption.service.ts
import { Injectable } from '@nestjs/common';
import { createDecipheriv } from 'crypto';

export interface AESDecryptionResult {
  decryptedData: Buffer;
}

@Injectable()
export class AESDecryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32;

  /**
   * Decrypts data using AES-256-GCM
   * @param encryptedData Encrypted data
   * @param key AES key (32 bytes)
   * @param iv Initialization vector (12 bytes)
   * @param authTag Authentication tag (16 bytes)
   * @returns Decrypted plaintext
   */
  decrypt(
    encryptedData: Buffer,
    key: Buffer,
    iv: Buffer,
    authTag: Buffer,
  ): AESDecryptionResult {
    if (key.length !== this.keyLength) {
      throw new Error(`Key must be ${this.keyLength} bytes (256 bits)`);
    }

    if (iv.length !== 12) {
      throw new Error('IV must be 12 bytes for GCM');
    }

    if (authTag.length !== 16) {
      throw new Error('Authentication tag must be 16 bytes');
    }

    // Create decipher
    const decipher = createDecipheriv(this.algorithm, key, iv);
    decipher.setAuthTag(authTag);

    // Decrypt data
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return {
      decryptedData: decrypted,
    };
  }
}
```

## 4. RSA Encryption Implementation

### 4.1 RSA Encryption Service

```typescript
// packages/crypto-lib/src/rsa/rsa-encryption.service.ts
import { Injectable } from '@nestjs/common';
import { publicEncrypt, constants } from 'crypto';
import { KeyLoaderService } from '../keys/key-loader.service';

@Injectable()
export class RSAEncryptionService {
  constructor(private keyLoader: KeyLoaderService) {}

  /**
   * Encrypts data using RSA-OAEP
   * @param data Data to encrypt (max 190 bytes for RSA-2048)
   * @param publicKeyPath Path to public key file
   * @returns Encrypted data
   */
  async encrypt(data: Buffer, publicKeyPath: string): Promise<Buffer> {
    const publicKey = await this.keyLoader.loadPublicKey(publicKeyPath);

    // RSA-OAEP with SHA-256
    const encrypted = publicEncrypt(
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      data,
    );

    return encrypted;
  }

  /**
   * Encrypts data using RSA-OAEP (key provided directly)
   * @param data Data to encrypt
   * @param publicKey Public key as PEM string
   * @returns Encrypted data
   */
  encryptWithKey(data: Buffer, publicKey: string): Buffer {
    const encrypted = publicEncrypt(
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      data,
    );

    return encrypted;
  }
}
```

### 4.2 RSA Decryption Service

```typescript
// packages/crypto-lib/src/rsa/rsa-decryption.service.ts
import { Injectable } from '@nestjs/common';
import { privateDecrypt, constants } from 'crypto';
import { KeyLoaderService } from '../keys/key-loader.service';

@Injectable()
export class RSADecryptionService {
  constructor(private keyLoader: KeyLoaderService) {}

  /**
   * Decrypts data using RSA-OAEP
   * @param encryptedData Encrypted data
   * @param privateKeyPath Path to private key file
   * @returns Decrypted data
   */
  async decrypt(encryptedData: Buffer, privateKeyPath: string): Promise<Buffer> {
    const privateKey = await this.keyLoader.loadPrivateKey(privateKeyPath);

    // RSA-OAEP with SHA-256
    const decrypted = privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encryptedData,
    );

    return decrypted;
  }

  /**
   * Decrypts data using RSA-OAEP (key provided directly)
   * @param encryptedData Encrypted data
   * @param privateKey Private key as PEM string
   * @returns Decrypted data
   */
  decryptWithKey(encryptedData: Buffer, privateKey: string): Buffer {
    const decrypted = privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encryptedData,
    );

    return decrypted;
  }
}
```

## 5. Digital Signature Implementation

### 5.1 Signature Generation

```typescript
// packages/crypto-lib/src/signatures/signature.service.ts
import { Injectable } from '@nestjs/common';
import { createSign, constants } from 'crypto';
import { KeyLoaderService } from '../keys/key-loader.service';

@Injectable()
export class SignatureService {
  constructor(private keyLoader: KeyLoaderService) {}

  /**
   * Generates RSA-PSS digital signature
   * @param data Data to sign
   * @param privateKeyPath Path to private key file
   * @returns Digital signature
   */
  async sign(data: Buffer, privateKeyPath: string): Promise<Buffer> {
    const privateKey = await this.keyLoader.loadPrivateKey(privateKeyPath);

    // Create sign object
    const sign = createSign('RSA-SHA256');
    sign.update(data);
    sign.end();

    // Generate signature with RSA-PSS padding
    const signature = sign.sign(
      {
        key: privateKey,
        padding: constants.RSA_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
      },
      'base64',
    );

    return Buffer.from(signature, 'base64');
  }

  /**
   * Generates signature with key provided directly
   * @param data Data to sign
   * @param privateKey Private key as PEM string
   * @returns Digital signature
   */
  signWithKey(data: Buffer, privateKey: string): Buffer {
    const sign = createSign('RSA-SHA256');
    sign.update(data);
    sign.end();

    const signature = sign.sign(
      {
        key: privateKey,
        padding: constants.RSA_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
      },
      'base64',
    );

    return Buffer.from(signature, 'base64');
  }
}
```

### 5.2 Signature Verification

```typescript
// packages/crypto-lib/src/signatures/signature-verification.service.ts
import { Injectable } from '@nestjs/common';
import { createVerify, constants } from 'crypto';
import { KeyLoaderService } from '../keys/key-loader.service';

@Injectable()
export class SignatureVerificationService {
  constructor(private keyLoader: KeyLoaderService) {}

  /**
   * Verifies RSA-PSS digital signature
   * @param data Original data
   * @param signature Digital signature
   * @param publicKeyPath Path to public key file
   * @returns True if signature is valid
   */
  async verify(
    data: Buffer,
    signature: Buffer,
    publicKeyPath: string,
  ): Promise<boolean> {
    const publicKey = await this.keyLoader.loadPublicKey(publicKeyPath);

    // Create verify object
    const verify = createVerify('RSA-SHA256');
    verify.update(data);
    verify.end();

    // Verify signature
    const isValid = verify.verify(
      {
        key: publicKey,
        padding: constants.RSA_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
      },
      signature,
    );

    return isValid;
  }

  /**
   * Verifies signature with key provided directly
   * @param data Original data
   * @param signature Digital signature
   * @param publicKey Public key as PEM string
   * @returns True if signature is valid
   */
  verifyWithKey(data: Buffer, signature: Buffer, publicKey: string): boolean {
    const verify = createVerify('RSA-SHA256');
    verify.update(data);
    verify.end();

    const isValid = verify.verify(
      {
        key: publicKey,
        padding: constants.RSA_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
      },
      signature,
    );

    return isValid;
  }
}
```

## 6. Key Management

### 6.1 Key Loader Service

```typescript
// packages/crypto-lib/src/keys/key-loader.service.ts
import { Injectable } from '@nestjs/common';
import { readFileSync } from 'fs';
import { createPublicKey, createPrivateKey } from 'crypto';

@Injectable()
export class KeyLoaderService {
  /**
   * Loads public key from file
   * @param keyPath Path to public key file
   * @returns Public key as PEM string
   */
  async loadPublicKey(keyPath: string): Promise<string> {
    try {
      const keyData = readFileSync(keyPath, 'utf8');
      
      // Validate key format
      const publicKey = createPublicKey(keyData);
      
      return keyData;
    } catch (error) {
      throw new Error(`Failed to load public key from ${keyPath}: ${error.message}`);
    }
  }

  /**
   * Loads private key from file
   * @param keyPath Path to private key file
   * @returns Private key as PEM string
   */
  async loadPrivateKey(keyPath: string): Promise<string> {
    try {
      const keyData = readFileSync(keyPath, 'utf8');
      
      // Validate key format
      const privateKey = createPrivateKey(keyData);
      
      return keyData;
    } catch (error) {
      throw new Error(`Failed to load private key from ${keyPath}: ${error.message}`);
    }
  }

  /**
   * Validates key format
   * @param keyData Key data as string
   * @param isPrivate Whether key is private
   * @returns True if key is valid
   */
  validateKey(keyData: string, isPrivate: boolean): boolean {
    try {
      if (isPrivate) {
        createPrivateKey(keyData);
      } else {
        createPublicKey(keyData);
      }
      return true;
    } catch {
      return false;
    }
  }
}
```

## 7. Envelope Builder Service

### 7.1 Envelope Generation

```typescript
// packages/crypto-lib/src/envelope/envelope-builder.service.ts
import { Injectable } from '@nestjs/common';
import { AESEncryptionService } from '../aes/aes-encryption.service';
import { RSAEncryptionService } from '../rsa/rsa-encryption.service';
import { SignatureService } from '../signatures/signature.service';
import { KeyLoaderService } from '../keys/key-loader.service';

export interface EnvelopeData {
  encryptedData: string; // Base64
  encryptedKey: string; // Base64
  iv: string; // Base64
  authTag: string; // Base64
  signature: string; // Base64
  algorithm: string;
  keyAlgorithm: string;
  signatureAlgorithm: string;
}

export interface EncryptOptions {
  data: string;
  receiverPublicKeyPath: string;
  senderPrivateKeyPath: string;
  metadata?: Record<string, any>;
}

@Injectable()
export class EnvelopeBuilderService {
  constructor(
    private aesEncryption: AESEncryptionService,
    private rsaEncryption: RSAEncryptionService,
    private signatureService: SignatureService,
    private keyLoader: KeyLoaderService,
  ) {}

  /**
   * Creates an encrypted envelope
   * @param options Encryption options
   * @returns Encrypted envelope data
   */
  async createEnvelope(options: EncryptOptions): Promise<EnvelopeData> {
    const { data, receiverPublicKeyPath, senderPrivateKeyPath, metadata } = options;

    // Step 1: Generate AES key
    const aesKey = this.aesEncryption.generateKey();

    // Step 2: Encrypt data with AES-256-GCM
    const aesResult = this.aesEncryption.encrypt(
      Buffer.from(data, 'utf8'),
      aesKey,
    );

    // Step 3: Encrypt AES key with RSA-OAEP
    const encryptedKey = await this.rsaEncryption.encrypt(
      aesKey,
      receiverPublicKeyPath,
    );

    // Step 4: Create payload for signing
    const payload = this.createPayload(
      aesResult.encryptedData,
      encryptedKey,
      aesResult.iv,
      aesResult.authTag,
      metadata,
    );

    // Step 5: Generate digital signature
    const signature = await this.signatureService.sign(
      Buffer.from(JSON.stringify(payload)),
      senderPrivateKeyPath,
    );

    // Step 6: Assemble envelope
    return {
      encryptedData: aesResult.encryptedData.toString('base64'),
      encryptedKey: encryptedKey.toString('base64'),
      iv: aesResult.iv.toString('base64'),
      authTag: aesResult.authTag.toString('base64'),
      signature: signature.toString('base64'),
      algorithm: 'AES-256-GCM',
      keyAlgorithm: 'RSA-OAEP',
      signatureAlgorithm: 'RSA-PSS',
    };
  }

  private createPayload(
    encryptedData: Buffer,
    encryptedKey: Buffer,
    iv: Buffer,
    authTag: Buffer,
    metadata?: Record<string, any>,
  ): any {
    return {
      encryptedData: encryptedData.toString('base64'),
      encryptedKey: encryptedKey.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      metadata: metadata || {},
      timestamp: new Date().toISOString(),
    };
  }
}
```

## 8. Envelope Decryptor Service

### 8.1 Envelope Decryption

```typescript
// packages/crypto-lib/src/envelope/envelope-decryptor.service.ts
import { Injectable } from '@nestjs/common';
import { AESDecryptionService } from '../aes/aes-decryption.service';
import { RSADecryptionService } from '../rsa/rsa-decryption.service';
import { SignatureVerificationService } from '../signatures/signature-verification.service';

export interface EnvelopeData {
  encryptedData: string; // Base64
  encryptedKey: string; // Base64
  iv: string; // Base64
  authTag: string; // Base64
  signature: string; // Base64
  algorithm: string;
  keyAlgorithm: string;
  signatureAlgorithm: string;
}

export interface DecryptOptions {
  envelope: EnvelopeData;
  receiverPrivateKeyPath: string;
  senderPublicKeyPath: string;
}

@Injectable()
export class EnvelopeDecryptorService {
  constructor(
    private aesDecryption: AESDecryptionService,
    private rsaDecryption: RSADecryptionService,
    private signatureVerification: SignatureVerificationService,
  ) {}

  /**
   * Decrypts an envelope
   * @param options Decryption options
   * @returns Decrypted plaintext
   */
  async decryptEnvelope(options: DecryptOptions): Promise<string> {
    const { envelope, receiverPrivateKeyPath, senderPublicKeyPath } = options;

    // Step 1: Verify signature
    const payload = this.createPayloadForVerification(envelope);
    const payloadBuffer = Buffer.from(JSON.stringify(payload));
    const signatureBuffer = Buffer.from(envelope.signature, 'base64');

    const signatureValid = await this.signatureVerification.verify(
      payloadBuffer,
      signatureBuffer,
      senderPublicKeyPath,
    );

    if (!signatureValid) {
      throw new Error('Invalid signature: envelope may have been tampered with');
    }

    // Step 2: Decrypt AES key with RSA
    const encryptedKeyBuffer = Buffer.from(envelope.encryptedKey, 'base64');
    const aesKey = await this.rsaDecryption.decrypt(
      encryptedKeyBuffer,
      receiverPrivateKeyPath,
    );

    // Step 3: Decrypt data with AES-256-GCM
    const encryptedDataBuffer = Buffer.from(envelope.encryptedData, 'base64');
    const ivBuffer = Buffer.from(envelope.iv, 'base64');
    const authTagBuffer = Buffer.from(envelope.authTag, 'base64');

    const decryptionResult = this.aesDecryption.decrypt(
      encryptedDataBuffer,
      aesKey,
      ivBuffer,
      authTagBuffer,
    );

    // Step 4: Return plaintext
    return decryptionResult.decryptedData.toString('utf8');
  }

  private createPayloadForVerification(envelope: EnvelopeData): any {
    return {
      encryptedData: envelope.encryptedData,
      encryptedKey: envelope.encryptedKey,
      iv: envelope.iv,
      authTag: envelope.authTag,
    };
  }
}
```

## 9. Error Handling

### 9.1 Custom Crypto Errors

```typescript
// packages/crypto-lib/src/errors/crypto-error.ts
export class CryptoError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly originalError?: Error,
  ) {
    super(message);
    this.name = 'CryptoError';
    Error.captureStackTrace(this, this.constructor);
  }
}

export class EncryptionError extends CryptoError {
  constructor(message: string, originalError?: Error) {
    super(message, 'ENCRYPTION_ERROR', originalError);
    this.name = 'EncryptionError';
  }
}

export class DecryptionError extends CryptoError {
  constructor(message: string, originalError?: Error) {
    super(message, 'DECRYPTION_ERROR', originalError);
    this.name = 'DecryptionError';
  }
}

export class SignatureError extends CryptoError {
  constructor(message: string, originalError?: Error) {
    super(message, 'SIGNATURE_ERROR', originalError);
    this.name = 'SignatureError';
  }
}
```

## 10. Security Considerations

### 10.1 Key Security
- Keys never logged or transmitted in plaintext
- Keys stored securely (file system with restricted permissions or key vault)
- Key rotation procedures in place
- Keys validated before use

### 10.2 Random Number Generation
- Use `crypto.randomBytes()` for all random data
- Never use predictable values for IVs or keys
- Ensure sufficient entropy

### 10.3 Algorithm Security
- AES-256-GCM: Industry standard, authenticated encryption
- RSA-2048: Minimum key size, OAEP padding for security
- RSA-PSS: Probabilistic signature scheme, more secure than PKCS1-v1_5
- SHA-256: Secure hash algorithm

### 10.4 Implementation Security
- Constant-time operations where possible
- No timing attacks
- Proper error handling (don't leak information)
- Input validation

## 11. Testing Cryptography

### 11.1 Unit Tests

```typescript
// packages/crypto-lib/src/aes/aes-encryption.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { AESEncryptionService } from './aes-encryption.service';
import { AESDecryptionService } from './aes-decryption.service';

describe('AES Encryption', () => {
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
});
```

