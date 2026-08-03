# Encrypto

A simple, powerful encryption utility for Node.js using the built-in `crypto` module. No external dependencies, no classes - just pure functions.

## Features

- 🔒 **AES-256-CBC** encryption by default
- 🎯 **Automatic key derivation** - Input any string, get properly sized keys
- ✅ **Built-in validation** - Ensures keys match algorithm requirements
- 🔧 **Flexible configuration** - Use defaults or exact keys
- 📦 **Zero dependencies** - Uses only Node.js native crypto
- 🚀 **Simple API** - Just `encr()` and `decr()` functions

## Installation

```bash
npm install encrypto
```

Or just copy the module into your project.

Quick Start

```javascript
const encrypto = require('./encrypto');

// Simple usage - auto-generates proper keys
const { encr, decr } = encrypto.Config({
  cipher: 'mySecretPassword123',
  iv: 'myIvKey456'
});

const encrypted = encr('Hello World');
console.log(encrypted); // hex string

const decrypted = decr(encrypted);
console.log(decrypted); // 'Hello World'
```

API Documentation

encrypto.Config(options)

Creates encryption/decryption functions.

Parameters

Parameter Type Required Default Description
algo string No 'aes-256-cbc' Encryption algorithm
cipher string/Buffer Depends - Cipher key (required if algo provided)
iv string/Buffer Depends - Initialization vector (required if algo provided)

Returns

Returns an object with two methods:

· encr(text) - Encrypts a string and returns hex
· decr(encryptedText) - Decrypts hex and returns string

Behavior

· When algo is NOT provided: Automatically hashes cipher and iv to the correct lengths (32 bytes for key, 16 bytes for IV)
· When algo IS provided: Uses exact cipher and iv values (must be correct length for the algorithm)

encrypto.validate(algo, cipher, iv)

Validates that cipher and IV have correct lengths for the algorithm.

```javascript
encrypto.validate('aes-256-cbc', myCipher, myIv); // Throws if invalid
```

encrypto.getKeyLength(algo)

Returns required key length in bytes for an algorithm.

```javascript
const length = encrypto.getKeyLength('aes-256-cbc'); // returns 32
```

Usage Examples

Example 1: Default Mode (Auto Key Derivation)

Best for most use cases. Just provide any strings as cipher and IV.

```javascript
const encrypto = require('./encrypto');

const { encr, decr } = encrypto.Config({
  cipher: 'any string you want',
  iv: 'any other string'
});

const secret = encr('Sensitive data');
console.log(secret);

const original = decr(secret);
console.log(original); // 'Sensitive data'
```

Example 2: Exact Mode (Manual Key Management)

Use when you need deterministic keys or have specific requirements.

```javascript
const encrypto = require('./encrypto');

// For aes-256-cbc: 32-byte key (64 hex chars), 16-byte IV (32 hex chars)
const { encr, decr } = encrypto.Config({
  algo: 'aes-256-cbc',
  cipher: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  iv: '1234567890abcdef1234567890abcdef'
});

const encrypted = encr('Fixed encryption key');
const decrypted = decr(encrypted);
console.log(decrypted);
```

Example 3: Different Algorithms

```javascript
// AES-128 (16-byte key = 32 hex chars)
const { encr: encr128 } = encrypto.Config({
  algo: 'aes-128-cbc',
  cipher: '0123456789abcdef0123456789abcdef',
  iv: '1234567890abcdef1234567890abcdef'
});

// AES-192 (24-byte key = 48 hex chars)
const { encr: encr192 } = encrypto.Config({
  algo: 'aes-192-cbc',
  cipher: '0123456789abcdef0123456789abcdef0123456789abcdef',
  iv: '1234567890abcdef1234567890abcdef'
});
```

Example 4: Working with Buffers

```javascript
const crypto = require('crypto');
const encrypto = require('./encrypto');

// Generate random keys as buffers
const randomKey = crypto.randomBytes(32);
const randomIv = crypto.randomBytes(16);

const { encr, decr } = encrypto.Config({
  algo: 'aes-256-cbc',
  cipher: randomKey,
  iv: randomIv
});

const encrypted = encr('Message with buffer keys');
const decrypted = decr(encrypted);
console.log(decrypted);
```

Example 5: Validation

```javascript
const encrypto = require('./encrypto');

try {
  // This will throw - wrong key length for aes-256
  encrypto.validate('aes-256-cbc', 'tooShort', '1234567890abcdef1234567890abcdef');
} catch (error) {
  console.log('Validation failed:', error.message);
}

// This passes
encrypto.validate(
  'aes-256-cbc',
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  '1234567890abcdef1234567890abcdef'
);
```

Example 6: Environment Variables

```javascript
const encrypto = require('./encrypto');

// Use environment variables for keys
const { encr, decr } = encrypto.Config({
  cipher: process.env.ENCRYPTION_KEY,
  iv: process.env.ENCRYPTION_IV
});

// Encrypt user data
const userData = JSON.stringify({ id: 123, email: 'user@example.com' });
const encrypted = encr(userData);

// Store in database
await db.users.create({ encrypted_data: encrypted });
```

Example 7: Error Handling

```javascript
const encrypto = require('./encrypto');

const { encr, decr } = encrypto.Config({
  cipher: 'myKey',
  iv: 'myIv'
});

try {
  const encrypted = encr('Secret message');
  const decrypted = decr(encrypted);
  console.log('Success:', decrypted);
} catch (error) {
  console.error('Encryption failed:', error.message);
}
```

Supported Algorithms

Algorithm Key Length Key Format
aes-128-cbc 16 bytes 32 hex chars
aes-128-gcm 16 bytes 32 hex chars
aes-192-cbc 24 bytes 48 hex chars
aes-192-gcm 24 bytes 48 hex chars
aes-256-cbc 32 bytes 64 hex chars
aes-256-gcm 32 bytes 64 hex chars
aes-256-ctr 32 bytes 64 hex chars
aes-256-ccm 32 bytes 64 hex chars
aes-256-ocb 32 bytes 64 hex chars

All algorithms require 16-byte IV (32 hex chars).

Security Best Practices

✅ DO:

· Use environment variables for keys in production
· Rotate keys periodically
· Use different keys for different environments
· Store IVs alongside encrypted data
· Use default mode for simpler key management

❌ DON'T:

· Hardcode keys in source code
· Use the same key for encryption and hashing
· Share keys across different applications
· Log encrypted or decrypted data
· Use weak or predictable keys

How It Works

Default Mode (No algo specified)

1. Takes your cipher and iv strings
2. Hashes them with SHA256
3. Trims to proper lengths (64 chars for key, 32 chars for IV)
4. Creates AES-256-CBC cipher
5. Returns encr() and decr() functions

Exact Mode (algo specified)

1. Validates key lengths match algorithm
2. Converts hex strings to buffers
3. Creates cipher with exact keys
4. Returns encr() and decr() functions

License

MIT

Contributing

Issues and pull requests welcome!

Changelog

v1.0.0

· Initial release
· Support for multiple AES algorithms
· Automatic key derivation
· Built-in validation

```