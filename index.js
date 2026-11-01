/**
 * Encrypto – flexible, zero-dependency encryption for Node.js
 *
 * API style:
 *   encrypto.cbc(key, iv).encr(data)
 *   encrypto.gcm(key, { salt? }).encr(data)
 *   encrypto.gcm(key).encrFile(in, out)
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const { pipeline } = require('stream/promises');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const DEFAULT_PBKDF2_ITERATIONS = 100_000;
const DEFAULT_PBKDF2_DIGEST = 'sha512';

const KEY_LENGTHS = {
  'aes-128-cbc': 16,
  'aes-128-gcm': 16,
  'aes-192-cbc': 24,
  'aes-192-gcm': 24,
  'aes-256-cbc': 32,
  'aes-256-gcm': 32,
  'aes-256-ctr': 32,
  'aes-256-ccm': 32,
  'aes-256-ocb': 32,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function getKeyLength(algo) {
  return KEY_LENGTHS[algo];
}

function isAuthenticated(algo) {
  return /-(gcm|ccm|ocb)$/.test(algo);
}

function toBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (typeof data === 'string') return Buffer.from(data, 'utf8');
  throw new TypeError('Data must be string or Buffer');
}

function normalizeKey(key, keyLength, salt, iterations) {
  // Already correct length → use directly
  if (Buffer.isBuffer(key) && key.length === keyLength) {
    return key;
  }

  // Derive with PBKDF2 when salt is provided
  if (salt) {
    return crypto.pbkdf2Sync(
      key,
      salt,
      iterations || DEFAULT_PBKDF2_ITERATIONS,
      keyLength,
      DEFAULT_PBKDF2_DIGEST
    );
  }

  // Fallback: SHA-256 then truncate
  return crypto.createHash('sha256').update(String(key)).digest().subarray(0, keyLength);
}

function createRandomIV() {
  return crypto.randomBytes(IV_LENGTH);
}

// ---------------------------------------------------------------------------
// Core Cipher instance
// ---------------------------------------------------------------------------
function createCipherInstance(algo, keyBuf, options = {}) {
  const authenticated = isAuthenticated(algo);
  const fixedIv = options.iv || null; // only used by CBC / CTR style

  /**
   * Encrypt data → Buffer (iv + ciphertext [+ tag])
   */
  function encr(data) {
    const plaintext = toBuffer(data);
    const iv = fixedIv || createRandomIV();

    const cipher = crypto.createCipheriv(algo, keyBuf, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

    if (authenticated) {
      const tag = cipher.getAuthTag();
      return Buffer.concat([iv, ciphertext, tag]);
    }
    return Buffer.concat([iv, ciphertext]);
  }

  /**
   * Decrypt Buffer produced by encr()
   */
  function decr(encrypted) {
    const buf = Buffer.isBuffer(encrypted) ? encrypted : Buffer.from(encrypted);

    if (buf.length < IV_LENGTH + (authenticated ? AUTH_TAG_LENGTH : 0)) {
      throw new Error('Ciphertext too short');
    }

    const iv = buf.subarray(0, IV_LENGTH);
    let ciphertext, tag;

    if (authenticated) {
      tag = buf.subarray(buf.length - AUTH_TAG_LENGTH);
      ciphertext = buf.subarray(IV_LENGTH, buf.length - AUTH_TAG_LENGTH);
    } else {
      ciphertext = buf.subarray(IV_LENGTH);
    }

    const decipher = crypto.createDecipheriv(algo, keyBuf, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    if (authenticated) {
      decipher.setAuthTag(tag);
    }

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * Stream-encrypt a file and write to disk
   */
  async function encrFile(inputPath, outputPath) {
    const iv = fixedIv || createRandomIV();
    const cipher = crypto.createCipheriv(algo, keyBuf, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    const readStream = fs.createReadStream(inputPath);
    const writeStream = fs.createWriteStream(outputPath);

    // Write IV first
    writeStream.write(iv);

    await pipeline(readStream, cipher, writeStream);

    // Append auth tag for authenticated modes
    if (authenticated) {
      const tag = cipher.getAuthTag();
      await fs.promises.appendFile(outputPath, tag);
    }
  }

  /**
   * Stream-decrypt a file and write to disk
   */
  async function decrFile(inputPath, outputPath) {
    const fd = await fs.promises.open(inputPath, 'r');
    const stat = await fd.stat();
    const totalSize = stat.size;

    if (totalSize < IV_LENGTH + (authenticated ? AUTH_TAG_LENGTH : 0)) {
      await fd.close();
      throw new Error('File too small to be valid ciphertext');
    }

    // Read IV
    const ivBuf = Buffer.alloc(IV_LENGTH);
    await fd.read(ivBuf, 0, IV_LENGTH, 0);

    let tag = null;
    let dataStart = IV_LENGTH;
    let dataEnd = totalSize;

    if (authenticated) {
      tag = Buffer.alloc(AUTH_TAG_LENGTH);
      await fd.read(tag, 0, AUTH_TAG_LENGTH, totalSize - AUTH_TAG_LENGTH);
      dataEnd = totalSize - AUTH_TAG_LENGTH;
    }

    await fd.close();

    const decipher = crypto.createDecipheriv(algo, keyBuf, ivBuf, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    if (authenticated) {
      decipher.setAuthTag(tag);
    }

    const readStream = fs.createReadStream(inputPath, {
      start: dataStart,
      end: dataEnd - 1,
    });
    const writeStream = fs.createWriteStream(outputPath);

    await pipeline(readStream, decipher, writeStream);
  }

  return {
    encr,
    decr,
    encrFile,
    decrFile,
    algo,
    // aliases
    encrypt: encr,
    decrypt: decr,
  };
}

// ---------------------------------------------------------------------------
// Public factories
// ---------------------------------------------------------------------------

/**
 * AES-256-CBC
 * @param {string|Buffer} key
 * @param {string|Buffer} iv  – 16 bytes recommended
 */
function cbc(key, iv) {
  const algo = 'aes-256-cbc';
  const keyLength = getKeyLength(algo);

  const keyBuf = normalizeKey(key, keyLength);
  let ivBuf = Buffer.isBuffer(iv) ? iv : Buffer.from(String(iv));

  if (ivBuf.length !== IV_LENGTH) {
    ivBuf = crypto.createHash('sha256').update(ivBuf).digest().subarray(0, IV_LENGTH);
  }

  return createCipherInstance(algo, keyBuf, { iv: ivBuf });
}

/**
 * AES-256-GCM (recommended)
 * @param {string|Buffer} key
 * @param {object} [options]
 * @param {string|Buffer} [options.salt]     – provide your own salt
 * @param {boolean} [options.generateSalt]   – auto-generate salt (default: true if no salt given)
 * @param {number}  [options.iterations]     – PBKDF2 iterations
 */
function gcm(key, options = {}) {
  const algo = 'aes-256-gcm';
  const keyLength = getKeyLength(algo);

  let salt = options.salt || null;

  // Auto-generate salt unless user explicitly disabled it
  if (!salt && options.generateSalt !== false) {
    salt = crypto.randomBytes(16);
  }

  const keyBuf = normalizeKey(key, keyLength, salt, options.iterations);
  const instance = createCipherInstance(algo, keyBuf);
  instance.salt = salt; // so caller can store it if it was generated
  return instance;
}

/**
 * AES-256-CTR
 */
function ctr(key, iv) {
  const algo = 'aes-256-ctr';
  const keyLength = getKeyLength(algo);
  const keyBuf = normalizeKey(key, keyLength);

  let ivBuf = Buffer.isBuffer(iv) ? iv : Buffer.from(String(iv));
  if (ivBuf.length !== IV_LENGTH) {
    ivBuf = crypto.createHash('sha256').update(ivBuf).digest().subarray(0, IV_LENGTH);
  }

  return createCipherInstance(algo, keyBuf, { iv: ivBuf });
}

/**
 * AES-256-CCM
 */
function ccm(key, options = {}) {
  const algo = 'aes-256-ccm';
  const keyLength = getKeyLength(algo);

  let salt = options.salt || null;
  if (!salt && options.generateSalt !== false) {
    salt = crypto.randomBytes(16);
  }

  const keyBuf = normalizeKey(key, keyLength, salt, options.iterations);
  const instance = createCipherInstance(algo, keyBuf);
  instance.salt = salt;
  return instance;
}

/**
 * AES-256-OCB
 */
function ocb(key, options = {}) {
  const algo = 'aes-256-ocb';
  const keyLength = getKeyLength(algo);

  let salt = options.salt || null;
  if (!salt && options.generateSalt !== false) {
    salt = crypto.randomBytes(16);
  }

  const keyBuf = normalizeKey(key, keyLength, salt, options.iterations);
  const instance = createCipherInstance(algo, keyBuf);
  instance.salt = salt;
  return instance;
}

// ---------------------------------------------------------------------------
// Extra helpers
// ---------------------------------------------------------------------------
function generateKey(bytes = 32) {
  return crypto.randomBytes(bytes);
}

function generateSalt(bytes = 16) {
  return crypto.randomBytes(bytes);
}

function generateIV() {
  return crypto.randomBytes(IV_LENGTH);
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------
module.exports = {
  // Algorithm factories
  cbc,
  gcm,
  ctr,
  ccm,
  ocb,

  // Helpers
  generateKey,
  generateSalt,
  generateIV,
  getKeyLength,
  isAuthenticated,
};
