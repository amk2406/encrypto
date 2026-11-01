# Encrypto – Complete Guide (A to Z)

A simple but powerful **encryption utility** for Node.js, written with zero dependencies.

It uses only the built-in Node.js `crypto` module.  
No external packages. Clean, flexible API.

This README explains **everything** – from the very basics to every supported algorithm – with clear examples and simple English.

---

## Table of Contents

1. [What is Encrypto?](#1-what-is-encrypto)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [Supported Algorithms](#4-supported-algorithms)
5. [How each algorithm works](#5-how-each-algorithm-works)
6. [Algorithm Requirements (Key, IV, Tag)](#6-algorithm-requirements-key-iv-tag)
7. [Creating a Cipher](#7-creating-a-cipher)
8. [Basic Operations – encr & decr](#8-basic-operations--encr--decr)
9. [File Encryption – encrFile & decrFile](#9-file-encryption--encrfile--decrfile)
10. [Salt & Key Derivation (GCM / CCM / OCB)](#10-salt--key-derivation-gcm--ccm--ocb)
11. [Helper Functions](#11-helper-functions)
12. [Output Format](#12-output-format)
13. [Complete Real-World Examples](#13-complete-real-world-examples)
14. [Security Best Practices](#14-security-best-practices)
15. [Quick Reference (Cheat Sheet)](#15-quick-reference-cheat-sheet)

---

## 1. What is Encrypto?

Encrypto lets you easily encrypt and decrypt text or files in Node.js.

You choose the algorithm you want (CBC, GCM, CTR, etc.), give it a key (and sometimes an IV or salt), and then call simple methods like `.encr()` or `.encrFile()`.

**Key features:**

- Zero dependencies (only Node.js built-in `crypto`)
- Multiple algorithms: CBC, GCM, CTR, CCM, OCB
- Simple chainable API: `encrypto.gcm(key).encr(data)`
- Streaming file encryption (good for large files)
- Returns `Buffer` so you control the encoding (hex, base64, etc.)
- Optional automatic salt generation for password-based encryption

**What it is NOT:**

- It is **not** a full cryptography suite (no RSA, no elliptic curves, no hashing helpers beyond what is needed for keys).
- It is **not** a replacement for proper key management (you are still responsible for keeping your keys secret).

---

## 2. Installation

```bash
npm install encrypto
```

Or just copy the `index.js` file into your project.

```js
const encrypto = require('encrypto');
// or
const encrypto = require('./index.js');
```

---

## 3. Quick Start

### Classic CBC style

```js
const encrypto = require('encrypto');

const cipher = encrypto.cbc('my-secret-key', 'my-iv');

const encrypted = cipher.encr('Hello World');
console.log(encrypted.toString('hex'));

const decrypted = cipher.decr(encrypted);
console.log(decrypted.toString()); // Hello World
```

### Modern GCM style (recommended)

```js
const cipher = encrypto.gcm('my-password');

// cipher.salt contains the auto-generated salt
const encrypted = cipher.encr('Sensitive data');
const decrypted = cipher.decr(encrypted);

console.log(decrypted.toString()); // Sensitive data
```

### Encrypt a file

```js
const cipher = encrypto.gcm('file-secret');

await cipher.encrFile('./document.pdf', './document.pdf.enc');
await cipher.decrFile('./document.pdf.enc', './document-restored.pdf');
```

---

## 4. Supported Algorithms

| Short name | Full algorithm     | Authenticated? | Recommended for new projects? |
|------------|--------------------|----------------|-------------------------------|
| `cbc`      | AES-256-CBC        | No             | Only for compatibility        |
| `gcm`      | AES-256-GCM        | **Yes**        | **Yes (best choice)**         |
| `ctr`      | AES-256-CTR        | No             | Sometimes (streaming)         |
| `ccm`      | AES-256-CCM        | **Yes**        | Yes                           |
| `ocb`      | AES-256-OCB        | **Yes**        | Yes                           |

- **Authenticated** means the ciphertext cannot be tampered with without detection.  
  GCM, CCM and OCB will throw an error if someone changes even one bit of the encrypted data.
- CBC and CTR do **not** detect tampering. Prefer GCM for almost all new code.

---

## 5. How each algorithm works

### AES-256-CBC (`encrypto.cbc`)

- One of the oldest and most widely supported modes.
- Requires a key **and** an Initialization Vector (IV).
- The same IV + key always produces the same ciphertext for the same plaintext (deterministic).
- **Does not** protect against tampering.
- Still useful when you need compatibility with older systems or other languages that only support CBC.

### AES-256-GCM (`encrypto.gcm`) – Recommended

- Modern mode that provides both **confidentiality** and **authenticity**.
- Generates a random IV automatically on every encryption.
- Produces an authentication tag. If the data is modified, decryption fails.
- Best default choice for almost every use case.

### AES-256-CTR (`encrypto.ctr`)

- Turns AES into a stream cipher.
- Good when you need to encrypt data of arbitrary length without padding.
- Does **not** provide authentication (same weakness as CBC).
- Useful for certain streaming or low-level protocols.

### AES-256-CCM (`encrypto.ccm`)

- Authenticated mode (like GCM).
- Slightly different internal design from GCM.
- Good alternative when GCM is not available or when you specifically need CCM.

### AES-256-OCB (`encrypto.ocb`)

- Another authenticated mode.
- Designed to be fast and patent-unencumbered in many jurisdictions.
- Good modern alternative to GCM.

---

## 6. Algorithm Requirements (Key, IV, Tag)

| Algorithm     | Key length | IV length | Auth Tag | Notes |
|---------------|------------|-----------|----------|-------|
| aes-256-cbc   | 32 bytes   | 16 bytes  | No       | You must supply IV |
| aes-256-gcm   | 32 bytes   | 16 bytes  | 16 bytes | IV generated automatically |
| aes-256-ctr   | 32 bytes   | 16 bytes  | No       | You must supply IV |
| aes-256-ccm   | 32 bytes   | 16 bytes  | 16 bytes | IV generated automatically |
| aes-256-ocb   | 32 bytes   | 16 bytes  | 16 bytes | IV generated automatically |

**Important notes about keys:**

- If you pass a string as the key, Encrypto will derive a proper-length key from it.
- For GCM / CCM / OCB you can (and should) also pass a **salt**.  
  When a salt is present, PBKDF2 is used (100 000 iterations by default).
- If the IV you give to CBC or CTR is not exactly 16 bytes, it will be hashed down to 16 bytes.

---

## 7. Creating a Cipher

### CBC and CTR (you supply key + IV)

```js
const cipher = encrypto.cbc('my-key', 'my-iv');
const cipher2 = encrypto.ctr('my-key', 'my-iv');
```

### GCM / CCM / OCB (recommended)

```js
// Auto-generate a random salt
const cipher = encrypto.gcm('my-password');
console.log(cipher.salt); // ← store this if you need it later

// Provide your own salt
const salt = encrypto.generateSalt();
const cipher2 = encrypto.gcm('my-password', { salt });

// Disable automatic salt generation
const cipher3 = encrypto.gcm(rawKeyBuffer, { generateSalt: false });
```

**Options for GCM / CCM / OCB:**

| Option         | Type             | Default     | Meaning |
|----------------|------------------|-------------|---------|
| `salt`         | string \| Buffer | –           | Your own salt |
| `generateSalt` | boolean          | `true`      | Generate random salt when none is given |
| `iterations`   | number           | `100000`    | PBKDF2 iterations |

---

## 8. Basic Operations – encr & decr

```js
const cipher = encrypto.gcm('secret');

// Encrypt
const encrypted = cipher.encr('Hello World');
// encrypted is a Buffer

// You decide the encoding
encrypted.toString('hex');
encrypted.toString('base64');
encrypted.toString('base64url');

// Decrypt
const decrypted = cipher.decr(encrypted);
console.log(decrypted.toString()); // Hello World
```

`encr()` accepts both `string` and `Buffer`.  
`decr()` accepts a `Buffer` (or a string that can be turned into a Buffer).

---

## 9. File Encryption – encrFile & decrFile

These methods stream the file, so they work well even with large files.

```js
const cipher = encrypto.gcm('file-password');

// Encrypt
await cipher.encrFile('./photo.jpg', './photo.jpg.enc');

// Decrypt
await cipher.decrFile('./photo.jpg.enc', './photo-restored.jpg');
```

Both methods return a `Promise`.  
They write the IV (and authentication tag when applicable) into the output file automatically.

---

## 10. Salt & Key Derivation (GCM / CCM / OCB)

When you use a **password** (instead of a raw 32-byte key), a salt is very important.

**Without a salt** the same password always produces the same key → weaker security.  
**With a salt** each encryption can have a unique derived key.

```js
// Best practice
const salt = encrypto.generateSalt();          // or load from config
const cipher = encrypto.gcm(process.env.SECRET, { salt });

// Later, when you need to decrypt, use the same salt
const cipher2 = encrypto.gcm(process.env.SECRET, { salt });
```

If you let Encrypto generate the salt, remember to **save** `cipher.salt` somewhere (it is not secret, but you need it for decryption).

---

## 11. Helper Functions

```js
encrypto.generateKey(32)     // random 32-byte key (Buffer)
encrypto.generateSalt(16)    // random 16-byte salt (Buffer)
encrypto.generateIV()        // random 16-byte IV (Buffer)

encrypto.getKeyLength('aes-256-gcm')  // → 32
encrypto.isAuthenticated('aes-256-gcm') // → true
encrypto.isAuthenticated('aes-256-cbc') // → false
```

---

## 12. Output Format

Every call to `encr()` returns a single `Buffer` with this layout:

```
┌────────────────┬────────────────────────────┬──────────────────┐
│   16-byte IV   │        Ciphertext          │  16-byte Tag     │
└────────────────┴────────────────────────────┴──────────────────┘
                 (Tag only exists in GCM / CCM / OCB)
```

This makes storage and transmission simple – you just save one Buffer (or its hex/base64 representation).

---

## 13. Complete Real-World Examples

### Example A – Encrypt user data before saving to database

```js
const encrypto = require('encrypto');

const salt = Buffer.from(process.env.ENCRYPTION_SALT, 'hex');
const cipher = encrypto.gcm(process.env.ENCRYPTION_KEY, { salt });

function encryptUser(user) {
  const json = JSON.stringify(user);
  return cipher.encr(json).toString('base64');
}

function decryptUser(encryptedBase64) {
  const buf = Buffer.from(encryptedBase64, 'base64');
  const json = cipher.decr(buf).toString();
  return JSON.parse(json);
}
```

### Example B – Encrypt uploaded files

```js
const cipher = encrypto.gcm(process.env.FILE_SECRET);

app.post('/upload', async (req, res) => {
  const tempPath = req.file.path;
  const encryptedPath = tempPath + '.enc';

  await cipher.encrFile(tempPath, encryptedPath);
  // save encryptedPath to storage, delete tempPath
});
```

### Example C – Simple password-based note encryption

```js
const salt = encrypto.generateSalt();
const cipher = encrypto.gcm(userPassword, { salt });

// Store both the salt and the ciphertext
const payload = {
  salt: salt.toString('hex'),
  data: cipher.encr(noteText).toString('base64')
};
```

---

## 14. Security Best Practices

**Do**

- Prefer `gcm` (or `ccm` / `ocb`) over `cbc` and `ctr`.
- Use a strong unique secret or a randomly generated key (`generateKey()`).
- Always use a salt when the key is a password.
- Store the salt together with the ciphertext (or in your config).
- Keep your secret keys in environment variables or a secrets manager.

**Don’t**

- Hard-code secrets in your source code.
- Re-use the same key across completely different applications.
- Use CBC unless you have a specific compatibility requirement.
- Log or print decrypted sensitive data in production.

---

## 15. Quick Reference (Cheat Sheet)

```js
const encrypto = require('encrypto');

// Create ciphers
const cbc  = encrypto.cbc(key, iv);
const gcm  = encrypto.gcm(key);                        // auto salt
const gcm2 = encrypto.gcm(key, { salt });              // your salt
const ctr  = encrypto.ctr(key, iv);
const ccm  = encrypto.ccm(key, { salt });
const ocb  = encrypto.ocb(key, { salt });

// Text
const encrypted = gcm.encr('hello');           // Buffer
const decrypted = gcm.decr(encrypted);         // Buffer

// Files
await gcm.encrFile('in.pdf', 'out.enc');
await gcm.decrFile('out.enc', 'restored.pdf');

// Helpers
encrypto.generateKey(32);
encrypto.generateSalt();
encrypto.generateIV();
```

---

## License

MIT
