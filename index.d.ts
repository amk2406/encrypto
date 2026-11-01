/// <reference types="node" />

/**
 * Supported AES algorithms.
 */
export type Algorithm =
  | 'aes-128-cbc'
  | 'aes-128-gcm'
  | 'aes-192-cbc'
  | 'aes-192-gcm'
  | 'aes-256-cbc'
  | 'aes-256-gcm'
  | 'aes-256-ctr'
  | 'aes-256-ccm'
  | 'aes-256-ocb';

/**
 * Options for authenticated modes (GCM, CCM, OCB).
 */
export interface GcmOptions {
  /**
   * Provide your own salt for key derivation.
   * If omitted and `generateSalt` is not `false`, a random 16-byte salt is generated.
   */
  salt?: string | Buffer;

  /**
   * Automatically generate a random salt when none is provided.
   * @default true
   */
  generateSalt?: boolean;

  /**
   * Number of PBKDF2 iterations used when deriving the key from a password.
   * Higher = slower but more resistant to brute-force.
   * @default 100000
   */
  iterations?: number;
}

/**
 * A configured cipher instance returned by `cbc()`, `gcm()`, `ctr()`, etc.
 *
 * All methods that produce ciphertext return a `Buffer`.
 * You can convert it with `.toString('hex')`, `.toString('base64')`, etc.
 */
export interface CipherInstance {
  /**
   * Encrypt data.
   *
   * @param data - String or Buffer to encrypt
   * @returns Buffer containing: IV + ciphertext [+ auth tag]
   *
   * @example
   * ```js
   * const encrypted = cipher.encr('hello');
   * console.log(encrypted.toString('hex'));
   * ```
   */
  encr(data: string | Buffer): Buffer;

  /**
   * Decrypt data previously produced by `encr()`.
   *
   * @param encrypted - Buffer (or base64/hex string) created by `encr()`
   * @returns Decrypted Buffer (call `.toString()` to get a string)
   *
   * @example
   * ```js
   * const decrypted = cipher.decr(encrypted);
   * console.log(decrypted.toString()); // original text
   * ```
   */
  decr(encrypted: Buffer | string): Buffer;

  /**
   * Stream-encrypt a file and write the result to disk.
   * Suitable for large files – data is not fully loaded into memory.
   *
   * @param inputPath  - Path of the file to encrypt
   * @param outputPath - Path where the encrypted file will be saved
   *
   * @example
   * ```js
   * await cipher.encrFile('./document.pdf', './document.pdf.enc');
   * ```
   */
  encrFile(inputPath: string, outputPath: string): Promise<void>;

  /**
   * Stream-decrypt a file previously encrypted with `encrFile()`.
   *
   * @param inputPath  - Path of the encrypted file
   * @param outputPath - Path where the decrypted file will be saved
   *
   * @example
   * ```js
   * await cipher.decrFile('./document.pdf.enc', './document-restored.pdf');
   * ```
   */
  decrFile(inputPath: string, outputPath: string): Promise<void>;

  /**
   * The algorithm used by this cipher instance (e.g. `'aes-256-gcm'`).
   */
  readonly algo: string;

  /**
   * The salt used for key derivation.
   * Only present on instances created by `gcm()`, `ccm()`, or `ocb()`.
   * Store this value if you generated it and need to decrypt later.
   */
  readonly salt?: Buffer;

  /** Alias of `encr` */
  encrypt: CipherInstance['encr'];

  /** Alias of `decr` */
  decrypt: CipherInstance['decr'];
}

/* -------------------------------------------------------------------------- */
/*                             Algorithm Factories                            */
/* -------------------------------------------------------------------------- */

/**
 * Create an AES-256-CBC cipher.
 *
 * CBC is a classic mode. Prefer `gcm()` for new projects because it provides authentication.
 *
 * @param key - Password or raw key material
 * @param iv  - Initialization vector (16 bytes recommended). If wrong length it will be hashed.
 *
 * @example
 * ```js
 * const cipher = encrypto.cbc('my-key', 'my-iv');
 * const encrypted = cipher.encr('hello');
 * ```
 */
export function cbc(key: string | Buffer, iv: string | Buffer): CipherInstance;

/**
 * Create an AES-256-GCM cipher (recommended).
 *
 * GCM provides both confidentiality and authenticity.
 * A random IV is generated automatically on every `encr()` / `encrFile()` call.
 *
 * @param key     - Password or raw key material
 * @param options - Optional salt and PBKDF2 settings
 *
 * @example
 * ```js
 * // Auto-generate salt
 * const cipher = encrypto.gcm('my-password');
 * console.log(cipher.salt); // store this if needed
 *
 * // Provide your own salt
 * const salt = encrypto.generateSalt();
 * const cipher2 = encrypto.gcm('my-password', { salt });
 * ```
 */
export function gcm(key: string | Buffer, options?: GcmOptions): CipherInstance;

/**
 * Create an AES-256-CTR cipher.
 *
 * @param key - Password or raw key material
 * @param iv  - Initialization vector (16 bytes recommended)
 */
export function ctr(key: string | Buffer, iv: string | Buffer): CipherInstance;

/**
 * Create an AES-256-CCM cipher (authenticated).
 *
 * @param key     - Password or raw key material
 * @param options - Optional salt and PBKDF2 settings
 */
export function ccm(key: string | Buffer, options?: GcmOptions): CipherInstance;

/**
 * Create an AES-256-OCB cipher (authenticated).
 *
 * @param key     - Password or raw key material
 * @param options - Optional salt and PBKDF2 settings
 */
export function ocb(key: string | Buffer, options?: GcmOptions): CipherInstance;

/* -------------------------------------------------------------------------- */
/*                                   Helpers                                  */
/* -------------------------------------------------------------------------- */

/**
 * Generate a cryptographically secure random key.
 *
 * @param bytes - Length in bytes (default: 32 → 256-bit key)
 * @returns Random Buffer suitable for use as a raw key
 *
 * @example
 * ```js
 * const key = encrypto.generateKey(32);
 * const cipher = encrypto.gcm(key, { generateSalt: false });
 * ```
 */
export function generateKey(bytes?: number): Buffer;

/**
 * Generate a cryptographically secure random salt.
 *
 * @param bytes - Length in bytes (default: 16)
 * @returns Random Buffer
 *
 * @example
 * ```js
 * const salt = encrypto.generateSalt();
 * const cipher = encrypto.gcm('password', { salt });
 * ```
 */
export function generateSalt(bytes?: number): Buffer;

/**
 * Generate a random 16-byte Initialization Vector.
 *
 * @returns Random 16-byte Buffer
 */
export function generateIV(): Buffer;

/**
 * Get the required key length (in bytes) for a given algorithm.
 *
 * @param algo - Algorithm name (e.g. `'aes-256-gcm'`)
 * @returns Key length in bytes, or `undefined` if the algorithm is unknown
 */
export function getKeyLength(algo: string): number | undefined;

/**
 * Check whether an algorithm provides authentication (GCM / CCM / OCB).
 *
 * @param algo - Algorithm name
 * @returns `true` if the mode is authenticated
 */
export function isAuthenticated(algo: string): boolean;
