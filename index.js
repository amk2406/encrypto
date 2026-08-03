const crypto = require('crypto');

const encrypto = {
  /**
   * Get the required key length in bytes for a given algorithm
   * @param {string} algo - The encryption algorithm
   * @returns {number|undefined} Key length in bytes or undefined if unsupported
   */
  getKeyLength: (algo) => {
    const keyLengths = {
      'aes-128-cbc': 16,
      'aes-128-gcm': 16,
      'aes-192-cbc': 24,
      'aes-192-gcm': 24,
      'aes-256-cbc': 32,
      'aes-256-gcm': 32,
      'aes-256-ctr': 32,
      'aes-256-ccm': 32,
      'aes-256-ocb': 32
    };
    return keyLengths[algo];
  },

  /**
   * Hash a cipher key to achieve the required length
   * Uses SHA256 to generate a deterministic key from any input
   * @param {string} cipher - The cipher key to hash
   * @param {number} targetLength - Desired length in bytes
   * @returns {string} Hashed key as hex string with targetLength * 2 characters
   */
  hashCipher: (cipher, targetLength) => {
    // SHA256 produces 64 hex characters (32 bytes)
    const hash = crypto.createHash('sha256').update(cipher).digest('hex');
    // Trim to target length in characters (targetLength bytes * 2 chars per byte)
    const targetChars = targetLength * 2;
    if (hash.length >= targetChars) {
      return hash.slice(0, targetChars);
    } else {
      // Repeat hash if needed (fallback for unusually large target lengths)
      return hash.repeat(Math.ceil(targetChars / hash.length)).slice(0, targetChars);
    }
  },

  /**
   * Hash an IV to get exactly 32 hex characters (16 bytes)
   * @param {string} iv - The IV to hash
   * @returns {string} Hashed IV as 32-character hex string
   */
  hashIv: (iv) => {
    // SHA256 gives 64 chars, slice to first 32 chars (16 bytes)
    return crypto.createHash('sha256').update(iv).digest('hex').slice(0, 32);
  },

  /**
   * Validate that cipher and IV have correct lengths for the algorithm
   * @param {string} algo - The encryption algorithm
   * @param {string|Buffer} cipher - The cipher key
   * @param {string|Buffer} iv - The initialization vector
   * @returns {Object} Object containing cipherBuffer and ivBuffer
   * @throws {Error} If algorithm is unsupported or lengths are invalid
   */
  validate: (algo, cipher, iv) => {
    const requiredKeyLength = encrypto.getKeyLength(algo);
    if (!requiredKeyLength) {
      throw new Error(`Unsupported algorithm: ${algo}`);
    }

    // Validate and convert cipher
    let cipherBuffer;
    // Check if cipher is a hex string of the exact required length
    if (typeof cipher === 'string' && cipher.length === requiredKeyLength * 2) {
      cipherBuffer = Buffer.from(cipher, 'hex');
    } else if (Buffer.isBuffer(cipher)) {
      cipherBuffer = cipher;
    } else {
      cipherBuffer = Buffer.from(cipher);
    }

    if (cipherBuffer.length !== requiredKeyLength) {
      throw new Error(
        `Invalid cipher length. Expected ${requiredKeyLength} bytes ` +
        `(or ${requiredKeyLength * 2} hex chars) for ${algo}, got ${cipherBuffer.length} bytes`
      );
    }

    // Validate and convert IV (must be 16 bytes for all supported algorithms)
    let ivBuffer;
    if (typeof iv === 'string' && iv.length === 32) {
      ivBuffer = Buffer.from(iv, 'hex');
    } else if (Buffer.isBuffer(iv)) {
      ivBuffer = iv;
    } else {
      ivBuffer = Buffer.from(iv);
    }

    if (ivBuffer.length !== 16) {
      throw new Error(
        `Invalid IV length. Expected 16 bytes (or 32 hex chars), got ${ivBuffer.length} bytes`
      );
    }

    return { cipherBuffer, ivBuffer };
  },

  /**
   * Configure encryption/decryption functions
   * @param {Object} options - Configuration options
   * @param {string} [options.algo] - Algorithm (defaults to 'aes-256-cbc' if not provided)
   * @param {string|Buffer} [options.cipher] - Cipher key (required if algo provided)
   * @param {string|Buffer} [options.iv] - Initialization vector (required if algo provided)
   * @returns {Object} Object with encr() and decr() methods
   * 
   * Behavior:
   * - If algo is NOT provided: Uses 'aes-256-cbc', hashes cipher and IV to correct lengths
   * - If algo IS provided: Uses exact cipher and IV values (must be correct length)
   */
  Config: ({ algo, cipher, iv } = {}) => {
    let finalAlgo = algo;
    let finalCipher = cipher;
    let finalIv = iv;

    // If no algorithm specified, use defaults with automatic key derivation via hashing
    if (!algo) {
      finalAlgo = 'aes-256-cbc';                    // Default algorithm
      finalCipher = encrypto.hashCipher(cipher || 'defaultCipherKey', 32);  // Hash to 32 bytes (64 hex chars)
      finalIv = encrypto.hashIv(iv || 'defaultIvKey');                       // Hash to 16 bytes (32 hex chars)
    }

    // Validate the final configuration (ensures correct lengths)
    const { cipherBuffer, ivBuffer } = encrypto.validate(finalAlgo, finalCipher, finalIv);
    
    // Return encryption and decryption functions
    return {
      /**
       * Encrypt a text string
       * @param {string} text - The plain text to encrypt
       * @returns {string} Encrypted text as hex string
       */
      encr: (text) => {
        const cipherIv = crypto.createCipheriv(finalAlgo, cipherBuffer, ivBuffer);
        let encrypted = cipherIv.update(text, 'utf8', 'hex');
        encrypted += cipherIv.final('hex');
        return encrypted;
      },
      
      /**
       * Decrypt an encrypted hex string
       * @param {string} encryptedText - The encrypted hex string from encr()
       * @returns {string} Decrypted plain text
       */
      decr: (encryptedText) => {
        const decipher = crypto.createDecipheriv(finalAlgo, cipherBuffer, ivBuffer);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
      }
    };
  }
};

module.exports = encrypto;