'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const encrypto = require('./index');

async function run() {
  console.log('Running Encrypto tests...\n');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'encrypto-'));

  // 1. CBC classic style
  {
    const key = 'my-secret-key';
    const iv = 'my-fixed-iv-16b';

    const cipher = encrypto.cbc(key, iv);

    const plain = 'Hello CBC world';
    const encrypted = cipher.encr(plain);
    const decrypted = cipher.decr(encrypted);

    assert.ok(Buffer.isBuffer(encrypted));
    assert.strictEqual(decrypted.toString('utf8'), plain);
    console.log('✓ cbc().encr / decr');
  }

  // 2. GCM with auto-generated salt
  {
    const cipher = encrypto.gcm('password123');

    assert.ok(cipher.salt, 'salt should be generated');
    const plain = 'Secret GCM message';
    const encrypted = cipher.encr(plain);
    const decrypted = cipher.decr(encrypted);

    assert.strictEqual(decrypted.toString('utf8'), plain);
    console.log('✓ gcm() with auto salt');
  }

  // 3. GCM with user-provided salt
  {
    const salt = encrypto.generateSalt();
    const cipher = encrypto.gcm('password123', { salt });

    assert.deepStrictEqual(cipher.salt, salt);

    const encrypted = cipher.encr('same salt test');
    const decrypted = cipher.decr(encrypted);
    assert.strictEqual(decrypted.toString('utf8'), 'same salt test');
    console.log('✓ gcm() with user salt');
  }

  // 4. Random IV → different ciphertexts
  {
    const cipher = encrypto.gcm('key');
    const a = cipher.encr('same text');
    const b = cipher.encr('same text');
    assert.notDeepStrictEqual(a, b);
    console.log('✓ Random IV produces unique ciphertexts');
  }

  // 5. GCM detects tampering
  {
    const cipher = encrypto.gcm('key');
    const encrypted = cipher.encr('important');
    encrypted[20] ^= 0x01; // flip a bit

    let failed = false;
    try {
      cipher.decr(encrypted);
    } catch {
      failed = true;
    }
    assert.ok(failed, 'Should reject tampered data');
    console.log('✓ GCM rejects tampered ciphertext');
  }

  // 6. File streaming
  {
    const inputFile = path.join(tmpDir, 'plain.txt');
    const encryptedFile = path.join(tmpDir, 'plain.txt.enc');
    const decryptedFile = path.join(tmpDir, 'plain-restored.txt');

    fs.writeFileSync(inputFile, 'This is a file that will be encrypted with streaming.\n'.repeat(50));

    const cipher = encrypto.gcm('file-secret');

    await cipher.encrFile(inputFile, encryptedFile);
    await cipher.decrFile(encryptedFile, decryptedFile);

    const original = fs.readFileSync(inputFile);
    const restored = fs.readFileSync(decryptedFile);
    assert.deepStrictEqual(restored, original);
    console.log('✓ encrFile / decrFile streaming');
  }

  // 7. Helpers
  {
    const key = encrypto.generateKey(32);
    const salt = encrypto.generateSalt();
    const iv = encrypto.generateIV();

    assert.strictEqual(key.length, 32);
    assert.strictEqual(salt.length, 16);
    assert.strictEqual(iv.length, 16);
    console.log('✓ generateKey / generateSalt / generateIV');
  }

  // 8. CTR mode
  {
    const cipher = encrypto.ctr('ctr-key', 'ctr-iv');
    const encrypted = cipher.encr('ctr test');
    const decrypted = cipher.decr(encrypted);
    assert.strictEqual(decrypted.toString(), 'ctr test');
    console.log('✓ ctr() mode');
  }

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });

  console.log('\nAll tests passed ✅');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
