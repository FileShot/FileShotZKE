// Zero-Knowledge Encryption Utilities
// KDF: Argon2id (hash-wasm via zke-hash-wasm.bundle.js) | PBKDF2-SHA256 legacy decrypt
// Format v2: [0x02][salt32][iv12][ciphertext]
// Format v1 (legacy): [salt16][iv12][ciphertext]

const ZK_ALGORITHM = 'AES-GCM';
const ZK_KEY_LENGTH = 256;
const IV_LENGTH = 12;
const SALT_LENGTH = 32;
const LEGACY_SALT_LENGTH = 16;
const FORMAT_VERSION = 0x02;

const ARGON2_MEMORY = 65536;
const ARGON2_ITERATIONS = 2;
const ARGON2_PARALLELISM = 1;

const _textEncoder = new TextEncoder();

const _concatU8 = (parts) => {
  const total = parts.reduce((s, p) => s + p.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.byteLength; }
  return out;
};

function argon2BundleReady() {
  const g = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : null;
  return g && g.ZkeKdfArgon2 && typeof g.ZkeKdfArgon2.deriveRaw === 'function';
}

async function _deriveKeyArgon2id(password, salt, kdf = {}) {
  if (!argon2BundleReady()) {
    throw new Error('Load zke-hash-wasm.bundle.js before zero-knowledge.js');
  }
  const g = globalThis.ZkeKdfArgon2 || window.ZkeKdfArgon2;
  const raw = await g.deriveRaw(String(password), salt, {
    memory: kdf.memory ?? ARGON2_MEMORY,
    iterations: kdf.iterations ?? ARGON2_ITERATIONS,
    parallelism: kdf.parallelism ?? ARGON2_PARALLELISM
  });
  return crypto.subtle.importKey('raw', raw, { name: ZK_ALGORITHM }, false, ['encrypt', 'decrypt']);
}

async function _deriveKeyPBKDF2(password, salt) {
  const passwordKey = await crypto.subtle.importKey('raw', _textEncoder.encode(String(password)), { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    passwordKey,
    { name: ZK_ALGORITHM, length: ZK_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptFileZeroKnowledge(file, password) {
  try {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const fileData = await file.arrayBuffer();
    let combined;

    if (argon2BundleReady()) {
      try {
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
        const key = await _deriveKeyArgon2id(password, salt);
        const encryptedData = await crypto.subtle.encrypt({ name: ZK_ALGORITHM, iv }, key, fileData);
        combined = _concatU8([new Uint8Array([FORMAT_VERSION]), salt, iv, new Uint8Array(encryptedData)]);
      } catch (err) {
        console.warn('[ZKE] Argon2id encrypt failed, using PBKDF2:', err);
      }
    }

    if (!combined) {
      const salt = crypto.getRandomValues(new Uint8Array(LEGACY_SALT_LENGTH));
      const key = await _deriveKeyPBKDF2(password, salt);
      const encryptedData = await crypto.subtle.encrypt({ name: ZK_ALGORITHM, iv }, key, fileData);
      combined = _concatU8([salt, iv, new Uint8Array(encryptedData)]);
    }

    const encryptedBlob = new Blob([combined], { type: 'application/octet-stream' });
    return {
      encryptedBlob,
      metadata: { originalName: file.name, originalSize: file.size, originalType: file.type, encryptedSize: encryptedBlob.size }
    };
  } catch (error) {
    console.error('Zero-knowledge encryption error:', error);
    throw new Error('Failed to encrypt file: ' + error.message);
  }
}

async function decryptFileZeroKnowledge(encryptedBlob, password, originalName, originalType) {
  try {
    const bytes = new Uint8Array(await encryptedBlob.arrayBuffer());
    let key, iv, encryptedData;

    if (bytes[0] === FORMAT_VERSION) {
      const salt = bytes.slice(1, 1 + SALT_LENGTH);
      iv = bytes.slice(1 + SALT_LENGTH, 1 + SALT_LENGTH + IV_LENGTH);
      encryptedData = bytes.slice(1 + SALT_LENGTH + IV_LENGTH);
      key = await _deriveKeyArgon2id(password, salt);
    } else {
      const salt = bytes.slice(0, LEGACY_SALT_LENGTH);
      iv = bytes.slice(LEGACY_SALT_LENGTH, LEGACY_SALT_LENGTH + IV_LENGTH);
      encryptedData = bytes.slice(LEGACY_SALT_LENGTH + IV_LENGTH);
      key = await _deriveKeyPBKDF2(password, salt);
    }

    const decryptedData = await crypto.subtle.decrypt({ name: ZK_ALGORITHM, iv }, key, encryptedData);
    return new Blob([decryptedData], { type: originalType || 'application/octet-stream' });
  } catch (error) {
    console.error('Zero-knowledge decryption error:', error);
    if (error.name === 'OperationError') {
      throw new Error('Decryption failed. Please check that you entered the correct password.');
    }
    throw new Error('Failed to decrypt file. Incorrect password or corrupted file.');
  }
}

function promptEncryptionPassword(fileName) {
  return new Promise((resolve, reject) => {
    const password = prompt(`Enter a password to encrypt "${fileName}"\n\n⚠️ IMPORTANT: We cannot recover your files if you lose this password.\n\nPassword:`);
    if (!password || password.length < 4) {
      reject(new Error('Password must be at least 4 characters long'));
      return;
    }
    const confirm = prompt('Confirm password:');
    if (password !== confirm) {
      reject(new Error('Passwords do not match'));
      return;
    }
    resolve(password);
  });
}

function promptDecryptionPassword(fileName) {
  return prompt(`Enter password to decrypt "${fileName}":`);
}

if (typeof window !== 'undefined') {
  window.zeroKnowledgeEncrypt = encryptFileZeroKnowledge;
  window.zeroKnowledgeDecrypt = decryptFileZeroKnowledge;
  window.promptEncryptionPassword = promptEncryptionPassword;
  window.promptDecryptionPassword = promptDecryptionPassword;
}
