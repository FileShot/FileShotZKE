// Zero-Knowledge Encryption Utilities using Web Crypto API
// Files are encrypted in the browser before upload

const ZK_ALGORITHM = 'AES-GCM';
const ZK_KEY_LENGTH = 256;
const IV_LENGTH = 12; // 96 bits for GCM
const SALT_LENGTH = 16;
const PBKDF2_ITERATIONS = 100000;

/**
 * Derive encryption key from password using PBKDF2
 */
async function deriveKeyFromPassword(password, salt) {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    passwordKey,
    { name: ZK_ALGORITHM, length: ZK_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt file in browser before upload
 * Returns encrypted Blob and metadata needed for decryption
 */
async function encryptFileZeroKnowledge(file, password) {
  try {
    // Generate random salt
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    
    // Derive encryption key from password
    const key = await deriveKeyFromPassword(password, salt);
    
    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    
    // Read file as ArrayBuffer
    const fileData = await file.arrayBuffer();
    
    // Encrypt file data
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: ZK_ALGORITHM,
        iv: iv
      },
      key,
      fileData
    );
    
    // Combine: salt (16 bytes) + iv (12 bytes) + encrypted data
    const combined = new Uint8Array(SALT_LENGTH + IV_LENGTH + encryptedData.byteLength);
    combined.set(salt, 0);
    combined.set(iv, SALT_LENGTH);
    combined.set(new Uint8Array(encryptedData), SALT_LENGTH + IV_LENGTH);
    
    // Create Blob from encrypted data
    const encryptedBlob = new Blob([combined], { type: 'application/octet-stream' });
    
    // Store metadata (not encrypted) for reference
    const metadata = {
      originalName: file.name,
      originalSize: file.size,
      originalType: file.type,
      encryptedSize: encryptedBlob.size
    };
    
    return {
      encryptedBlob,
      metadata
    };
  } catch (error) {
    console.error('Zero-knowledge encryption error:', error);
    throw new Error('Failed to encrypt file: ' + error.message);
  }
}

/**
 * Decrypt file in browser after download
 */
async function decryptFileZeroKnowledge(encryptedBlob, password, originalName, originalType) {
  try {
    // Read encrypted blob as ArrayBuffer
    const encryptedArrayBuffer = await encryptedBlob.arrayBuffer();
    const encryptedBytes = new Uint8Array(encryptedArrayBuffer);
    
    // Extract salt, IV, and encrypted data
    const salt = encryptedBytes.slice(0, SALT_LENGTH);
    const iv = encryptedBytes.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const encryptedData = encryptedBytes.slice(SALT_LENGTH + IV_LENGTH);
    
    // Derive key from password
    const key = await deriveKeyFromPassword(password, salt);
    
    // Decrypt data
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: ZK_ALGORITHM,
        iv: iv
      },
      key,
      encryptedData
    );
    
    // Create Blob from decrypted data with original MIME type
    const decryptedBlob = new Blob([decryptedData], { type: originalType || 'application/octet-stream' });
    
    return decryptedBlob;
  } catch (error) {
    console.error('Zero-knowledge decryption error:', error);
    if (error.name === 'OperationError' || error.message.includes('decrypt')) {
      throw new Error('Decryption failed. Please check that you entered the correct password. The password must match exactly what was used during encryption.');
    }
    throw new Error('Failed to decrypt file. Incorrect password or corrupted file.');
  }
}

/**
 * Prompt user for encryption password
 */
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

/**
 * Prompt user for decryption password
 */
function promptDecryptionPassword(fileName) {
  return prompt(`Enter password to decrypt "${fileName}":`);
}

// Export functions for use in other scripts
if (typeof window !== 'undefined') {
  window.zeroKnowledgeEncrypt = encryptFileZeroKnowledge;
  window.zeroKnowledgeDecrypt = decryptFileZeroKnowledge;
  window.promptEncryptionPassword = promptEncryptionPassword;
  window.promptDecryptionPassword = promptDecryptionPassword;
}

