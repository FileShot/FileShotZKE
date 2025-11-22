# FileShot Zero-Knowledge Encryption (ZKE)

Client-side, open-source zero-knowledge encryption used by FileShot.io.

This repository contains the browser-based encryption system that powers FileShot’s zero-knowledge upload pipeline. All encryption occurs locally in the user’s browser via the Web Crypto API. FileShot servers never receive passwords, keys, or unencrypted data.

This ensures files stored and shared through FileShot remain unreadable by FileShot, third parties, attackers, or governments.

---

## What Zero-Knowledge Encryption Means

Zero-knowledge encryption ensures:

* Files are encrypted before they leave the browser.
* Decryption keys never leave the user’s device.
* FileShot servers store only encrypted blobs.
* No one, including FileShot, can decrypt user files.

All cryptographic operations are performed client-side using the Web Crypto API.

---

## Full FileShot Feature Set

### Core Privacy Features

* Client-side zero-knowledge encryption.
* No accounts or identity required.
* No analytics, tracking, or fingerprinting.
* Keys and passwords never transmitted.
* Open-source encryption implementation.
* Servers store encrypted data only.

### Upload & Sharing Features

* Uploads up to 15GB per file.
* Secure, shareable links.
* Expiration settings from 1 hour to 30 days.
* Optional password protection.
* Anonymous download information.
* NVMe-backed high-speed infrastructure.

### Monetization Features

* Optional paid-access downloads.
* Up to 50% commission per download.
* Payments integrated without compromising encryption.

### Built-In File Tools

#### PDF Tools

* Edit PDFs.
* Merge PDFs.
* Split PDFs.
* Compress PDFs.
* Convert PDFs to and from images.

#### Conversion Tools

* Video to MP4.
* Audio to MP3.
* Image format conversion (PNG, JPG, WebP, AVIF).
* Document conversion (PDF ↔ DOCX, TXT → PDF, etc.).
* Archive conversion (ZIP, TAR, 7Z when supported).

#### Archive Tools

* Create ZIP, TAR, and 7Z archives.
* Extract ZIP, RAR, TAR, GZ, and 7Z.

#### Compression Tools

* Image compression.
* Video compression.
* General file compression.

#### Utility Tools

* File metadata inspection.
* SHA-256 hash generation.
* Secure local file deletion.

### Platform-Level Features

* Zero-knowledge encryption pipeline.
* Secure link signing.
* Client-side metadata handling.
* Private, self-hosted infrastructure.
* Modern high-performance UI.
* Web Crypto API for all cryptographic operations.

---

## Quick Start

### Try the Demo

1. Open `demo.html`.
2. Select a file and encrypt it.
3. Download the encrypted output.
4. Decrypt using the same password.

---

## Using in Your Own Project

```html
<script src="zero-knowledge.js"></script>
<script>
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];
  const password = 'your-secure-password';

  const result = await window.zeroKnowledgeEncrypt(file, password);

  const decrypted = await window.zeroKnowledgeDecrypt(
    encryptedBlob,
    password,
    originalFileName,
    originalFileType
  );
</script>
```

---

## How It Works

1. **Key Derivation** – A random salt is generated; a key is derived using PBKDF2 (100,000 iterations, SHA-256).
2. **Encryption** – AES-256-GCM encrypts the file with a 12-byte IV.
3. **Upload** – Only the encrypted blob is transmitted.
4. **Storage** – Servers store encrypted blobs and encrypted metadata only.
5. **Download & Decryption** – Recipients decrypt files entirely in-browser using the shared password.

---

## Security Details

* AES-256-GCM.
* PBKDF2 (SHA-256, 100,000 iterations).
* 16-byte salt.
* 12-byte IV for GCM.
* 256-bit keys.

---

## File Structure

```
fileshot-zke/
├── zero-knowledge.js
├── demo.html
├── README.md
└── LICENSE
```

---

## Testing

* Encrypt and decrypt files.
* Validate metadata.
* Verify incorrect passwords fail.

---

## API Reference

### zeroKnowledgeEncrypt(file, password)

Encrypts a file client-side.

Returns:

```js
{
  encryptedBlob: Blob,
  metadata: {
    originalName: string,
    originalSize: number,
    originalType: string,
    encryptedSize: number
  }
}
```

### zeroKnowledgeDecrypt(encryptedBlob, password, originalName, originalType)

Decrypts encrypted data client-side.

Returns:
A Blob containing the decrypted file.

---

## Important Security Notes

* Use strong, unique passwords.
* Share passwords securely.
* Lost passwords cannot be recovered.
* Keep browsers and systems up to date.
* Use HTTPS in production.

---

## Verification

Users can verify:

* Client code matches this repository.
* Encryption runs entirely in the browser.
* No keys or plaintext leave the client.

Verification page: [https://fileshot.io/verify-encryption.html](https://fileshot.io/verify-encryption.html)

---

## Browser Support

* Chrome 37+
* Firefox 34+
* Safari 11+
* Edge 12+
* Opera 24+

---

## Security Policy

Report vulnerabilities privately to:

[fileshot.adm@gmail.com](mailto:fileshot.adm@gmail.com)

---

## License

MIT License.
