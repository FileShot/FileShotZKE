# FileShotZKE
ZKE method

# FileShot Zero-Knowledge Encryption

**Open-source zero-knowledge encryption implementation using Web Crypto API**

This repository contains the client-side encryption code that powers FileShot.io's zero-knowledge encryption feature. Files are encrypted entirely in your browser before upload, ensuring that even FileShot's servers cannot decrypt your files.

What is Zero-Knowledge Encryption?

Zero-knowledge encryption means that **we cannot decrypt your files**, even if we wanted to. The encryption happens entirely in your browser using the Web Crypto API, and we never receive your encryption key or password.

### Key Features

- ✅ **AES-256-GCM encryption** - Industry-standard encryption algorithm
- ✅ **PBKDF2 key derivation** - 100,000 iterations for password-based key derivation
- ✅ **Client-side only** - All encryption happens in your browser
- ✅ **No server access** - We cannot decrypt your files, even with a court order
- ✅ **Open source** - Review the code yourself

## Quick Start

### Try the Demo

1. Open `demo.html` in your browser
2. Select a file and encrypt it
3. Download the encrypted file
4. Decrypt it with the same password

### Use in Your Project

```html
<script src="zero-knowledge.js"></script>
<script>
  // Encrypt a file
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];
  const password = 'your-secure-password';
  
  const result = await window.zeroKnowledgeEncrypt(file, password);
  // result.encryptedBlob - encrypted file ready to upload
  // result.metadata - file metadata (name, size, type)
  
  // Decrypt a file
  const decryptedBlob = await window.zeroKnowledgeDecrypt(
    encryptedBlob,
    password,
    originalFileName,
    originalFileType
  );
</script>
```

##  How It Works

1. **Key Generation**: Your browser generates a random salt and derives an encryption key from your password using PBKDF2
2. **Encryption**: Your file is encrypted using AES-256-GCM before upload
3. **Upload**: Only the encrypted data is sent to FileShot's servers
4. **Storage**: We store encrypted blobs that we cannot decrypt
5. **Download**: Recipients decrypt files in their browser using the password you shared

##  Security Details

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2 with SHA-256
- **Iterations**: 100,000 (recommended for 2025)
- **Salt Length**: 16 bytes (128 bits)
- **IV Length**: 12 bytes (96 bits) for GCM
- **Key Length**: 256 bits

##  File Structure

```
fileshot-zke/
├── zero-knowledge.js    # Main encryption implementation
├── demo.html            # Interactive demo page
├── README.md           # This file
└── LICENSE             # MIT License
```

##  Testing

Open `demo.html` in a modern browser to test the encryption implementation. The demo allows you to:

- Encrypt files with a password
- Download encrypted files
- Decrypt files with the correct password
- Verify that incorrect passwords fail

##  API Reference

### `zeroKnowledgeEncrypt(file, password)`

Encrypts a file in the browser.

**Parameters:**
- `file` (File/Blob): The file to encrypt
- `password` (string): Encryption password

**Returns:** Promise resolving to:
```javascript
{
  encryptedBlob: Blob,      // Encrypted file data
  metadata: {                // File metadata (not encrypted)
    originalName: string,
    originalSize: number,
    originalType: string,
    encryptedSize: number
  }
}
```

### `zeroKnowledgeDecrypt(encryptedBlob, password, originalName, originalType)`

Decrypts a file in the browser.

**Parameters:**
- `encryptedBlob` (Blob): Encrypted file data
- `password` (string): Decryption password
- `originalName` (string): Original filename
- `originalType` (string): Original MIME type

**Returns:** Promise resolving to a Blob containing the decrypted file.

##  Important Security Notes

1. **Password Strength**: Use a strong, unique password for each file
2. **Password Sharing**: Share passwords through a secure channel (not via FileShot)
3. **Password Loss**: If you lose your password, the file cannot be recovered
4. **Browser Security**: Ensure your browser and system are secure and up-to-date
5. **HTTPS Only**: Only use this on HTTPS connections in production

##  Verification

This code is used by FileShot.io. You can verify:

1. The code served on FileShot.io matches this repository
2. Encryption happens client-side (check Network tab in DevTools)
3. The encryption key never leaves your browser

##  License

MIT License - See [LICENSE](LICENSE) file for details.

##  Contributing

We welcome security reviews and improvements! Please:

1. Fork the repository
2. Review the code
3. Submit issues or pull requests
4. Report security vulnerabilities responsibly

##  Security Policy

If you discover a security vulnerability, please email **fileshot.adm@gmail.como** instead of opening a public issue.

## 📞 Contact

- **Website**: [FileShot.io](https://fileshot.io)
- **Verification Page**: [Verify Encryption](https://fileshot.io/verify-encryption.html)

## ✅ Browser Support

This implementation uses the Web Crypto API, which is supported in:

- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 12+
- Opera 24+

## 🙏 Acknowledgments

Built using the Web Crypto API, which provides secure cryptographic primitives in modern browsers.

---

**Remember**: This is client-side encryption code. The security of your files depends on:
- Using a strong password
- Keeping your password secret
- Using a secure browser and system
- Verifying you're on the real FileShot.io domain (check SSL certificate)

