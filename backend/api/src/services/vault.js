// ============================================================
// NHI SHIELD — Credential Vault (AES-256-GCM)
// Encrypts/decrypts all integration credentials
// NEVER logs credential values
// ============================================================
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT = Buffer.from('nhi-shield-vault-v1', 'utf8');
const PBKDF2_ITERATIONS = 480000;

let _encryptionKey = null;

function getEncryptionKey() {
    if (_encryptionKey) return _encryptionKey;
    const masterKey = process.env.MASTER_ENCRYPTION_KEY;
    if (!masterKey || masterKey.length < 32) {
        throw new Error('MASTER_ENCRYPTION_KEY must be at least 32 characters');
    }
    _encryptionKey = crypto.pbkdf2Sync(masterKey, SALT, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
    return _encryptionKey;
}

/**
 * Encrypt plaintext string → Buffer (IV + authTag + ciphertext)
 * Each call generates a unique random IV — same input = different output
 */
function encrypt(plaintext) {
    const key = getEncryptionKey();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // Pack: [IV (16)] + [authTag (16)] + [ciphertext (...)]
    return Buffer.concat([iv, authTag, encrypted]);
}

/**
 * Decrypt Buffer → plaintext string
 * Validates authentication tag — throws if tampered
 */
function decrypt(encryptedBuffer) {
    const key = getEncryptionKey();

    // Unpack the components
    const iv = encryptedBuffer.slice(0, IV_LENGTH);
    const authTag = encryptedBuffer.slice(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
    const ciphertext = encryptedBuffer.slice(IV_LENGTH + AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    decipher.setAuthTag(authTag);

    return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
    ]).toString('utf8');
}

/**
 * Encrypt credentials object → Buffer for DB storage
 */
function encryptCredentials(credentialsObj) {
    const json = JSON.stringify(credentialsObj);
    return encrypt(json);
}

/**
 * Decrypt Buffer from DB → credentials object
 */
function decryptCredentials(encryptedBuffer) {
    const json = decrypt(encryptedBuffer);
    return JSON.parse(json);
}

module.exports = { encrypt, decrypt, encryptCredentials, decryptCredentials };
