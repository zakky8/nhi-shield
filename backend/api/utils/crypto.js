/**
 * NHI Shield - Encryption Utility
 * Provides AES-256-GCM encryption/decryption for sensitive data
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

/**
 * Get the encryption key from environment or generate a secure one
 * @returns {Buffer} 32-byte encryption key
 */
function getEncryptionKey() {
    const envKey = process.env.ENCRYPTION_KEY;
    
    if (!envKey) {
        if (process.env.NODE_ENV === 'production') {
            throw new Error('FATAL: ENCRYPTION_KEY must be set in production. Refusing to start with no key.');
        }
        console.warn('WARNING: ENCRYPTION_KEY not set. Using insecure default — NEVER use in production.');
        return Buffer.from('default_32_char_key_change_this!', 'utf8').slice(0, KEY_LENGTH);
    }
    
    // Ensure key is exactly 32 bytes
    if (envKey.length < KEY_LENGTH) {
        throw new Error('ENCRYPTION_KEY must be at least 32 characters long');
    }
    
    return Buffer.from(envKey, 'utf8').slice(0, KEY_LENGTH);
}

/**
 * Encrypt data using AES-256-GCM
 * @param {string} plaintext - Data to encrypt
 * @returns {string} JSON string containing iv, authTag, and encrypted data
 */
function encrypt(plaintext) {
    try {
        const key = getEncryptionKey();
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        
        return JSON.stringify({
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex'),
            encrypted: encrypted,
            version: 1 // For future key rotation support
        });
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Failed to encrypt data');
    }
}

/**
 * Decrypt data encrypted with AES-256-GCM
 * @param {string} encryptedData - JSON string containing iv, authTag, and encrypted data
 * @returns {string} Decrypted plaintext
 */
function decrypt(encryptedData) {
    try {
        const key = getEncryptionKey();
        const data = JSON.parse(encryptedData);
        
        if (data.iv == null || data.authTag == null || data.encrypted == null) {
            throw new Error('Invalid encrypted data format');
        }
        
        const iv = Buffer.from(data.iv, 'hex');
        const authTag = Buffer.from(data.authTag, 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Failed to decrypt data');
    }
}

/**
 * Hash a password using PBKDF2
 * @param {string} password - Plain text password
 * @param {string} salt - Optional salt (generated if not provided)
 * @returns {Object} Object containing hash and salt
 */
function hashPassword(password, salt = null) {
    const iterations = 480000; // OWASP recommended minimum
    const keyLength = 64;
    const digest = 'sha512';
    
    if (!salt) {
        salt = crypto.randomBytes(16).toString('hex');
    }
    
    const hash = crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest).toString('hex');
    
    return { hash, salt };
}

/**
 * Verify a password against a hash
 * @param {string} password - Plain text password
 * @param {string} hash - Stored password hash
 * @param {string} salt - Salt used for hashing
 * @returns {boolean} True if password matches
 */
function verifyPassword(password, hash, salt) {
    const { hash: newHash } = hashPassword(password, salt);
    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(newHash));
}

/**
 * Generate a cryptographically secure random token
 * @param {number} length - Length of token in bytes (default 32)
 * @returns {string} Hex-encoded random token
 */
function generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate a secure API key
 * @returns {string} Base64-encoded API key with prefix
 */
function generateApiKey() {
    const prefix = 'nhi';
    const randomPart = crypto.randomBytes(32).toString('base64url');
    return `${prefix}_${randomPart}`;
}

/**
 * Hash data using SHA-256
 * @param {string} data - Data to hash
 * @returns {string} Hex-encoded hash
 */
function sha256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = {
    encrypt,
    decrypt,
    hashPassword,
    verifyPassword,
    generateToken,
    generateApiKey,
    sha256
};
