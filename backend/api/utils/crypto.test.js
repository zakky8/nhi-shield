/**
 * Crypto Utility Tests
 * Tests for encryption, decryption, password hashing, and token generation
 */

const crypto = require('./crypto');

describe('Crypto Utility Tests', () => {
    describe('Encryption/Decryption', () => {
        test('should encrypt and decrypt data correctly', () => {
            const plaintext = 'sensitive data';
            const encrypted = crypto.encrypt(plaintext);
            const decrypted = crypto.decrypt(encrypted);
            
            expect(decrypted).toBe(plaintext);
        });

        test('should produce different encrypted outputs for same input', () => {
            const plaintext = 'test data';
            const encrypted1 = crypto.encrypt(plaintext);
            const encrypted2 = crypto.encrypt(plaintext);
            
            // Should be different due to random IV
            expect(encrypted1).not.toBe(encrypted2);
            
            // But both should decrypt to same plaintext
            expect(crypto.decrypt(encrypted1)).toBe(plaintext);
            expect(crypto.decrypt(encrypted2)).toBe(plaintext);
        });

        test('should handle JSON objects', () => {
            const obj = { apiKey: 'secret123', credentials: { user: 'test', pass: 'test123' } };
            const encrypted = crypto.encrypt(JSON.stringify(obj));
            const decrypted = JSON.parse(crypto.decrypt(encrypted));
            
            expect(decrypted).toEqual(obj);
        });

        test('should fail to decrypt tampered data', () => {
            const plaintext = 'sensitive data';
            const encrypted = crypto.encrypt(plaintext);
            
            // Tamper with the encrypted data
            const tamperedData = JSON.parse(encrypted);
            tamperedData.encrypted = tamperedData.encrypted.slice(0, -2) + 'FF';
            
            expect(() => {
                crypto.decrypt(JSON.stringify(tamperedData));
            }).toThrow();
        });

        test('should handle empty strings', () => {
            const encrypted = crypto.encrypt('');
            const decrypted = crypto.decrypt(encrypted);
            
            expect(decrypted).toBe('');
        });

        test('should handle special characters', () => {
            const plaintext = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\n\t\\';
            const encrypted = crypto.encrypt(plaintext);
            const decrypted = crypto.decrypt(encrypted);
            
            expect(decrypted).toBe(plaintext);
        });

        test('should handle unicode characters', () => {
            const plaintext = '你好世界 🚀 émojis';
            const encrypted = crypto.encrypt(plaintext);
            const decrypted = crypto.decrypt(encrypted);
            
            expect(decrypted).toBe(plaintext);
        });

        test('encrypted data should be in correct format', () => {
            const encrypted = crypto.encrypt('test');
            const data = JSON.parse(encrypted);
            
            expect(data).toHaveProperty('iv');
            expect(data).toHaveProperty('authTag');
            expect(data).toHaveProperty('encrypted');
            expect(data).toHaveProperty('version');
            expect(data.version).toBe(1);
        });
    });

    describe('Password Hashing', () => {
        test('should hash passwords correctly', () => {
            const password = 'testPassword123';
            const { hash, salt } = crypto.hashPassword(password);
            
            expect(hash).toBeDefined();
            expect(salt).toBeDefined();
            expect(hash.length).toBe(128); // 64 bytes in hex = 128 characters
            expect(salt.length).toBe(32);  // 16 bytes in hex = 32 characters
        });

        test('should produce different hashes with different salts', () => {
            const password = 'testPassword123';
            const { hash: hash1, salt: salt1 } = crypto.hashPassword(password);
            const { hash: hash2, salt: salt2 } = crypto.hashPassword(password);
            
            expect(hash1).not.toBe(hash2);
            expect(salt1).not.toBe(salt2);
        });

        test('should produce same hash with same salt', () => {
            const password = 'testPassword123';
            const { hash: hash1, salt } = crypto.hashPassword(password);
            const { hash: hash2 } = crypto.hashPassword(password, salt);
            
            expect(hash1).toBe(hash2);
        });

        test('should verify correct passwords', () => {
            const password = 'correctPassword';
            const { hash, salt } = crypto.hashPassword(password);
            
            const isValid = crypto.verifyPassword(password, hash, salt);
            expect(isValid).toBe(true);
        });

        test('should reject incorrect passwords', () => {
            const password = 'correctPassword';
            const { hash, salt } = crypto.hashPassword(password);
            
            const isValid = crypto.verifyPassword('wrongPassword', hash, salt);
            expect(isValid).toBe(false);
        });

        test('should handle empty passwords', () => {
            const { hash, salt } = crypto.hashPassword('');
            expect(hash).toBeDefined();
            expect(salt).toBeDefined();
        });
    });

    describe('Token Generation', () => {
        test('should generate tokens of correct length', () => {
            const token = crypto.generateToken(32);
            expect(token.length).toBe(64); // 32 bytes = 64 hex characters
        });

        test('should generate unique tokens', () => {
            const token1 = crypto.generateToken();
            const token2 = crypto.generateToken();
            
            expect(token1).not.toBe(token2);
        });

        test('should accept custom length', () => {
            const token16 = crypto.generateToken(16);
            const token64 = crypto.generateToken(64);
            
            expect(token16.length).toBe(32);  // 16 bytes = 32 hex chars
            expect(token64.length).toBe(128); // 64 bytes = 128 hex chars
        });

        test('should only contain hex characters', () => {
            const token = crypto.generateToken(32);
            expect(/^[0-9a-f]+$/.test(token)).toBe(true);
        });
    });

    describe('API Key Generation', () => {
        test('should generate API keys with correct prefix', () => {
            const apiKey = crypto.generateApiKey();
            expect(apiKey.startsWith('nhi_')).toBe(true);
        });

        test('should generate unique API keys', () => {
            const key1 = crypto.generateApiKey();
            const key2 = crypto.generateApiKey();
            
            expect(key1).not.toBe(key2);
        });

        test('should generate keys with reasonable length', () => {
            const apiKey = crypto.generateApiKey();
            expect(apiKey.length).toBeGreaterThan(40);
            expect(apiKey.length).toBeLessThan(60);
        });

        test('should only contain URL-safe characters', () => {
            const apiKey = crypto.generateApiKey();
            const keyPart = apiKey.substring(4); // Remove "nhi_" prefix
            expect(/^[A-Za-z0-9_-]+$/.test(keyPart)).toBe(true);
        });
    });

    describe('SHA-256 Hashing', () => {
        test('should hash data correctly', () => {
            const data = 'test data';
            const hash = crypto.sha256(data);
            
            expect(hash).toBeDefined();
            expect(hash.length).toBe(64); // SHA-256 produces 32 bytes = 64 hex chars
        });

        test('should produce consistent hashes', () => {
            const data = 'test data';
            const hash1 = crypto.sha256(data);
            const hash2 = crypto.sha256(data);
            
            expect(hash1).toBe(hash2);
        });

        test('should produce different hashes for different data', () => {
            const hash1 = crypto.sha256('data1');
            const hash2 = crypto.sha256('data2');
            
            expect(hash1).not.toBe(hash2);
        });

        test('should only contain hex characters', () => {
            const hash = crypto.sha256('test');
            expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
        });

        test('should handle empty strings', () => {
            const hash = crypto.sha256('');
            expect(hash).toBeDefined();
            expect(hash.length).toBe(64);
        });
    });

    describe('Error Handling', () => {
        test('should throw error on invalid encrypted data format', () => {
            expect(() => {
                crypto.decrypt('invalid json');
            }).toThrow();
        });

        test('should throw error on missing encryption fields', () => {
            expect(() => {
                crypto.decrypt('{"iv":"abc"}');
            }).toThrow();
        });

        test('should throw error on invalid IV', () => {
            expect(() => {
                crypto.decrypt('{"iv":"invalid","authTag":"abc","encrypted":"def"}');
            }).toThrow();
        });
    });

    describe('Performance', () => {
        test('encryption should be reasonably fast', () => {
            const start = Date.now();
            const iterations = 1000;
            
            for (let i = 0; i < iterations; i++) {
                crypto.encrypt('test data');
            }
            
            const duration = Date.now() - start;
            const avgTime = duration / iterations;
            
            // Should average less than 5ms per encryption
            expect(avgTime).toBeLessThan(5);
        });

        test('password hashing should take reasonable time', () => {
            const start = Date.now();
            crypto.hashPassword('testPassword123');
            const duration = Date.now() - start;
            
            // PBKDF2 with 480k iterations should take 100-1000ms
            expect(duration).toBeGreaterThan(10);
            expect(duration).toBeLessThan(2000);
        });
    });
});
