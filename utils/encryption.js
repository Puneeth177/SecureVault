const crypto = require('crypto');

// Encryption configuration
const ALGORITHM = 'aes-256-cbc';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits

// Get encryption key from environment variable
function getEncryptionKey() {
    const key = process.env.ENCRYPTION_KEY;
    if (!key) {
        throw new Error('ENCRYPTION_KEY environment variable is not set');
    }
    
    if (key.length !== KEY_LENGTH) {
        // If key is not exactly 32 characters, derive it using PBKDF2
        return crypto.pbkdf2Sync(key, 'securevault-salt', 100000, KEY_LENGTH, 'sha256');
    }
    
    return Buffer.from(key, 'utf8');
}

/**
 * Encrypt a plaintext string
 * @param {string} plaintext - The text to encrypt
 * @returns {object} - Object containing encrypted data, IV, and auth tag
 */
function encrypt(plaintext) {
    try {
        if (!plaintext || typeof plaintext !== 'string') {
            throw new Error('Invalid plaintext provided');
        }
        
        const key = getEncryptionKey();
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return {
            encryptedData: encrypted,
            iv: iv.toString('hex')
        };
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Encryption failed');
    }
}

/**
 * Decrypt an encrypted string
 * @param {string} encryptedData - The encrypted data
 * @param {string} ivHex - The initialization vector in hex format
 * @returns {string} - The decrypted plaintext
 */
function decrypt(encryptedData, ivHex) {
    try {
        if (!encryptedData || !ivHex) {
            throw new Error('Invalid encrypted data or IV provided');
        }
        
        const key = getEncryptionKey();
        const iv = Buffer.from(ivHex, 'hex');
        
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Decryption failed');
    }
}

/**
 * Generate a secure random password
 * @param {number} length - Password length (default: 16)
 * @param {object} options - Password generation options
 * @returns {string} - Generated password
 */
function generateSecurePassword(length = 16, options = {}) {
    const {
        includeUppercase = true,
        includeLowercase = true,
        includeNumbers = true,
        includeSymbols = true,
        excludeSimilar = true,
        excludeAmbiguous = true
    } = options;
    
    let charset = '';
    
    if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (includeNumbers) charset += '0123456789';
    if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    if (excludeSimilar) {
        charset = charset.replace(/[il1Lo0O]/g, '');
    }
    
    if (excludeAmbiguous) {
        charset = charset.replace(/[{}[\]()\/\\'"~,;.<>]/g, '');
    }
    
    if (!charset) {
        throw new Error('No valid characters available for password generation');
    }
    
    let password = '';
    const charsetLength = charset.length;
    
    for (let i = 0; i < length; i++) {
        const randomIndex = crypto.randomInt(0, charsetLength);
        password += charset[randomIndex];
    }
    
    return password;
}

/**
 * Hash a password using bcrypt-like approach with crypto
 * @param {string} password - Password to hash
 * @param {number} rounds - Number of rounds (default: 12)
 * @returns {string} - Hashed password
 */
function hashPassword(password, rounds = 12) {
    try {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync(password, salt, Math.pow(2, rounds), 64, 'sha256').toString('hex');
        return `${rounds}$${salt}$${hash}`;
    } catch (error) {
        console.error('Password hashing error:', error);
        throw new Error('Password hashing failed');
    }
}

/**
 * Verify a password against its hash
 * @param {string} password - Password to verify
 * @param {string} hashedPassword - Hashed password to compare against
 * @returns {boolean} - True if password matches
 */
function verifyPassword(password, hashedPassword) {
    try {
        const [rounds, salt, hash] = hashedPassword.split('$');
        const verifyHash = crypto.pbkdf2Sync(password, salt, Math.pow(2, parseInt(rounds)), 64, 'sha256').toString('hex');
        return hash === verifyHash;
    } catch (error) {
        console.error('Password verification error:', error);
        return false;
    }
}

/**
 * Generate a secure random token
 * @param {number} length - Token length in bytes (default: 32)
 * @returns {string} - Random token in hex format
 */
function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Create HMAC signature
 * @param {string} data - Data to sign
 * @param {string} secret - Secret key
 * @returns {string} - HMAC signature
 */
function createHMAC(data, secret) {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * Verify HMAC signature
 * @param {string} data - Original data
 * @param {string} signature - HMAC signature to verify
 * @param {string} secret - Secret key
 * @returns {boolean} - True if signature is valid
 */
function verifyHMAC(data, signature, secret) {
    const expectedSignature = createHMAC(data, secret);
    return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSignature, 'hex'));
}

module.exports = {
    encrypt,
    decrypt,
    generateSecurePassword,
    hashPassword,
    verifyPassword,
    generateSecureToken,
    createHMAC,
    verifyHMAC,
    ALGORITHM,
    KEY_LENGTH,
    IV_LENGTH
};