const crypto = require('crypto');

function generateSecureKey(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

function generateJWTSecret(length = 64) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

console.log('🔐 SecureVault - Security Keys Generator');
console.log('=====================================');
console.log('');
console.log('Copy these values to your .env file:');
console.log('');
console.log(`JWT_SECRET=${generateJWTSecret(64)}`);
console.log(`ENCRYPTION_KEY=${generateSecureKey(32)}`);
console.log('');
console.log('⚠️  IMPORTANT: Keep these keys secure and never share them!');
console.log('⚠️  Use different keys for production and development!');
console.log('');
console.log('Additional recommendations:');
console.log('- Change ADMIN_PASSWORD to something unique');
console.log('- Use a strong MongoDB connection string');
console.log('- Enable MongoDB authentication in production');
console.log('');