const crypto = require('crypto');
const { logSecurityEvent } = require('./securityMonitor');

/**
 * Advanced Password Security Utilities
 */
class PasswordSecurity {
    constructor() {
        this.commonPasswords = new Set([
            'password', 'password123', '123456', '123456789', 'qwerty', 'abc123',
            'password1', 'admin', 'letmein', 'welcome', 'monkey', '1234567890',
            'dragon', 'master', 'hello', 'login', 'pass', 'admin123', 'root',
            'user', 'test', 'guest', 'default', 'changeme', 'secret', 'temp'
        ]);
        
        this.weakPatterns = [
            /^(.)\1+$/, // All same character
            /^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$/i, // Sequential
            /^(qwerty|asdfgh|zxcvbn|qwertyuiop|asdfghjkl|zxcvbnm)+$/i, // Keyboard patterns
            /^(.{1,3})\1+$/, // Repeated short patterns
        ];
    }

    /**
     * Comprehensive password strength analysis
     */
    analyzePassword(password, userInfo = {}) {
        const analysis = {
            score: 0,
            strength: 'very-weak',
            feedback: [],
            isAcceptable: false,
            entropy: 0
        };

        // Basic length check
        if (password.length < 8) {
            analysis.feedback.push('Password must be at least 8 characters long');
            return analysis;
        }

        // Calculate entropy
        analysis.entropy = this.calculateEntropy(password);
        
        // Length scoring
        if (password.length >= 12) analysis.score += 25;
        else if (password.length >= 10) analysis.score += 15;
        else if (password.length >= 8) analysis.score += 10;

        // Character variety scoring
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
        
        let charTypes = 0;
        if (hasLower) { analysis.score += 10; charTypes++; }
        if (hasUpper) { analysis.score += 10; charTypes++; }
        if (hasNumbers) { analysis.score += 10; charTypes++; }
        if (hasSpecial) { analysis.score += 15; charTypes++; }

        // Entropy bonus
        if (analysis.entropy > 60) analysis.score += 20;
        else if (analysis.entropy > 40) analysis.score += 10;

        // Penalty checks
        if (this.isCommonPassword(password)) {
            analysis.score -= 30;
            analysis.feedback.push('This is a commonly used password');
        }

        if (this.hasWeakPatterns(password)) {
            analysis.score -= 20;
            analysis.feedback.push('Password contains predictable patterns');
        }

        if (this.containsPersonalInfo(password, userInfo)) {
            analysis.score -= 25;
            analysis.feedback.push('Password should not contain personal information');
        }

        if (this.hasRepeatedChars(password)) {
            analysis.score -= 15;
            analysis.feedback.push('Avoid repeated characters');
        }

        // Determine strength
        if (analysis.score >= 80) {
            analysis.strength = 'very-strong';
            analysis.isAcceptable = true;
        } else if (analysis.score >= 60) {
            analysis.strength = 'strong';
            analysis.isAcceptable = true;
        } else if (analysis.score >= 40) {
            analysis.strength = 'medium';
            analysis.isAcceptable = charTypes >= 3;
        } else if (analysis.score >= 20) {
            analysis.strength = 'weak';
            analysis.isAcceptable = false;
        } else {
            analysis.strength = 'very-weak';
            analysis.isAcceptable = false;
        }

        // Add positive feedback
        if (analysis.isAcceptable) {
            if (password.length >= 16) analysis.feedback.push('✓ Excellent length');
            if (charTypes === 4) analysis.feedback.push('✓ Good character variety');
            if (analysis.entropy > 60) analysis.feedback.push('✓ High entropy');
        } else {
            analysis.feedback.push('Password does not meet security requirements');
        }

        return analysis;
    }

    /**
     * Calculate password entropy
     */
    calculateEntropy(password) {
        const charSets = {
            lowercase: /[a-z]/,
            uppercase: /[A-Z]/,
            numbers: /\d/,
            special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/,
            other: /[^\w!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/
        };

        let charsetSize = 0;
        Object.values(charSets).forEach(regex => {
            if (regex.test(password)) {
                if (regex === charSets.lowercase) charsetSize += 26;
                else if (regex === charSets.uppercase) charsetSize += 26;
                else if (regex === charSets.numbers) charsetSize += 10;
                else if (regex === charSets.special) charsetSize += 32;
                else charsetSize += 10; // other characters
            }
        });

        return password.length * Math.log2(charsetSize);
    }

    /**
     * Check if password is commonly used
     */
    isCommonPassword(password) {
        const lower = password.toLowerCase();
        return this.commonPasswords.has(lower) || 
               this.commonPasswords.has(lower.replace(/\d+$/, '')) || // Remove trailing numbers
               this.commonPasswords.has(lower.replace(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+$/, '')); // Remove trailing special chars
    }

    /**
     * Check for weak patterns
     */
    hasWeakPatterns(password) {
        return this.weakPatterns.some(pattern => pattern.test(password));
    }

    /**
     * Check if password contains personal information
     */
    containsPersonalInfo(password, userInfo) {
        const lower = password.toLowerCase();
        const checks = [
            userInfo.username?.toLowerCase(),
            userInfo.email?.split('@')[0]?.toLowerCase(),
            userInfo.firstName?.toLowerCase(),
            userInfo.lastName?.toLowerCase(),
            userInfo.birthYear?.toString()
        ].filter(Boolean);

        return checks.some(info => 
            info.length >= 3 && lower.includes(info)
        );
    }

    /**
     * Check for excessive repeated characters
     */
    hasRepeatedChars(password) {
        // Check for 3 or more consecutive identical characters
        return /(.)\1{2,}/.test(password);
    }

    /**
     * Generate secure password suggestions
     */
    generateSecurePassword(length = 16, options = {}) {
        const {
            includeUppercase = true,
            includeLowercase = true,
            includeNumbers = true,
            includeSpecial = true,
            excludeSimilar = true,
            excludeAmbiguous = true
        } = options;

        let charset = '';
        
        if (includeLowercase) {
            charset += excludeSimilar ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
        }
        
        if (includeUppercase) {
            charset += excludeSimilar ? 'ABCDEFGHJKMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        }
        
        if (includeNumbers) {
            charset += excludeSimilar ? '23456789' : '0123456789';
        }
        
        if (includeSpecial) {
            charset += excludeAmbiguous ? '!@#$%^&*-_=+[]{}|;:,.<>?' : '!@#$%^&*()_+-=[]{}|;:\'",.<>?/~`';
        }

        let password = '';
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        
        for (let i = 0; i < length; i++) {
            password += charset[array[i] % charset.length];
        }

        // Ensure password meets requirements
        const analysis = this.analyzePassword(password);
        if (!analysis.isAcceptable && length >= 12) {
            // Try again with different parameters
            return this.generateSecurePassword(length, options);
        }

        return password;
    }

    /**
     * Check if password has been compromised (basic implementation)
     */
    async checkCompromised(password) {
        // In a real implementation, you would check against:
        // - HaveIBeenPwned API
        // - Local breach database
        // - Custom blacklists
        
        // For now, just check against common passwords
        const isCompromised = this.isCommonPassword(password);
        
        if (isCompromised) {
            await logSecurityEvent('compromised_password_attempt', {
                timestamp: new Date().toISOString(),
                passwordLength: password.length
            });
        }

        return {
            isCompromised,
            source: isCompromised ? 'common_passwords' : null
        };
    }

    /**
     * Password policy validation
     */
    validatePasswordPolicy(password, userInfo = {}) {
        const policy = {
            minLength: parseInt(process.env.PASSWORD_MIN_LENGTH) || 12,
            requireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE !== 'false',
            requireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE !== 'false',
            requireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS !== 'false',
            requireSpecial: process.env.PASSWORD_REQUIRE_SPECIAL !== 'false',
            maxLength: 128,
            preventReuse: true
        };

        const violations = [];

        if (password.length < policy.minLength) {
            violations.push(`Password must be at least ${policy.minLength} characters long`);
        }

        if (password.length > policy.maxLength) {
            violations.push(`Password must not exceed ${policy.maxLength} characters`);
        }

        if (policy.requireUppercase && !/[A-Z]/.test(password)) {
            violations.push('Password must contain at least one uppercase letter');
        }

        if (policy.requireLowercase && !/[a-z]/.test(password)) {
            violations.push('Password must contain at least one lowercase letter');
        }

        if (policy.requireNumbers && !/\d/.test(password)) {
            violations.push('Password must contain at least one number');
        }

        if (policy.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            violations.push('Password must contain at least one special character');
        }

        const analysis = this.analyzePassword(password, userInfo);
        if (!analysis.isAcceptable) {
            violations.push('Password does not meet security strength requirements');
        }

        return {
            isValid: violations.length === 0,
            violations,
            analysis
        };
    }
}

// Create singleton instance
const passwordSecurity = new PasswordSecurity();

module.exports = {
    PasswordSecurity,
    passwordSecurity
};