#!/usr/bin/env node

/**
 * Security Check Script
 * Run this before deployment to ensure security configuration is correct
 */

const { validateSecurityConfig, getSecurityRecommendations } = require('../config/security');
const { passwordSecurity } = require('../utils/passwordSecurity');
const crypto = require('crypto');
require('dotenv').config();

console.log('🔒 SecureVault Security Configuration Check\n');

/**
 * Check environment variables
 */
function checkEnvironmentVariables() {
    console.log('📋 Checking Environment Variables...');
    const issues = [];
    const warnings = [];
    
    // Critical environment variables
    const criticalVars = [
        'MONGODB_URI',
        'JWT_SECRET',
        'ENCRYPTION_KEY',
        'ADMIN_PASSWORD'
    ];
    
    criticalVars.forEach(varName => {
        const value = process.env[varName];
        if (!value) {
            issues.push(`❌ ${varName} is not set`);
        } else {
            console.log(`✅ ${varName} is set`);
            
            // Check strength of secrets
            if (varName === 'JWT_SECRET' && value.length < 32) {
                warnings.push(`⚠️  ${varName} should be at least 32 characters long`);
            }
            
            if (varName === 'ENCRYPTION_KEY' && value.length < 32) {
                warnings.push(`⚠️  ${varName} should be at least 32 characters long`);
            }
            
            if (varName === 'ADMIN_PASSWORD') {
                const analysis = passwordSecurity.analyzePassword(value);
                if (!analysis.isAcceptable) {
                    warnings.push(`⚠️  ${varName} is weak: ${analysis.feedback.join(', ')}`);
                }
            }
        }
    });
    
    // Optional but recommended variables
    const recommendedVars = [
        'REFRESH_TOKEN_SECRET',
        'CORS_ORIGIN',
        'NODE_ENV'
    ];
    
    recommendedVars.forEach(varName => {
        const value = process.env[varName];
        if (!value) {
            warnings.push(`⚠️  ${varName} is not set (recommended)`);
        } else {
            console.log(`✅ ${varName} is set`);
        }
    });
    
    return { issues, warnings };
}

/**
 * Check security configuration
 */
function checkSecurityConfiguration() {
    console.log('\n🛡️  Checking Security Configuration...');
    
    const validation = validateSecurityConfig();
    
    if (validation.isValid) {
        console.log('✅ Security configuration is valid');
    } else {
        console.log('❌ Security configuration has issues:');
        validation.issues.forEach(issue => {
            console.log(`   - ${issue}`);
        });
    }
    
    return validation;
}

/**
 * Check for security recommendations
 */
function checkSecurityRecommendations() {
    console.log('\n💡 Security Recommendations...');
    
    const recommendations = getSecurityRecommendations();
    
    if (recommendations.length === 0) {
        console.log('✅ No additional security recommendations');
    } else {
        recommendations.forEach(rec => {
            const priority = rec.priority === 'high' ? '🔴' : rec.priority === 'medium' ? '🟡' : '🟢';
            console.log(`${priority} [${rec.type.toUpperCase()}] ${rec.message}`);
        });
    }
    
    return recommendations;
}

/**
 * Check database connection security
 */
function checkDatabaseSecurity() {
    console.log('\n🗄️  Checking Database Security...');
    
    const mongoUri = process.env.MONGODB_URI;
    if (!mongoUri) {
        console.log('❌ MONGODB_URI not set');
        return false;
    }
    
    // Check if using SSL
    if (mongoUri.includes('ssl=true') || mongoUri.includes('tls=true')) {
        console.log('✅ Database connection uses SSL/TLS');
    } else {
        console.log('⚠️  Database connection may not use SSL/TLS');
    }
    
    // Check if using authentication
    if (mongoUri.includes('@')) {
        console.log('✅ Database connection uses authentication');
    } else {
        console.log('❌ Database connection does not use authentication');
        return false;
    }
    
    // Check for localhost in production
    if (process.env.NODE_ENV === 'production' && mongoUri.includes('localhost')) {
        console.log('⚠️  Using localhost database in production environment');
    }
    
    return true;
}

/**
 * Check CORS configuration
 */
function checkCORSConfiguration() {
    console.log('\n🌐 Checking CORS Configuration...');
    
    const corsOrigin = process.env.CORS_ORIGIN;
    
    if (!corsOrigin) {
        console.log('⚠️  CORS_ORIGIN not set, will default to localhost');
        return false;
    }
    
    if (corsOrigin === '*') {
        console.log('❌ CORS_ORIGIN is set to wildcard (*) - this is insecure for production');
        return false;
    }
    
    if (corsOrigin.startsWith('http://') && process.env.NODE_ENV === 'production') {
        console.log('⚠️  CORS_ORIGIN uses HTTP in production - consider using HTTPS');
    }
    
    console.log(`✅ CORS_ORIGIN is set to: ${corsOrigin}`);
    return true;
}

/**
 * Generate security report
 */
function generateSecurityReport(results) {
    console.log('\n📊 Security Report Summary');
    console.log('=' .repeat(50));
    
    const totalIssues = results.envCheck.issues.length + 
                       (results.configCheck.isValid ? 0 : results.configCheck.issues.length);
    
    const totalWarnings = results.envCheck.warnings.length + 
                         results.recommendations.length;
    
    console.log(`Critical Issues: ${totalIssues}`);
    console.log(`Warnings: ${totalWarnings}`);
    console.log(`Database Security: ${results.dbCheck ? '✅ Good' : '❌ Issues'}`);
    console.log(`CORS Security: ${results.corsCheck ? '✅ Good' : '❌ Issues'}`);
    
    if (totalIssues === 0) {
        console.log('\n🎉 Security check passed! Your application is ready for deployment.');
        return true;
    } else {
        console.log('\n🚨 Security check failed! Please fix the issues above before deployment.');
        return false;
    }
}

/**
 * Generate secure secrets
 */
function generateSecureSecrets() {
    console.log('\n🔑 Generated Secure Secrets (use these in production):');
    console.log('=' .repeat(50));
    
    const jwtSecret = crypto.randomBytes(64).toString('hex');
    const encryptionKey = crypto.randomBytes(32).toString('hex').substring(0, 32);
    const refreshTokenSecret = crypto.randomBytes(64).toString('hex');
    const adminPassword = passwordSecurity.generateSecurePassword(16);
    
    console.log(`JWT_SECRET=${jwtSecret}`);
    console.log(`ENCRYPTION_KEY=${encryptionKey}`);
    console.log(`REFRESH_TOKEN_SECRET=${refreshTokenSecret}`);
    console.log(`ADMIN_PASSWORD=${adminPassword}`);
    
    console.log('\n⚠️  Store these secrets securely and never commit them to version control!');
}

/**
 * Main security check function
 */
async function runSecurityCheck() {
    try {
        const results = {
            envCheck: checkEnvironmentVariables(),
            configCheck: checkSecurityConfiguration(),
            recommendations: checkSecurityRecommendations(),
            dbCheck: checkDatabaseSecurity(),
            corsCheck: checkCORSConfiguration()
        };
        
        const passed = generateSecurityReport(results);
        
        // If running with --generate-secrets flag, generate new secrets
        if (process.argv.includes('--generate-secrets')) {
            generateSecureSecrets();
        }
        
        // Exit with appropriate code
        process.exit(passed ? 0 : 1);
        
    } catch (error) {
        console.error('\n❌ Security check failed with error:', error.message);
        process.exit(1);
    }
}

// Run the security check
if (require.main === module) {
    runSecurityCheck();
}

module.exports = {
    runSecurityCheck,
    checkEnvironmentVariables,
    checkSecurityConfiguration,
    checkDatabaseSecurity,
    checkCORSConfiguration
};