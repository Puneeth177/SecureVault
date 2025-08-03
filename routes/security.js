const express = require('express');
const { requireAdmin } = require('../middleware/auth');
const { adminRateLimit } = require('../middleware/security');
const { asyncHandler } = require('../middleware/errorHandler');
const { getSecurityStats, getRecentEvents } = require('../utils/securityMonitor');
const { getSecurityConfig, validateSecurityConfig, getSecurityRecommendations } = require('../config/security');
const User = require('../models/User');
const Password = require('../models/Password');

const router = express.Router();

// Apply security middleware
router.use(adminRateLimit);
router.use(requireAdmin);

/**
 * @route   GET /api/security/dashboard
 * @desc    Get security dashboard data
 * @access  Private (Admin only)
 */
router.get('/dashboard', asyncHandler(async (req, res) => {
    const timeframe = parseInt(req.query.hours) || 24;
    
    // Get security statistics
    const securityStats = await getSecurityStats(timeframe);
    const recentEvents = await getRecentEvents(timeframe);
    
    // Get user security metrics
    const userMetrics = {
        totalUsers: await User.countDocuments({ isActive: true }),
        lockedAccounts: await User.countDocuments({ 
            isActive: true, 
            lockUntil: { $gt: new Date() } 
        }),
        usersWithWeakPasswords: await User.countDocuments({
            isActive: true,
            'passwordHistory.0': { $exists: false } // Users who haven't changed password
        }),
        adminUsers: await User.countDocuments({ isActive: true, isAdmin: true })
    };
    
    // Get password security metrics
    const passwordMetrics = {
        totalPasswords: await Password.countDocuments(),
        expiredPasswords: await Password.countDocuments({
            expiresAt: { $lt: new Date() }
        }),
        compromisedPasswords: await Password.countDocuments({
            isCompromised: true
        }),
        weakPasswords: await Password.countDocuments({
            strength: { $in: ['weak', 'very-weak'] }
        })
    };
    
    // Get configuration status
    const configValidation = validateSecurityConfig();
    const recommendations = getSecurityRecommendations();
    
    // Calculate security score
    const securityScore = calculateSecurityScore({
        userMetrics,
        passwordMetrics,
        securityStats,
        configValidation
    });
    
    res.json({
        success: true,
        data: {
            securityScore,
            timeframe: `${timeframe} hours`,
            metrics: {
                users: userMetrics,
                passwords: passwordMetrics,
                events: securityStats
            },
            recentEvents: recentEvents.slice(0, 20), // Last 20 events
            configuration: {
                isValid: configValidation.isValid,
                issues: configValidation.issues
            },
            recommendations,
            alerts: generateSecurityAlerts(securityStats, userMetrics, passwordMetrics)
        }
    });
}));

/**
 * @route   GET /api/security/events
 * @desc    Get security events with filtering
 * @access  Private (Admin only)
 */
router.get('/events', asyncHandler(async (req, res) => {
    const {
        hours = 24,
        eventType,
        severity,
        limit = 50,
        offset = 0
    } = req.query;
    
    let events = await getRecentEvents(parseInt(hours), eventType);
    
    // Filter by severity if specified
    if (severity) {
        events = events.filter(event => event.severity === severity);
    }
    
    // Apply pagination
    const total = events.length;
    const paginatedEvents = events.slice(parseInt(offset), parseInt(offset) + parseInt(limit));
    
    res.json({
        success: true,
        data: {
            events: paginatedEvents,
            pagination: {
                total,
                limit: parseInt(limit),
                offset: parseInt(offset),
                hasMore: parseInt(offset) + parseInt(limit) < total
            }
        }
    });
}));

/**
 * @route   GET /api/security/config
 * @desc    Get current security configuration
 * @access  Private (Admin only)
 */
router.get('/config', asyncHandler(async (req, res) => {
    const config = getSecurityConfig();
    const validation = validateSecurityConfig(config);
    const recommendations = getSecurityRecommendations();
    
    // Remove sensitive information
    const sanitizedConfig = {
        ...config,
        // Don't expose actual secrets, just their status
        secrets: {
            jwtSecretSet: !!process.env.JWT_SECRET,
            encryptionKeySet: !!process.env.ENCRYPTION_KEY,
            refreshTokenSecretSet: !!process.env.REFRESH_TOKEN_SECRET
        }
    };
    
    res.json({
        success: true,
        data: {
            configuration: sanitizedConfig,
            validation,
            recommendations
        }
    });
}));

/**
 * @route   GET /api/security/threats
 * @desc    Get current security threats and suspicious activity
 * @access  Private (Admin only)
 */
router.get('/threats', asyncHandler(async (req, res) => {
    const hours = parseInt(req.query.hours) || 24;
    
    // Get suspicious events
    const suspiciousEvents = await getRecentEvents(hours);
    const threats = suspiciousEvents.filter(event => 
        ['brute_force_attempt', 'sql_injection_attempt', 'xss_attempt', 'unauthorized_access'].includes(event.eventType)
    );
    
    // Analyze threat patterns
    const threatAnalysis = analyzeThreatPatterns(threats);
    
    // Get blocked IPs (this would come from your rate limiting or firewall)
    const blockedIPs = getBlockedIPs();
    
    res.json({
        success: true,
        data: {
            threats,
            analysis: threatAnalysis,
            blockedIPs,
            riskLevel: calculateRiskLevel(threats, threatAnalysis)
        }
    });
}));

/**
 * @route   POST /api/security/block-ip
 * @desc    Block an IP address
 * @access  Private (Admin only)
 */
router.post('/block-ip', asyncHandler(async (req, res) => {
    const { ip, reason, duration = 24 } = req.body;
    
    if (!ip) {
        return res.status(400).json({
            success: false,
            message: 'IP address is required'
        });
    }
    
    // This would integrate with your firewall or rate limiting system
    const result = await blockIP(ip, reason, duration);
    
    // Log the admin action
    await logSecurityEvent('admin_ip_block', {
        ip,
        reason,
        duration,
        adminUser: req.user.username,
        timestamp: new Date().toISOString()
    });
    
    res.json({
        success: true,
        message: `IP ${ip} has been blocked for ${duration} hours`,
        data: result
    });
}));

/**
 * @route   POST /api/security/unblock-ip
 * @desc    Unblock an IP address
 * @access  Private (Admin only)
 */
router.post('/unblock-ip', asyncHandler(async (req, res) => {
    const { ip } = req.body;
    
    if (!ip) {
        return res.status(400).json({
            success: false,
            message: 'IP address is required'
        });
    }
    
    const result = await unblockIP(ip);
    
    // Log the admin action
    await logSecurityEvent('admin_ip_unblock', {
        ip,
        adminUser: req.user.username,
        timestamp: new Date().toISOString()
    });
    
    res.json({
        success: true,
        message: `IP ${ip} has been unblocked`,
        data: result
    });
}));

/**
 * Calculate overall security score
 */
function calculateSecurityScore(metrics) {
    let score = 100;
    
    // Deduct points for security issues
    if (metrics.userMetrics.lockedAccounts > 0) {
        score -= Math.min(metrics.userMetrics.lockedAccounts * 2, 10);
    }
    
    if (metrics.passwordMetrics.compromisedPasswords > 0) {
        score -= Math.min(metrics.passwordMetrics.compromisedPasswords * 5, 20);
    }
    
    if (metrics.passwordMetrics.weakPasswords > 0) {
        score -= Math.min(metrics.passwordMetrics.weakPasswords * 2, 15);
    }
    
    if (!metrics.configValidation.isValid) {
        score -= metrics.configValidation.issues.length * 5;
    }
    
    // Deduct for high-severity events
    const criticalEvents = metrics.securityStats.eventsBySeverity?.critical || 0;
    const highEvents = metrics.securityStats.eventsBySeverity?.high || 0;
    
    score -= criticalEvents * 10;
    score -= highEvents * 5;
    
    return Math.max(score, 0);
}

/**
 * Generate security alerts
 */
function generateSecurityAlerts(securityStats, userMetrics, passwordMetrics) {
    const alerts = [];
    
    if (userMetrics.lockedAccounts > 5) {
        alerts.push({
            type: 'warning',
            message: `${userMetrics.lockedAccounts} accounts are currently locked`,
            action: 'Review locked accounts and investigate potential attacks'
        });
    }
    
    if (passwordMetrics.compromisedPasswords > 0) {
        alerts.push({
            type: 'critical',
            message: `${passwordMetrics.compromisedPasswords} compromised passwords detected`,
            action: 'Force password reset for affected accounts'
        });
    }
    
    const failedLogins = securityStats.eventsByType?.failed_login || 0;
    if (failedLogins > 50) {
        alerts.push({
            type: 'warning',
            message: `High number of failed login attempts: ${failedLogins}`,
            action: 'Monitor for brute force attacks'
        });
    }
    
    return alerts;
}

/**
 * Analyze threat patterns
 */
function analyzeThreatPatterns(threats) {
    const patterns = {
        topAttackTypes: {},
        topSourceIPs: {},
        attackFrequency: {},
        timeDistribution: {}
    };
    
    threats.forEach(threat => {
        // Count attack types
        patterns.topAttackTypes[threat.eventType] = (patterns.topAttackTypes[threat.eventType] || 0) + 1;
        
        // Count source IPs
        const ip = threat.details?.ip || 'unknown';
        patterns.topSourceIPs[ip] = (patterns.topSourceIPs[ip] || 0) + 1;
        
        // Time distribution
        const hour = new Date(threat.timestamp).getHours();
        patterns.timeDistribution[hour] = (patterns.timeDistribution[hour] || 0) + 1;
    });
    
    return patterns;
}

/**
 * Calculate risk level
 */
function calculateRiskLevel(threats, analysis) {
    const threatCount = threats.length;
    const uniqueIPs = Object.keys(analysis.topSourceIPs).length;
    
    if (threatCount > 100 || uniqueIPs > 20) {
        return 'critical';
    } else if (threatCount > 50 || uniqueIPs > 10) {
        return 'high';
    } else if (threatCount > 10 || uniqueIPs > 5) {
        return 'medium';
    } else {
        return 'low';
    }
}

/**
 * Mock functions for IP blocking (implement based on your infrastructure)
 */
function getBlockedIPs() {
    // This would integrate with your firewall or rate limiting system
    return [];
}

async function blockIP(ip, reason, duration) {
    // Implement IP blocking logic here
    console.log(`🚫 Blocking IP ${ip} for ${duration} hours. Reason: ${reason}`);
    return { blocked: true, ip, duration };
}

async function unblockIP(ip) {
    // Implement IP unblocking logic here
    console.log(`✅ Unblocking IP ${ip}`);
    return { unblocked: true, ip };
}

module.exports = router;