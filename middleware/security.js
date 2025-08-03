const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');

/**
 * Enhanced Rate Limiting Configuration
 */
const createRateLimit = (windowMs, max, message, skipSuccessfulRequests = false) => {
    return rateLimit({
        windowMs,
        max,
        message: {
            success: false,
            message,
            retryAfter: Math.ceil(windowMs / 1000)
        },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests,
        handler: (req, res) => {
            console.warn(`🚨 Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
            res.status(429).json({
                success: false,
                message,
                retryAfter: Math.ceil(windowMs / 1000)
            });
        }
    });
};

/**
 * Strict Authentication Rate Limiting
 */
const authRateLimit = createRateLimit(
    parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS) || 5, // 5 attempts
    'Too many authentication attempts. Please try again later.',
    false
);

/**
 * Password Reset Rate Limiting
 */
const passwordResetRateLimit = createRateLimit(
    60 * 60 * 1000, // 1 hour
    3, // 3 attempts per hour
    'Too many password reset attempts. Please try again later.',
    false
);

/**
 * Admin Action Rate Limiting
 */
const adminRateLimit = createRateLimit(
    5 * 60 * 1000, // 5 minutes
    20, // 20 admin actions per 5 minutes
    'Too many admin actions. Please slow down.',
    true
);

/**
 * General API Rate Limiting
 */
const apiRateLimit = createRateLimit(
    parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // 100 requests
    'Too many requests. Please try again later.',
    true
);

/**
 * Progressive Delay for Suspicious Activity
 */
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 50, // allow 50 requests per windowMs without delay
    delayMs: 500, // add 500ms delay per request after delayAfter
    maxDelayMs: 20000, // maximum delay of 20 seconds
    skipSuccessfulRequests: true
});

/**
 * Input Sanitization Middleware
 */
const sanitizeInput = [
    // Prevent NoSQL injection attacks
    mongoSanitize({
        replaceWith: '_',
        onSanitize: ({ req, key }) => {
            console.warn(`🚨 Potential NoSQL injection attempt from IP: ${req.ip}, key: ${key}`);
        }
    }),
    
    // Prevent XSS attacks
    xss(),
    
    // Prevent HTTP Parameter Pollution
    hpp({
        whitelist: ['tags', 'categories'] // Allow arrays for these parameters
    })
];

/**
 * Security Headers Middleware
 */
const securityHeaders = (req, res, next) => {
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Enable XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Permissions policy
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    // Remove server information
    res.removeHeader('X-Powered-By');
    
    next();
};

/**
 * Request Logging for Security Monitoring
 */
const securityLogger = (req, res, next) => {
    const startTime = Date.now();
    
    // Log suspicious patterns
    const suspiciousPatterns = [
        /\.\./,  // Directory traversal
        /<script/i,  // XSS attempts
        /union.*select/i,  // SQL injection
        /javascript:/i,  // JavaScript injection
        /vbscript:/i,  // VBScript injection
        /onload=/i,  // Event handler injection
        /onerror=/i  // Error handler injection
    ];
    
    const userAgent = req.get('User-Agent') || '';
    const requestBody = JSON.stringify(req.body);
    const requestUrl = req.originalUrl;
    
    // Check for suspicious patterns
    const isSuspicious = suspiciousPatterns.some(pattern => 
        pattern.test(requestUrl) || 
        pattern.test(requestBody) || 
        pattern.test(userAgent)
    );
    
    if (isSuspicious) {
        console.warn(`🚨 Suspicious request detected:`, {
            ip: req.ip,
            userAgent,
            url: requestUrl,
            body: requestBody,
            timestamp: new Date().toISOString()
        });
    }
    
    // Log response time for performance monitoring
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        if (duration > 5000) { // Log slow requests (>5s)
            console.warn(`⏱️ Slow request: ${req.method} ${requestUrl} - ${duration}ms`);
        }
    });
    
    next();
};

/**
 * IP Whitelist Middleware (for admin endpoints)
 */
const ipWhitelist = (allowedIPs = []) => {
    return (req, res, next) => {
        if (allowedIPs.length === 0) {
            return next(); // No whitelist configured
        }
        
        const clientIP = req.ip || req.connection.remoteAddress;
        
        if (!allowedIPs.includes(clientIP)) {
            console.warn(`🚨 Unauthorized IP access attempt: ${clientIP}`);
            return res.status(403).json({
                success: false,
                message: 'Access denied from this IP address'
            });
        }
        
        next();
    };
};

/**
 * Request Size Limiter
 */
const requestSizeLimiter = (req, res, next) => {
    const maxSize = 1024 * 1024; // 1MB
    
    if (req.headers['content-length'] && parseInt(req.headers['content-length']) > maxSize) {
        return res.status(413).json({
            success: false,
            message: 'Request entity too large'
        });
    }
    
    next();
};

/**
 * Brute Force Protection
 */
const bruteForceProtection = new Map();

const checkBruteForce = (identifier, maxAttempts = 5, windowMs = 15 * 60 * 1000) => {
    return (req, res, next) => {
        const key = req.body[identifier] || req.ip;
        const now = Date.now();
        
        if (!bruteForceProtection.has(key)) {
            bruteForceProtection.set(key, { attempts: 0, lastAttempt: now });
        }
        
        const record = bruteForceProtection.get(key);
        
        // Reset if window has passed
        if (now - record.lastAttempt > windowMs) {
            record.attempts = 0;
            record.lastAttempt = now;
        }
        
        if (record.attempts >= maxAttempts) {
            console.warn(`🚨 Brute force attempt blocked for: ${key}`);
            return res.status(429).json({
                success: false,
                message: 'Too many failed attempts. Please try again later.',
                retryAfter: Math.ceil(windowMs / 1000)
            });
        }
        
        // Increment attempts on failed requests
        res.on('finish', () => {
            if (res.statusCode === 401 || res.statusCode === 403) {
                record.attempts++;
                record.lastAttempt = now;
            } else if (res.statusCode === 200) {
                // Reset on successful login
                record.attempts = 0;
            }
        });
        
        next();
    };
};

module.exports = {
    authRateLimit,
    passwordResetRateLimit,
    adminRateLimit,
    apiRateLimit,
    speedLimiter,
    sanitizeInput,
    securityHeaders,
    securityLogger,
    ipWhitelist,
    requestSizeLimiter,
    checkBruteForce
};