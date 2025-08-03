const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * Middleware to authenticate JWT tokens
 */
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
        
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access token is required'
            });
        }
        
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if user still exists
        const user = await User.findById(decoded.userId).select('+passwordChangedAt');
        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'User no longer exists or is inactive'
            });
        }
        
        // Check if user is locked
        if (user.isLocked) {
            return res.status(423).json({
                success: false,
                message: 'Account is temporarily locked due to multiple failed login attempts'
            });
        }
        
        // Check if password was changed after token was issued
        if (user.changedPasswordAfter(decoded.iat)) {
            return res.status(401).json({
                success: false,
                message: 'Password was recently changed. Please log in again.'
            });
        }
        
        // Check token expiration (additional check)
        if (decoded.exp < Date.now() / 1000) {
            return res.status(401).json({
                success: false,
                message: 'Token has expired'
            });
        }
        
        // Add user to request object
        req.user = user;
        req.userId = user._id;
        
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token has expired'
            });
        }
        
        return res.status(500).json({
            success: false,
            message: 'Authentication failed'
        });
    }
};

/**
 * Middleware to check if user is admin
 */
const requireAdmin = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }
        
        if (!req.user.isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Admin privileges required'
            });
        }
        
        next();
    } catch (error) {
        console.error('Admin check error:', error);
        return res.status(500).json({
            success: false,
            message: 'Authorization check failed'
        });
    }
};

/**
 * Generate JWT token for user
 */
const generateToken = (userId, expiresIn = '24h') => {
    return jwt.sign(
        { 
            userId,
            iat: Math.floor(Date.now() / 1000)
        },
        process.env.JWT_SECRET,
        { 
            expiresIn,
            issuer: 'SecureVault',
            audience: 'SecureVault-Users'
        }
    );
};

/**
 * Generate refresh token
 */
const generateRefreshToken = (userId) => {
    return jwt.sign(
        { 
            userId,
            type: 'refresh',
            iat: Math.floor(Date.now() / 1000)
        },
        process.env.JWT_SECRET,
        { 
            expiresIn: '7d',
            issuer: 'SecureVault',
            audience: 'SecureVault-Users'
        }
    );
};

/**
 * Verify refresh token
 */
const verifyRefreshToken = (token) => {
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.type !== 'refresh') {
            throw new Error('Invalid token type');
        }
        
        return decoded;
    } catch (error) {
        throw new Error('Invalid refresh token');
    }
};

/**
 * Middleware for optional authentication (doesn't fail if no token)
 */
const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return next();
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (user && user.isActive && !user.isLocked) {
            req.user = user;
            req.userId = user._id;
        }
        
        next();
    } catch (error) {
        // Continue without authentication
        next();
    }
};

/**
 * Rate limiting for authentication endpoints
 */
const authRateLimit = require('express-rate-limit')({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs for auth endpoints
    message: {
        success: false,
        message: 'Too many authentication attempts, please try again later.',
        retryAfter: 15 * 60 // 15 minutes in seconds
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for successful requests
        return req.method === 'GET' || (req.body && req.body.success);
    }
});

module.exports = {
    authenticateToken,
    requireAdmin,
    generateToken,
    generateRefreshToken,
    verifyRefreshToken,
    optionalAuth,
    authRateLimit
};