const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const DeletedUser = require('../models/DeletedUser');
const RestoredUser = require('../models/RestoredUser');
const { generateToken, generateRefreshToken, verifyRefreshToken, authRateLimit } = require('../middleware/auth');
const { asyncHandler, formatValidationErrors } = require('../middleware/errorHandler');

const router = express.Router();

// Validation rules
const registerValidation = [
    body('username')
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be between 3 and 30 characters')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username can only contain letters, numbers, and underscores'),
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
];

const loginValidation = [
    body('identifier')
        .notEmpty()
        .withMessage('Username or email is required'),
    body('password')
        .notEmpty()
        .withMessage('Password is required')
];

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', authRateLimit, registerValidation, asyncHandler(async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: formatValidationErrors(errors)
        });
    }
    
    const { username, email, password } = req.body;
    
    try {
        // Check if username or email already exists in active users
        const existingUser = await User.findOne({
            $or: [
                { username: username },
                { email: email.toLowerCase() }
            ],
            isActive: true
        });
        
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Username or email already exists'
            });
        }
        
        // Check if user was previously deleted
        const deletedUser = await DeletedUser.wasDeleted(username) || await DeletedUser.wasDeleted(email);
        
        // Create new user
        const user = new User({
            username,
            email,
            password
        });
        
        await user.save();
        
        // If user was previously deleted, create restoration record and remove from deleted users
        if (deletedUser) {
            await RestoredUser.createFromDeletion(user, deletedUser, 'self_registration');
            await DeletedUser.deleteOne({ _id: deletedUser._id });
            
            console.log(`🔄 User restored from deletion: ${username} (${email})`);
        }
        
        // Generate tokens
        const token = generateToken(user._id);
        const refreshToken = generateRefreshToken(user._id);
        
        // Update last login
        user.lastLogin = new Date();
        await user.save({ validateBeforeSave: false });
        
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            data: {
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    isAdmin: user.isAdmin,
                    createdAt: user.createdAt
                },
                token,
                refreshToken
            }
        });
    } catch (error) {
        // Handle duplicate key errors
        if (error.code === 11000) {
            const duplicateField = Object.keys(error.keyPattern)[0];
            return res.status(400).json({
                success: false,
                message: `${duplicateField.charAt(0).toUpperCase() + duplicateField.slice(1)} already exists`
            });
        }
        
        // Re-throw other errors
        throw error;
    }
}));

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', authRateLimit, loginValidation, asyncHandler(async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: formatValidationErrors(errors)
        });
    }
    
    const { identifier, password } = req.body;
    
    // Check if user was deleted
    const deletedUser = await DeletedUser.wasDeleted(identifier);
    if (deletedUser) {
        return res.status(403).json({
            success: false,
            message: '🚫 Your account has been removed by the administrator. Please contact support if you believe this is an error.',
            deletedAt: deletedUser.createdAt,
            deletedBy: deletedUser.deletedByUsername
        });
    }
    
    // Find user by username or email
    const user = await User.findByIdentifier(identifier).select('+password');
    
    if (!user) {
        return res.status(401).json({
            success: false,
            message: 'Invalid credentials'
        });
    }
    
    // Check if account is locked
    if (user.isLocked) {
        return res.status(423).json({
            success: false,
            message: 'Account is temporarily locked due to multiple failed login attempts. Please try again later.',
            lockUntil: user.lockUntil
        });
    }
    
    // Check password
    const isPasswordValid = await user.comparePassword(password);
    
    if (!isPasswordValid) {
        // Increment login attempts
        await user.incLoginAttempts();
        
        return res.status(401).json({
            success: false,
            message: 'Invalid credentials'
        });
    }
    
    // Reset login attempts and update last login
    await user.resetLoginAttempts();
    
    // Generate tokens
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    
    res.json({
        success: true,
        message: 'Login successful',
        data: {
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                isAdmin: user.isAdmin,
                lastLogin: user.lastLogin,
                createdAt: user.createdAt
            },
            token,
            refreshToken
        }
    });
}));

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token
 * @access  Public
 */
router.post('/refresh', asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
        return res.status(401).json({
            success: false,
            message: 'Refresh token is required'
        });
    }
    
    try {
        const decoded = verifyRefreshToken(refreshToken);
        
        // Check if user still exists
        const user = await User.findById(decoded.userId);
        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'User no longer exists or is inactive'
            });
        }
        
        // Generate new tokens
        const newToken = generateToken(user._id);
        const newRefreshToken = generateRefreshToken(user._id);
        
        res.json({
            success: true,
            message: 'Token refreshed successfully',
            data: {
                token: newToken,
                refreshToken: newRefreshToken
            }
        });
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'Invalid refresh token'
        });
    }
}));

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Reset password (simplified version)
 * @access  Public
 */
router.post('/forgot-password', authRateLimit, [
    body('username').notEmpty().withMessage('Username is required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('newPassword')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
], asyncHandler(async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: formatValidationErrors(errors)
        });
    }
    
    const { username, email, newPassword } = req.body;
    
    // Find user by username and email
    const user = await User.findOne({ 
        username, 
        email: email.toLowerCase(),
        isActive: true 
    });
    
    if (!user) {
        return res.status(404).json({
            success: false,
            message: 'User not found or email does not match'
        });
    }
    
    // Update password
    user.password = newPassword;
    await user.save();
    
    res.json({
        success: true,
        message: 'Password updated successfully'
    });
}));

/**
 * @route   DELETE /api/auth/delete-account
 * @desc    Delete user account
 * @access  Public
 */
router.delete('/delete-account', authRateLimit, [
    body('username').notEmpty().withMessage('Username is required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required')
], asyncHandler(async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: formatValidationErrors(errors)
        });
    }
    
    const { username, email, password } = req.body;
    
    // Find user by username and email
    const user = await User.findOne({ 
        username, 
        email: email.toLowerCase(),
        isActive: true 
    }).select('+password');
    
    if (!user) {
        return res.status(404).json({
            success: false,
            message: 'User not found or credentials do not match'
        });
    }
    
    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
        return res.status(401).json({
            success: false,
            message: 'Invalid password'
        });
    }
    
    // Create deletion record
    await DeletedUser.createFromUser(user, user, 'self_deletion');
    
    // Delete user's passwords
    const Password = require('../models/Password');
    await Password.deleteMany({ userId: user._id });
    
    // Delete user
    await User.deleteOne({ _id: user._id });
    
    res.json({
        success: true,
        message: 'Account deleted successfully'
    });
}));

/**
 * @route   GET /api/auth/me
 * @desc    Get current user info
 * @access  Private
 */
router.get('/me', require('../middleware/auth').authenticateToken, asyncHandler(async (req, res) => {
    res.json({
        success: true,
        data: {
            user: {
                id: req.user._id,
                username: req.user.username,
                email: req.user.email,
                isAdmin: req.user.isAdmin,
                lastLogin: req.user.lastLogin,
                createdAt: req.user.createdAt,
                twoFactorEnabled: req.user.twoFactorEnabled
            }
        }
    });
}));

/**
 * @route   POST /api/auth/check-username
 * @desc    Check if username is available
 * @access  Public
 */
router.post('/check-username', asyncHandler(async (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({
            success: false,
            message: 'Username is required'
        });
    }
    
    // Check if username already exists
    const existingUser = await User.findOne({ username });
    
    if (existingUser) {
        return res.json({
            success: false,
            message: 'Username already exists'
        });
    }
    
    res.json({
        success: true,
        message: 'Username is available'
    });
}));

/**
 * @route   POST /api/auth/check-email
 * @desc    Check if email is available
 * @access  Public
 */
router.post('/check-email', asyncHandler(async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({
            success: false,
            message: 'Email is required'
        });
    }
    
    // Check if email already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    
    if (existingUser) {
        return res.json({
            success: false,
            message: 'Email already exists'
        });
    }
    
    res.json({
        success: true,
        message: 'Email is available'
    });
}));

/**
 * @route   POST /api/auth/verify-admin
 * @desc    Verify a password against any admin account to get a temporary admin token
 * @access  Public
 */
router.post('/verify-admin', authRateLimit, [
    body('password').notEmpty().withMessage('Password is required')
], asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: formatValidationErrors(errors)
        });
    }

    const { password } = req.body;

    // Find all admin users, including those who may have been "deleted" (soft delete, isActive: false).
    // This is crucial for the recovery scenario where an admin might have been accidentally deleted.
    const adminUsers = await User.find({ isAdmin: true }).select('+password');

    if (!adminUsers || adminUsers.length === 0) {
        return res.status(403).json({ success: false, message: 'No admin accounts configured.' });
    }

    let passwordMatch = false;
    let matchedAdmin = null;
    for (const admin of adminUsers) {
        const isMatch = await admin.comparePassword(password);
        if (isMatch) {
            passwordMatch = true;
            matchedAdmin = admin;
            break;
        }
    }

    if (!passwordMatch) {
        return res.status(401).json({ success: false, message: 'Incorrect admin password' });
    }

    // Generate a short-lived admin token (e.g., 5 minutes)
    const adminToken = generateToken(matchedAdmin._id, '5m');

    res.json({
        success: true,
        message: 'Admin password verified successfully.',
        data: {
            adminToken
        }
    });
}));

module.exports = router;
