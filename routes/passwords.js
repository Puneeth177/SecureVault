const express = require('express');
const { body, query, validationResult } = require('express-validator');
const Password = require('../models/Password');
const { asyncHandler, formatValidationErrors } = require('../middleware/errorHandler');
const { generateSecurePassword } = require('../utils/encryption');

const router = express.Router();

// Validation rules
const passwordValidation = [
    body('website')
        .notEmpty()
        .withMessage('Website is required')
        .isLength({ max: 200 })
        .withMessage('Website name cannot exceed 200 characters'),
    body('username')
        .notEmpty()
        .withMessage('Username is required')
        .isLength({ max: 100 })
        .withMessage('Username cannot exceed 100 characters'),
    body('password')
        .notEmpty()
        .withMessage('Password is required'),
    body('category')
        .optional()
        .isIn(['social', 'work', 'personal', 'financial', 'shopping', 'entertainment', 'other'])
        .withMessage('Invalid category'),
    body('notes')
        .optional()
        .isLength({ max: 500 })
        .withMessage('Notes cannot exceed 500 characters'),
    body('url')
        .optional()
        .isLength({ max: 500 })
        .withMessage('URL cannot exceed 500 characters'),
    body('tags')
        .optional()
        .isArray()
        .withMessage('Tags must be an array'),
    body('tags.*')
        .optional()
        .isLength({ max: 30 })
        .withMessage('Each tag cannot exceed 30 characters')
];

/**
 * @route   GET /api/passwords
 * @desc    Get all passwords for the authenticated user
 * @access  Private
 */
router.get('/', [
    query('category').optional().isIn(['social', 'work', 'personal', 'financial', 'shopping', 'entertainment', 'other']),
    query('favorite').optional().isBoolean(),
    query('search').optional().isLength({ min: 1, max: 100 }),
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 100 }),
    query('sort').optional().isIn(['createdAt', '-createdAt', 'website', '-website', 'lastAccessed', '-lastAccessed'])
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
    
    const {
        category,
        favorite,
        search,
        page = 1,
        limit = 50,
        sort = '-createdAt'
    } = req.query;
    
    const options = {
        sort: sort,
        limit: parseInt(limit),
        skip: (parseInt(page) - 1) * parseInt(limit)
    };
    
    if (category) options.category = category;
    if (favorite !== undefined) options.isFavorite = favorite === 'true';
    
    let passwords;
    
    if (search) {
        passwords = await Password.searchByUser(req.userId, search);
        // Add decrypted passwords for search results
        passwords = passwords.map(password => ({
            ...password.toJSON(),
            password: password.getPassword()
        }));
    } else {
        // Get passwords with decrypted passwords
        passwords = await Password.findByUser(req.userId, options);
        const passwordsWithDecrypted = passwords.map(password => ({
            ...password.toJSON(),
            password: password.getPassword()
        }));
        passwords = passwordsWithDecrypted;
    }
    
    // Get total count for pagination
    const total = await Password.countDocuments({ userId: req.userId });
    
    res.json({
        success: true,
        data: {
            passwords,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / parseInt(limit))
            }
        }
    });
}));

/**
 * @route   GET /api/passwords/:id
 * @desc    Get a specific password (with decrypted password)
 * @access  Private
 */
router.get('/:id', asyncHandler(async (req, res) => {
    const password = await Password.findOne({
        _id: req.params.id,
        userId: req.userId
    });
    
    if (!password) {
        return res.status(404).json({
            success: false,
            message: 'Password not found'
        });
    }
    
    // Get decrypted password
    const decryptedPassword = password.getPassword();
    
    res.json({
        success: true,
        data: {
            password: {
                ...password.toJSON(),
                password: decryptedPassword
            }
        }
    });
}));

/**
 * @route   POST /api/passwords
 * @desc    Create a new password entry
 * @access  Private
 */
router.post('/', passwordValidation, asyncHandler(async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: formatValidationErrors(errors)
        });
    }
    
    const {
        website,
        username,
        password,
        category = 'other',
        notes = '',
        url = '',
        tags = [],
        isFavorite = false,
        expiresAt
    } = req.body;
    
    // Create new password entry
    const passwordEntry = new Password({
        userId: req.userId,
        website,
        username,
        category,
        notes,
        url,
        tags,
        isFavorite,
        expiresAt
    });
    
    // Set encrypted password
    const encryptionSuccess = passwordEntry.setPassword(password);
    if (!encryptionSuccess) {
        return res.status(500).json({
            success: false,
            message: 'Failed to encrypt password'
        });
    }
    
    await passwordEntry.save();
    
    res.status(201).json({
        success: true,
        message: 'Password saved successfully',
        data: {
            password: passwordEntry
        }
    });
}));

/**
 * @route   PUT /api/passwords/:id
 * @desc    Update a password entry
 * @access  Private
 */
router.put('/:id', passwordValidation, asyncHandler(async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: formatValidationErrors(errors)
        });
    }
    
    const password = await Password.findOne({
        _id: req.params.id,
        userId: req.userId
    });
    
    if (!password) {
        return res.status(404).json({
            success: false,
            message: 'Password not found'
        });
    }
    
    const {
        website,
        username,
        password: newPassword,
        category,
        notes,
        url,
        tags,
        isFavorite,
        expiresAt
    } = req.body;
    
    // Update fields
    password.website = website;
    password.username = username;
    password.category = category || password.category;
    password.notes = notes !== undefined ? notes : password.notes;
    password.url = url !== undefined ? url : password.url;
    password.tags = tags || password.tags;
    password.isFavorite = isFavorite !== undefined ? isFavorite : password.isFavorite;
    password.expiresAt = expiresAt !== undefined ? expiresAt : password.expiresAt;
    
    // Update password if provided
    if (newPassword) {
        const encryptionSuccess = password.setPassword(newPassword);
        if (!encryptionSuccess) {
            return res.status(500).json({
                success: false,
                message: 'Failed to encrypt password'
            });
        }
    }
    
    await password.save();
    
    res.json({
        success: true,
        message: 'Password updated successfully',
        data: {
            password
        }
    });
}));

/**
 * @route   DELETE /api/passwords/:id
 * @desc    Delete a password entry
 * @access  Private
 */
router.delete('/:id', asyncHandler(async (req, res) => {
    const password = await Password.findOne({
        _id: req.params.id,
        userId: req.userId
    });
    
    if (!password) {
        return res.status(404).json({
            success: false,
            message: 'Password not found'
        });
    }
    
    await Password.deleteOne({ _id: password._id });
    
    res.json({
        success: true,
        message: 'Password deleted successfully'
    });
}));

/**
 * @route   DELETE /api/passwords
 * @desc    Delete multiple password entries
 * @access  Private
 */
router.delete('/', [
    body('passwordIds')
        .isArray({ min: 1 })
        .withMessage('Password IDs array is required')
        .custom((value) => {
            if (!value.every(id => typeof id === 'string' && id.length === 24)) {
                throw new Error('Invalid password ID format');
            }
            return true;
        })
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
    
    const { passwordIds } = req.body;
    
    const result = await Password.deleteMany({
        _id: { $in: passwordIds },
        userId: req.userId
    });
    
    res.json({
        success: true,
        message: `${result.deletedCount} password(s) deleted successfully`,
        data: {
            deletedCount: result.deletedCount
        }
    });
}));

/**
 * @route   POST /api/passwords/generate
 * @desc    Generate a secure password
 * @access  Private
 */
router.post('/generate', [
    body('length').optional().isInt({ min: 8, max: 128 }).withMessage('Length must be between 8 and 128'),
    body('includeUppercase').optional().isBoolean(),
    body('includeLowercase').optional().isBoolean(),
    body('includeNumbers').optional().isBoolean(),
    body('includeSymbols').optional().isBoolean(),
    body('excludeSimilar').optional().isBoolean(),
    body('excludeAmbiguous').optional().isBoolean()
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
    
    const {
        length = 16,
        includeUppercase = true,
        includeLowercase = true,
        includeNumbers = true,
        includeSymbols = true,
        excludeSimilar = true,
        excludeAmbiguous = true
    } = req.body;
    
    try {
        const password = generateSecurePassword(length, {
            includeUppercase,
            includeLowercase,
            includeNumbers,
            includeSymbols,
            excludeSimilar,
            excludeAmbiguous
        });
        
        res.json({
            success: true,
            data: {
                password
            }
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            message: error.message
        });
    }
}));

/**
 * @route   GET /api/passwords/stats
 * @desc    Get password statistics for the user
 * @access  Private
 */
router.get('/stats/overview', asyncHandler(async (req, res) => {
    const userId = req.userId;
    
    // Get basic counts
    const totalPasswords = await Password.countDocuments({ userId });
    const favoritePasswords = await Password.countDocuments({ userId, isFavorite: true });
    const expiredPasswords = await Password.countDocuments({ 
        userId, 
        expiresAt: { $lt: new Date() } 
    });
    const compromisedPasswords = await Password.countDocuments({ userId, isCompromised: true });
    
    // Get category breakdown
    const categoryStats = await Password.aggregate([
        { $match: { userId: req.userId } },
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
    ]);
    
    // Get strength breakdown
    const strengthStats = await Password.aggregate([
        { $match: { userId: req.userId } },
        { $group: { _id: '$strength', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
    ]);
    
    // Get recent activity
    const recentPasswords = await Password.find({ userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .select('website username createdAt');
    
    res.json({
        success: true,
        data: {
            overview: {
                total: totalPasswords,
                favorites: favoritePasswords,
                expired: expiredPasswords,
                compromised: compromisedPasswords
            },
            categories: categoryStats,
            strength: strengthStats,
            recent: recentPasswords
        }
    });
}));

module.exports = router;