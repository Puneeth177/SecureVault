const express = require('express');
const { body, query, validationResult } = require('express-validator');
const User = require('../models/User');
const Password = require('../models/Password');
const DeletedUser = require('../models/DeletedUser');
const RestoredUser = require('../models/RestoredUser');
const { requireAdmin } = require('../middleware/auth');
const { asyncHandler, formatValidationErrors } = require('../middleware/errorHandler');

const router = express.Router();

// Apply admin middleware to all routes
router.use(requireAdmin);

/**
 * @route   GET /api/admin/stats
 * @desc    Get admin dashboard statistics
 * @access  Private (Admin only)
 */
router.get('/stats', asyncHandler(async (req, res) => {
    // User statistics
    const totalUsers = await User.countDocuments({ isActive: true });
    const adminUsers = await User.countDocuments({ isActive: true, isAdmin: true });
    const lockedUsers = await User.countDocuments({ 
        isActive: true, 
        lockUntil: { $gt: new Date() } 
    });
    const newUsersThisMonth = await User.countDocuments({
        isActive: true,
        createdAt: { $gte: new Date(new Date().setDate(1)) }
    });
    
    // Password statistics
    const totalPasswords = await Password.countDocuments();
    const compromisedPasswords = await Password.countDocuments({ isCompromised: true });
    const expiredPasswords = await Password.countDocuments({ 
        expiresAt: { $lt: new Date() } 
    });
    
    // Deletion and restoration statistics
    const deletedUsers = await DeletedUser.countDocuments();
    const restoredUsers = await RestoredUser.countDocuments();
    const deletionsThisMonth = await DeletedUser.countDocuments({
        createdAt: { $gte: new Date(new Date().setDate(1)) }
    });
    const restorationsThisMonth = await RestoredUser.countDocuments({
        createdAt: { $gte: new Date(new Date().setDate(1)) }
    });
    
    // Recent activity
    const recentUsers = await User.find({ isActive: true })
        .sort({ createdAt: -1 })
        .limit(5)
        .select('username email createdAt lastLogin');
    
    const recentDeletions = await DeletedUser.find()
        .populate('deletedBy', 'username')
        .sort({ createdAt: -1 })
        .limit(5);
    
    res.json({
        success: true,
        data: {
            users: {
                total: totalUsers,
                admins: adminUsers,
                locked: lockedUsers,
                newThisMonth: newUsersThisMonth
            },
            passwords: {
                total: totalPasswords,
                compromised: compromisedPasswords,
                expired: expiredPasswords
            },
            deletions: {
                total: deletedUsers,
                thisMonth: deletionsThisMonth
            },
            restorations: {
                total: restoredUsers,
                thisMonth: restorationsThisMonth
            },
            recent: {
                users: recentUsers,
                deletions: recentDeletions
            }
        }
    });
}));

/**
 * @route   GET /api/admin/users
 * @desc    Get all users with pagination and filtering
 * @access  Private (Admin only)
 */
router.get('/users', [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 100 }),
    query('search').optional().isLength({ min: 1, max: 100 }),
    query('isAdmin').optional().isBoolean(),
    query('isLocked').optional().isBoolean(),
    query('sort').optional().isIn(['createdAt', '-createdAt', 'username', '-username', 'lastLogin', '-lastLogin'])
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
        page = 1,
        limit = 20,
        search,
        isAdmin,
        isLocked,
        sort = '-createdAt'
    } = req.query;
    
    // Build query
    const query = { isActive: true };
    
    if (search) {
        query.$or = [
            { username: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } }
        ];
    }
    
    if (isAdmin !== undefined) {
        query.isAdmin = isAdmin === 'true';
    }
    
    if (isLocked === 'true') {
        query.lockUntil = { $gt: new Date() };
    } else if (isLocked === 'false') {
        query.$or = [
            { lockUntil: { $exists: false } },
            { lockUntil: { $lte: new Date() } }
        ];
    }
    
    // Execute query
    const users = await User.find(query)
        .sort(sort)
        .limit(parseInt(limit))
        .skip((parseInt(page) - 1) * parseInt(limit))
        .select('-password -twoFactorSecret');
    
    // Get total count
    const total = await User.countDocuments(query);
    
    // Get password counts for each user
    const usersWithPasswordCounts = await Promise.all(
        users.map(async (user) => {
            const passwordCount = await Password.countDocuments({ userId: user._id });
            return {
                ...user.toJSON(),
                passwordCount,
                isLocked: user.isLocked
            };
        })
    );
    
    res.json({
        success: true,
        data: {
            users: usersWithPasswordCounts,
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
 * @route   DELETE /api/admin/users/:id
 * @desc    Delete a user (admin action)
 * @access  Private (Admin only)
 */
router.delete('/users/:id', asyncHandler(async (req, res) => {
    const userId = req.params.id;
    
    // Prevent admin from deleting themselves
    if (userId === req.user._id.toString()) {
        return res.status(400).json({
            success: false,
            message: 'You cannot delete your own account'
        });
    }
    
    // Find the user
    const user = await User.findById(userId);
    if (!user || !user.isActive) {
        return res.status(404).json({
            success: false,
            message: 'User not found'
        });
    }
    
    // Get user's password count
    const passwordCount = await Password.countDocuments({ userId: user._id });
    
    // Create deleted user record
    await DeletedUser.createFromUser(user, req.user, 'admin_deletion', passwordCount);
    
    // Delete user's passwords
    await Password.deleteMany({ userId: user._id });
    
    // Deactivate user (soft delete)
    user.isActive = false;
    await user.save();
    
    res.json({
        success: true,
        message: 'User deleted successfully',
        data: {
            deletedUser: {
                id: user._id,
                username: user.username,
                email: user.email,
                passwordCount
            }
        }
    });
}));

/**
 * @route   DELETE /api/admin/users
 * @desc    Delete multiple users (bulk delete)
 * @access  Private (Admin only)
 */
router.delete('/users', [
    body('userIds')
        .isArray({ min: 1 })
        .withMessage('User IDs array is required')
        .custom((value) => {
            if (!value.every(id => typeof id === 'string' && id.length === 24)) {
                throw new Error('Invalid user ID format');
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
    
    const { userIds } = req.body;
    
    // Remove current admin from the list
    const filteredUserIds = userIds.filter(id => id !== req.user._id.toString());
    
    if (filteredUserIds.length === 0) {
        return res.status(400).json({
            success: false,
            message: 'No valid users to delete'
        });
    }
    
    // Find users to delete
    const users = await User.find({
        _id: { $in: filteredUserIds },
        isActive: true
    });
    
    let deletedCount = 0;
    
    // Process each user
    for (const user of users) {
        // Get user's password count
        const passwordCount = await Password.countDocuments({ userId: user._id });
        
        // Create deleted user record
        await DeletedUser.createFromUser(user, req.user, 'bulk_deletion', passwordCount);
        
        // Delete user's passwords
        await Password.deleteMany({ userId: user._id });
        
        // Deactivate user
        user.isActive = false;
        await user.save();
        
        deletedCount++;
    }
    
    res.json({
        success: true,
        message: `${deletedCount} user(s) deleted successfully`,
        data: {
            deletedCount,
            requestedCount: userIds.length,
            skippedCount: userIds.length - deletedCount
        }
    });
}));

/**
 * @route   GET /api/admin/deleted-users
 * @desc    Get deleted users history
 * @access  Private (Admin only)
 */
router.get('/deleted-users', [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 100 }),
    query('deletedBy').optional().isMongoId(),
    query('reason').optional().isIn(['admin_deletion', 'self_deletion', 'legacy_cleanup', 'bulk_deletion'])
], asyncHandler(async (req, res) => {
    const {
        page = 1,
        limit = 20,
        deletedBy,
        reason
    } = req.query;
    
    const options = {
        limit: parseInt(limit),
        skip: (parseInt(page) - 1) * parseInt(limit)
    };
    
    if (deletedBy) options.deletedBy = deletedBy;
    if (reason) options.reason = reason;
    
    const deletedUsers = await DeletedUser.getDeletionHistory(options);
    const total = await DeletedUser.countDocuments(
        deletedBy || reason ? { 
            ...(deletedBy && { deletedBy }), 
            ...(reason && { deletionReason: reason }) 
        } : {}
    );
    
    res.json({
        success: true,
        data: {
            deletedUsers,
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
 * @route   GET /api/admin/restored-users
 * @desc    Get restored users history
 * @access  Private (Admin only)
 */
router.get('/restored-users', [
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 100 }),
    query('method').optional().isIn(['self_registration', 'admin_restoration'])
], asyncHandler(async (req, res) => {
    const {
        page = 1,
        limit = 20,
        method
    } = req.query;
    
    const options = {
        limit: parseInt(limit),
        skip: (parseInt(page) - 1) * parseInt(limit)
    };
    
    if (method) options.method = method;
    
    const restoredUsers = await RestoredUser.getRestorationHistory(options);
    const total = await RestoredUser.countDocuments(
        method ? { restorationMethod: method } : {}
    );
    
    res.json({
        success: true,
        data: {
            restoredUsers,
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
 * @route   DELETE /api/admin/deleted-users
 * @desc    Clear deleted users history
 * @access  Private (Admin only)
 */
router.delete('/deleted-users', asyncHandler(async (req, res) => {
    const result = await DeletedUser.deleteMany({});
    
    res.json({
        success: true,
        message: 'Deleted users history cleared successfully',
        data: {
            deletedCount: result.deletedCount
        }
    });
}));

/**
 * @route   DELETE /api/admin/restored-users
 * @desc    Clear restored users history
 * @access  Private (Admin only)
 */
router.delete('/restored-users', asyncHandler(async (req, res) => {
    const result = await RestoredUser.deleteMany({});
    
    res.json({
        success: true,
        message: 'Restored users history cleared successfully',
        data: {
            deletedCount: result.deletedCount
        }
    });
}));

/**
 * @route   POST /api/admin/users/:id/unlock
 * @desc    Unlock a locked user account
 * @access  Private (Admin only)
 */
router.post('/users/:id/unlock', asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    
    if (!user || !user.isActive) {
        return res.status(404).json({
            success: false,
            message: 'User not found'
        });
    }
    
    // Reset login attempts and unlock
    await user.updateOne({
        $unset: { loginAttempts: 1, lockUntil: 1 }
    });
    
    res.json({
        success: true,
        message: 'User account unlocked successfully'
    });
}));

/**
 * @route   POST /api/admin/users/:id/toggle-admin
 * @desc    Toggle admin status for a user
 * @access  Private (Admin only)
 */
router.post('/users/:id/toggle-admin', asyncHandler(async (req, res) => {
    const userId = req.params.id;
    
    // Prevent admin from removing their own admin status
    if (userId === req.user._id.toString()) {
        return res.status(400).json({
            success: false,
            message: 'You cannot modify your own admin status'
        });
    }
    
    const user = await User.findById(userId);
    
    if (!user || !user.isActive) {
        return res.status(404).json({
            success: false,
            message: 'User not found'
        });
    }
    
    user.isAdmin = !user.isAdmin;
    await user.save();
    
    res.json({
        success: true,
        message: `User ${user.isAdmin ? 'promoted to' : 'demoted from'} admin successfully`,
        data: {
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                isAdmin: user.isAdmin
            }
        }
    });
}));

module.exports = router;