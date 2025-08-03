const mongoose = require('mongoose');

const deletedUserSchema = new mongoose.Schema({
    originalUserId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true
    },
    username: {
        type: String,
        required: [true, 'Username is required'],
        trim: true
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        trim: true,
        lowercase: true
    },
    deletedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    deletedByUsername: {
        type: String,
        required: true
    },
    deletionReason: {
        type: String,
        enum: ['admin_deletion', 'self_deletion', 'legacy_cleanup', 'bulk_deletion'],
        default: 'admin_deletion'
    },
    userCreatedAt: {
        type: Date,
        required: true
    },
    passwordCount: {
        type: Number,
        default: 0
    },
    lastLoginAt: {
        type: Date,
        default: null
    },
    metadata: {
        isAdmin: { type: Boolean, default: false },
        loginAttempts: { type: Number, default: 0 },
        twoFactorEnabled: { type: Boolean, default: false }
    }
}, {
    timestamps: true
});

// Indexes
deletedUserSchema.index({ username: 1 });
deletedUserSchema.index({ email: 1 });
deletedUserSchema.index({ deletedBy: 1 });
deletedUserSchema.index({ createdAt: -1 });
deletedUserSchema.index({ deletionReason: 1 });

// TTL index to automatically delete records after 1 year
deletedUserSchema.index({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });

// Static method to create deleted user record
deletedUserSchema.statics.createFromUser = async function(user, deletedBy, reason = 'admin_deletion', passwordCount = 0) {
    return this.create({
        originalUserId: user._id,
        username: user.username,
        email: user.email,
        deletedBy: deletedBy._id,
        deletedByUsername: deletedBy.username,
        deletionReason: reason,
        userCreatedAt: user.createdAt,
        passwordCount: passwordCount,
        lastLoginAt: user.lastLogin,
        metadata: {
            isAdmin: user.isAdmin,
            loginAttempts: user.loginAttempts,
            twoFactorEnabled: user.twoFactorEnabled
        }
    });
};

// Static method to check if user was deleted
deletedUserSchema.statics.wasDeleted = function(identifier) {
    return this.findOne({
        $or: [
            { username: identifier },
            { email: identifier.toLowerCase() }
        ]
    });
};

// Static method to get deletion history
deletedUserSchema.statics.getDeletionHistory = function(options = {}) {
    const query = {};
    
    if (options.deletedBy) query.deletedBy = options.deletedBy;
    if (options.reason) query.deletionReason = options.reason;
    if (options.dateFrom) query.createdAt = { $gte: options.dateFrom };
    if (options.dateTo) {
        query.createdAt = query.createdAt || {};
        query.createdAt.$lte = options.dateTo;
    }
    
    return this.find(query)
        .populate('deletedBy', 'username email')
        .sort({ createdAt: -1 })
        .limit(options.limit || 100);
};

module.exports = mongoose.model('DeletedUser', deletedUserSchema);