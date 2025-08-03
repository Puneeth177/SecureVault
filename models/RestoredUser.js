const mongoose = require('mongoose');

const restoredUserSchema = new mongoose.Schema({
    newUserId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
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
    originalDeletedAt: {
        type: Date,
        required: true
    },
    deletedByUsername: {
        type: String,
        required: true
    },
    restorationMethod: {
        type: String,
        enum: ['self_registration', 'admin_restoration'],
        default: 'self_registration'
    },
    previousPasswordCount: {
        type: Number,
        default: 0
    },
    timeBetweenDeletionAndRestoration: {
        type: Number, // in milliseconds
        required: true
    }
}, {
    timestamps: true
});

// Indexes
restoredUserSchema.index({ username: 1 });
restoredUserSchema.index({ email: 1 });
restoredUserSchema.index({ newUserId: 1 });
restoredUserSchema.index({ createdAt: -1 });
restoredUserSchema.index({ restorationMethod: 1 });

// TTL index to automatically delete records after 1 year
restoredUserSchema.index({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });

// Virtual for restoration time in human readable format
restoredUserSchema.virtual('restorationTimeFormatted').get(function() {
    const ms = this.timeBetweenDeletionAndRestoration;
    const days = Math.floor(ms / (24 * 60 * 60 * 1000));
    const hours = Math.floor((ms % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
    const minutes = Math.floor((ms % (60 * 60 * 1000)) / (60 * 1000));
    
    if (days > 0) return `${days} days, ${hours} hours`;
    if (hours > 0) return `${hours} hours, ${minutes} minutes`;
    return `${minutes} minutes`;
});

// Static method to create restoration record
restoredUserSchema.statics.createFromDeletion = async function(newUser, deletedUserRecord, method = 'self_registration') {
    const timeDiff = new Date() - deletedUserRecord.createdAt;
    
    return this.create({
        newUserId: newUser._id,
        username: newUser.username,
        email: newUser.email,
        originalDeletedAt: deletedUserRecord.createdAt,
        deletedByUsername: deletedUserRecord.deletedByUsername,
        restorationMethod: method,
        previousPasswordCount: deletedUserRecord.passwordCount || 0,
        timeBetweenDeletionAndRestoration: timeDiff
    });
};

// Static method to get restoration history
restoredUserSchema.statics.getRestorationHistory = function(options = {}) {
    const query = {};
    
    if (options.method) query.restorationMethod = options.method;
    if (options.dateFrom) query.createdAt = { $gte: options.dateFrom };
    if (options.dateTo) {
        query.createdAt = query.createdAt || {};
        query.createdAt.$lte = options.dateTo;
    }
    
    return this.find(query)
        .populate('newUserId', 'username email')
        .sort({ createdAt: -1 })
        .limit(options.limit || 100);
};

// Static method to get restoration statistics
restoredUserSchema.statics.getRestorationStats = async function() {
    const stats = await this.aggregate([
        {
            $group: {
                _id: '$restorationMethod',
                count: { $sum: 1 },
                avgRestorationTime: { $avg: '$timeBetweenDeletionAndRestoration' }
            }
        }
    ]);
    
    const totalRestorations = await this.countDocuments();
    const recentRestorations = await this.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } // Last 30 days
    });
    
    return {
        total: totalRestorations,
        recent: recentRestorations,
        byMethod: stats
    };
};

module.exports = mongoose.model('RestoredUser', restoredUserSchema);