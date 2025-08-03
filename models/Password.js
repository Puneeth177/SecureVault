const mongoose = require('mongoose');
const { encrypt, decrypt } = require('../utils/encryption');

const passwordSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'User ID is required'],
        index: true
    },
    website: {
        type: String,
        required: [true, 'Website is required'],
        trim: true,
        maxlength: [200, 'Website name cannot exceed 200 characters']
    },
    username: {
        type: String,
        required: [true, 'Username is required'],
        trim: true,
        maxlength: [100, 'Username cannot exceed 100 characters']
    },
    encryptedPassword: {
        type: String,
        required: [true, 'Password is required']
    },
    iv: {
        type: String,
        required: [true, 'Initialization vector is required']
    },
    category: {
        type: String,
        enum: ['social', 'work', 'personal', 'financial', 'shopping', 'entertainment', 'other'],
        default: 'other'
    },
    notes: {
        type: String,
        maxlength: [500, 'Notes cannot exceed 500 characters'],
        default: ''
    },
    url: {
        type: String,
        maxlength: [500, 'URL cannot exceed 500 characters'],
        default: ''
    },
    isFavorite: {
        type: Boolean,
        default: false
    },
    lastAccessed: {
        type: Date,
        default: null
    },
    accessCount: {
        type: Number,
        default: 0
    },
    strength: {
        type: String,
        enum: ['weak', 'medium', 'strong', 'very-strong'],
        default: 'medium'
    },
    tags: [{
        type: String,
        trim: true,
        maxlength: [30, 'Tag cannot exceed 30 characters']
    }],
    expiresAt: {
        type: Date,
        default: null
    },
    isCompromised: {
        type: Boolean,
        default: false
    },
    compromisedAt: {
        type: Date,
        default: null
    }
}, {
    timestamps: true,
    toJSON: {
        transform: function(doc, ret) {
            delete ret.encryptedPassword;
            delete ret.iv;
            delete ret.__v;
            return ret;
        }
    }
});

// Indexes for performance
passwordSchema.index({ userId: 1, createdAt: -1 });
passwordSchema.index({ userId: 1, website: 1 });
passwordSchema.index({ userId: 1, category: 1 });
passwordSchema.index({ userId: 1, isFavorite: 1 });
passwordSchema.index({ userId: 1, tags: 1 });
passwordSchema.index({ expiresAt: 1 }, { sparse: true });

// Virtual for decrypted password (not stored in DB)
passwordSchema.virtual('password').get(function() {
    if (this.encryptedPassword && this.iv) {
        try {
            return decrypt(this.encryptedPassword, this.iv);
        } catch (error) {
            console.error('Password decryption failed:', error);
            return null;
        }
    }
    return null;
});

// Method to set encrypted password
passwordSchema.methods.setPassword = function(plainPassword) {
    try {
        const encrypted = encrypt(plainPassword);
        this.encryptedPassword = encrypted.encryptedData;
        this.iv = encrypted.iv;
        
        // Calculate password strength
        this.strength = this.calculatePasswordStrength(plainPassword);
        
        return true;
    } catch (error) {
        console.error('Password encryption failed:', error);
        return false;
    }
};

// Method to get decrypted password
passwordSchema.methods.getPassword = function() {
    try {
        if (this.encryptedPassword && this.iv) {
            // Update access tracking
            this.lastAccessed = new Date();
            this.accessCount += 1;
            this.save({ validateBeforeSave: false });
            
            return decrypt(this.encryptedPassword, this.iv);
        }
        return null;
    } catch (error) {
        console.error('Password decryption failed:', error);
        return null;
    }
};

// Method to calculate password strength
passwordSchema.methods.calculatePasswordStrength = function(password) {
    let score = 0;
    
    // Length check
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    
    // Character variety checks
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    
    // Pattern checks (reduce score for common patterns)
    if (/(.)\1{2,}/.test(password)) score -= 1; // Repeated characters
    if (/123|abc|qwe/i.test(password)) score -= 1; // Sequential patterns
    
    // Determine strength level
    if (score <= 2) return 'weak';
    if (score <= 4) return 'medium';
    if (score <= 6) return 'strong';
    return 'very-strong';
};

// Method to check if password is expired
passwordSchema.methods.isExpired = function() {
    return this.expiresAt && this.expiresAt < new Date();
};

// Method to mark as compromised
passwordSchema.methods.markAsCompromised = function() {
    this.isCompromised = true;
    this.compromisedAt = new Date();
    return this.save();
};

// Static method to find passwords by user
passwordSchema.statics.findByUser = function(userId, options = {}) {
    const query = { userId };
    
    if (options.category) query.category = options.category;
    if (options.isFavorite !== undefined) query.isFavorite = options.isFavorite;
    if (options.tags && options.tags.length > 0) query.tags = { $in: options.tags };
    
    let mongoQuery = this.find(query);
    
    if (options.sort) {
        mongoQuery = mongoQuery.sort(options.sort);
    } else {
        mongoQuery = mongoQuery.sort({ createdAt: -1 });
    }
    
    if (options.limit) mongoQuery = mongoQuery.limit(options.limit);
    if (options.skip) mongoQuery = mongoQuery.skip(options.skip);
    
    return mongoQuery;
};

// Static method to search passwords
passwordSchema.statics.searchByUser = function(userId, searchTerm) {
    return this.find({
        userId,
        $or: [
            { website: { $regex: searchTerm, $options: 'i' } },
            { username: { $regex: searchTerm, $options: 'i' } },
            { notes: { $regex: searchTerm, $options: 'i' } },
            { tags: { $regex: searchTerm, $options: 'i' } }
        ]
    }).sort({ createdAt: -1 });
};

// Pre-save middleware
passwordSchema.pre('save', function(next) {
    // Update timestamps
    if (this.isNew) {
        this.lastAccessed = null;
        this.accessCount = 0;
    }
    
    next();
});

module.exports = mongoose.model('Password', passwordSchema);