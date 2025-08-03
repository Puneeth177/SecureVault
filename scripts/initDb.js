const mongoose = require('mongoose');
const User = require('../models/User');
require('dotenv').config();

async function initializeDatabase() {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        
        console.log('✅ Connected to MongoDB');
        
        // Check if admin user exists
        const adminExists = await User.findOne({ isAdmin: true });
        
        if (!adminExists) {
            // Create default admin user
            const adminUser = new User({
                username: 'admin',
                email: 'admin@securevault.local',
                password: process.env.ADMIN_PASSWORD || 'SecureVault2024!',
                isAdmin: true
            });
            
            await adminUser.save();
            console.log('✅ Default admin user created');
            console.log('   Username: admin');
            console.log('   Email: admin@securevault.local');
            console.log('   Password: SecureVault2024!');
            console.log('   ⚠️  Please change the admin password after first login!');
        } else {
            console.log('ℹ️  Admin user already exists');
        }
        
        // Create indexes for better performance
        await User.createIndexes();
        console.log('✅ User indexes created');
        
        const Password = require('../models/Password');
        await Password.createIndexes();
        console.log('✅ Password indexes created');
        
        const DeletedUser = require('../models/DeletedUser');
        await DeletedUser.createIndexes();
        console.log('✅ DeletedUser indexes created');
        
        const RestoredUser = require('../models/RestoredUser');
        await RestoredUser.createIndexes();
        console.log('✅ RestoredUser indexes created');
        
        console.log('🎉 Database initialization complete!');
        
    } catch (error) {
        console.error('❌ Database initialization failed:', error);
        process.exit(1);
    } finally {
        await mongoose.connection.close();
        console.log('📦 Database connection closed');
    }
}

// Run initialization
initializeDatabase();