const mongoose = require('mongoose');
require('dotenv').config();

// Import models
const User = require('../models/User');
const Password = require('../models/Password');
const DeletedUser = require('../models/DeletedUser');
const RestoredUser = require('../models/RestoredUser');

async function viewDatabaseData() {
    try {
        console.log('🔄 Connecting to MongoDB Atlas...\n');
        
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Connected to MongoDB Atlas!\n');
        
        // View Users
        console.log('👥 USERS:');
        console.log('=' .repeat(50));
        const users = await User.find({}).select('-password').sort({ createdAt: -1 });
        if (users.length === 0) {
            console.log('   No users found');
        } else {
            users.forEach((user, index) => {
                console.log(`   ${index + 1}. Username: ${user.username}`);
                console.log(`      Email: ${user.email}`);
                console.log(`      Created: ${user.createdAt}`);
                console.log(`      Last Login: ${user.lastLogin || 'Never'}`);
                console.log(`      Active: ${user.isActive ? 'Yes' : 'No'}`);
                console.log(`      Admin: ${user.isAdmin ? 'Yes' : 'No'}`);
                console.log('');
            });
        }
        
        // View Passwords (encrypted data only, not decrypted for security)
        console.log('🔐 PASSWORDS:');
        console.log('=' .repeat(50));
        const passwords = await Password.find({}).populate('userId', 'username').sort({ createdAt: -1 });
        if (passwords.length === 0) {
            console.log('   No passwords found');
        } else {
            passwords.forEach((password, index) => {
                console.log(`   ${index + 1}. Website: ${password.website}`);
                console.log(`      Username: ${password.username}`);
                console.log(`      Owner: ${password.userId ? password.userId.username : 'Unknown'}`);
                console.log(`      Category: ${password.category}`);
                console.log(`      Strength: ${password.strength}`);
                console.log(`      Favorite: ${password.isFavorite ? 'Yes' : 'No'}`);
                console.log(`      Created: ${password.createdAt}`);
                console.log(`      Last Accessed: ${password.lastAccessed || 'Never'}`);
                console.log(`      Access Count: ${password.accessCount}`);
                if (password.notes) console.log(`      Notes: ${password.notes}`);
                if (password.url) console.log(`      URL: ${password.url}`);
                if (password.tags && password.tags.length > 0) console.log(`      Tags: ${password.tags.join(', ')}`);
                console.log('');
            });
        }
        
        // View Deleted Users
        console.log('🗑️  DELETED USERS:');
        console.log('=' .repeat(50));
        const deletedUsers = await DeletedUser.find({}).sort({ deletedAt: -1 });
        if (deletedUsers.length === 0) {
            console.log('   No deleted users found');
        } else {
            deletedUsers.forEach((user, index) => {
                console.log(`   ${index + 1}. Username: ${user.username}`);
                console.log(`      Email: ${user.email || 'N/A'}`);
                console.log(`      Deleted At: ${user.deletedAt}`);
                console.log(`      Deleted By: ${user.deletedBy}`);
                console.log('');
            });
        }
        
        // View Restored Users
        console.log('🔄 RESTORED USERS:');
        console.log('=' .repeat(50));
        const restoredUsers = await RestoredUser.find({}).sort({ restoredAt: -1 });
        if (restoredUsers.length === 0) {
            console.log('   No restored users found');
        } else {
            restoredUsers.forEach((user, index) => {
                console.log(`   ${index + 1}. Username: ${user.username}`);
                console.log(`      Email: ${user.email || 'N/A'}`);
                console.log(`      Restored At: ${user.restoredAt}`);
                console.log(`      Restored By: ${user.restoredBy}`);
                console.log('');
            });
        }
        
        // Database Statistics
        console.log('📊 DATABASE STATISTICS:');
        console.log('=' .repeat(50));
        console.log(`   Total Users: ${users.length}`);
        console.log(`   Total Passwords: ${passwords.length}`);
        console.log(`   Total Deleted Users: ${deletedUsers.length}`);
        console.log(`   Total Restored Users: ${restoredUsers.length}`);
        
        // Collection Information
        console.log('\n📁 COLLECTION INFORMATION:');
        console.log('=' .repeat(50));
        const collections = await mongoose.connection.db.listCollections().toArray();
        for (const collection of collections) {
            const stats = await mongoose.connection.db.collection(collection.name).stats();
            console.log(`   ${collection.name}:`);
            console.log(`      Documents: ${stats.count}`);
            console.log(`      Size: ${(stats.size / 1024).toFixed(2)} KB`);
            console.log(`      Indexes: ${stats.nindexes}`);
            console.log('');
        }
        
    } catch (error) {
        console.error('❌ Error viewing data:', error.message);
    } finally {
        await mongoose.connection.close();
        console.log('📦 Database connection closed');
        process.exit(0);
    }
}

// Run viewer if this file is executed directly
if (require.main === module) {
    viewDatabaseData();
}

module.exports = { viewDatabaseData };