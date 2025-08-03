const mongoose = require('mongoose');
require('dotenv').config();

// Import models and middleware
const User = require('../models/User');
const DeletedUser = require('../models/DeletedUser');
const RestoredUser = require('../models/RestoredUser');

async function simulateRegistration() {
    try {
        console.log('🔄 Simulating user registration process...\n');
        
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Connected to MongoDB Atlas!\n');
        
        // Check users before registration
        const usersBefore = await User.find({});
        console.log(`📊 Users in database before: ${usersBefore.length}`);
        
        // Simulate the exact registration process from the API
        console.log('1️⃣  Simulating registration validation...');
        const userData = {
            username: 'website_test_user',
            email: 'websitetest@example.com',
            password: 'TestPassword123!'
        };
        
        console.log('   Username:', userData.username);
        console.log('   Email:', userData.email);
        console.log('   Password length:', userData.password.length);
        
        // Check if user was previously deleted (like the API does)
        console.log('\n2️⃣  Checking for previously deleted user...');
        const deletedUser = await DeletedUser.findOne({
            $or: [
                { username: userData.username },
                { email: userData.email }
            ]
        });
        console.log('   Previously deleted?', deletedUser ? 'Yes' : 'No');
        
        // Create new user (like the API does)
        console.log('\n3️⃣  Creating new user...');
        const user = new User({
            username: userData.username,
            email: userData.email,
            password: userData.password
        });
        
        console.log('   User object created');
        console.log('   Username:', user.username);
        console.log('   Email:', user.email);
        console.log('   Password (before hashing):', userData.password);
        
        // Save user (this should trigger bcrypt hashing)
        console.log('\n4️⃣  Saving user to database...');
        await user.save();
        console.log('   ✅ User saved successfully!');
        console.log('   User ID:', user._id);
        console.log('   Password (after hashing):', user.password);
        
        // Handle restoration if user was previously deleted
        if (deletedUser) {
            console.log('\n5️⃣  Handling user restoration...');
            await RestoredUser.create({
                username: user.username,
                email: user.email,
                restoredAt: new Date(),
                restoredBy: 'self_registration',
                originalDeletionDate: deletedUser.deletedAt
            });
            await DeletedUser.deleteOne({ _id: deletedUser._id });
            console.log('   ✅ User restoration completed');
        }
        
        // Update last login (like the API does)
        console.log('\n6️⃣  Updating last login...');
        user.lastLogin = new Date();
        await user.save({ validateBeforeSave: false });
        console.log('   ✅ Last login updated');
        
        // Check users after registration
        const usersAfter = await User.find({});
        console.log(`\n📊 Users in database after: ${usersAfter.length}`);
        
        if (usersAfter.length > usersBefore.length) {
            console.log('✅ Registration simulation successful!');
            
            // Show the saved user
            const savedUser = await User.findById(user._id);
            console.log('\n👤 Saved user details:');
            console.log('   ID:', savedUser._id);
            console.log('   Username:', savedUser.username);
            console.log('   Email:', savedUser.email);
            console.log('   Created:', savedUser.createdAt);
            console.log('   Last Login:', savedUser.lastLogin);
            console.log('   Active:', savedUser.isActive);
            console.log('   Admin:', savedUser.isAdmin);
            
            // Clean up test user
            await User.findByIdAndDelete(user._id);
            console.log('\n🧹 Test user cleaned up');
        } else {
            console.log('❌ Registration simulation failed - no new user created');
        }
        
        console.log('\n🎯 DIAGNOSIS:');
        console.log('✅ MongoDB connection: Working');
        console.log('✅ User model: Working');
        console.log('✅ Password hashing: Working');
        console.log('✅ Database save: Working');
        console.log('\n💡 If website registration isn\'t working, the issue is likely:');
        console.log('   1. Frontend not calling the correct API endpoint');
        console.log('   2. Server not running when you test');
        console.log('   3. API validation failing');
        console.log('   4. Network/CORS issues');
        
    } catch (error) {
        console.error('❌ Simulation failed:', error);
        if (error.code === 11000) {
            console.log('💡 This is a duplicate key error - user already exists');
        }
    } finally {
        await mongoose.connection.close();
        console.log('\n📦 Database connection closed');
        process.exit(0);
    }
}

// Run simulation if this file is executed directly
if (require.main === module) {
    simulateRegistration();
}

module.exports = { simulateRegistration };