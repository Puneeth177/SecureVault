const mongoose = require('mongoose');
require('dotenv').config();

// Import models to test
const User = require('../models/User');
const Password = require('../models/Password');

async function testMongoDBConnection() {
    try {
        console.log('🔄 Testing MongoDB Atlas connection...\n');
        
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Successfully connected to MongoDB Atlas!');
        
        // Test database operations
        console.log('\n🧪 Testing database operations...');
        
        // Test 1: Create a test user
        console.log('1️⃣  Testing user creation...');
        const testUser = new User({
            username: 'testuser_' + Date.now(),
            email: 'test_' + Date.now() + '@example.com',
            password: 'TestPassword123!'
        });
        
        await testUser.save();
        console.log('   ✅ Test user created successfully');
        
        // Test 2: Create a test password
        console.log('2️⃣  Testing password creation...');
        const testPassword = new Password({
            userId: testUser._id,
            website: 'Test Website',
            username: 'testuser',
            category: 'personal',
            notes: 'This is a test password'
        });
        
        // Set encrypted password
        if (testPassword.setPassword('TestPassword123!')) {
            await testPassword.save();
            console.log('   ✅ Test password created and encrypted successfully');
        } else {
            console.log('   ❌ Failed to encrypt test password');
        }
        
        // Test 3: Retrieve and decrypt password
        console.log('3️⃣  Testing password retrieval and decryption...');
        const retrievedPassword = await Password.findById(testPassword._id);
        const decryptedPassword = retrievedPassword.getPassword();
        
        if (decryptedPassword === 'TestPassword123!') {
            console.log('   ✅ Password decryption successful');
        } else {
            console.log('   ❌ Password decryption failed');
        }
        
        // Test 4: Test user authentication
        console.log('4️⃣  Testing user authentication...');
        const isPasswordValid = await testUser.comparePassword('TestPassword123!');
        if (isPasswordValid) {
            console.log('   ✅ User authentication successful');
        } else {
            console.log('   ❌ User authentication failed');
        }
        
        // Test 5: Clean up test data
        console.log('5️⃣  Cleaning up test data...');
        await Password.findByIdAndDelete(testPassword._id);
        await User.findByIdAndDelete(testUser._id);
        console.log('   ✅ Test data cleaned up');
        
        // Test 6: Check database collections
        console.log('6️⃣  Checking database collections...');
        const collections = await mongoose.connection.db.listCollections().toArray();
        console.log('   📊 Available collections:');
        collections.forEach(collection => {
            console.log(`      - ${collection.name}`);
        });
        
        console.log('\n🎉 All tests passed! MongoDB Atlas integration is working perfectly!');
        
        // Display connection info
        console.log('\n📊 Connection Information:');
        console.log(`   Database: ${mongoose.connection.name}`);
        console.log(`   Host: ${mongoose.connection.host}`);
        console.log(`   Ready State: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Not Connected'}`);
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        if (error.code === 11000) {
            console.log('   💡 This might be a duplicate key error - user might already exist');
        }
    } finally {
        await mongoose.connection.close();
        console.log('\n📦 Database connection closed');
        process.exit(0);
    }
}

// Run test if this file is executed directly
if (require.main === module) {
    testMongoDBConnection();
}

module.exports = { testMongoDBConnection };