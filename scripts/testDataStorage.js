const mongoose = require('mongoose');
require('dotenv').config();

// Import models
const User = require('../models/User');
const Password = require('../models/Password');

async function testDataStorage() {
    try {
        console.log('🔄 Testing data storage format...\n');
        
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Connected to MongoDB Atlas!\n');
        
        // Create a test user
        console.log('1️⃣  Creating test user...');
        const testUser = new User({
            username: 'demo_user',
            email: 'demo@example.com',
            password: 'MySecretPassword123!'
        });
        
        await testUser.save();
        console.log('   ✅ User created');
        
        // Show how user data is stored
        const savedUser = await User.findById(testUser._id).select('+password');
        console.log('\n📊 USER DATA IN DATABASE:');
        console.log('   Username (plain text):', savedUser.username);
        console.log('   Email (plain text):', savedUser.email);
        console.log('   Password (bcrypt hash):', savedUser.password);
        console.log('   Original password was: MySecretPassword123!');
        
        // Create a test password entry
        console.log('\n2️⃣  Creating test password entry...');
        const testPassword = new Password({
            userId: testUser._id,
            website: 'Gmail',
            username: 'demo@gmail.com',
            category: 'personal',
            notes: 'My personal email'
        });
        
        // Set the password (this will encrypt it)
        testPassword.setPassword('GmailPassword123!');
        await testPassword.save();
        console.log('   ✅ Password entry created');
        
        // Show how password data is stored
        const savedPassword = await Password.findById(testPassword._id);
        console.log('\n📊 PASSWORD DATA IN DATABASE:');
        console.log('   Website (plain text):', savedPassword.website);
        console.log('   Username (plain text):', savedPassword.username);
        console.log('   Category (plain text):', savedPassword.category);
        console.log('   Notes (plain text):', savedPassword.notes);
        console.log('   Encrypted Password:', savedPassword.encryptedPassword);
        console.log('   IV (Initialization Vector):', savedPassword.iv);
        console.log('   Original password was: GmailPassword123!');
        
        // Test decryption
        console.log('\n3️⃣  Testing password decryption...');
        const decryptedPassword = savedPassword.getPassword();
        console.log('   Decrypted password:', decryptedPassword);
        console.log('   Matches original?', decryptedPassword === 'GmailPassword123!' ? '✅ Yes' : '❌ No');
        
        // Test user authentication
        console.log('\n4️⃣  Testing user authentication...');
        const isValidPassword = await savedUser.comparePassword('MySecretPassword123!');
        console.log('   Authentication test:', isValidPassword ? '✅ Success' : '❌ Failed');
        
        // Clean up test data
        console.log('\n5️⃣  Cleaning up test data...');
        await Password.findByIdAndDelete(testPassword._id);
        await User.findByIdAndDelete(testUser._id);
        console.log('   ✅ Test data cleaned up');
        
        console.log('\n🎉 DATA STORAGE SUMMARY:');
        console.log('=' .repeat(50));
        console.log('✅ Usernames: Plain text (searchable)');
        console.log('✅ Emails: Plain text (searchable)');
        console.log('✅ User passwords: Bcrypt hashed (secure, one-way)');
        console.log('✅ Website names: Plain text (searchable)');
        console.log('✅ Website usernames: Plain text (searchable)');
        console.log('✅ Website passwords: AES-256 encrypted (secure, reversible)');
        console.log('\n💡 This is the correct and secure approach!');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
    } finally {
        await mongoose.connection.close();
        console.log('\n📦 Database connection closed');
        process.exit(0);
    }
}

// Run test if this file is executed directly
if (require.main === module) {
    testDataStorage();
}

module.exports = { testDataStorage };