const axios = require('axios');
const mongoose = require('mongoose');
require('dotenv').config();

// Import models
const User = require('../models/User');

async function testRegistrationAPI() {
    try {
        console.log('🔄 Testing registration API...\n');
        
        // Connect to MongoDB to check data
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Connected to MongoDB Atlas!\n');
        
        // Check users before registration
        const usersBefore = await User.find({});
        console.log(`📊 Users in database before test: ${usersBefore.length}`);
        
        // Test registration via API
        console.log('🧪 Testing registration API call...');
        const testUser = {
            username: 'api_test_user',
            email: 'apitest@example.com',
            password: 'TestPassword123!'
        };
        
        try {
            const response = await axios.post('http://localhost:3000/api/auth/register', testUser, {
                headers: {
                    'Content-Type': 'application/json'
                },
                timeout: 10000
            });
            
            console.log('✅ Registration API Response:');
            console.log('   Status:', response.status);
            console.log('   Success:', response.data.success);
            console.log('   Message:', response.data.message);
            if (response.data.data && response.data.data.user) {
                console.log('   User ID:', response.data.data.user.id);
                console.log('   Username:', response.data.data.user.username);
                console.log('   Email:', response.data.data.user.email);
            }
            
        } catch (apiError) {
            console.log('❌ Registration API Error:');
            if (apiError.response) {
                console.log('   Status:', apiError.response.status);
                console.log('   Error:', apiError.response.data);
            } else if (apiError.code === 'ECONNREFUSED') {
                console.log('   Server is not running on port 3000');
                console.log('   Please start the server with: npm start');
            } else {
                console.log('   Error:', apiError.message);
            }
        }
        
        // Check users after registration attempt
        const usersAfter = await User.find({});
        console.log(`\n📊 Users in database after test: ${usersAfter.length}`);
        
        if (usersAfter.length > usersBefore.length) {
            console.log('✅ New user was successfully saved to MongoDB!');
            const newUser = usersAfter[usersAfter.length - 1];
            console.log('   New user details:');
            console.log('   - Username:', newUser.username);
            console.log('   - Email:', newUser.email);
            console.log('   - Created:', newUser.createdAt);
            
            // Clean up test user
            await User.findByIdAndDelete(newUser._id);
            console.log('   🧹 Test user cleaned up');
        } else {
            console.log('❌ No new user was saved to MongoDB');
        }
        
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
    testRegistrationAPI();
}

module.exports = { testRegistrationAPI };