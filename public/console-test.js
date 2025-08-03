// Copy and paste this into your browser console to test the API directly

console.log('🔧 SecureVault API Test');

// Test 1: Health Check
async function testHealth() {
    console.log('🏥 Testing health endpoint...');
    try {
        const response = await fetch('/api/health');
        const data = await response.json();
        console.log('✅ Health check successful:', data);
        return true;
    } catch (error) {
        console.error('❌ Health check failed:', error);
        return false;
    }
}

// Test 2: Registration
async function testRegistration() {
    console.log('🧪 Testing registration endpoint...');
    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: 'console_test_user',
                email: 'consoletest@example.com',
                password: 'TestPassword123!'
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log('✅ Registration successful:', data);
            return true;
        } else {
            console.log('❌ Registration failed:', response.status, data);
            return false;
        }
    } catch (error) {
        console.error('❌ Registration error:', error);
        return false;
    }
}

// Run tests
async function runTests() {
    console.log('🚀 Starting API tests...');
    
    const healthOk = await testHealth();
    if (healthOk) {
        await testRegistration();
    }
    
    console.log('🏁 Tests completed');
}

// Auto-run tests
runTests();