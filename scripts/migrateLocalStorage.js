const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Import models
const User = require('../models/User');
const Password = require('../models/Password');
const DeletedUser = require('../models/DeletedUser');
const RestoredUser = require('../models/RestoredUser');

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB for migration'))
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });

/**
 * Migration script to transfer localStorage data to MongoDB
 * This script helps migrate data from the client-side localStorage format
 * to the new MongoDB backend structure.
 */

async function migrateLocalStorageData() {
    console.log('🔄 Starting localStorage to MongoDB migration...\n');

    try {
        // Example localStorage data structure (you'll need to provide actual data)
        const exampleLocalStorageData = {
            // Users data from localStorage 'securepass_users'
            users: {
                "testuser": {
                    email: "test@example.com",
                    password: "TestPassword123!",
                    createdAt: "2024-01-01T00:00:00.000Z"
                }
            },
            
            // Passwords data from localStorage 'securepass_passwords_username'
            passwords: {
                "testuser": [
                    {
                        website: "Gmail",
                        username: "test@gmail.com",
                        password: "GmailPassword123!",
                        category: "personal",
                        notes: "Personal email account",
                        url: "https://gmail.com"
                    }
                ]
            },
            
            // Deleted users from localStorage 'securepass_deleted_users'
            deletedUsers: [
                {
                    username: "deleteduser",
                    email: "deleted@example.com",
                    deletedAt: "2024-01-01T00:00:00.000Z",
                    deletedBy: "admin"
                }
            ],
            
            // Restored users from localStorage 'securepass_restored_users'
            restoredUsers: [
                {
                    username: "restoreduser",
                    email: "restored@example.com",
                    restoredAt: "2024-01-01T00:00:00.000Z",
                    restoredBy: "self-registration"
                }
            ]
        };

        // Migrate Users
        console.log('👥 Migrating users...');
        let userCount = 0;
        for (const [username, userData] of Object.entries(exampleLocalStorageData.users)) {
            try {
                // Check if user already exists
                const existingUser = await User.findOne({ 
                    $or: [
                        { username: username },
                        { email: userData.email }
                    ]
                });

                if (existingUser) {
                    console.log(`⚠️  User ${username} already exists, skipping...`);
                    continue;
                }

                // Create new user
                const newUser = new User({
                    username: username,
                    email: userData.email,
                    password: userData.password, // Will be hashed by pre-save middleware
                    createdAt: userData.createdAt || new Date()
                });

                await newUser.save();
                userCount++;
                console.log(`✅ Migrated user: ${username}`);

                // Migrate passwords for this user
                if (exampleLocalStorageData.passwords[username]) {
                    console.log(`🔐 Migrating passwords for ${username}...`);
                    let passwordCount = 0;
                    
                    for (const passwordData of exampleLocalStorageData.passwords[username]) {
                        try {
                            const newPassword = new Password({
                                userId: newUser._id,
                                website: passwordData.website,
                                username: passwordData.username,
                                category: passwordData.category || 'other',
                                notes: passwordData.notes || '',
                                url: passwordData.url || '',
                                isFavorite: passwordData.isFavorite || false,
                                tags: passwordData.tags || []
                            });

                            // Set encrypted password
                            if (newPassword.setPassword(passwordData.password)) {
                                await newPassword.save();
                                passwordCount++;
                                console.log(`   ✅ Migrated password for ${passwordData.website}`);
                            } else {
                                console.log(`   ❌ Failed to encrypt password for ${passwordData.website}`);
                            }
                        } catch (error) {
                            console.log(`   ❌ Error migrating password for ${passwordData.website}:`, error.message);
                        }
                    }
                    
                    console.log(`   📊 Migrated ${passwordCount} passwords for ${username}\n`);
                }

            } catch (error) {
                console.log(`❌ Error migrating user ${username}:`, error.message);
            }
        }

        // Migrate Deleted Users
        console.log('🗑️  Migrating deleted users...');
        let deletedCount = 0;
        for (const deletedUserData of exampleLocalStorageData.deletedUsers) {
            try {
                const existingDeleted = await DeletedUser.findOne({ 
                    username: deletedUserData.username 
                });

                if (!existingDeleted) {
                    const newDeletedUser = new DeletedUser(deletedUserData);
                    await newDeletedUser.save();
                    deletedCount++;
                    console.log(`✅ Migrated deleted user: ${deletedUserData.username}`);
                }
            } catch (error) {
                console.log(`❌ Error migrating deleted user ${deletedUserData.username}:`, error.message);
            }
        }

        // Migrate Restored Users
        console.log('🔄 Migrating restored users...');
        let restoredCount = 0;
        for (const restoredUserData of exampleLocalStorageData.restoredUsers) {
            try {
                const existingRestored = await RestoredUser.findOne({ 
                    username: restoredUserData.username 
                });

                if (!existingRestored) {
                    const newRestoredUser = new RestoredUser(restoredUserData);
                    await newRestoredUser.save();
                    restoredCount++;
                    console.log(`✅ Migrated restored user: ${restoredUserData.username}`);
                }
            } catch (error) {
                console.log(`❌ Error migrating restored user ${restoredUserData.username}:`, error.message);
            }
        }

        console.log('\n📊 Migration Summary:');
        console.log(`   👥 Users migrated: ${userCount}`);
        console.log(`   🗑️  Deleted users migrated: ${deletedCount}`);
        console.log(`   🔄 Restored users migrated: ${restoredCount}`);
        console.log('\n✅ Migration completed successfully!');

    } catch (error) {
        console.error('❌ Migration failed:', error);
    } finally {
        await mongoose.connection.close();
        console.log('📦 Database connection closed');
        process.exit(0);
    }
}

/**
 * Instructions for using this migration script:
 * 
 * 1. Export your localStorage data from the browser:
 *    - Open browser console on your SecureVault page
 *    - Run: console.log(JSON.stringify({
 *        users: JSON.parse(localStorage.getItem('securepass_users') || '{}'),
 *        passwords: Object.keys(localStorage).filter(key => key.startsWith('securepass_passwords_')).reduce((acc, key) => {
 *          const username = key.replace('securepass_passwords_', '');
 *          acc[username] = JSON.parse(localStorage.getItem(key) || '[]');
 *          return acc;
 *        }, {}),
 *        deletedUsers: JSON.parse(localStorage.getItem('securepass_deleted_users') || '[]'),
 *        restoredUsers: JSON.parse(localStorage.getItem('securepass_restored_users') || '[]')
 *      }, null, 2));
 * 
 * 2. Copy the output and replace the exampleLocalStorageData object above
 * 
 * 3. Run the migration: npm run migrate-localstorage
 */

// Run migration if this file is executed directly
if (require.main === module) {
    migrateLocalStorageData();
}

module.exports = { migrateLocalStorageData };