/**
 * Script to create your first admin user
 * Run: node scripts/create-admin.js YOUR_TELEGRAM_ID
 * 
 * To get your Telegram ID:
 * 1. Message @userinfobot on Telegram
 * 2. It will reply with your ID (a number like 123456789)
 */

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');

async function createAdmin() {
  try {
    // Get Telegram ID from command line
    const telegramId = process.argv[2];

    if (!telegramId) {
      console.error('❌ Please provide your Telegram ID');
      console.log('\nUsage: node scripts/create-admin.js YOUR_TELEGRAM_ID');
      console.log('\nTo get your Telegram ID:');
      console.log('1. Message @userinfobot on Telegram');
      console.log('2. Copy the ID number it sends you');
      process.exit(1);
    }

    // Connect to MongoDB
    console.log('📡 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // Check if user already exists
    const existingUser = await User.findOne({ telegramId });
    if (existingUser) {
      console.log(`\n⚠️ User with ID ${telegramId} already exists!`);
      console.log(`   Role: ${existingUser.role}`);
      console.log(`   Name: ${existingUser.firstName || 'N/A'}`);

      // Upgrade to admin if not already
      if (existingUser.role !== 'admin') {
        existingUser.role = 'admin';
        if (!existingUser.expiryDate) {
          existingUser.expiryDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year
        }
        await existingUser.save();
        console.log(`\n✅ Updated user to admin role!`);
      } else {
        console.log(`\n✅ User is already an admin!`);
      }
      await mongoose.disconnect();
      return;
    }

    // Create new admin user
    const adminUser = new User({
      telegramId: telegramId,
      role: 'admin',
      firstName: 'Admin',
      expiryDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
      createdAt: new Date(),
      lastActive: new Date()
    });

    await adminUser.save();
    console.log(`\n✅ Admin user created successfully!`);
    console.log(`   Telegram ID: ${telegramId}`);
    console.log(`   Role: admin`);
    console.log(`   Expiry: 1 year from now`);
    console.log(`\n🎉 You can now use the bot! Send /start to your bot.`);

    await mongoose.disconnect();
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

createAdmin();
