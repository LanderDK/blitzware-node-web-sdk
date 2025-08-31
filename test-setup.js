#!/usr/bin/env node

/**
 * Quick setup script to test the BlitzWare Node.js SDK
 * 
 * This script helps you set up environment variables for testing
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log('🚀 BlitzWare Node.js SDK Test Setup\n');
console.log('This will help you create a .env file for testing the examples.\n');

const questions = [
  {
    key: 'BLITZWARE_CLIENT_ID',
    prompt: 'Enter your BlitzWare Client ID: ',
    required: true
  },
  {
    key: 'BLITZWARE_CLIENT_SECRET',
    prompt: 'Enter your BlitzWare Client Secret: ',
    required: true
  },
  {
    key: 'BLITZWARE_REDIRECT_URI',
    prompt: 'Enter your redirect URI (default: http://localhost:3000/callback): ',
    default: 'http://localhost:3000/callback'
  },
  {
    key: 'SESSION_SECRET',
    prompt: 'Enter a session secret (default: random): ',
    default: require('crypto').randomBytes(32).toString('hex')
  },
  {
    key: 'PORT',
    prompt: 'Enter port number (default: 3000): ',
    default: '3000'
  }
];

const envVars = {};
let currentQuestion = 0;

function askQuestion() {
  if (currentQuestion >= questions.length) {
    writeEnvFile();
    return;
  }

  const question = questions[currentQuestion];
  rl.question(question.prompt, (answer) => {
    const value = answer.trim() || question.default;
    
    if (question.required && !value) {
      console.log('❌ This field is required. Please try again.\n');
      askQuestion(); // Ask the same question again
      return;
    }
    
    envVars[question.key] = value;
    currentQuestion++;
    askQuestion();
  });
}

function writeEnvFile() {
  const envContent = Object.entries(envVars)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n') + '\n';

  const envPath = path.join(__dirname, '.env');
  
  try {
    fs.writeFileSync(envPath, envContent);
    console.log('\n✅ .env file created successfully!');
    console.log('\nNext steps:');
    console.log('1. Make sure you have the correct OAuth app configuration in BlitzWare');
    console.log('2. Run the Express example: node examples/express-example.js');
    console.log('3. Visit http://localhost:' + envVars.PORT);
    console.log('\n📁 .env file location:', envPath);
  } catch (error) {
    console.error('\n❌ Error creating .env file:', error.message);
  }
  
  rl.close();
}

// Check if .env already exists
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  rl.question('\n⚠️  .env file already exists. Overwrite? (y/N): ', (answer) => {
    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
      console.log('');
      askQuestion();
    } else {
      console.log('Setup cancelled.');
      rl.close();
    }
  });
} else {
  askQuestion();
}
