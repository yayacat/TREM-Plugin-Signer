#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// 命令行參數處理
const args = process.argv.slice(2);
const command = args[0];

function generateKeyPair(outputPath) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  fs.writeFileSync(path.join(outputPath, 'private.pem'), privateKey);
  fs.writeFileSync(path.join(outputPath, 'public.pem'), publicKey);
  console.log('Keys generated successfully!');
}

function signPlugin(pluginPath, privateKeyPath) {
  const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
  const files = fs.readdirSync(pluginPath);
  const fileContents = {};
  
  files.forEach(file => {
    if (file !== 'signature.json') {
      const filePath = path.join(pluginPath, file);
      if (fs.statSync(filePath).isFile()) {
        const content = fs.readFileSync(filePath);
        fileContents[file] = content;
      }
    }
  });
  
  const fileHashes = {};
  Object.entries(fileContents).forEach(([file, content]) => {
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    fileHashes[file] = hash;
  });
  
  const sign = crypto.createSign('SHA256');
  sign.write(JSON.stringify(fileHashes));
  sign.end();
  const signature = sign.sign(privateKey, 'base64');
  
  const signatureData = {
    timestamp: Date.now(),
    fileHashes,
    signature
  };
  
  fs.writeFileSync(
    path.join(pluginPath, 'signature.json'),
    JSON.stringify(signatureData, null, 2)
  );
  console.log('Plugin signed successfully!');
}

function showHelp() {
  console.log(`
TREM Plugin Signer
Usage:
  npx trem-plugin-signer generate <output-path>  - Generate new key pair
  npx trem-plugin-signer sign <plugin-path> <private-key-path>  - Sign a plugin
  `);
}

// 主程序
try {
  switch (command) {
    case 'generate':
      generateKeyPair(args[1] || '.');
      break;
    case 'sign':
      if (args.length < 3) {
        console.error('Missing plugin path or private key path');
        showHelp();
        process.exit(1);
      }
      signPlugin(args[1], args[2]);
      break;
    default:
      showHelp();
      break;
  }
} catch (error) {
  console.error('Error:', error.message);
  process.exit(1);
}
