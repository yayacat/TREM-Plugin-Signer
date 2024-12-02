#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const args = process.argv.slice(2);
const command = args[0];

function generateKeyPair(outputPath) {
  try {
    fs.mkdirSync(outputPath, { recursive: true });
  } catch (err) {
    if (err.code !== 'EEXIST') {
      throw err;
    }
  }

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

  const privatePath = path.join(outputPath, 'private.pem');
  const publicPath = path.join(outputPath, 'public.pem');
  
  fs.writeFileSync(privatePath, privateKey);
  fs.writeFileSync(publicPath, publicKey);
  
  console.log(`Keys generated successfully in ${outputPath}!`);
  console.log(`Private key: ${privatePath}`);
  console.log(`Public key: ${publicPath}`);
}

function normalizeContent(content) {
  return content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

function getAllFiles(dir, baseDir = dir) {
  let results = {};
  const list = fs.readdirSync(dir);

  for (const file of list) {
    if (file.startsWith('.') || file === 'signature.json') continue;

    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);

    if (stat.isDirectory()) {
      Object.assign(results, getAllFiles(filePath, baseDir));
    } else {
      const relativePath = path.relative(baseDir, filePath).replace(/\\/g, '/');
      const content = normalizeContent(fs.readFileSync(filePath, 'utf8'));
      results[relativePath] = content;
    }
  }

  return results;
}

function signPlugin(pluginPath, privateKeyPath) {
  if (!fs.existsSync(pluginPath)) {
    throw new Error(`Plugin directory not found: ${pluginPath}`);
  }
  if (!fs.existsSync(privateKeyPath)) {
    throw new Error(`Private key not found: ${privateKeyPath}`);
  }

  const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
  const fileContents = getAllFiles(pluginPath);

  if (Object.keys(fileContents).length === 0) {
    throw new Error(`No files found in plugin directory: ${pluginPath}`);
  }
  
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
  
  const signaturePath = path.join(pluginPath, 'signature.json');
  fs.writeFileSync(
    signaturePath,
    JSON.stringify(signatureData, null, 2)
  );
  
  console.log('Plugin signed successfully!');
  console.log(`Signature file created: ${signaturePath}`);
  console.log('Files included in signature:');
  Object.keys(fileHashes).forEach(file => console.log(`  ${file}`));
}

function verifyPlugin(pluginPath, publicKeyPath) {
  if (!fs.existsSync(pluginPath)) {
    throw new Error(`Plugin directory not found: ${pluginPath}`);
  }
  if (!fs.existsSync(publicKeyPath)) {
    throw new Error(`Public key not found: ${publicKeyPath}`);
  }

  const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
  const signaturePath = path.join(pluginPath, 'signature.json');

  if (!fs.existsSync(signaturePath)) {
    throw new Error('Missing signature.json');
  }

  const signatureData = JSON.parse(fs.readFileSync(signaturePath));
  const { fileHashes, signature, timestamp } = signatureData;

  for (const [file, expectedHash] of Object.entries(fileHashes)) {
    const filePath = path.join(pluginPath, file);
    
    if (!fs.existsSync(filePath)) {
      throw new Error(`Missing file: ${file}`);
    }
    
    const content = normalizeContent(fs.readFileSync(filePath, 'utf8'));
    const actualHash = crypto.createHash('sha256')
      .update(content)
      .digest('hex');
      
    if (actualHash !== expectedHash) {
      throw new Error(`File modified: ${file}`);
    }
  }
  
  const verify = crypto.createVerify('SHA256');
  verify.write(JSON.stringify(fileHashes));
  verify.end();
  
  const isValid = verify.verify(publicKey, signature, 'base64');
  
  if (!isValid) {
    throw new Error('Invalid signature');
  }

  console.log('Plugin verification successful!');
  console.log(`Signature timestamp: ${new Date(timestamp).toLocaleString()}`);
}

function showHelp() {
  console.log(`
TREM Plugin Signer
Usage:
  generate <output-path>             - Generate new key pair
  sign <plugin-path> <private-key>   - Sign a plugin
  verify <plugin-path> <public-key>  - Verify a plugin signature
  help                              - Show this help
  `);
}

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
    case 'verify':
      if (args.length < 3) {
        console.error('Missing plugin path or public key path');
        showHelp();
        process.exit(1);
      }
      verifyPlugin(args[1], args[2]);
      break;
    case 'help':
    default:
      showHelp();
      break;
  }
} catch (error) {
  console.error('Error:', error.message);
  process.exit(1);
}
