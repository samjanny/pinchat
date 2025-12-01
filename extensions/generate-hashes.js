#!/usr/bin/env node
/**
 * PinChat Hash Generator and Signer
 *
 * This script generates SHA-256 hashes of all static files
 * and signs them with an ECDSA P-256 private key.
 *
 * Usage:
 *   node generate-hashes.js --private-key path/to/private.pem --output hashes.json.signed
 *
 * To generate a new ECDSA P-256 key pair:
 *   openssl ecparam -genkey -name prime256v1 -noout -out private.pem
 *   openssl ec -in private.pem -pubout -out public.pem
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Files to hash (relative to static directory)
const FILES_TO_HASH = [
  // HTML pages
  '/index.html',
  '/login.html',
  '/chat.html',
  
  // CSS
  '/css/style.css',
  
  // JavaScript
  '/js/alpine-csp.min.js',
  '/js/app.js',
  '/js/crypto.js',
  '/js/double-ratchet.js',
  '/js/ecdh.js',
  '/js/emoji.js',
  '/js/homepage.js',
  '/js/identity.js',
  '/js/nicknames.js',
  '/js/pow.js',
  '/js/websocket.js'
];

/**
 * Calculate SHA-256 hash of a file
 */
function hashFile(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Sign data with ECDSA P-256 private key
 */
function signData(data, privateKeyPem) {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();

    // Sign and return base64 encoded signature
    const signature = sign.sign(privateKeyPem);
    return signature.toString('base64');
}

/**
 * Parse command line arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);
    const options = {
        privateKey: null,
        output: 'hashes.json.signed',
        staticDir: path.join(__dirname, '..', 'static'),
        help: false,
        noSign: false
    };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--private-key':
            case '-k':
                options.privateKey = args[++i];
                break;
            case '--output':
            case '-o':
                options.output = args[++i];
                break;
            case '--static-dir':
            case '-s':
                options.staticDir = args[++i];
                break;
            case '--help':
            case '-h':
                options.help = true;
                break;
            case '--no-sign':
                options.noSign = true;
                break;
        }
    }

    return options;
}

/**
 * Print usage information
 */
function printUsage() {
    console.log(`
PinChat Hash Generator and Signer

Usage:
  node generate-hashes.js --private-key <path> [options]
  node generate-hashes.js --no-sign [options]

Options:
  -k, --private-key <path>  Path to ECDSA P-256 private key (PEM format)
  -o, --output <path>       Output file path (default: hashes.json.signed)
  -s, --static-dir <path>   Path to static files directory (default: ../static)
  --no-sign                 Generate hashes only, without signing
  -h, --help                Show this help message

Generate a new key pair:
  openssl ecparam -genkey -name prime256v1 -noout -out private.pem
  openssl ec -in private.pem -pubout -out public.pem

Example:
  node generate-hashes.js -k private.pem -o ../hashes.json.signed
`);
}

/**
 * Main function
 */
function main() {
    const options = parseArgs();

    if (options.help) {
        printUsage();
        process.exit(0);
    }

    if (!options.noSign && !options.privateKey) {
        console.error('Error: Private key path is required (or use --no-sign)');
        printUsage();
        process.exit(1);
    }

    // Check if private key exists (only if signing)
    if (!options.noSign && !fs.existsSync(options.privateKey)) {
        console.error(`Error: Private key file not found: ${options.privateKey}`);
        process.exit(1);
    }

    // Check if static directory exists
    if (!fs.existsSync(options.staticDir)) {
        console.error(`Error: Static directory not found: ${options.staticDir}`);
        process.exit(1);
    }

    console.log('PinChat Hash Generator');
    console.log('======================');
    console.log(`Static directory: ${options.staticDir}`);
    console.log(`Output file: ${options.output}`);
    console.log('');

    // Generate hashes for all files
    const files = [];
    let errorCount = 0;

    for (const filePath of FILES_TO_HASH) {
        const fullPath = path.join(options.staticDir, filePath);

        if (!fs.existsSync(fullPath)) {
            console.error(`Warning: File not found: ${filePath}`);
            errorCount++;
            continue;
        }

        const hash = hashFile(fullPath);
        files.push({ path: filePath, hash });
        console.log(`  ${filePath}: ${hash.substring(0, 16)}...`);
    }

    if (errorCount > 0) {
        console.log(`\nWarning: ${errorCount} file(s) not found`);
    }

    // Create data object
    const data = {
        version: '1.0.0',
        generated: new Date().toISOString(),
        site: 'https://pinchat.io',
        files
    };

    // If --no-sign, save hashes without signature and exit
    if (options.noSign) {
        fs.writeFileSync(options.output, JSON.stringify(data, null, 2));
        console.log(`\nHashes generated (unsigned): ${options.output}`);
        process.exit(0);
    }

    // Read private key
    const privateKeyPem = fs.readFileSync(options.privateKey, 'utf8');

    // Sign the data
    const dataString = JSON.stringify(data);
    const signature = signData(dataString, privateKeyPem);

    console.log(`\nSigned with ECDSA P-256`);
    console.log(`Signature: ${signature.substring(0, 32)}...`);

    // Create final output
    const output = {
        data,
        signature
    };

    // Write output file
    fs.writeFileSync(options.output, JSON.stringify(output, null, 2));
    console.log(`\nOutput written to: ${options.output}`);

    // Also output the public key reminder
    console.log(`
IMPORTANT: Copy your public key to the browser extensions!
Run: openssl ec -in ${options.privateKey} -pubout

Then update the PUBLIC_KEY constant in:
  - extensions/chrome/background.js
  - extensions/firefox/background.js
`);
}

main();
