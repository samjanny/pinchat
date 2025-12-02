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
const readline = require('readline');

// Files to hash (URL paths as seen by browser)
// HTML files are in static/ and served at /static/*.html
const FILES_TO_HASH = [
  // HTML pages
  '/static/index.html',
  '/static/login.html',
  '/static/chat.html',

  // CSS
  '/static/css/style.css',

  // JavaScript
  '/static/js/alpine-csp.min.js',
  '/static/js/app.js',
  '/static/js/crypto.js',
  '/static/js/double-ratchet.js',
  '/static/js/ecdh.js',
  '/static/js/emoji.js',
  '/static/js/homepage.js',
  '/static/js/identity.js',
  '/static/js/login.js',
  '/static/js/nicknames.js',
  '/static/js/pow.js',
  '/static/js/websocket.js'
];

/**
 * Convert URL path to filesystem path relative to static directory
 * URLs use /static/... but files are in static/... (without the /static prefix)
 */
function urlPathToFilePath(urlPath) {
    // Remove /static prefix if present, since staticDir is already the static folder
    if (urlPath.startsWith('/static/')) {
        return urlPath.substring('/static'.length); // returns /css/style.css
    }
    return urlPath;
}

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
 * Prompt for password without echoing to terminal
 */
function promptPassword(prompt) {
    return new Promise((resolve) => {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        // Disable echo for password input
        process.stdout.write(prompt);
        process.stdin.setRawMode(true);
        process.stdin.resume();

        let password = '';
        const onData = (char) => {
            char = char.toString();

            if (char === '\n' || char === '\r' || char === '\u0004') {
                // Enter or Ctrl+D pressed
                process.stdin.setRawMode(false);
                process.stdin.removeListener('data', onData);
                rl.close();
                console.log(''); // New line after password
                resolve(password);
            } else if (char === '\u0003') {
                // Ctrl+C pressed
                process.stdin.setRawMode(false);
                process.exit(1);
            } else if (char === '\u007F' || char === '\b') {
                // Backspace
                if (password.length > 0) {
                    password = password.slice(0, -1);
                }
            } else {
                password += char;
            }
        };

        process.stdin.on('data', onData);
    });
}

/**
 * Decrypt an OpenSSL-encrypted PEM file (aes-256-cbc with pbkdf2)
 * OpenSSL format: "Salted__" + 8 bytes salt + encrypted data
 */
function decryptPemFile(encryptedData, password) {
    // Check for OpenSSL "Salted__" header
    const header = encryptedData.slice(0, 8).toString('utf8');
    if (header !== 'Salted__') {
        throw new Error('Invalid encrypted file format: missing OpenSSL "Salted__" header');
    }

    // Extract salt (8 bytes after "Salted__")
    const salt = encryptedData.slice(8, 16);
    const ciphertext = encryptedData.slice(16);

    // Derive key and IV using PBKDF2 (OpenSSL default: 10000 iterations, SHA-256)
    // AES-256-CBC needs 32-byte key + 16-byte IV = 48 bytes total
    const keyIv = crypto.pbkdf2Sync(password, salt, 10000, 48, 'sha256');
    const key = keyIv.slice(0, 32);
    const iv = keyIv.slice(32, 48);

    // Decrypt
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString('utf8');
}

/**
 * Securely clear a buffer or string from memory
 */
function secureClear(data) {
    if (Buffer.isBuffer(data)) {
        data.fill(0);
    } else if (typeof data === 'string') {
        // Strings are immutable in JS, but we can at least dereference
        // For true security, use Buffer for sensitive data
        return null;
    }
}

/**
 * Parse command line arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);
    const options = {
        privateKey: null,
        encryptedKey: null,
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
            case '--encrypted-key':
            case '-e':
                options.encryptedKey = args[++i];
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
  node generate-hashes.js --encrypted-key <path> [options]
  node generate-hashes.js --no-sign [options]

Options:
  -k, --private-key <path>    Path to ECDSA P-256 private key (PEM format)
  -e, --encrypted-key <path>  Path to encrypted private key (.pem.enc)
                              Key is decrypted in RAM only during signing
  -o, --output <path>         Output file path (default: hashes.json.signed)
  -s, --static-dir <path>     Path to static files directory (default: ../static)
  --no-sign                   Generate hashes only, without signing
  -h, --help                  Show this help message

Generate a new key pair:
  openssl ecparam -genkey -name prime256v1 -noout -out private.pem
  openssl ec -in private.pem -pubout -out public.pem

Encrypt an existing private key:
  openssl enc -aes-256-cbc -pbkdf2 -in private.pem -out private.pem.enc

Examples:
  node generate-hashes.js -k private.pem -o ../hashes.json.signed
  node generate-hashes.js -e private.pem.enc -o ../hashes.json.signed
`);
}

/**
 * Main function
 */
async function main() {
    const options = parseArgs();

    if (options.help) {
        printUsage();
        process.exit(0);
    }

    // Validate key options
    if (!options.noSign && !options.privateKey && !options.encryptedKey) {
        console.error('Error: Private key path is required (use -k, -e, or --no-sign)');
        printUsage();
        process.exit(1);
    }

    if (options.privateKey && options.encryptedKey) {
        console.error('Error: Cannot use both --private-key and --encrypted-key');
        process.exit(1);
    }

    // Check if key file exists (only if signing)
    const keyPath = options.privateKey || options.encryptedKey;
    if (!options.noSign && !fs.existsSync(keyPath)) {
        console.error(`Error: Key file not found: ${keyPath}`);
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

    for (const urlPath of FILES_TO_HASH) {
        // Convert URL path to filesystem path
        const fsPath = urlPathToFilePath(urlPath);
        const fullPath = path.join(options.staticDir, fsPath);

        if (!fs.existsSync(fullPath)) {
            console.error(`Warning: File not found: ${urlPath} (looked in ${fullPath})`);
            errorCount++;
            continue;
        }

        const hash = hashFile(fullPath);
        // Store the URL path (as seen by browser), not the filesystem path
        files.push({ path: urlPath, hash });
        console.log(`  ${urlPath}: ${hash.substring(0, 16)}...`);
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
    // NOTE: Output is compact JSON (no formatting) to match what the extension
    // expects when verifying signatures (JSON.stringify produces compact output)
    if (options.noSign) {
        fs.writeFileSync(options.output, JSON.stringify(data));
        console.log(`\nHashes generated (unsigned, compact JSON): ${options.output}`);
        process.exit(0);
    }

    // Get private key (decrypt if encrypted)
    let privateKeyPem;
    let encryptedBuffer = null;

    if (options.encryptedKey) {
        console.log('\nUsing encrypted key (decrypting in RAM only)...');
        encryptedBuffer = fs.readFileSync(options.encryptedKey);

        try {
            const password = await promptPassword('Enter key password: ');
            privateKeyPem = decryptPemFile(encryptedBuffer, password);
            // Clear password from memory (best effort)
            secureClear(password);
        } catch (error) {
            console.error(`Error decrypting key: ${error.message}`);
            process.exit(1);
        }
    } else {
        privateKeyPem = fs.readFileSync(options.privateKey, 'utf8');
    }

    // Sign the data
    const dataString = JSON.stringify(data);
    let signature;

    try {
        signature = signData(dataString, privateKeyPem);
    } finally {
        // Clear private key from memory immediately after signing
        if (options.encryptedKey) {
            privateKeyPem = secureClear(privateKeyPem);
            if (encryptedBuffer) {
                secureClear(encryptedBuffer);
            }
            console.log('(Key cleared from memory)');
        }
    }

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
    const keySource = options.encryptedKey
        ? `${options.encryptedKey} (after decryption)`
        : options.privateKey;
    console.log(`
IMPORTANT: Copy your public key to the browser extensions!
Run: openssl ec -in ${options.privateKey || '<decrypted-key>'} -pubout

Then update the PUBLIC_KEY constant in:
  - extensions/chrome/background.js
  - extensions/firefox/background.js
`);
}

main().catch(error => {
    console.error('Fatal error:', error.message);
    process.exit(1);
});
