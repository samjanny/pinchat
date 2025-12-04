#!/usr/bin/env node
/**
 * PinChat Hash Generator and Signer with SRI Support
 *
 * This script:
 * 1. Generates SHA-256 hashes of JS/CSS files
 * 2. Injects SRI integrity attributes into HTML files
 * 3. Generates hashes of the updated HTML files
 * 4. Signs everything with an ECDSA P-256 private key
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

// Files to hash - order matters: JS/CSS first, then HTML (which depends on JS/CSS hashes)
const JS_CSS_FILES = [
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

const HTML_FILES = [
  '/static/index.html',
  '/static/login.html',
  '/static/chat.html'
];

/**
 * Convert URL path to filesystem path relative to static directory
 */
function urlPathToFilePath(urlPath) {
    if (urlPath.startsWith('/static/')) {
        return urlPath.substring('/static'.length);
    }
    return urlPath;
}

/**
 * Calculate SHA-256 hash of a file (hex format for manifest)
 */
function hashFileHex(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Calculate SHA-256 hash of a file (base64 format for SRI)
 */
function hashFileSRI(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const hash = crypto.createHash('sha256').update(content).digest('base64');
    return `sha256-${hash}`;
}

/**
 * Calculate SHA-256 hash of content (base64 format for SRI)
 */
function hashContentSRI(content) {
    const hash = crypto.createHash('sha256').update(content).digest('base64');
    return `sha256-${hash}`;
}

/**
 * Inject SRI attributes into HTML file
 * Returns the modified HTML content
 */
function injectSRIIntoHTML(htmlPath, sriMap) {
    let content = fs.readFileSync(htmlPath, 'utf8');

    // Inject integrity into <script src="..."> tags
    content = content.replace(
        /<script\s+([^>]*?)src="([^"]+)"([^>]*?)>/gi,
        (match, before, src, after) => {
            // Skip if already has integrity
            if (before.includes('integrity=') || after.includes('integrity=')) {
                return match;
            }

            // Get SRI for this file
            const sri = sriMap[src];
            if (sri) {
                // Remove any existing crossorigin attribute
                before = before.replace(/crossorigin="[^"]*"\s*/gi, '');
                after = after.replace(/crossorigin="[^"]*"\s*/gi, '');
                return `<script ${before}src="${src}" integrity="${sri}" crossorigin="anonymous"${after}>`;
            }
            return match;
        }
    );

    // Inject integrity into <link rel="stylesheet" href="..."> tags
    content = content.replace(
        /<link\s+([^>]*?)href="([^"]+)"([^>]*?)>/gi,
        (match, before, href, after) => {
            // Check if it's a stylesheet
            const fullTag = before + after;
            if (!fullTag.includes('rel="stylesheet"') && !fullTag.includes("rel='stylesheet'")) {
                return match;
            }

            // Skip if already has integrity
            if (before.includes('integrity=') || after.includes('integrity=')) {
                return match;
            }

            // Get SRI for this file
            const sri = sriMap[href];
            if (sri) {
                // Remove any existing crossorigin attribute
                before = before.replace(/crossorigin="[^"]*"\s*/gi, '');
                after = after.replace(/crossorigin="[^"]*"\s*/gi, '');
                return `<link ${before}href="${href}" integrity="${sri}" crossorigin="anonymous"${after}>`;
            }
            return match;
        }
    );

    return content;
}

/**
 * Sign data with ECDSA P-256 private key
 */
function signData(data, privateKeyPem) {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
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

        process.stdout.write(prompt);
        process.stdin.setRawMode(true);
        process.stdin.resume();

        let password = '';
        const onData = (char) => {
            char = char.toString();

            if (char === '\n' || char === '\r' || char === '\u0004') {
                process.stdin.setRawMode(false);
                process.stdin.removeListener('data', onData);
                rl.close();
                console.log('');
                resolve(password);
            } else if (char === '\u0003') {
                process.stdin.setRawMode(false);
                process.exit(1);
            } else if (char === '\u007F' || char === '\b') {
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
 * Decrypt an OpenSSL-encrypted PEM file
 */
function decryptPemFile(encryptedData, password) {
    const header = encryptedData.slice(0, 8).toString('utf8');
    if (header !== 'Salted__') {
        throw new Error('Invalid encrypted file format: missing OpenSSL "Salted__" header');
    }

    const salt = encryptedData.slice(8, 16);
    const ciphertext = encryptedData.slice(16);

    const keyIv = crypto.pbkdf2Sync(password, salt, 10000, 48, 'sha256');
    const key = keyIv.slice(0, 32);
    const iv = keyIv.slice(32, 48);

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
    }
    return null;
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
        noSign: false,
        dryRun: false,
        sequence: null  // Optional sequence override
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
            case '--dry-run':
                options.dryRun = true;
                break;
            case '--sequence':
                options.sequence = parseInt(args[++i], 10);
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
PinChat Hash Generator with SRI Support

Usage:
  node generate-hashes.js --private-key <path> [options]
  node generate-hashes.js --encrypted-key <path> [options]
  node generate-hashes.js --no-sign [options]

Options:
  -k, --private-key <path>    Path to ECDSA P-256 private key (PEM format)
  -e, --encrypted-key <path>  Path to encrypted private key (.pem.enc)
  -o, --output <path>         Output file path (default: hashes.json.signed)
  -s, --static-dir <path>     Path to static files directory (default: ../static)
  --sequence <number>         Override sequence number (default: auto-increment)
  --no-sign                   Generate hashes only, without signing
  --dry-run                   Show what would be changed without modifying files
  -h, --help                  Show this help message

This script:
  1. Calculates SRI hashes for all JS/CSS files
  2. Injects integrity attributes into HTML files
  3. Calculates hashes of updated HTML files
  4. Signs the manifest with ECDSA P-256
  5. Increments sequence number for anti-downgrade protection

Generate a new key pair:
  openssl ecparam -genkey -name prime256v1 -noout -out private.pem
  openssl ec -in private.pem -pubout -out public.pem
`);
}

/**
 * Get current sequence number from existing manifest
 */
function getCurrentSequence(outputPath) {
    try {
        if (fs.existsSync(outputPath)) {
            const content = fs.readFileSync(outputPath, 'utf8');
            const manifest = JSON.parse(content);
            // Handle both signed and unsigned formats
            const data = manifest.data || manifest;
            return data.sequence || 0;
        }
    } catch (e) {
        console.log('  No existing manifest found, starting sequence at 1');
    }
    return 0;
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

    if (!options.noSign && !options.privateKey && !options.encryptedKey) {
        console.error('Error: Private key path is required (use -k, -e, or --no-sign)');
        printUsage();
        process.exit(1);
    }

    if (options.privateKey && options.encryptedKey) {
        console.error('Error: Cannot use both --private-key and --encrypted-key');
        process.exit(1);
    }

    const keyPath = options.privateKey || options.encryptedKey;
    if (!options.noSign && !fs.existsSync(keyPath)) {
        console.error(`Error: Key file not found: ${keyPath}`);
        process.exit(1);
    }

    if (!fs.existsSync(options.staticDir)) {
        console.error(`Error: Static directory not found: ${options.staticDir}`);
        process.exit(1);
    }

    console.log('PinChat Hash Generator with SRI');
    console.log('================================');
    console.log(`Static directory: ${options.staticDir}`);
    console.log(`Output file: ${options.output}`);
    if (options.dryRun) {
        console.log('DRY RUN - no files will be modified');
    }
    console.log('');

    // Step 1: Generate SRI hashes for JS/CSS files
    console.log('Step 1: Generating SRI hashes for JS/CSS files...');
    const sriMap = {};  // URL path -> SRI hash
    const files = [];   // Final manifest entries
    let errorCount = 0;

    for (const urlPath of JS_CSS_FILES) {
        const fsPath = urlPathToFilePath(urlPath);
        const fullPath = path.join(options.staticDir, fsPath);

        if (!fs.existsSync(fullPath)) {
            console.error(`  Warning: File not found: ${urlPath}`);
            errorCount++;
            continue;
        }

        const sriHash = hashFileSRI(fullPath);
        const hexHash = hashFileHex(fullPath);
        sriMap[urlPath] = sriHash;
        files.push({ path: urlPath, hash: hexHash });
        console.log(`  ${urlPath}: ${sriHash.substring(0, 30)}...`);
    }

    // Step 2: Inject SRI into HTML files
    console.log('\nStep 2: Injecting SRI attributes into HTML files...');
    const htmlUpdates = [];

    for (const urlPath of HTML_FILES) {
        const fsPath = urlPathToFilePath(urlPath);
        const fullPath = path.join(options.staticDir, fsPath);

        if (!fs.existsSync(fullPath)) {
            console.error(`  Warning: HTML file not found: ${urlPath}`);
            errorCount++;
            continue;
        }

        const originalContent = fs.readFileSync(fullPath, 'utf8');
        const updatedContent = injectSRIIntoHTML(fullPath, sriMap);

        if (originalContent !== updatedContent) {
            console.log(`  ${urlPath}: Updated with SRI attributes`);
            htmlUpdates.push({ path: fullPath, content: updatedContent });
        } else {
            console.log(`  ${urlPath}: No changes needed`);
        }
    }

    // Step 3: Write updated HTML files (unless dry run)
    if (!options.dryRun && htmlUpdates.length > 0) {
        console.log('\nStep 3: Writing updated HTML files...');
        for (const update of htmlUpdates) {
            fs.writeFileSync(update.path, update.content);
            console.log(`  Written: ${update.path}`);
        }
    }

    // Step 4: Calculate hashes of HTML files (after SRI injection)
    console.log('\nStep 4: Calculating HTML file hashes...');
    for (const urlPath of HTML_FILES) {
        const fsPath = urlPathToFilePath(urlPath);
        const fullPath = path.join(options.staticDir, fsPath);

        if (!fs.existsSync(fullPath)) {
            continue;
        }

        // If we have an update pending, hash the new content, otherwise read from disk
        const update = htmlUpdates.find(u => u.path === fullPath);
        let hexHash;
        if (update && !options.dryRun) {
            // Hash the updated content (already written to disk)
            hexHash = hashFileHex(fullPath);
        } else if (update) {
            // Dry run: hash the content that would be written
            hexHash = crypto.createHash('sha256').update(update.content).digest('hex');
        } else {
            hexHash = hashFileHex(fullPath);
        }

        files.push({ path: urlPath, hash: hexHash });
        console.log(`  ${urlPath}: ${hexHash.substring(0, 16)}...`);
    }

    if (errorCount > 0) {
        console.log(`\nWarning: ${errorCount} file(s) not found`);
    }

    // Get and increment sequence number (anti-downgrade protection)
    console.log('\nStep 5: Setting sequence number...');
    let sequence;
    if (options.sequence !== null) {
        sequence = options.sequence;
        console.log(`  Using override sequence: ${sequence}`);
    } else {
        const currentSequence = getCurrentSequence(options.output);
        sequence = currentSequence + 1;
        console.log(`  Previous sequence: ${currentSequence}, new sequence: ${sequence}`);
    }

    // Create data object
    const data = {
        version: '1.2.0',  // Bumped version for anti-downgrade support
        sequence: sequence,  // Anti-downgrade sequence number
        generated: new Date().toISOString(),
        site: 'https://pinchat.io',
        files
    };

    if (options.noSign) {
        fs.writeFileSync(options.output, JSON.stringify(data));
        console.log(`\nHashes generated (unsigned): ${options.output}`);
        process.exit(0);
    }

    // Get private key
    let privateKeyPem;
    let encryptedBuffer = null;

    if (options.encryptedKey) {
        console.log('\nUsing encrypted key (decrypting in RAM only)...');
        encryptedBuffer = fs.readFileSync(options.encryptedKey);

        try {
            const password = await promptPassword('Enter key password: ');
            privateKeyPem = decryptPemFile(encryptedBuffer, password);
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

    const output = {
        data,
        signature
    };

    fs.writeFileSync(options.output, JSON.stringify(output, null, 2));
    console.log(`\nOutput written to: ${options.output}`);

    // Summary
    console.log(`
Summary:
  - JS/CSS files: ${JS_CSS_FILES.length}
  - HTML files: ${HTML_FILES.length}
  - HTML files updated with SRI: ${htmlUpdates.length}
  - Total files in manifest: ${files.length}
  - Sequence number: ${sequence}

IMPORTANT:
  1. Commit the updated HTML files to git
  2. Upload hashes.json.signed to GitHub
  3. Update extension PUBLIC_KEY if key changed

ANTI-DOWNGRADE PROTECTION:
  The sequence number (${sequence}) prevents replay attacks with old manifests.
  Extensions will reject any manifest with a lower sequence number.
`);
}

main().catch(error => {
    console.error('Fatal error:', error.message);
    process.exit(1);
});
