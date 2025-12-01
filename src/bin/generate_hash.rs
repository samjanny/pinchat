//! CLI utility to generate Argon2id password hashes for configuration
//!
//! Reads a password from STDIN (or the first CLI argument) and prints the
//! resulting hash together with ready-to-copy `.env` snippets.

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use rand::rngs::OsRng;
use std::io::{self, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let password = if args.len() > 1 {
        // Accept the password from the first positional argument to support
        // non-interactive usage (e.g., scripting or CI).
        args[1].clone()
    } else {
        // Prompt interactively when no argument is provided to avoid
        // accidentally hashing an empty string.
        print!("Enter password to hash: ");
        io::stdout().flush().unwrap();

        let mut password = String::new();
        io::stdin().read_line(&mut password).unwrap();
        password.trim().to_string()
    };

    if password.is_empty() {
        eprintln!("Error: Password cannot be empty");
        std::process::exit(1);
    }

    // Generate a fresh salt to ensure each invocation produces a unique hash
    // even when the input password is identical.
    let salt = SaltString::generate(&mut OsRng);

    // Configure Argon2id with the OWASP 2024 recommended parameters for
    // interactive logins: ~47 MiB memory, a single iteration, and a single
    // thread to balance security and runtime for this CLI tool.
    let argon2 = match Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(47104, 1, 1, None).unwrap(),
    ) {
        params => params,
    };

    // Produce the hash and emit clear instructions for .env configuration.
    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => {
            println!("\n=== Argon2id Password Hash ===");
            println!("\nHash:");
            println!("{}", hash);
            println!("\n=== For .env file ===");
            println!("Copy this line directly into your .env file:");
            println!("(single quotes prevent dotenvy from interpreting $ as variables)");
            println!("\nPINCHAT_PASSWORD_HASHES='{}'", hash);
            println!("\nFor multiple passwords, separate with semicolons inside the quotes:");
            println!("PINCHAT_PASSWORD_HASHES='hash1;hash2;hash3'");
        }
        Err(e) => {
            eprintln!("Error hashing password: {}", e);
            std::process::exit(1);
        }
    }
}
