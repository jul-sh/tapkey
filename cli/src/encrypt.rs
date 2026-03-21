use age::x25519;
use std::fs;
use std::io::{Read, Write};
use std::str::FromStr;

/// Encrypt a file to self (derived age identity) plus optional additional recipients.
/// Writes output to `<path>.age`.
pub fn encrypt_file(
    raw_key: &[u8],
    path: &str,
    additional_recipients: &[String],
    recipients_files: &[String],
    include_self: bool,
) {
    let plaintext = fs::read(path).unwrap_or_else(|e| {
        crate::die(&format!("failed to read {path}: {e}"));
    });

    let mut recipients: Vec<Box<dyn age::Recipient>> = Vec::new();

    if include_self {
        let identity = identity_from_raw_key(raw_key);
        recipients.push(Box::new(identity.to_public()));
    }

    // Parse --to recipients
    for r in additional_recipients {
        let recipient = x25519::Recipient::from_str(r).unwrap_or_else(|e| {
            crate::die(&format!("invalid recipient {r}: {e}"));
        });
        recipients.push(Box::new(recipient));
    }

    // Parse -R recipients files
    for file in recipients_files {
        let contents = fs::read_to_string(file).unwrap_or_else(|e| {
            crate::die(&format!("failed to read recipients file {file}: {e}"));
        });
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let recipient = x25519::Recipient::from_str(line).unwrap_or_else(|e| {
                crate::die(&format!("invalid recipient in {file}: {line}: {e}"));
            });
            recipients.push(Box::new(recipient));
        }
    }

    if recipients.is_empty() {
        crate::die("no recipients specified (use --to, -R, or remove --no-self)");
    }

    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
        .unwrap_or_else(|e| {
            crate::die(&format!("failed to create encryptor: {e}"));
        });

    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .unwrap_or_else(|e| {
            crate::die(&format!("encryption failed: {e}"));
        });
    writer.write_all(&plaintext).unwrap_or_else(|e| {
        crate::die(&format!("encryption failed: {e}"));
    });
    writer.finish().unwrap_or_else(|e| {
        crate::die(&format!("encryption failed: {e}"));
    });

    let out_path = format!("{path}.age");
    fs::write(&out_path, &encrypted).unwrap_or_else(|e| {
        crate::die(&format!("failed to write {out_path}: {e}"));
    });

    eprintln!("{out_path}");
}

/// Decrypt a `.age` file using the derived age identity. Writes plaintext to stdout.
pub fn decrypt_file(raw_key: &[u8], path: &str) {
    let ciphertext = fs::read(path).unwrap_or_else(|e| {
        crate::die(&format!("failed to read {path}: {e}"));
    });

    let identity = identity_from_raw_key(raw_key);

    let decryptor = match age::Decryptor::new(&ciphertext[..]) {
        Ok(d) => d,
        Err(e) => crate::die(&format!("failed to read age file: {e}")),
    };

    let mut reader = match decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)) {
        Ok(r) => r,
        Err(e) => crate::die(&format!("decryption failed: {e}")),
    };

    let mut plaintext = vec![];
    reader.read_to_end(&mut plaintext).unwrap_or_else(|e| {
        crate::die(&format!("decryption failed: {e}"));
    });

    std::io::stdout().write_all(&plaintext).unwrap_or_else(|e| {
        crate::die(&format!("write failed: {e}"));
    });
}

fn identity_from_raw_key(raw_key: &[u8]) -> x25519::Identity {
    let secret_key_str = tapkey_core::format_private_key(raw_key, tapkey_core::PrivateKeyFormat::AgeSecretKey)
        .unwrap_or_else(|e| crate::die(&format!("key format error: {e}")));
    let secret_key_str = String::from_utf8(secret_key_str)
        .unwrap_or_else(|e| crate::die(&format!("key format error: {e}")));
    x25519::Identity::from_str(&secret_key_str)
        .unwrap_or_else(|e| crate::die(&format!("invalid age identity: {e}")))
}
