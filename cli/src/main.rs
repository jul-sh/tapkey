mod encrypt;
mod nearby;

use clap::{Parser, ValueEnum};
use std::io::Write;
use keytap_core::{PrivateKeyFormat, PublicKeyFormat};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "keytap", version)]
struct Cli {
    /// Create the passkey (only needed once)
    #[arg(long)]
    init: bool,

    /// Key name for domain separation
    #[arg(default_value = "default", conflicts_with = "init")]
    name: Option<String>,

    /// Output format
    #[arg(long, default_value = "hex", conflicts_with = "init")]
    format: Format,

    /// Output the public key instead of the private key
    #[arg(long, conflicts_with_all = ["init", "encrypt", "decrypt"])]
    public: bool,

    /// Encrypt a file with the derived age identity
    #[arg(long, conflicts_with_all = ["init", "format"])]
    encrypt: Option<String>,

    /// Decrypt an age-encrypted file with the derived age identity
    #[arg(long, conflicts_with_all = ["init", "format", "encrypt"])]
    decrypt: Option<String>,

    /// Additional age recipient (can be repeated)
    #[arg(long = "to", requires = "encrypt", conflicts_with_all = ["init", "decrypt"])]
    recipients: Vec<String>,

    /// File containing age recipients (one per line)
    #[arg(short = 'R', requires = "encrypt", conflicts_with_all = ["init", "decrypt"])]
    recipients_file: Vec<String>,

    /// Don't include self as a recipient when encrypting
    #[arg(long, requires = "encrypt", conflicts_with_all = ["init", "decrypt"])]
    no_self: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Format {
    Hex,
    Base64,
    Age,
    Raw,
    Ssh,
}

fn main() {
    let cli = Cli::parse();

    if cli.init {
        register();
        return;
    }

    let name = cli.name.as_deref().unwrap_or("default");
    let prf_output = authenticate(name);
    let raw_key = derive_key(&prf_output);

    if cli.public {
        if matches!(cli.format, Format::Raw) {
            die("--format raw is not supported with --public");
        }
        emit_public_key(&raw_key, cli.format);
        return;
    }

    if let Some(ref path) = cli.encrypt {
        encrypt::encrypt_file(&raw_key, path, &cli.recipients, &cli.recipients_file, !cli.no_self);
    } else if let Some(ref path) = cli.decrypt {
        encrypt::decrypt_file(&raw_key, path);
    } else {
        emit_private_key(&raw_key, cli.format);
    }
}

/// Authenticate with passkey and return the PRF output.
#[cfg(feature = "native-passkey")]
fn authenticate(name: &str) -> Zeroizing<Vec<u8>> {
    for attempt in 1..=3 {
        match keytap_macos::assert(name) {
            keytap_macos::AssertionOutcome::Success { prf_output, .. } => {
                return Zeroizing::new(prf_output);
            }
            keytap_macos::AssertionOutcome::Error(msg) if msg == "cancelled" => {
                die(&msg);
            }
            keytap_macos::AssertionOutcome::Error(msg) => {
                if attempt < 3 {
                    eprintln!("Native passkey failed (attempt {attempt}/3): {msg}");
                } else {
                    eprintln!("Couldn't open native passkey flow.");
                    return Zeroizing::new(nearby::authenticate_nearby(name));
                }
            }
        }
    }
    unreachable!()
}

#[cfg(not(feature = "native-passkey"))]
fn authenticate(name: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(nearby::authenticate_nearby(name))
}

fn derive_key(prf_output: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(keytap_core::derive_raw_key(prf_output).unwrap_or_else(|e| {
        die(&format!("key derivation failed: {e}"));
    }))
}

#[cfg(feature = "native-passkey")]
fn register() {
    for attempt in 1..=3 {
        match keytap_macos::register() {
            keytap_macos::RegistrationOutcome::Success => {
                eprintln!("Passkey registered successfully.");
                return;
            }
            keytap_macos::RegistrationOutcome::Error(msg) if msg == "cancelled" => {
                die(&msg);
            }
            keytap_macos::RegistrationOutcome::Error(msg) => {
                if attempt < 3 {
                    eprintln!("Native passkey failed (attempt {attempt}/3): {msg}");
                } else {
                    eprintln!("Couldn't open native passkey flow.");
                    nearby::register_nearby();
                    return;
                }
            }
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn register() {
    nearby::register_nearby();
}

fn emit_private_key(raw_key: &[u8], format: Format) {
    let priv_format = match format {
        Format::Hex => PrivateKeyFormat::Hex,
        Format::Base64 => PrivateKeyFormat::Base64,
        Format::Age => PrivateKeyFormat::AgeSecretKey,
        Format::Raw => PrivateKeyFormat::Raw,
        Format::Ssh => PrivateKeyFormat::SshPrivateKey,
    };
    match keytap_core::format_private_key(raw_key, priv_format) {
        Ok(bytes) => {
            if matches!(format, Format::Raw) {
                std::io::stdout().write_all(&bytes).unwrap();
            } else if matches!(format, Format::Ssh) {
                print!("{}", String::from_utf8(bytes).unwrap());
            } else {
                println!("{}", String::from_utf8(bytes).unwrap());
            }
        }
        Err(e) => die(&format!("format error: {e}")),
    }
}

fn emit_public_key(raw_key: &[u8], format: Format) {
    let pub_format = match format {
        Format::Hex => PublicKeyFormat::Hex,
        Format::Base64 => PublicKeyFormat::Base64,
        Format::Age => PublicKeyFormat::AgeRecipient,
        Format::Ssh => PublicKeyFormat::SshPublicKey,
        Format::Raw => die("--format raw is not supported with --public"),
    };
    match keytap_core::format_public_key(raw_key, pub_format) {
        Ok(s) => println!("{s}"),
        Err(e) => die(&format!("format error: {e}")),
    }
}

pub(crate) fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
