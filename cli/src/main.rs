mod encrypt;
mod nearby;

use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use tapkey_core::{PrivateKeyFormat, PublicKeyFormat};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "tapkey", version)]
struct Cli {
    /// Create the passkey (only needed once)
    #[arg(long)]
    init: bool,

    #[command(subcommand)]
    command: Option<Cmd>,

    /// Key name for domain separation
    #[arg(default_value = "default", conflicts_with = "init")]
    name: Option<String>,

    /// Output format
    #[arg(long, default_value = "hex", conflicts_with = "init")]
    format: Format,

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

#[derive(Subcommand)]
enum Cmd {
    /// Show the public key for a derived key
    PublicKey {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,
        /// Output format
        #[arg(long, default_value = "age")]
        format: Format,
    },
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

    if let Some(Cmd::PublicKey { name, format }) = cli.command {
        if matches!(format, Format::Raw) {
            die("--format raw is not supported for public-key");
        }
        let prf_output = authenticate(&name);
        let raw_key = derive_key(&prf_output);
        emit_public_key(&raw_key, format);
        return;
    }

    let name = cli.name.as_deref().unwrap_or("default");
    let prf_output = authenticate(name);
    let raw_key = derive_key(&prf_output);

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
    match tapkey_macos::assert(name) {
        tapkey_macos::AssertionOutcome::Success { prf_output, .. } => Zeroizing::new(prf_output),
        tapkey_macos::AssertionOutcome::Error(msg) if msg == "cancelled" => {
            die(&msg);
        }
        tapkey_macos::AssertionOutcome::Error(msg) => {
            eprintln!("Native passkey failed: {msg}");
            eprintln!("Falling back to QR code flow…");
            Zeroizing::new(nearby::authenticate_nearby(name))
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn authenticate(name: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(nearby::authenticate_nearby(name))
}

fn derive_key(prf_output: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(tapkey_core::derive_raw_key(prf_output).unwrap_or_else(|e| {
        die(&format!("key derivation failed: {e}"));
    }))
}

#[cfg(feature = "native-passkey")]
fn register() {
    match tapkey_macos::register() {
        tapkey_macos::RegistrationOutcome::Success => {
            eprintln!("Passkey registered successfully.");
        }
        tapkey_macos::RegistrationOutcome::Error(msg) if msg == "cancelled" => {
            die(&msg);
        }
        tapkey_macos::RegistrationOutcome::Error(msg) => {
            eprintln!("Native passkey failed: {msg}");
            eprintln!("Falling back to QR code flow…");
            nearby::register_nearby();
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
    match tapkey_core::format_private_key(raw_key, priv_format) {
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
        Format::Raw => die("--format raw is not supported for public-key"),
    };
    match tapkey_core::format_public_key(raw_key, pub_format) {
        Ok(s) => println!("{s}"),
        Err(e) => die(&format!("format error: {e}")),
    }
}

pub(crate) fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
