mod auth;
mod credential;

use clap::{Parser, Subcommand, ValueEnum};
use objc2::{msg_send, MainThreadOnly};
use objc2_app_kit::{NSApplication, NSBackingStoreType, NSWindow, NSWindowStyleMask};
use objc2_foundation::{MainThreadMarker, NSPoint, NSRect, NSSize};
use std::io::Write;
use tapkey_core::{PrivateKeyFormat, PublicKeyFormat};

#[derive(Parser)]
#[command(name = "tapkey", version)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the passkey root
    Register {
        /// Replace the locally registered passkey root
        #[arg(long)]
        replace: bool,
    },
    /// Derive key material from your passkey
    Derive {
        /// Key name for domain separation
        #[arg(long, default_value = "default")]
        name: String,
        /// Output format
        #[arg(long, default_value = "hex")]
        format: Format,
    },
    /// Show the public key for a derived key
    PublicKey {
        /// Key name for domain separation
        #[arg(long, default_value = "default")]
        name: String,
        /// Output format
        #[arg(long, default_value = "age")]
        format: Format,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Hex,
    Base64,
    Age,
    Raw,
    Ssh,
}

fn main() {
    let cli = Cli::parse();
    let mtm = MainThreadMarker::new().expect("tapkey must run on the main thread");

    unsafe {
        let app = NSApplication::sharedApplication(mtm);
        let _: () = msg_send![&app, setActivationPolicy: 1i64]; // .accessory

        match cli.command {
            Cmd::Register { replace } => {
                if !replace && credential::load().is_ok() {
                    die("a tapkey passkey is already registered on this Mac\n  Run 'tapkey derive' to use it.\n  Use 'tapkey register --replace' only if you intend to rotate every derived key.");
                }
                start_registration(mtm);
            }
            Cmd::Derive { name, format } => {
                start_assertion(mtm, &name, format, false);
            }
            Cmd::PublicKey { name, format } => {
                if matches!(format, Format::Raw) {
                    die("--format raw is not supported for public-key");
                }
                start_assertion(mtm, &name, format, true);
            }
        }

        app.run();
    }
}

fn start_registration(mtm: MainThreadMarker) {
    let anchor = create_anchor_window(mtm);
    auth::start_registration(
        mtm,
        &anchor,
        Box::new(move |outcome| match outcome {
            auth::RegistrationOutcome::Success { credential_id } => {
                if let Err(e) = credential::save(&credential::StoredCredential::new(credential_id))
                {
                    die(&format!("failed to save credential: {e}"));
                }
                eprintln!("Passkey registered successfully.");
                eprintln!(
                    "Credential saved to {}",
                    credential::credential_path().display()
                );
                std::process::exit(0);
            }
            auth::RegistrationOutcome::Error(msg) => die(&msg),
        }),
    );
    std::mem::forget(anchor);
}

fn start_assertion(mtm: MainThreadMarker, name: &str, format: Format, is_public: bool) {
    let preferred_id = credential::load().ok().map(|c| c.credential_id);
    let name = name.to_string();

    let anchor = create_anchor_window(mtm);
    auth::start_assertion(
        mtm,
        &anchor,
        &name,
        preferred_id.as_deref(),
        Box::new(move |outcome| match outcome {
            auth::AssertionOutcome::Success {
                credential_id,
                prf_output,
            } => {
                if let Err(e) = credential::cache_if_needed(&credential_id) {
                    die(&format!("failed to cache credential: {e}"));
                }
                emit_key(&prf_output, format, is_public);
            }
            auth::AssertionOutcome::Error(msg) => die(&msg),
        }),
    );
    std::mem::forget(anchor);
}

// -- Output --

fn emit_key(prf_output: &[u8], format: Format, is_public: bool) {
    let raw_key = match tapkey_core::derive_raw_key(prf_output) {
        Ok(k) => k,
        Err(e) => die(&format!("key derivation failed: {e}")),
    };

    if is_public {
        let pub_format = match format {
            Format::Hex => PublicKeyFormat::Hex,
            Format::Base64 => PublicKeyFormat::Base64,
            Format::Age => PublicKeyFormat::AgeRecipient,
            Format::Ssh => PublicKeyFormat::SshPublicKey,
            Format::Raw => die("--format raw is not supported for public-key"),
        };
        match tapkey_core::format_public_key(&raw_key, pub_format) {
            Ok(s) => {
                println!("{s}");
                std::process::exit(0);
            }
            Err(e) => die(&format!("format error: {e}")),
        }
    } else {
        let priv_format = match format {
            Format::Hex => PrivateKeyFormat::Hex,
            Format::Base64 => PrivateKeyFormat::Base64,
            Format::Age => PrivateKeyFormat::AgeSecretKey,
            Format::Raw => PrivateKeyFormat::Raw,
            Format::Ssh => PrivateKeyFormat::SshPrivateKey,
        };
        match tapkey_core::format_private_key(&raw_key, priv_format) {
            Ok(bytes) => {
                if matches!(format, Format::Raw) {
                    std::io::stdout().write_all(&bytes).unwrap();
                } else if matches!(format, Format::Ssh) {
                    print!("{}", String::from_utf8(bytes).unwrap());
                } else {
                    println!("{}", String::from_utf8(bytes).unwrap());
                }
                std::process::exit(0);
            }
            Err(e) => die(&format!("format error: {e}")),
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn create_anchor_window(mtm: MainThreadMarker) -> objc2::rc::Retained<NSWindow> {
    let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(1.0, 1.0));
    unsafe {
        NSWindow::initWithContentRect_styleMask_backing_defer(
            NSWindow::alloc(mtm),
            frame,
            NSWindowStyleMask::empty(),
            NSBackingStoreType::Buffered,
            true,
        )
    }
}
