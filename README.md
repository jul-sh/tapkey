# tapkey

Derive deterministic symmetric keys from a passkey stored in your passkey provider, using Touch ID.

Tap Touch ID on any Mac with the same passkey — get the same key. Works with iCloud Keychain, 1Password, or any passkey provider macOS supports. No server, no secrets to copy between machines.

## Install

### From release (recommended)

Download the latest attested release:

```bash
gh release download --repo jul-sh/tapkey --pattern 'tapkey-*.zip'
unzip tapkey-*.zip
# Remove macOS quarantine (the binary is attested but not Apple-notarized)
xattr -dr com.apple.quarantine Tapkey.app
# Symlink into PATH
mkdir -p ~/.local/bin
ln -sf "$(pwd)/Tapkey.app/Contents/MacOS/tapkey" ~/.local/bin/tapkey
```

Verify the build attestation:

```bash
gh attestation verify tapkey-*.zip --owner jul-sh
```

### From source

Requires macOS 15+, Xcode Command Line Tools, and a [paid Apple Developer Program membership](https://developer.apple.com/programs/) (Associated Domains entitlement requires it).

```bash
git clone https://github.com/jul-sh/tapkey.git
cd tapkey
make install
```

This compiles, codesigns with entitlements, and symlinks to `~/.local/bin/tapkey`.

## Usage

### First-time setup

Create a passkey (one-time setup — macOS will let you choose your passkey provider):

```bash
tapkey register
```

### Derive a key

```bash
tapkey derive                              # 32-byte key as hex (default)
tapkey derive --format base64              # base64
tapkey derive --format raw                 # raw bytes to stdout
tapkey derive --format age                 # AGE-SECRET-KEY-1...
tapkey derive --format ssh                 # OpenSSH Ed25519 private key
```

### Named keys

Use `--name` to derive different keys from the same passkey. Each name deterministically produces a different key:

```bash
tapkey derive --name backup                # one key for backups
tapkey derive --name deploy                # a different key for deploys
tapkey derive --name age --format age      # age encryption key
tapkey derive --name ssh --format ssh      # SSH key
```

The default name is `"default"`.

### Public keys

```bash
tapkey public-key                          # age public key (age1...)
tapkey public-key --name ssh --format ssh  # ssh-ed25519 AAAA...
```

### Use with age

```bash
# Encrypt
echo "secret" | age -r $(tapkey public-key --name age) > secret.age

# Decrypt
age -d -i <(tapkey derive --name age --format age) secret.age
```

### Use with SSH

```bash
# Write SSH key (tap Touch ID once)
tapkey derive --name ssh --format ssh > ~/.ssh/id_tapkey
chmod 600 ~/.ssh/id_tapkey

# Get public key for authorized_keys / GitHub
tapkey public-key --name ssh --format ssh
```

## How it works

1. **Register** creates a passkey via `ASAuthorizationPlatformPublicKeyCredentialProvider` with the relying party `tapkey.jul.sh`. The passkey is stored in your chosen passkey provider (iCloud Keychain, 1Password, etc.) and syncs across devices.

2. **Derive** performs a WebAuthn assertion with the [PRF extension](https://w3c.github.io/webauthn/#prf-extension) (macOS 15+). The PRF extension takes a fixed salt and returns a deterministic 32-byte `SymmetricKey` bound to the passkey credential.

3. The PRF output is passed through **HKDF-SHA256** with info string `"tapkey:<name>"` to derive 32 bytes of key material. Different `--name` values produce different keys from the same PRF output.

4. The derived bytes are formatted as hex, base64, an age secret key (Bech32), an OpenSSH Ed25519 key, or raw bytes.

## Security model

### What's trusted

- **Your passkey provider** (iCloud Keychain, 1Password, etc.) — passkeys are synced via the provider's E2E encryption
- **The Secure Enclave** — Touch ID / PRF evaluation happens in hardware
- **The PRF extension** — deterministic output bound to the specific credential; different credentials produce different outputs even with the same salt
- **HKDF-SHA256** — standard key derivation with domain separation via the `--name` parameter

### What's public and safe to expose

- **PRF salt** (`SHA256("tapkey:prf-salt-v1")`) — fixed, deterministic, public. Knowing the salt doesn't help without the passkey.
- **Credential ID** (stored in `~/.config/tapkey/credential.json`) — identifies which passkey to use, not secret. It's equivalent to a username.
- **HKDF info strings** (`"tapkey:<name>"`) — public domain-separation labels.

### Domain separation

The `--name` flag sets the HKDF info string to `"tapkey:<name>"`. Since HKDF info is part of the expand step in the extract-then-expand construction, different names are cryptographically guaranteed to produce independent keys. The name is not length-limited but must be non-empty.

### Threat model

- **Attacker with physical access to unlocked Mac**: Can derive keys (same as any key in memory). tapkey doesn't add protection beyond what Touch ID provides — it's a convenience tool, not a vault.
- **Attacker with stolen credentials**: Would also need a trusted device to approve passkey sync. Your provider's recovery protections apply.
- **Attacker who compromises the binary**: Build attestation via GitHub Actions + `actions/attest-build-provenance` provides supply chain verification. Verify with `gh attestation verify`.
- **Malicious HKDF info string**: No risk — HKDF info is a standard parameter that cannot cause collisions or oracle attacks regardless of content. Two different info strings always produce independent outputs.

### What tapkey does NOT do

- Store or transmit derived keys — they're printed to stdout and forgotten
- Cache PRF output or derived keys
- Phone home or make network requests
- Run persistently — it launches, presents Touch ID, outputs the key, and exits

## Requirements

- macOS 15.0 (Sequoia) or later
- Apple Silicon (arm64)
- A passkey provider with PRF support (iCloud Keychain, 1Password, etc.)
- Paid Apple Developer Program membership (for building from source — Associated Domains entitlement requires it)

## Development

```bash
# Enter dev shell (provides age, gh)
nix develop

# Build and sign
make

# Build, sign, and install
make install

# Verify codesigning
make verify

# Clean
make clean
```

### Encrypting secrets for CI

```bash
# Encrypt a secret
echo -n "secret-value" | age -R secrets/age-recipients.txt -o secrets/SECRET_NAME.age

# Decrypt (locally)
AGE_SECRET_KEY=$(./distribution/get-age-key.sh)
echo "$AGE_SECRET_KEY" | age -d -i - secrets/SECRET_NAME.age
```

## License

MIT
