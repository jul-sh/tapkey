import AppKit
import AuthenticationServices
import CryptoKit
import Foundation

private let fallbackTapkeyVersion = "0.1.2"

func currentTapkeyVersion() -> String {
    Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        ?? fallbackTapkeyVersion
}

// MARK: - Bech32

enum Bech32 {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

    private static func polymod(_ values: [UInt32]) -> UInt32 {
        let gen: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        var chk: UInt32 = 1
        for v in values {
            let b = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in 0..<5 {
                chk ^= ((b >> i) & 1) != 0 ? gen[i] : 0
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt32] {
        let chars = Array(hrp.utf8)
        var result = chars.map { UInt32($0) >> 5 }
        result.append(0)
        result += chars.map { UInt32($0) & 31 }
        return result
    }

    private static func createChecksum(_ hrp: String, _ data: [UInt32]) -> [UInt32] {
        let values = hrpExpand(hrp) + data + [0, 0, 0, 0, 0, 0]
        let mod = polymod(values) ^ 1
        return (0..<6).map { (mod >> (5 * (5 - $0))) & 31 }
    }

    static func encode(hrp: String, data: Data) -> String {
        var acc: UInt32 = 0
        var bits: UInt32 = 0
        var result: [UInt32] = []
        for byte in data {
            acc = (acc << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                result.append((acc >> bits) & 31)
            }
        }
        if bits > 0 {
            result.append((acc << (5 - bits)) & 31)
        }
        let checksum = createChecksum(hrp, result)
        let encoded = (result + checksum).map { charset[Int($0)] }
        return hrp + "1" + String(encoded)
    }
}

// MARK: - OpenSSH Ed25519 Key Formatting

enum SSHKey {
    private static let checkIntLabel = Data("tapkey:ssh-checkint".utf8)

    // Encode a 32-byte Ed25519 seed as an OpenSSH PEM private key.
    // Format: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
    static func privateKeyPEM(seed: Data) -> String {
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let pubBytes = privateKey.publicKey.rawRepresentation

        let magic = Data("openssh-key-v1\0".utf8)
        let cipherName = sshString("none")
        let kdfName = sshString("none")
        let kdfOptions = sshString("")
        let numKeys = uint32BE(1)

        let pubBlob = sshString("ssh-ed25519") + sshBytes(pubBytes)
        let pubSection = sshBytes(pubBlob)

        let checkInt = deterministicCheckInt(seed: seed)
        var privPayload = Data()
        privPayload += uint32BE(checkInt)
        privPayload += uint32BE(checkInt)
        privPayload += sshString("ssh-ed25519")
        privPayload += sshBytes(pubBytes)
        privPayload += sshBytes(seed + pubBytes)
        privPayload += sshString("")

        let blockSize = 8
        var padByte: UInt8 = 1
        while privPayload.count % blockSize != 0 {
            privPayload.append(padByte)
            padByte += 1
        }

        let privSection = sshBytes(privPayload)
        let blob = magic + cipherName + kdfName + kdfOptions + numKeys + pubSection + privSection
        let b64 = blob.base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed])
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n\(b64)\n-----END OPENSSH PRIVATE KEY-----\n"
    }

    static func publicKeyLine(seed: Data) -> String {
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let pubBytes = privateKey.publicKey.rawRepresentation
        let blob = sshString("ssh-ed25519") + sshBytes(pubBytes)
        return "ssh-ed25519 \(blob.base64EncodedString()) tapkey"
    }

    private static func deterministicCheckInt(seed: Data) -> UInt32 {
        var input = checkIntLabel
        input.append(seed)
        return SHA256.hash(data: input).prefix(4).reduce(0) { ($0 << 8) | UInt32($1) }
    }

    private static func uint32BE(_ v: UInt32) -> Data {
        var be = v.bigEndian
        return Data(bytes: &be, count: 4)
    }

    private static func sshString(_ s: String) -> Data {
        let d = Data(s.utf8)
        return uint32BE(UInt32(d.count)) + d
    }

    private static func sshBytes(_ d: Data) -> Data {
        uint32BE(UInt32(d.count)) + d
    }
}

// MARK: - Config

struct Config {
    static let relyingParty = "tapkey.jul.sh"
    static let registrationName = "tapkey"
    static let registrationUserID = Data("tapkey-user".utf8)
    static let registrationChallenge = Data(SHA256.hash(data: Data("tapkey:registration".utf8)))
    static let assertionChallenge = Data(SHA256.hash(data: Data("tapkey:assertion".utf8)))

    static let configDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".config/tapkey")
    static let credentialFile = configDir.appendingPathComponent("credential.json")

    // Fixed PRF salt — public, deterministic. Changing this rotates all derived keys.
    static let prfSalt: Data = {
        let hash = SHA256.hash(data: Data("tapkey:prf-salt-v1".utf8))
        return Data(hash)
    }()
}

// MARK: - Output

enum OutputFormat: String {
    case hex
    case base64
    case age
    case raw
    case ssh
}

struct KeyOptions {
    let name: String
    let format: OutputFormat
}

// MARK: - Credential Storage

struct StoredCredential: Codable, Equatable {
    let credentialID: Data
    let createdAt: String

    init(credentialID: Data) {
        self.credentialID = credentialID
        let formatter = ISO8601DateFormatter()
        self.createdAt = formatter.string(from: Date())
    }
}

func saveCredential(_ credential: StoredCredential) throws {
    try FileManager.default.createDirectory(at: Config.configDir, withIntermediateDirectories: true)
    let encoder = JSONEncoder()
    encoder.outputFormatting = .prettyPrinted
    let data = try encoder.encode(credential)
    try data.write(to: Config.credentialFile, options: .atomic)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: Config.credentialFile.path
    )
}

func loadCredential() throws -> StoredCredential {
    let data = try Data(contentsOf: Config.credentialFile)
    return try JSONDecoder().decode(StoredCredential.self, from: data)
}

func cacheCredentialIDIfNeeded(_ credentialID: Data) throws {
    if let stored = try? loadCredential(), stored.credentialID == credentialID {
        return
    }
    try saveCredential(StoredCredential(credentialID: credentialID))
}

// MARK: - Key Derivation

func deriveRawKey(from prfOutput: SymmetricKey, name: String) -> Data {
    let info = Data("tapkey:\(name)".utf8)
    let key = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: prfOutput,
        info: info,
        outputByteCount: 32
    )
    return key.withUnsafeBytes { Data($0) }
}

func formatKey(_ rawKey: Data, format: OutputFormat) -> String {
    switch format {
    case .hex:
        return rawKey.map { String(format: "%02x", $0) }.joined()
    case .base64:
        return rawKey.base64EncodedString()
    case .age:
        return Bech32.encode(hrp: "age-secret-key-", data: rawKey).uppercased()
    case .raw:
        fatalError("raw format should be handled before calling formatKey")
    case .ssh:
        return SSHKey.privateKeyPEM(seed: rawKey)
    }
}

func formatPublicKey(_ rawKey: Data, format: OutputFormat) -> String {
    switch format {
    case .age:
        let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawKey)
        return Bech32.encode(hrp: "age", data: privateKey.publicKey.rawRepresentation)
    case .ssh:
        return SSHKey.publicKeyLine(seed: rawKey)
    case .hex:
        let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawKey)
        return privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    case .base64:
        let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawKey)
        return privateKey.publicKey.rawRepresentation.base64EncodedString()
    case .raw:
        fatalError("raw format should be handled before calling formatPublicKey")
    }
}

// MARK: - Commands

enum Command {
    case register(replaceExisting: Bool)
    case derive(KeyOptions)
    case publicKey(KeyOptions)
    case version
}

struct Arguments {
    let command: Command

    static func parse() -> Arguments {
        let args = Array(CommandLine.arguments.dropFirst())

        if args.contains("--version") || args.contains("-v") {
            return Arguments(command: .version)
        }

        if args.contains("--help") || args.contains("-h") || args.isEmpty {
            printUsage()
            exit(0)
        }

        guard let subcommand = args.first else {
            printUsage()
            exit(1)
        }

        switch subcommand {
        case "register":
            return Arguments(command: parseRegister(arguments: Array(args.dropFirst())))
        case "derive":
            return Arguments(command: .derive(parseKeyOptions(arguments: Array(args.dropFirst()), defaultFormat: .hex)))
        case "public-key":
            return Arguments(command: .publicKey(parseKeyOptions(arguments: Array(args.dropFirst()), defaultFormat: .age)))
        default:
            fputs("error: unknown command '\(subcommand)'\n", stderr)
            printUsage()
            exit(1)
        }
    }

    private static func parseRegister(arguments: [String]) -> Command {
        var replaceExisting = false

        for argument in arguments {
            switch argument {
            case "--replace":
                replaceExisting = true
            default:
                fputs("error: unknown option '\(argument)'\n", stderr)
                exit(1)
            }
        }

        return .register(replaceExisting: replaceExisting)
    }

    private static func parseKeyOptions(arguments: [String], defaultFormat: OutputFormat) -> KeyOptions {
        var name = "default"
        var format = defaultFormat

        var index = 0
        while index < arguments.count {
            switch arguments[index] {
            case "--name":
                guard index + 1 < arguments.count else {
                    fputs("error: --name requires a value\n", stderr)
                    exit(1)
                }
                index += 1
                name = arguments[index]
                validateKeyName(name)
            case "--format":
                guard index + 1 < arguments.count else {
                    fputs("error: --format requires a value (hex, base64, age, raw, ssh)\n", stderr)
                    exit(1)
                }
                index += 1
                guard let parsedFormat = OutputFormat(rawValue: arguments[index]) else {
                    fputs("error: unknown format '\(arguments[index])'. Use: hex, base64, age, raw, ssh\n", stderr)
                    exit(1)
                }
                format = parsedFormat
            default:
                fputs("error: unknown option '\(arguments[index])'\n", stderr)
                exit(1)
            }
            index += 1
        }

        return KeyOptions(name: name, format: format)
    }

    private static func validateKeyName(_ name: String) {
        if name.isEmpty {
            fputs("error: --name cannot be empty\n", stderr)
            exit(1)
        }
        if name.utf8.count > 1024 {
            fputs("error: --name must be at most 1024 bytes\n", stderr)
            exit(1)
        }
        if !name.allSatisfy({ $0.isASCII }) {
            fputs("error: --name must contain only ASCII characters\n", stderr)
            exit(1)
        }
    }

    static func printUsage() {
        fputs("""
        Usage: tapkey <command> [options]

        Commands:
          register [--replace]  Create the passkey root (one-time setup)
          derive                Derive key material from your passkey
          public-key            Show the public key for a derived key

        Options:
          --name <name>         Key name for domain separation (default: "default")
          --format <fmt>        Output format: hex, base64, age, raw, ssh
          --replace             Replace the locally registered passkey root
          --version             Show version

        Examples:
          tapkey register
          tapkey derive
          tapkey derive --name backup --format base64
          tapkey derive --name ssh --format ssh > ~/.ssh/id_tapkey
          tapkey public-key --name ssh --format ssh
          tapkey register --replace

        On a new Mac with the passkey already synced, you can run 'tapkey derive'
        directly. It will discover the passkey and cache the credential locally.

        """, stderr)
    }
}

// MARK: - App Delegate

class AppDelegate: NSObject, NSApplicationDelegate {
    enum AssertionCommand {
        case derive(KeyOptions)
        case publicKey(KeyOptions)
    }

    enum CredentialSelection {
        case stored(StoredCredential)
        case discoverable
    }

    let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 1, height: 1),
        styleMask: [],
        backing: .buffered,
        defer: true
    )

    let command: Command
    var activeController: ASAuthorizationController?
    var activeDelegate: NSObject?

    init(command: Command) {
        self.command = command
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        switch command {
        case .version:
            print("tapkey \(currentTapkeyVersion())")
            exit(0)
        case .register(let replaceExisting):
            performRegistration(replaceExisting: replaceExisting)
        case .derive(let options):
            performAssertion(command: .derive(options))
        case .publicKey(let options):
            performAssertion(command: .publicKey(options))
        }
    }

    func performRegistration(replaceExisting: Bool) {
        if (try? loadCredential()) != nil && !replaceExisting {
            fputs("error: a tapkey passkey is already registered on this Mac\n", stderr)
            fputs("  Run 'tapkey derive' to use it.\n", stderr)
            fputs("  Use 'tapkey register --replace' only if you intend to rotate every derived key.\n", stderr)
            exit(1)
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: Config.relyingParty
        )

        let request = provider.createCredentialRegistrationRequest(
            challenge: Config.registrationChallenge,
            name: Config.registrationName,
            userID: Config.registrationUserID
        )

        if #available(macOS 15.0, *) {
            request.prf = .checkForSupport
        } else {
            fputs("error: tapkey requires macOS 15.0 or later (PRF extension)\n", stderr)
            exit(1)
        }

        let controller = ASAuthorizationController(authorizationRequests: [request])
        let delegate = RegistrationDelegate()
        beginAuthorization(controller: controller, delegate: delegate)
    }

    func performAssertion(command: AssertionCommand) {
        let selection: CredentialSelection
        if let stored = try? loadCredential() {
            selection = .stored(stored)
        } else {
            selection = .discoverable
        }
        startAssertion(command: command, selection: selection)
    }

    func startAssertion(command: AssertionCommand, selection: CredentialSelection) {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: Config.relyingParty
        )

        let request = provider.createCredentialAssertionRequest(challenge: Config.assertionChallenge)
        switch selection {
        case .stored(let stored):
            request.allowedCredentials = [
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(
                    credentialID: stored.credentialID
                )
            ]
        case .discoverable:
            break
        }

        if #available(macOS 15.0, *) {
            let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues
                .saltInput1(Config.prfSalt)
            request.prf = .inputValues(inputValues)
        } else {
            fputs("error: tapkey requires macOS 15.0 or later (PRF extension)\n", stderr)
            exit(1)
        }

        let retryWithoutStoredCredential: (() -> Void)?
        switch selection {
        case .stored:
            retryWithoutStoredCredential = { [weak self] in
                self?.startAssertion(command: command, selection: .discoverable)
            }
        case .discoverable:
            retryWithoutStoredCredential = nil
        }

        let controller = ASAuthorizationController(authorizationRequests: [request])
        let delegate = AssertionDelegate(
            command: command,
            selection: selection,
            retryWithoutStoredCredential: retryWithoutStoredCredential
        )
        beginAuthorization(controller: controller, delegate: delegate)
    }

    func beginAuthorization(controller: ASAuthorizationController, delegate: NSObject & ASAuthorizationControllerDelegate) {
        controller.delegate = delegate
        controller.presentationContextProvider = self
        activeController = controller
        activeDelegate = delegate
        controller.performRequests()
    }
}

extension AppDelegate: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        window
    }
}

// MARK: - Registration Delegate

class RegistrationDelegate: NSObject, ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            fputs("error: unexpected credential type\n", stderr)
            exit(1)
        }

        if #available(macOS 15.0, *) {
            guard let prfOutput = credential.prf, prfOutput.isSupported else {
                fputs("error: passkey created but PRF is not supported by this authenticator\n", stderr)
                fputs("  Platform passkeys on macOS 15+ should support PRF.\n", stderr)
                fputs("  Hardware security keys may not support the PRF extension.\n", stderr)
                exit(1)
            }
        }

        do {
            try saveCredential(StoredCredential(credentialID: credential.credentialID))
        } catch {
            fputs("error: failed to save credential: \(error.localizedDescription)\n", stderr)
            exit(1)
        }

        fputs("Passkey registered successfully.\n", stderr)
        fputs("Credential saved to \(Config.credentialFile.path)\n", stderr)
        exit(0)
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithError error: Error) {
        let nsError = error as NSError
        if nsError.domain == ASAuthorizationError.errorDomain {
            switch ASAuthorizationError.Code(rawValue: nsError.code) {
            case .canceled:
                fputs("Registration cancelled.\n", stderr)
            case .failed:
                fputs("error: registration failed — ensure your passkey provider is available\n", stderr)
            case .notHandled:
                fputs("error: registration not handled — Associated Domains may not be configured\n", stderr)
                fputs("  The AASA file at tapkey.jul.sh may not be cached yet.\n", stderr)
            default:
                fputs("error: registration failed: \(error.localizedDescription)\n", stderr)
            }
        } else {
            fputs("error: registration failed: \(error.localizedDescription)\n", stderr)
        }
        exit(1)
    }
}

// MARK: - Assertion Delegate

class AssertionDelegate: NSObject, ASAuthorizationControllerDelegate {
    let command: AppDelegate.AssertionCommand
    let selection: AppDelegate.CredentialSelection
    let retryWithoutStoredCredential: (() -> Void)?

    init(command: AppDelegate.AssertionCommand,
         selection: AppDelegate.CredentialSelection,
         retryWithoutStoredCredential: (() -> Void)?) {
        self.command = command
        self.selection = selection
        self.retryWithoutStoredCredential = retryWithoutStoredCredential
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        guard let credential = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            fputs("error: unexpected credential type\n", stderr)
            exit(1)
        }

        if #available(macOS 15.0, *) {
            guard let prfOutput = credential.prf else {
                fputs("error: PRF output not available\n", stderr)
                fputs("  Your passkey may not support the PRF extension.\n", stderr)
                exit(1)
            }

            do {
                try cacheCredentialIDIfNeeded(credential.credentialID)
            } catch {
                fputs("error: failed to cache credential: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

            let rawKey = deriveRawKey(from: prfOutput.first, name: keyName(for: command))

            switch command {
            case .derive(let options):
                if options.format == .raw {
                    FileHandle.standardOutput.write(rawKey)
                } else {
                    let output = formatKey(rawKey, format: options.format)
                    if options.format == .ssh {
                        print(output, terminator: "")
                    } else {
                        print(output)
                    }
                }
            case .publicKey(let options):
                if options.format == .raw {
                    fputs("error: --format raw is not supported for public-key\n", stderr)
                    exit(1)
                }
                print(formatPublicKey(rawKey, format: options.format))
            }
        } else {
            fputs("error: tapkey requires macOS 15.0 or later\n", stderr)
            exit(1)
        }

        exit(0)
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithError error: Error) {
        let nsError = error as NSError
        if nsError.domain == ASAuthorizationError.errorDomain {
            switch ASAuthorizationError.Code(rawValue: nsError.code) {
            case .canceled:
                fputs("Authentication cancelled.\n", stderr)
            case .failed:
                fputs("error: authentication failed — biometric or passkey authentication may have failed\n", stderr)
            case .notHandled:
                switch selection {
                case .stored:
                    if let retryWithoutStoredCredential {
                        fputs("Stored credential selection was not available on this Mac. Retrying with discoverable passkeys...\n", stderr)
                        retryWithoutStoredCredential()
                        return
                    }
                    fputs("error: stored credential is not available on this Mac\n", stderr)
                case .discoverable:
                    fputs("error: no tapkey passkey is available on this Mac\n", stderr)
                    fputs("  If you created one elsewhere, wait for your passkey provider to sync.\n", stderr)
                    fputs("  Otherwise run 'tapkey register' to create one.\n", stderr)
                }
            default:
                fputs("error: authentication failed: \(error.localizedDescription)\n", stderr)
            }
        } else {
            fputs("error: authentication failed: \(error.localizedDescription)\n", stderr)
        }
        exit(1)
    }

    private func keyName(for command: AppDelegate.AssertionCommand) -> String {
        switch command {
        case .derive(let options), .publicKey(let options):
            return options.name
        }
    }
}

// MARK: - Main

let arguments = Arguments.parse()
let app = NSApplication.shared
let appDelegate = AppDelegate(command: arguments.command)
app.delegate = appDelegate
app.run()
