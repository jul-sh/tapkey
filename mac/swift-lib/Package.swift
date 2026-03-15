// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PasskeyBridge",
    platforms: [.macOS("15.0")],
    products: [
        .library(name: "PasskeyBridge", type: .static, targets: ["PasskeyBridge"]),
    ],
    targets: [
        .target(
            name: "PasskeyBridge",
            path: "Sources/PasskeyBridge"
        ),
    ]
)
