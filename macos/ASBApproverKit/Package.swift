// swift-tools-version:5.9
// ASBApproverKit: the platform-neutral part of the approver app (models, API client, OIDC sign-in
// with PKCE, token storage, the long-poll feed). Foundation only (plus CryptoKit for PKCE and
// Security for the Keychain store); no third-party dependencies.
import PackageDescription

let package = Package(
    name: "ASBApproverKit",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "ASBApproverKit", targets: ["ASBApproverKit"]),
    ],
    targets: [
        .target(name: "ASBApproverKit"),
        .testTarget(
            name: "ASBApproverKitTests",
            dependencies: ["ASBApproverKit"],
            resources: [.copy("Fixtures/pending.json")]
        ),
    ]
)
