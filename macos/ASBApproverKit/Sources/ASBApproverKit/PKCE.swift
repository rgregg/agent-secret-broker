import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
#error("ASBApproverKit needs CryptoKit (macOS or iOS)")
#endif

/// RFC 7636 proof key, S256 only. The verifier is 43 characters of base64url (32 random bytes),
/// within the RFC's 43-128 range; the challenge is base64url(SHA-256(verifier)) without padding.
public struct PKCE: Equatable, Sendable {
    public let verifier: String
    public let challenge: String
    public var method: String { "S256" }

    /// A proof key for a given verifier (tests use the RFC 7636 Appendix B vector).
    public init(verifier: String) {
        self.verifier = verifier
        self.challenge = PKCE.s256(verifier)
    }

    public static func make() -> PKCE {
        PKCE(verifier: randomURLSafe(bytes: 32))
    }

    /// `bytes` random bytes as unpadded base64url (also used for the OAuth `state`).
    public static func randomURLSafe(bytes: Int = 32) -> String {
        var rng = SystemRandomNumberGenerator()     // the system CSPRNG on Apple platforms
        let raw = (0..<max(bytes, 1)).map { _ in UInt8.random(in: UInt8.min...UInt8.max, using: &rng) }
        return base64URL(Data(raw))
    }

    static func s256(_ verifier: String) -> String {
        base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
