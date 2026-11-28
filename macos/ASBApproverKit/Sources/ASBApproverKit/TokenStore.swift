import Foundation
#if canImport(Security)
import Security
#endif

/// The OIDC tokens the app holds.
public struct Tokens: Codable, Equatable, Sendable {
    public var accessToken: String
    public var refreshToken: String?
    /// When the access token expires (from `expires_in`), if the provider said.
    public var expiresAt: Date?
    public var idToken: String?

    public init(accessToken: String, refreshToken: String? = nil, expiresAt: Date? = nil, idToken: String? = nil) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
        self.idToken = idToken
    }
}

/// Where the tokens persist between launches.
public protocol TokenStore: Sendable {
    func load() -> Tokens?
    func save(_ tokens: Tokens)
    func clear()
}

/// In memory only (tests, previews).
public final class MemoryTokenStore: TokenStore, @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: Tokens?

    public init(_ tokens: Tokens? = nil) {
        self.tokens = tokens
    }

    public func load() -> Tokens? {
        lock.lock()
        defer { lock.unlock() }
        return tokens
    }

    public func save(_ tokens: Tokens) {
        lock.lock()
        defer { lock.unlock() }
        self.tokens = tokens
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        tokens = nil
    }
}

#if canImport(Security)
/// One generic-password Keychain item (service `asb-approver`), readable only after the first
/// unlock and never migrated to another device. The item holds the JSON-encoded `Tokens`.
public final class KeychainTokenStore: TokenStore {
    public let service: String
    public let account: String

    public init(service: String = "asb-approver", account: String = "tokens") {
        self.service = service
        self.account = account
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    public func load() -> Tokens? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else {
            return nil
        }
        return try? JSONDecoder().decode(Tokens.self, from: data)
    }

    public func save(_ tokens: Tokens) {
        guard let data = try? JSONEncoder().encode(tokens) else { return }
        let attrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            for (k, v) in attrs { add[k] = v }
            _ = SecItemAdd(add as CFDictionary, nil)
        }
    }

    public func clear() {
        _ = SecItemDelete(query as CFDictionary)
    }
}
#endif
