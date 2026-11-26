import Foundation

public enum OIDCError: Error, Equatable, Sendable {
    /// No session, or the refresh token was refused: show "Sign in again" and stop polling.
    case signInRequired
    /// The discovery document failed, did not decode, named a different issuer, or a non-https endpoint.
    case discoveryFailed
    /// The callback's `state` is not the one this sign-in sent.
    case stateMismatch
    /// The provider answered the authorization with `error=<code>`.
    case authorizationFailed(String)
    /// The token endpoint answered a status that is not a refusal of the grant (for example 5xx).
    case tokenRequestFailed(status: Int)
    /// A response that is not what OAuth promises.
    case invalidResponse
}

/// The provider endpoints the app uses, from `<issuer>/.well-known/openid-configuration`.
public struct OIDCEndpoints: Codable, Equatable, Sendable {
    public var authorizationEndpoint: URL
    public var tokenEndpoint: URL
    public var endSessionEndpoint: URL?
    public var revocationEndpoint: URL?

    public init(authorizationEndpoint: URL, tokenEndpoint: URL, endSessionEndpoint: URL? = nil,
                revocationEndpoint: URL? = nil) {
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.endSessionEndpoint = endSessionEndpoint
        self.revocationEndpoint = revocationEndpoint
    }
}

/// Authorization code + PKCE (S256) sign-in for a public client, and refresh with rotation.
/// The browser part (`ASWebAuthenticationSession`) lives in the app: it opens `authorizeURL`,
/// passes the callback to `authorizationCode(from:expectedState:)`, then calls `exchange`.
public final class OIDCClient: TokenProvider, Sendable {
    public static let defaultRedirectURI = URL(string: "asb-approver://callback")!
    /// Refresh proactively when the access token expires within this many seconds. A broker under
    /// an invalid-token flood answers 429 rather than 401, so waiting for a 401 is not enough.
    public static let refreshLeeway: TimeInterval = 60

    public let config: ApproverConfig
    public let endpoints: OIDCEndpoints
    public let redirectURI: URL
    private let session: URLSession
    private let state: TokenState
    private let now: @Sendable () -> Date

    public init(config: ApproverConfig, endpoints: OIDCEndpoints, store: any TokenStore,
                redirectURI: URL = OIDCClient.defaultRedirectURI, session: URLSession = .shared,
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.config = config
        self.endpoints = endpoints
        self.redirectURI = redirectURI
        self.session = session
        self.state = TokenState(store: store)
        self.now = now
    }

    // MARK: - Discovery

    /// Fetches the discovery document. Its `issuer` must equal `issuer` exactly and the
    /// authorization and token endpoints must be https.
    public static func discover(issuer: URL, session: URLSession = .shared) async throws -> OIDCEndpoints {
        var base = issuer.absoluteString
        while base.hasSuffix("/") {
            base.removeLast()
        }
        guard let url = URL(string: base + "/.well-known/openid-configuration") else {
            throw OIDCError.discoveryFailed
        }
        var req = URLRequest(url: url)
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, resp) = try await session.data(for: req)     // network trouble stays a URLError
        guard let http = resp as? HTTPURLResponse, http.statusCode == 200,
              let doc = try? JSONDecoder.approverAPI().decode(DiscoveryDocument.self, from: data),
              doc.issuer == issuer.absoluteString,
              doc.authorizationEndpoint.scheme?.lowercased() == "https",
              doc.tokenEndpoint.scheme?.lowercased() == "https" else {
            throw OIDCError.discoveryFailed
        }
        return OIDCEndpoints(authorizationEndpoint: doc.authorizationEndpoint, tokenEndpoint: doc.tokenEndpoint,
                             endSessionEndpoint: doc.endSessionEndpoint, revocationEndpoint: doc.revocationEndpoint)
    }

    // MARK: - Sign-in

    /// The URL to open in the browser session.
    public func authorizeURL(state: String, pkce: PKCE) -> URL {
        var comps = URLComponents(url: endpoints.authorizationEndpoint, resolvingAgainstBaseURL: false)
            ?? URLComponents()
        var items = comps.percentEncodedQueryItems ?? []
        let params: [(String, String)] = [
            ("response_type", "code"),
            ("client_id", config.clientId),
            ("redirect_uri", redirectURI.absoluteString),
            ("scope", config.scopes.joined(separator: " ")),
            ("state", state),
            ("code_challenge", pkce.challenge),
            ("code_challenge_method", pkce.method),
        ]
        for (k, v) in params {
            items.append(URLQueryItem(name: Self.formEscape(k), value: Self.formEscape(v)))
        }
        comps.percentEncodedQueryItems = items
        return comps.url ?? endpoints.authorizationEndpoint
    }

    /// The authorization code from the redirect, after checking `state`.
    public static func authorizationCode(from callback: URL, expectedState: String) throws -> String {
        let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func value(_ name: String) -> String? { items.first(where: { $0.name == name })?.value }
        if let err = value("error") {
            throw OIDCError.authorizationFailed(err)
        }
        guard let got = value("state"), got == expectedState else { throw OIDCError.stateMismatch }
        guard let code = value("code"), !code.isEmpty else { throw OIDCError.invalidResponse }
        return code
    }

    /// Exchanges the authorization code (with the PKCE verifier) and stores the tokens.
    public func exchange(code: String, pkce: PKCE) async throws {
        let response = try await tokenRequest([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirectURI.absoluteString),
            ("client_id", config.clientId),
            ("code_verifier", pkce.verifier),
        ])
        await state.signIn(tokens(from: response, previousRefreshToken: nil))
    }

    /// Forgets the session (the Keychain item too).
    public func signOut() async {
        await state.signOut()
    }

    public func isSignedIn() async -> Bool {
        await state.current() != nil
    }

    // MARK: - TokenProvider

    public func accessToken() async throws -> String {
        guard let t = await state.current() else { throw OIDCError.signInRequired }
        guard let exp = t.expiresAt, now() >= exp.addingTimeInterval(-Self.refreshLeeway) else {
            return t.accessToken
        }
        guard t.refreshToken != nil else {
            if now() < exp { return t.accessToken }
            throw OIDCError.signInRequired
        }
        do {
            return try await refresh().accessToken
        } catch {
            // A transient failure (network, 5xx) while the token is still valid: use it for now.
            if (error as? OIDCError) == .signInRequired || now() >= exp {
                throw error
            }
            return t.accessToken
        }
    }

    public func refreshAfter401() async throws -> String {
        try await refresh().accessToken
    }

    // MARK: - Internals

    /// One refresh at a time: concurrent callers share the in-flight one (with rotation, a second
    /// refresh using the same refresh token would be refused).
    private func refresh() async throws -> Tokens {
        try await state.refresh { [self] refreshToken in
            let response: TokenResponse
            do {
                response = try await tokenRequest([
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refreshToken),
                    ("client_id", config.clientId),
                ])
            } catch OIDCError.tokenRequestFailed(let status) where status == 400 || status == 401 {
                throw OIDCError.signInRequired      // invalid_grant: revoked, expired or reused
            }
            return tokens(from: response, previousRefreshToken: refreshToken)
        }
    }

    private func tokens(from r: TokenResponse, previousRefreshToken: String?) -> Tokens {
        Tokens(accessToken: r.accessToken,
               refreshToken: r.refreshToken ?? previousRefreshToken,
               expiresAt: r.expiresIn.map { now().addingTimeInterval($0) },
               idToken: r.idToken)
    }

    private func tokenRequest(_ form: [(String, String)]) async throws -> TokenResponse {
        var req = URLRequest(url: endpoints.tokenEndpoint)
        req.httpMethod = "POST"
        req.cachePolicy = .reloadIgnoringLocalCacheData
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.httpBody = Data(form.map { "\(Self.formEscape($0.0))=\(Self.formEscape($0.1))" }
            .joined(separator: "&").utf8)
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw OIDCError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            throw OIDCError.tokenRequestFailed(status: http.statusCode)
        }
        guard let r = try? JSONDecoder.approverAPI().decode(TokenResponse.self, from: data),
              !r.accessToken.isEmpty else {
            throw OIDCError.invalidResponse
        }
        return r
    }

    private static let unreserved = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    /// Percent-encodes everything but RFC 3986 unreserved characters (form and query values).
    static func formEscape(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? ""
    }
}

struct TokenResponse: Decodable, Sendable {
    var accessToken: String
    var tokenType: String?
    var expiresIn: TimeInterval?
    var refreshToken: String?
    var idToken: String?
}

struct DiscoveryDocument: Decodable, Sendable {
    var issuer: String
    var authorizationEndpoint: URL
    var tokenEndpoint: URL
    var endSessionEndpoint: URL?
    var revocationEndpoint: URL?
}

/// The token state, its persistence, and the single in-flight refresh.
///
/// `epoch` counts sessions: sign-in and sign-out each start a new one. A refresh records the epoch
/// it started in and its result is applied only if that is still the current one, so a refresh
/// that finishes after a sign-out (or a new sign-in) can never bring the old session back.
actor TokenState {
    private let store: any TokenStore
    private var tokens: Tokens?
    private var epoch = 0
    private var inFlight: (epoch: Int, task: Task<Tokens, Error>)?

    init(store: any TokenStore) {
        self.store = store
        self.tokens = store.load()
    }

    func current() -> Tokens? {
        tokens
    }

    /// A new session (code exchange): replaces the tokens and abandons any refresh in flight.
    func signIn(_ t: Tokens) {
        epoch += 1
        inFlight?.task.cancel()
        inFlight = nil
        tokens = t
        store.save(t)
    }

    /// Ends the session: forgets the tokens and abandons any refresh in flight.
    func signOut() {
        epoch += 1
        inFlight?.task.cancel()
        inFlight = nil
        tokens = nil
        store.clear()
    }

    func refresh(_ perform: @escaping @Sendable (String) async throws -> Tokens) async throws -> Tokens {
        let started: Int
        let task: Task<Tokens, Error>
        if let running = inFlight {
            started = running.epoch
            task = running.task
        } else {
            guard let refreshToken = tokens?.refreshToken else {
                signOut()
                throw OIDCError.signInRequired
            }
            started = epoch
            task = Task<Tokens, Error> { try await perform(refreshToken) }
            inFlight = (started, task)
        }
        do {
            let fresh = try await task.value
            if epoch != started {
                return try afterSessionChange()
            }
            if inFlight?.task == task {         // the first waiter to resume applies it
                inFlight = nil
                tokens = fresh
                store.save(fresh)
            }
            return fresh
        } catch {
            if epoch != started {
                return try afterSessionChange()
            }
            if inFlight?.task == task {
                inFlight = nil
                if (error as? OIDCError) == .signInRequired {
                    signOut()
                }
            }
            throw error
        }
    }

    /// The session changed while a refresh ran: its result is discarded. The waiter gets the new
    /// session's tokens if there is one, else "sign in again".
    private func afterSessionChange() throws -> Tokens {
        if let t = tokens {
            return t
        }
        throw OIDCError.signInRequired
    }
}
