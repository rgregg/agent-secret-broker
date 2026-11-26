import XCTest
@testable import ASBApproverKit

final class OIDCClientTests: XCTestCase {
    private var servers: [StubServer] = []
    private let start = Date(timeIntervalSince1970: 1_800_000_000)

    override func tearDown() {
        servers.forEach { $0.close() }
        servers = []
        super.tearDown()
    }

    private func server(_ handler: @escaping StubHandler) -> StubServer {
        let s = StubServer(handler)
        servers.append(s)
        return s
    }

    private func config() -> ApproverConfig {
        ApproverConfig(issuer: URL(string: "https://idp.example.test/application/o/asb-approver/")!,
                       clientId: "asb-client", scopes: ["openid", "profile", "offline_access"], apiVersion: 1)
    }

    /// The IdP's token endpoint and the broker share the stub host; routes split by path.
    private func oidc(_ s: StubServer, store: any TokenStore, now: Date? = nil) -> OIDCClient {
        let fixed = now ?? start
        return OIDCClient(config: config(),
                          endpoints: OIDCEndpoints(authorizationEndpoint: URL(string: "https://idp.example.test/authorize?prompt=login")!,
                                                   tokenEndpoint: s.url("/token")),
                          store: store, session: s.session, now: { fixed })
    }

    private static func tokenBody(access: String, refresh: String?, expiresIn: Int = 300) throws -> Data {
        var obj: [String: Any] = ["access_token": access, "token_type": "Bearer", "expires_in": expiresIn]
        if let refresh {
            obj["refresh_token"] = refresh
        }
        return try JSONSerialization.data(withJSONObject: obj)
    }

    func testAuthorizeURLHasPKCEAndRedirect() throws {
        let s = server { _ in .json(500, ["error": "unused"]) }
        let client = oidc(s, store: MemoryTokenStore())
        let pkce = PKCE(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        let url = client.authorizeURL(state: "st-123", pkce: pkce)
        let comps = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        XCTAssertEqual(comps.scheme, "https")
        XCTAssertEqual(comps.host, "idp.example.test")
        XCTAssertEqual(comps.path, "/authorize")
        var q = [String: String]()
        for item in comps.queryItems ?? [] {
            q[item.name] = item.value
        }
        XCTAssertEqual(q["prompt"], "login")                    // the endpoint's own query is kept
        XCTAssertEqual(q["response_type"], "code")
        XCTAssertEqual(q["client_id"], "asb-client")
        XCTAssertEqual(q["redirect_uri"], "asb-approver://callback")
        XCTAssertEqual(q["scope"], "openid profile offline_access")
        XCTAssertEqual(q["state"], "st-123")
        XCTAssertEqual(q["code_challenge"], "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        XCTAssertEqual(q["code_challenge_method"], "S256")
        XCTAssertNil(q["code_verifier"])                        // the verifier never goes to the browser
        XCTAssertFalse(url.absoluteString.contains(" "))
    }

    func testAuthorizationCodeFromCallback() throws {
        let ok = URL(string: "asb-approver://callback?code=abc&state=s1")!
        XCTAssertEqual(try OIDCClient.authorizationCode(from: ok, expectedState: "s1"), "abc")
        XCTAssertThrowsError(try OIDCClient.authorizationCode(from: ok, expectedState: "other")) {
            XCTAssertEqual($0 as? OIDCError, .stateMismatch)
        }
        let denied = URL(string: "asb-approver://callback?error=access_denied&state=s1")!
        XCTAssertThrowsError(try OIDCClient.authorizationCode(from: denied, expectedState: "s1")) {
            XCTAssertEqual($0 as? OIDCError, .authorizationFailed("access_denied"))
        }
    }

    func testExchangeStoresTokens() async throws {
        let body = try Self.tokenBody(access: "a1", refresh: "r1", expiresIn: 300)
        let s = server { _ in .raw(200, body) }
        let store = MemoryTokenStore()
        let client = oidc(s, store: store)
        let pkce = PKCE.make()
        try await client.exchange(code: "the-code", pkce: pkce)

        let form = try XCTUnwrap(s.recorded(path: "/token").first).form
        XCTAssertEqual(form, ["grant_type": "authorization_code", "code": "the-code",
                              "redirect_uri": "asb-approver://callback", "client_id": "asb-client",
                              "code_verifier": pkce.verifier])
        let saved = try XCTUnwrap(store.load())
        XCTAssertEqual(saved.accessToken, "a1")
        XCTAssertEqual(saved.refreshToken, "r1")
        XCTAssertEqual(saved.expiresAt, start.addingTimeInterval(300))
        let token = try await client.accessToken()
        XCTAssertEqual(token, "a1")
        let signedIn = await client.isSignedIn()
        XCTAssertTrue(signedIn)
        await client.signOut()
        XCTAssertNil(store.load())
    }

    /// Review focus 3: the access token expires during a long poll. A 401 triggers exactly one
    /// refresh (with rotation) and one retry.
    func testRefreshOnceOn401ThenRetry() async throws {
        let fresh = try Self.tokenBody(access: "new", refresh: "r2")
        let page = try Fixtures.data("pending")
        let s = server { rec in
            switch rec.path {
            case "/token":
                return .raw(200, fresh)
            case "/v1/approver/pending":
                return rec.authorization == "Bearer new"
                    ? .raw(200, page)
                    : .json(401, ["error": "unauthorized"], headers: ["WWW-Authenticate": "Bearer"])
            default:
                return .json(404, ["error": "not found"])
            }
        }
        let store = MemoryTokenStore(Tokens(accessToken: "old", refreshToken: "r1",
                                            expiresAt: start.addingTimeInterval(3600)))
        let client = oidc(s, store: store)
        let api = APIClient(baseURL: s.baseURL, tokens: client, session: s.session)

        let got = try await api.pending(since: nil, wait: 0)
        XCTAssertEqual(got.version, 3)

        let tokenCalls = s.recorded(path: "/token")
        XCTAssertEqual(tokenCalls.count, 1)
        XCTAssertEqual(tokenCalls[0].form, ["grant_type": "refresh_token", "refresh_token": "r1",
                                            "client_id": "asb-client"])
        let polls = s.recorded(path: "/v1/approver/pending")
        XCTAssertEqual(polls.map { $0.authorization }, ["Bearer old", "Bearer new"])
        XCTAssertEqual(store.load()?.accessToken, "new")
        XCTAssertEqual(store.load()?.refreshToken, "r2")      // rotated
    }

    func testFailedRefreshRaisesSignInRequired() async throws {
        let s = server { rec in
            rec.path == "/token"
                ? .json(400, ["error": "invalid_grant"])
                : .json(401, ["error": "unauthorized"], headers: ["WWW-Authenticate": "Bearer"])
        }
        let store = MemoryTokenStore(Tokens(accessToken: "old", refreshToken: "r1",
                                            expiresAt: start.addingTimeInterval(3600)))
        let client = oidc(s, store: store)
        let api = APIClient(baseURL: s.baseURL, tokens: client, session: s.session)
        do {
            _ = try await api.pending(since: nil, wait: 0)
            XCTFail("should need sign-in")
        } catch {
            XCTAssertEqual(error as? OIDCError, .signInRequired)
        }
        XCTAssertEqual(s.recorded(path: "/v1/approver/pending").count, 1)    // no retry without a token
        XCTAssertEqual(s.recorded(path: "/token").count, 1)
        XCTAssertNil(store.load())                                           // the dead session is gone
        do {
            _ = try await client.accessToken()
            XCTFail("signed out")
        } catch {
            XCTAssertEqual(error as? OIDCError, .signInRequired)
        }
    }

    func testTransientRefreshFailureIsNotSignOut() async throws {
        let s = server { rec in
            rec.path == "/token" ? .json(502, ["error": "bad gateway"]) : .json(401, ["error": "unauthorized"])
        }
        let store = MemoryTokenStore(Tokens(accessToken: "old", refreshToken: "r1",
                                            expiresAt: start.addingTimeInterval(3600)))
        let client = oidc(s, store: store)
        do {
            _ = try await client.refreshAfter401()
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(error as? OIDCError, .tokenRequestFailed(status: 502))
        }
        XCTAssertEqual(store.load()?.refreshToken, "r1")
    }

    /// A broker under an invalid-token flood answers 429, not 401: refresh before expiry.
    func testProactiveRefreshNearExpiry() async throws {
        let fresh = try Self.tokenBody(access: "new", refresh: nil)
        let s = server { _ in .raw(200, fresh) }
        let store = MemoryTokenStore(Tokens(accessToken: "old", refreshToken: "r1",
                                            expiresAt: start.addingTimeInterval(30)))
        let client = oidc(s, store: store)
        let token = try await client.accessToken()
        XCTAssertEqual(token, "new")
        XCTAssertEqual(s.recorded(path: "/token").count, 1)
        XCTAssertEqual(store.load()?.refreshToken, "r1")      // no rotation offered: keep the old one
        XCTAssertEqual(store.load()?.expiresAt, start.addingTimeInterval(300))
    }

    func testNoRefreshWhileFresh() async throws {
        let s = server { _ in .json(500, ["error": "unused"]) }
        let store = MemoryTokenStore(Tokens(accessToken: "old", refreshToken: "r1",
                                            expiresAt: start.addingTimeInterval(61)))
        let token = try await oidc(s, store: store).accessToken()
        XCTAssertEqual(token, "old")
        XCTAssertEqual(s.recorded.count, 0)
    }

    func testConcurrentRefreshesShareOne() async throws {
        let fresh = try Self.tokenBody(access: "new", refresh: "r2")
        let s = server { _ in
            Thread.sleep(forTimeInterval: 0.3)         // keep the first refresh in flight
            return .raw(200, fresh)
        }
        let store = MemoryTokenStore(Tokens(accessToken: "old", refreshToken: "r1",
                                            expiresAt: start.addingTimeInterval(3600)))
        let client = oidc(s, store: store)
        async let a = client.refreshAfter401()
        async let b = client.refreshAfter401()
        let (x, y) = try await (a, b)
        XCTAssertEqual([x, y], ["new", "new"])
        XCTAssertEqual(s.recorded(path: "/token").count, 1)
    }

    /// A refresh still in flight when the user signs out must not sign them back in.
    func testSignOutDuringRefreshStaysSignedOut() async throws {
        let late = try Self.tokenBody(access: "resurrected", refresh: "r2")
        let s = server { _ in
            Thread.sleep(forTimeInterval: 0.5)         // the response arrives after the sign-out
            return .raw(200, late)
        }
        let store = MemoryTokenStore(Tokens(accessToken: "old", refreshToken: "r1",
                                            expiresAt: start.addingTimeInterval(3600)))
        let client = oidc(s, store: store)
        let refreshing = Task { try await client.refreshAfter401() }
        try await Task.sleep(nanoseconds: 100_000_000)  // the refresh is in flight
        await client.signOut()
        let outcome = await refreshing.result
        XCTAssertThrowsError(try outcome.get()) {
            XCTAssertEqual($0 as? OIDCError, .signInRequired)
        }
        try await Task.sleep(nanoseconds: 600_000_000)  // past the delayed response
        XCTAssertNil(store.load())
        let signedIn = await client.isSignedIn()
        XCTAssertFalse(signedIn)
        do {
            _ = try await client.accessToken()
            XCTFail("signed out")
        } catch {
            XCTAssertEqual(error as? OIDCError, .signInRequired)
        }
    }

    /// A new sign-in during a refresh wins; the waiter gets the new session's token.
    func testExchangeDuringRefreshKeepsNewSession() async throws {
        let late = try Self.tokenBody(access: "stale", refresh: "r2")
        let fresh = try Self.tokenBody(access: "new-session", refresh: "n1")
        let s = server { rec in
            if rec.form["grant_type"] == "refresh_token" {
                Thread.sleep(forTimeInterval: 0.5)
                return .raw(200, late)
            }
            return .raw(200, fresh)
        }
        let store = MemoryTokenStore(Tokens(accessToken: "old", refreshToken: "r1",
                                            expiresAt: start.addingTimeInterval(3600)))
        let client = oidc(s, store: store)
        let refreshing = Task { try await client.refreshAfter401() }
        try await Task.sleep(nanoseconds: 100_000_000)
        try await client.exchange(code: "c", pkce: PKCE.make())
        let token = try await refreshing.value
        XCTAssertEqual(token, "new-session")
        try await Task.sleep(nanoseconds: 600_000_000)
        XCTAssertEqual(store.load()?.accessToken, "new-session")
        XCTAssertEqual(store.load()?.refreshToken, "n1")
    }

    func testDiscoveryChecksIssuer() async throws {
        let s = server { rec in
            guard rec.path == "/application/o/asb-approver/.well-known/openid-configuration" else {
                return .json(404, ["error": "not found"])
            }
            let host = rec.request.url?.host ?? ""
            let doc: [String: Any] = ["issuer": "https://\(host)/application/o/asb-approver/",
                                      "authorization_endpoint": "https://\(host)/authorize",
                                      "token_endpoint": "https://\(host)/token"]
            return .json(200, doc)
        }
        let issuer = URL(string: "https://\(s.host)/application/o/asb-approver/")!
        let ep = try await OIDCClient.discover(issuer: issuer, session: s.session)
        XCTAssertEqual(ep.authorizationEndpoint, s.url("/authorize"))
        XCTAssertEqual(ep.tokenEndpoint, s.url("/token"))
        XCTAssertNil(ep.endSessionEndpoint)

        // Same discovery URL, but the document's issuer (with its trailing slash) is not this one
        // exactly: refused, as the broker refuses a token whose `iss` differs.
        let unslashed = URL(string: "https://\(s.host)/application/o/asb-approver")!
        do {
            _ = try await OIDCClient.discover(issuer: unslashed, session: s.session)
            XCTFail("issuer mismatch should be refused")
        } catch {
            XCTAssertEqual(error as? OIDCError, .discoveryFailed)
        }
    }
}
