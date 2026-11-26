import Foundation

/// Supplies the bearer token for the approver API. `OIDCClient` is the real one.
public protocol TokenProvider: Sendable {
    /// A token to send now (refreshed first when it is about to expire).
    func accessToken() async throws -> String
    /// The broker answered 401: refresh once and return the new token, or throw
    /// `OIDCError.signInRequired` when the session cannot be refreshed.
    func refreshAfter401() async throws -> String
}

public enum APIError: Error, Equatable, Sendable {
    /// Any other non-success status.
    case http(status: Int)
    /// 429; the broker sends `Retry-After: 60`.
    case rateLimited(retryAfter: TimeInterval)
    /// 503: the identity provider's keys are unavailable (`Retry-After: 30`).
    case unavailable(retryAfter: TimeInterval)
    /// Not HTTP, or a body that does not decode.
    case invalidResponse

    public var retryAfter: TimeInterval? {
        switch self {
        case .rateLimited(let s), .unavailable(let s): return s
        case .http, .invalidResponse: return nil
        }
    }
}

/// The broker's `/v1/approver/*` API on its client listener.
public actor APIClient {
    public nonisolated let baseURL: URL
    private let tokens: any TokenProvider
    private let session: URLSession

    public init(baseURL: URL, tokens: any TokenProvider, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.tokens = tokens
        self.session = session
    }

    /// `GET /v1/approver/config` (no auth), before any token exists.
    public static func fetchConfig(baseURL: URL, session: URLSession = .shared) async throws -> ApproverConfig {
        let req = makeRequest(baseURL: baseURL, method: "GET", path: "/v1/approver/config")
        let (data, resp) = try await send(req, session: session)
        guard (200..<300).contains(resp.statusCode) else { throw failure(resp) }
        return try decode(ApproverConfig.self, from: data)
    }

    public func config() async throws -> ApproverConfig {
        try await Self.fetchConfig(baseURL: baseURL, session: session)
    }

    /// `GET /v1/approver/pending?since=&wait=`. Returns at once when `since` is nil or not the
    /// broker's current version; otherwise blocks up to `wait` seconds (the broker caps it at 25).
    /// A `Retry-After` on the answer (waiter cap) is passed on as `PendingPage.retryAfter`.
    public func pending(since: Int?, wait: Int) async throws -> PendingPage {
        let w = max(0, wait)
        var query = [URLQueryItem]()
        if let since {
            query.append(URLQueryItem(name: "since", value: String(max(0, since))))
        }
        query.append(URLQueryItem(name: "wait", value: String(w)))
        let items = query
        let base = baseURL
        let (data, resp) = try await authorized { token in
            Self.makeRequest(baseURL: base, method: "GET", path: "/v1/approver/pending", query: items,
                             token: token, timeout: TimeInterval(w) + 15)
        }
        guard (200..<300).contains(resp.statusCode) else { throw Self.failure(resp) }
        var page = try Self.decode(PendingPage.self, from: data)
        page.retryAfter = Self.retryAfter(resp)
        return page
    }

    /// `POST /v1/approver/decide`. 200 `.ok`, 410 `.alreadyDecided`, 404 `.notFound`, 400 `.refused`;
    /// anything else throws. `device` is sent only when it is a valid label (1-64 of
    /// `A-Za-z0-9_.:-`); the broker refuses the whole decision otherwise.
    public func decide(id: String, _ d: Decision, device: String) async throws -> DecideResult {
        let body = try JSONSerialization.data(withJSONObject: Self.decideBody(id: id, d, device: device))
        let base = baseURL
        let (_, resp) = try await authorized { token in
            Self.makeRequest(baseURL: base, method: "POST", path: "/v1/approver/decide", token: token, body: body)
        }
        switch resp.statusCode {
        case 200..<300: return .ok
        case 410: return .alreadyDecided
        case 404: return .notFound
        case 400: return .refused
        default: throw Self.failure(resp)
        }
    }

    /// `POST /v1/approver/presence` with `{"active", "device"?}`. 429 throws `.rateLimited`.
    public func presence(active: Bool, device: String) async throws {
        var obj: [String: Any] = ["active": active]
        if Self.isValidDevice(device) {
            obj["device"] = device
        }
        let body = try JSONSerialization.data(withJSONObject: obj)
        let base = baseURL
        let (_, resp) = try await authorized { token in
            Self.makeRequest(baseURL: base, method: "POST", path: "/v1/approver/presence", token: token, body: body)
        }
        guard (200..<300).contains(resp.statusCode) else { throw Self.failure(resp) }
    }

    // MARK: - Internals

    /// Sends with the current token; on 401 refreshes once and retries once. A second 401 means
    /// the broker refuses this identity even with a fresh token: sign in again.
    private func authorized(_ make: @Sendable (String) -> URLRequest) async throws -> (Data, HTTPURLResponse) {
        let token = try await tokens.accessToken()
        let first = try await Self.send(make(token), session: session)
        guard first.1.statusCode == 401 else { return first }
        let fresh = try await tokens.refreshAfter401()
        let second = try await Self.send(make(fresh), session: session)
        if second.1.statusCode == 401 {
            throw OIDCError.signInRequired
        }
        return second
    }

    static func decideBody(id: String, _ d: Decision, device: String) -> [String: Any] {
        var body: [String: Any] = ["id": id]
        switch d {
        case .deny:
            body["decision"] = "deny"
        case .approve:
            body["decision"] = "approve"
        case .grant(let minutes):
            body["decision"] = "approve"
            body["grant_minutes"] = minutes
        case .always:
            body["decision"] = "approve"
            body["always"] = true
        case .alwaysScript:
            body["decision"] = "approve"
            body["always"] = "script"
        }
        if isValidDevice(device) {
            body["device"] = device
        }
        return body
    }

    /// `notify.DEVICE_RE` on the broker: `^[A-Za-z0-9_.:-]{1,64}$`.
    public static func isValidDevice(_ s: String) -> Bool {
        guard (1...64).contains(s.utf8.count) else { return false }
        return s.utf8.allSatisfy { b in
            (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
                || b == 0x5F || b == 0x2E || b == 0x3A || b == 0x2D
        }
    }

    static func makeRequest(baseURL: URL, method: String, path: String, query: [URLQueryItem] = [],
                            token: String? = nil, body: Data? = nil, timeout: TimeInterval = 30) -> URLRequest {
        var comps = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) ?? URLComponents()
        var basePath = comps.path
        while basePath.hasSuffix("/") {
            basePath.removeLast()
        }
        comps.path = basePath + path
        comps.queryItems = query.isEmpty ? nil : query
        var req = URLRequest(url: comps.url ?? baseURL)
        req.httpMethod = method
        req.timeoutInterval = timeout
        req.cachePolicy = .reloadIgnoringLocalCacheData
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return req
    }

    static func send(_ req: URLRequest, session: URLSession) async throws -> (Data, HTTPURLResponse) {
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw APIError.invalidResponse }
        return (data, http)
    }

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder.approverAPI().decode(type, from: data)
        } catch {
            throw APIError.invalidResponse
        }
    }

    static func retryAfter(_ resp: HTTPURLResponse) -> TimeInterval? {
        guard let raw = resp.value(forHTTPHeaderField: "Retry-After"),
              let s = TimeInterval(raw.trimmingCharacters(in: .whitespaces)), s >= 0 else { return nil }
        return s
    }

    static func failure(_ resp: HTTPURLResponse) -> APIError {
        switch resp.statusCode {
        case 429: return .rateLimited(retryAfter: retryAfter(resp) ?? 60)
        case 503: return .unavailable(retryAfter: retryAfter(resp) ?? 30)
        default: return .http(status: resp.statusCode)
        }
    }
}
