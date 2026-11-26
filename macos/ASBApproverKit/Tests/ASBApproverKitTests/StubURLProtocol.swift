import Foundation
import XCTest
@testable import ASBApproverKit

/// What a stub answers: status, headers, body.
struct StubResponse: Sendable {
    var status: Int
    var headers: [String: String] = ["Content-Type": "application/json"]
    var body: Data = Data()

    static func json(_ status: Int, _ object: Any, headers: [String: String] = [:]) -> StubResponse {
        let data = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
        var h = ["Content-Type": "application/json"]
        for (k, v) in headers { h[k] = v }
        return StubResponse(status: status, headers: h, body: data)
    }

    static func raw(_ status: Int, _ body: Data, headers: [String: String] = [:]) -> StubResponse {
        var h = ["Content-Type": "application/json"]
        for (k, v) in headers { h[k] = v }
        return StubResponse(status: status, headers: h, body: body)
    }

    /// Seconds before the response is delivered. Delivery is scheduled on a global queue, so a
    /// slow answer never blocks the URL loading thread (or other tests' stub traffic).
    var delay: TimeInterval = 0

    func after(_ seconds: TimeInterval) -> StubResponse {
        var r = self
        r.delay = seconds
        return r
    }
}

/// One recorded request (URLSession turns `httpBody` into a stream; the body is read back here).
struct Recorded: Sendable {
    var request: URLRequest
    var body: Data?

    var path: String { request.url?.path ?? "" }
    var authorization: String? { request.value(forHTTPHeaderField: "Authorization") }
    var query: [String: String] {
        var out = [String: String]()
        for item in URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems ?? [] {
            out[item.name] = item.value ?? ""
        }
        return out
    }
    var json: [String: Any] {
        guard let body, let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return [:] }
        return obj
    }
    var form: [String: String] {
        guard let body, let s = String(data: body, encoding: .utf8) else { return [:] }
        var out = [String: String]()
        for pair in s.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let k = String(kv[0]).removingPercentEncoding ?? ""
            let v = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? "") : ""
            out[k] = v
        }
        return out
    }
}

/// A handler; throwing a URLError makes the request fail with it.
typealias StubHandler = @Sendable (Recorded) throws -> StubResponse

/// Handlers keyed by host, so each test owns its own fake server (a unique `<uuid>.test` host).
final class StubRegistry: @unchecked Sendable {
    static let shared = StubRegistry()
    private let lock = NSLock()
    private var handlers: [String: StubHandler] = [:]
    private var log: [String: [Recorded]] = [:]

    func register(host: String, _ handler: @escaping StubHandler) {
        lock.lock()
        defer { lock.unlock() }
        handlers[host] = handler
        log[host] = []
    }

    func unregister(host: String) {
        lock.lock()
        defer { lock.unlock() }
        handlers[host] = nil
        log[host] = nil
    }

    func handle(_ rec: Recorded) -> StubHandler? {
        let host = rec.request.url?.host ?? ""
        lock.lock()
        defer { lock.unlock() }
        log[host, default: []].append(rec)
        return handlers[host]
    }

    func recorded(host: String) -> [Recorded] {
        lock.lock()
        defer { lock.unlock() }
        return log[host] ?? []
    }
}

final class StubURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let rec = Recorded(request: request, body: Self.body(of: request))
        guard let url = request.url, let handler = StubRegistry.shared.handle(rec) else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        do {
            let r = try handler(rec)
            guard let resp = HTTPURLResponse(url: url, statusCode: r.status, httpVersion: "HTTP/1.1",
                                             headerFields: r.headers) else {
                client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
                return
            }
            if r.delay > 0 {
                DispatchQueue.global().asyncAfter(deadline: .now() + r.delay) { [self] in
                    deliver(resp, r.body)
                }
            } else {
                deliver(resp, r.body)
            }
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    private let stateLock = NSLock()
    private var stopped = false

    private func deliver(_ resp: HTTPURLResponse, _ body: Data) {
        stateLock.lock()
        let cancelled = stopped
        stateLock.unlock()
        guard !cancelled else { return }        // the task was cancelled meanwhile
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {
        stateLock.lock()
        stopped = true
        stateLock.unlock()
    }

    static func body(of request: URLRequest) -> Data? {
        if let b = request.httpBody { return b }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let n = stream.read(&buf, maxLength: buf.count)
            if n <= 0 { break }
            data.append(buf, count: n)
        }
        return data
    }
}

/// A fake server on a unique host, reachable only through its own URLSession.
final class StubServer {
    let host: String
    let baseURL: URL
    let session: URLSession

    init(_ handler: @escaping StubHandler) {
        host = "t" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + ".test"
        baseURL = URL(string: "https://\(host)")!
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubURLProtocol.self]
        session = URLSession(configuration: cfg)
        StubRegistry.shared.register(host: host, handler)
    }

    func url(_ path: String) -> URL { URL(string: "https://\(host)\(path)")! }

    var recorded: [Recorded] { StubRegistry.shared.recorded(host: host) }

    func recorded(path: String) -> [Recorded] { recorded.filter { $0.path == path } }

    func close() {
        session.invalidateAndCancel()
        StubRegistry.shared.unregister(host: host)
    }
}

/// A thread-safe counter / flag box for handlers.
final class Box<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T

    init(_ value: T) { self.value = value }

    var get: T {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    @discardableResult
    func update<R>(_ f: (inout T) -> R) -> R {
        lock.lock()
        defer { lock.unlock() }
        return f(&value)
    }
}

/// A fixed token (no OIDC involved).
struct StaticTokens: TokenProvider {
    var token = "tok"
    func accessToken() async throws -> String { token }
    func refreshAfter401() async throws -> String { token }
}

/// A provider whose session is gone.
struct SignedOutTokens: TokenProvider {
    func accessToken() async throws -> String { "expired" }
    func refreshAfter401() async throws -> String { throw OIDCError.signInRequired }
}

enum Fixtures {
    static func data(_ name: String) throws -> Data {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json"))
        return try Data(contentsOf: url)
    }

    static func object(_ name: String) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data(name)) as? [String: Any])
    }

    /// A minimal `request_view` row.
    static func row(_ id: String, notified: Bool, actions: [String] = ["deny", "approve"]) -> [String: Any] {
        ["id": id, "mode": "http", "created": 1_700_000_000.5, "expires": 1_700_000_060.5,
         "credentials": ["svc"], "client": ["name": "agent", "id": "c1"], "summary": "Reads things",
         "summary_source": "model", "risk": ["level": "low", "reasons": ["model rated it low"]],
         "target": "GET https://api.example.test/x", "details": NSNull(), "notified": notified,
         "banner_actions": notified ? ["deny", "approve"] : [String](), "actions": actions,
         "browser_url": "https://approve.example.test/a/\(id)"]
    }

    static func page(_ version: Int, _ rows: [[String: Any]]) -> [String: Any] {
        ["version": version, "requests": rows]
    }
}

/// Collects a feed's events from one long-lived iteration; tests wait on a count with a timeout.
final class EventCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [FeedEvent] = []
    private var waiters: [(count: Int, exp: XCTestExpectation)] = []
    private var task: Task<Void, Never>?

    init(_ stream: AsyncStream<FeedEvent>) {
        task = Task { [weak self] in
            for await ev in stream {
                self?.add(ev)
            }
        }
    }

    private func add(_ ev: FeedEvent) {
        lock.lock()
        events.append(ev)
        let n = events.count
        let ready = waiters.filter { $0.count <= n }
        waiters.removeAll { $0.count <= n }
        lock.unlock()
        ready.forEach { $0.exp.fulfill() }
    }

    /// Fulfilled once at least `count` events have arrived.
    func expectation(count: Int) -> XCTestExpectation {
        let exp = XCTestExpectation(description: "\(count) feed events")
        lock.lock()
        let already = events.count >= count
        if !already {
            waiters.append((count, exp))
        }
        lock.unlock()
        if already {
            exp.fulfill()
        }
        return exp
    }

    var snapshot: [FeedEvent] {
        lock.lock()
        defer { lock.unlock() }
        return events
    }

    func cancel() {
        task?.cancel()
    }
}

extension FeedEvent {
    var page: PendingPage? {
        if case .page(let p) = self { return p }
        return nil
    }

    var newly: [PendingRequest]? {
        if case .newlyNotified(let r) = self { return r }
        return nil
    }

    var kind: String {
        switch self {
        case .page: return "page"
        case .newlyNotified: return "newlyNotified"
        case .unreachable: return "unreachable"
        case .signInRequired: return "signInRequired"
        }
    }
}

/// A one-shot gate: `wait()` suspends until `open()` (at once if it is already open).
final class Gate: @unchecked Sendable {
    private let lock = NSLock()
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            lock.lock()
            if isOpen {
                lock.unlock()
                c.resume()
            } else {
                waiters.append(c)
                lock.unlock()
            }
        }
    }

    func open() {
        lock.lock()
        isOpen = true
        let ready = waiters
        waiters = []
        lock.unlock()
        ready.forEach { $0.resume() }
    }
}
