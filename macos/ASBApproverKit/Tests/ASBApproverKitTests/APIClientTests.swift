import XCTest
@testable import ASBApproverKit

final class APIClientTests: XCTestCase {
    private var servers: [StubServer] = []

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

    private func client(_ s: StubServer, tokens: any TokenProvider = StaticTokens()) -> APIClient {
        APIClient(baseURL: s.baseURL, tokens: tokens, session: s.session)
    }

    private func decideServer(status: Int) -> StubServer {
        server { rec in
            rec.path == "/v1/approver/decide" ? .json(status, ["ok": status == 200]) : .json(404, ["error": "not found"])
        }
    }

    func testDecideMaps410ToAlreadyDecided() async throws {
        let s = decideServer(status: 410)
        let result = try await client(s).decide(id: "r1", .approve, device: "mac-1")
        XCTAssertEqual(result, .alreadyDecided)
    }

    func testDecideMapsStatuses() async throws {
        let cases: [(Int, DecideResult)] = [(200, .ok), (404, .notFound), (400, .refused)]
        for (status, want) in cases {
            let s = decideServer(status: status)
            let got = try await client(s).decide(id: "r1", .deny, device: "mac-1")
            XCTAssertEqual(got, want, "\(status)")
        }
        let s = decideServer(status: 500)
        do {
            _ = try await client(s).decide(id: "r1", .deny, device: "mac-1")
            XCTFail("500 should throw")
        } catch {
            XCTAssertEqual(error as? APIError, .http(status: 500))
        }
    }

    func testDecideBodies() async throws {
        let s = decideServer(status: 200)
        let api = client(s)
        _ = try await api.decide(id: "r1", .deny, device: "mac-1")
        _ = try await api.decide(id: "r2", .approve, device: "bad device!")
        _ = try await api.decide(id: "r3", .grant(minutes: 15), device: "mac-1")
        _ = try await api.decide(id: "r4", .always, device: "mac-1")
        _ = try await api.decide(id: "r5", .alwaysScript, device: "mac-1")
        let bodies = s.recorded(path: "/v1/approver/decide").map { $0.json }
        XCTAssertEqual(bodies.count, 5)

        XCTAssertEqual(bodies[0]["id"] as? String, "r1")
        XCTAssertEqual(bodies[0]["decision"] as? String, "deny")
        XCTAssertEqual(bodies[0]["device"] as? String, "mac-1")
        XCTAssertEqual(Set(bodies[0].keys), ["id", "decision", "device"])

        XCTAssertEqual(bodies[1]["decision"] as? String, "approve")
        XCTAssertNil(bodies[1]["device"])                       // invalid label: left out, not refused
        XCTAssertEqual(Set(bodies[1].keys), ["id", "decision"])

        XCTAssertEqual(bodies[2]["decision"] as? String, "approve")
        XCTAssertEqual(bodies[2]["grant_minutes"] as? Int, 15)
        XCTAssertNil(bodies[2]["always"])

        XCTAssertEqual(bodies[3]["decision"] as? String, "approve")
        XCTAssertEqual(bodies[3]["always"] as? Bool, true)
        XCTAssertNil(bodies[3]["grant_minutes"])

        XCTAssertEqual(bodies[4]["decision"] as? String, "approve")
        XCTAssertEqual(bodies[4]["always"] as? String, "script")

        let rec = try XCTUnwrap(s.recorded(path: "/v1/approver/decide").first)
        XCTAssertEqual(rec.request.httpMethod, "POST")
        XCTAssertEqual(rec.authorization, "Bearer tok")
        XCTAssertEqual(rec.request.value(forHTTPHeaderField: "Content-Type"), "application/json")
    }

    func testPendingQueryAuthAndRetryAfter() async throws {
        let body = try Fixtures.data("pending")
        let s = server { rec in
            .raw(200, body, headers: rec.query["since"] == "3" ? ["Retry-After": "2"] : [:])
        }
        let api = client(s)
        let first = try await api.pending(since: nil, wait: 25)
        XCTAssertEqual(first.version, 3)
        XCTAssertNil(first.retryAfter)
        let second = try await api.pending(since: 3, wait: 40)
        XCTAssertEqual(second.retryAfter, 2)

        let recs = s.recorded(path: "/v1/approver/pending")
        XCTAssertEqual(recs.count, 2)
        XCTAssertEqual(recs[0].query, ["wait": "25"])               // no since: answers at once
        XCTAssertEqual(recs[1].query, ["since": "3", "wait": "40"]) // the broker caps wait itself
        XCTAssertEqual(recs[0].authorization, "Bearer tok")
        XCTAssertEqual(recs[0].request.httpMethod, "GET")
        XCTAssertGreaterThan(recs[0].request.timeoutInterval, 25)
    }

    func testRateLimitedAndUnavailableCarryRetryAfter() async throws {
        let s = server { rec in
            rec.path == "/v1/approver/pending"
                ? .json(429, ["error": "rate limited"], headers: ["Retry-After": "60"])
                : .json(503, ["error": "identity provider unavailable"], headers: ["Retry-After": "30"])
        }
        let api = client(s)
        do {
            _ = try await api.pending(since: nil, wait: 0)
            XCTFail("429 should throw")
        } catch {
            XCTAssertEqual(error as? APIError, .rateLimited(retryAfter: 60))
        }
        do {
            try await api.presence(active: true, device: "mac-1")
            XCTFail("503 should throw")
        } catch {
            XCTAssertEqual(error as? APIError, .unavailable(retryAfter: 30))
        }
    }

    func testPresenceBody() async throws {
        let s = server { _ in .json(200, ["ok": true]) }
        let api = client(s)
        try await api.presence(active: true, device: "mac-1")
        try await api.presence(active: false, device: "")
        let bodies = s.recorded(path: "/v1/approver/presence").map { $0.json }
        XCTAssertEqual(bodies.count, 2)
        XCTAssertEqual(bodies[0]["active"] as? Bool, true)
        XCTAssertEqual(bodies[0]["device"] as? String, "mac-1")
        XCTAssertEqual(bodies[1]["active"] as? Bool, false)
        XCTAssertNil(bodies[1]["device"])
    }

    func testConfigNeedsNoToken() async throws {
        let body: [String: Any] = ["issuer": "https://idp.example.test/o/asb/", "client_id": "cid",
                                   "scopes": ["openid", "offline_access"], "api_version": 1]
        let data = try JSONSerialization.data(withJSONObject: body)
        let s = server { _ in .raw(200, data) }
        let cfg = try await APIClient.fetchConfig(baseURL: s.baseURL, session: s.session)
        XCTAssertEqual(cfg.clientId, "cid")
        XCTAssertEqual(cfg.apiVersion, 1)
        XCTAssertEqual(cfg.issuer.absoluteString, "https://idp.example.test/o/asb/")
        let rec = try XCTUnwrap(s.recorded.first)
        XCTAssertEqual(rec.path, "/v1/approver/config")
        XCTAssertNil(rec.authorization)
    }

    func testBaseURLWithPathAndTrailingSlash() {
        let req = APIClient.makeRequest(baseURL: URL(string: "https://broker.example.test:8800/asb/")!,
                                        method: "GET", path: "/v1/approver/pending",
                                        query: [URLQueryItem(name: "wait", value: "0")])
        XCTAssertEqual(req.url?.absoluteString, "https://broker.example.test:8800/asb/v1/approver/pending?wait=0")
    }

    func testDeviceLabelRule() {
        XCTAssertTrue(APIClient.isValidDevice("Office-Mac.local:1_a"))
        XCTAssertFalse(APIClient.isValidDevice(""))
        XCTAssertFalse(APIClient.isValidDevice(String(repeating: "a", count: 65)))
        XCTAssertTrue(APIClient.isValidDevice(String(repeating: "a", count: 64)))
        XCTAssertFalse(APIClient.isValidDevice("mac 1"))
        XCTAssertFalse(APIClient.isValidDevice("mäc"))
    }
}
