import XCTest
@testable import ASBApproverKit

final class PendingFeedTests: XCTestCase {
    private var servers: [StubServer] = []
    private var collectors: [EventCollector] = []
    private var feeds: [PendingFeed] = []

    override func tearDown() async throws {
        for f in feeds {
            await f.stop()
        }
        collectors.forEach { $0.cancel() }
        servers.forEach { $0.close() }
        feeds = []
        collectors = []
        servers = []
        try await super.tearDown()
    }

    private func server(_ handler: @escaping StubHandler) -> StubServer {
        let s = StubServer(handler)
        servers.append(s)
        return s
    }

    private func feed(_ s: StubServer, tokens: any TokenProvider = StaticTokens(),
                      sleep: @escaping PendingFeed.Sleeper = PendingFeed.defaultSleep) -> (PendingFeed, EventCollector) {
        let api = APIClient(baseURL: s.baseURL, tokens: tokens, session: s.session)
        let f = PendingFeed(api: api, wait: 25, sleep: sleep)
        let c = EventCollector(f.updates)
        feeds.append(f)
        collectors.append(c)
        return (f, c)
    }

    private static func json(_ obj: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: obj)) ?? Data()
    }

    func testNewlyNotifiedEmittedOnceAndOnlyWhenNotifiedTurnsTrue() async throws {
        let pages = [
            Self.json(Fixtures.page(1, [Fixtures.row("A", notified: false)])),
            Self.json(Fixtures.page(2, [Fixtures.row("A", notified: true)])),
            Self.json(Fixtures.page(3, [Fixtures.row("A", notified: true), Fixtures.row("B", notified: true)])),
        ]
        let calls = Box(0)
        let s = server { _ in
            let n = calls.update { (c: inout Int) -> Int in
                c += 1
                return c
            }
            // after the three pages: a long poll that keeps answering the same page
            return .raw(200, pages[min(n, pages.count) - 1]).after(n > pages.count ? 0.05 : 0)
        }
        let (f, events) = feed(s)
        await f.start()
        await fulfillment(of: [events.expectation(count: 5)], timeout: 10)
        try await Task.sleep(nanoseconds: 300_000_000)  // repeated v3 pages emit nothing more

        let got = events.snapshot
        XCTAssertEqual(got.map { $0.kind }, ["page", "page", "newlyNotified", "page", "newlyNotified"])
        XCTAssertEqual(got[0].page?.version, 1)
        XCTAssertEqual(got[1].page?.version, 2)
        XCTAssertEqual(got[2].newly?.map { $0.id }, ["A"])     // when notified turns true, not before
        XCTAssertEqual(got[3].page?.version, 3)
        XCTAssertEqual(got[4].newly?.map { $0.id }, ["B"])     // A is not announced again

        let polls = s.recorded(path: "/v1/approver/pending")
        XCTAssertGreaterThan(polls.count, 3)
        XCTAssertNil(polls[0].query["since"])
        XCTAssertEqual(polls[1].query["since"], "1")
        XCTAssertEqual(polls[3].query["since"], "3")
        XCTAssertEqual(polls[3].query["wait"], "25")
    }

    /// Review focus 2: a request decided elsewhere while the app shows it. `/decide` answers 410;
    /// the feed drops the row (so the app removes it and its banner) without an error.
    func testDecide410RemovesRequest() async throws {
        let fixture = try Fixtures.object("pending")
        let gone = "Kj1GZvGJdOU3JxoV_aTa2g"
        var after = fixture
        after["version"] = 4
        after["requests"] = (fixture["requests"] as? [[String: Any]] ?? []).filter { ($0["id"] as? String) != gone }
        let before = Self.json(fixture)
        let afterData = Self.json(after)
        let decided = Box(false)
        let s = server { rec in
            switch rec.path {
            case "/v1/approver/decide":
                decided.update { $0 = true }
                return .json(410, ["ok": false])
            case "/v1/approver/pending":
                return .raw(200, decided.get ? afterData : before).after(rec.query["since"] != nil ? 0.05 : 0)
            default:
                return .json(404, ["error": "not found"])
            }
        }
        let (f, events) = feed(s)
        await f.start()
        await fulfillment(of: [events.expectation(count: 2)], timeout: 10)    // page + newlyNotified
        XCTAssertTrue(events.snapshot[0].page?.requests.contains { $0.id == gone } ?? false)
        let shown = events.snapshot.count

        let result = try await f.decide(id: gone, .approve, device: "mac-1")
        XCTAssertEqual(result, .alreadyDecided)

        await fulfillment(of: [events.expectation(count: shown + 1)], timeout: 10)
        let next = try XCTUnwrap(events.snapshot.dropFirst(shown).compactMap { $0.page }.first)
        XCTAssertFalse(next.requests.contains { $0.id == gone })
        XCTAssertEqual(next.requests.count, 2)
        XCTAssertFalse(events.snapshot.contains { $0 == .unreachable || $0 == .signInRequired })
    }

    func testBackoffSequenceCapsAt30() async throws {
        XCTAssertEqual((0..<8).map { PendingFeed.backoff(attempt: $0) }, [1, 2, 4, 8, 16, 30, 30, 30])
        XCTAssertEqual(PendingFeed.backoff(attempt: 1_000), 30)

        // In the loop: seven failures, one success (which resets the backoff), then failures again.
        let ok = Self.json(Fixtures.page(1, [Fixtures.row("A", notified: false)]))
        let calls = Box(0)
        let s = server { _ in
            let n = calls.update { (c: inout Int) -> Int in
                c += 1
                return c
            }
            if n == 8 {
                return .raw(200, ok)
            }
            throw URLError(.cannotConnectToHost)
        }
        let delays = Box([TimeInterval]())
        let done = XCTestExpectation(description: "eight sleeps")
        let (f, events) = feed(s, sleep: { d in
            let count = delays.update { (all: inout [TimeInterval]) -> Int in
                all.append(d)
                return all.count
            }
            if count >= 8 {
                done.fulfill()
                throw CancellationError()       // ends the loop
            }
        })
        await f.start()
        await fulfillment(of: [done], timeout: 10)
        XCTAssertEqual(delays.get, [1, 2, 4, 8, 16, 30, 30, 1])
        await fulfillment(of: [events.expectation(count: 3)], timeout: 10)  // the collector runs on its own task
        XCTAssertEqual(events.snapshot.map { $0.kind }, ["unreachable", "page", "unreachable"])
    }

    /// After an outage the app must hear "reachable again" even when the list did not change.
    func testRecoveryEmitsPageEvenWhenUnchanged() async throws {
        let same = Self.json(Fixtures.page(1, [Fixtures.row("A", notified: false)]))
        let calls = Box(0)
        let s = server { _ in
            let n = calls.update { (c: inout Int) -> Int in
                c += 1
                return c
            }
            if n == 2 {
                throw URLError(.cannotConnectToHost)
            }
            return .raw(200, same).after(n > 3 ? 0.05 : 0)
        }
        let (f, events) = feed(s, sleep: { _ in })
        await f.start()
        await fulfillment(of: [events.expectation(count: 3)], timeout: 10)
        try await Task.sleep(nanoseconds: 300_000_000)  // further identical pages emit nothing
        XCTAssertEqual(events.snapshot.map { $0.kind }, ["page", "unreachable", "page"])
        XCTAssertEqual(events.snapshot[2].page?.version, 1)
        let polls = s.recorded(path: "/v1/approver/pending")
        XCTAssertGreaterThan(polls.count, 3)
        XCTAssertEqual(polls[1].query["wait"], "25")
        XCTAssertEqual(polls[2].query["wait"], "0")     // the first poll after an error answers at once
        XCTAssertEqual(polls[3].query["wait"], "25")
    }

    func testRetryAfterOnPageAndErrorsIsHonored() async throws {
        let ok = Self.json(Fixtures.page(1, []))
        let calls = Box(0)
        let s = server { _ in
            let n = calls.update { (c: inout Int) -> Int in
                c += 1
                return c
            }
            switch n {
            case 1: return .raw(200, ok, headers: ["Retry-After": "2"])        // waiter cap
            case 2: return .json(429, ["error": "rate limited"], headers: ["Retry-After": "60"])
            default: return .json(503, ["error": "unavailable"], headers: ["Retry-After": "30"])
            }
        }
        let delays = Box([TimeInterval]())
        let done = XCTestExpectation(description: "three sleeps")
        let (f, _) = feed(s, sleep: { d in
            let count = delays.update { (all: inout [TimeInterval]) -> Int in
                all.append(d)
                return all.count
            }
            if count >= 3 {
                done.fulfill()
                throw CancellationError()
            }
        })
        await f.start()
        await fulfillment(of: [done], timeout: 10)
        XCTAssertEqual(delays.get, [2, 60, 30])     // Retry-After beats the 1 s / 2 s backoff
    }

    /// Review focus 3, feed side: only a failed refresh stops the feed with "Sign in again".
    func testSignInRequiredStopsFeed() async throws {
        let s = server { _ in .json(401, ["error": "unauthorized"], headers: ["WWW-Authenticate": "Bearer"]) }
        let (f, events) = feed(s, tokens: SignedOutTokens())
        await f.start()
        await fulfillment(of: [events.expectation(count: 1)], timeout: 10)
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(events.snapshot, [.signInRequired])
        XCTAssertEqual(s.recorded(path: "/v1/approver/pending").count, 1)
        let running = await f.isRunning
        XCTAssertFalse(running)
    }
}
