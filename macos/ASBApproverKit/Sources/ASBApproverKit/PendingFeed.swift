import Foundation

public enum FeedEvent: Equatable, Sendable {
    /// The pending list changed (new version or different rows). Also means "reachable again".
    case page(PendingPage)
    /// Requests whose `notified` turned true since the last page (or that arrived already
    /// notified): post one banner each. Each id is reported once.
    case newlyNotified([PendingRequest])
    /// The broker could not be reached (reported once per outage); the feed keeps retrying.
    case unreachable
    /// The session cannot be refreshed: show "Sign in again". The feed has stopped; call
    /// `start()` after signing in.
    case signInRequired
}

/// The long-poll loop over `GET /v1/approver/pending`. One consumer of `updates` only.
public actor PendingFeed {
    public typealias Sleeper = @Sendable (TimeInterval) async throws -> Void

    public static let defaultSleep: Sleeper = { seconds in
        try await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
    }

    /// The feed's events. Finished when the feed is deinitialized.
    public nonisolated let updates: AsyncStream<FeedEvent>
    private let continuation: AsyncStream<FeedEvent>.Continuation
    private let api: APIClient
    private let waitSeconds: Int
    private let sleeper: Sleeper

    private var loop: Task<Void, Never>?
    private var generation = 0
    private var lastPage: PendingPage?
    private var notifiedIDs: Set<String> = []
    private var reachable = true

    /// `wait` is the long-poll seconds (the broker caps it at 25); `sleep` is injectable for tests.
    public init(api: APIClient, wait: Int = 25, sleep: @escaping Sleeper = PendingFeed.defaultSleep) {
        self.api = api
        self.waitSeconds = wait
        self.sleeper = sleep
        let (stream, continuation) = AsyncStream.makeStream(of: FeedEvent.self)
        self.updates = stream
        self.continuation = continuation
    }

    deinit {
        loop?.cancel()
        continuation.finish()
    }

    /// Delay before retry number `attempt` (0-based): 1, 2, 4, 8, 16, then 30 s.
    public static func backoff(attempt: Int) -> TimeInterval {
        let exp = min(max(attempt, 0), 5)
        return min(30, TimeInterval(1 << exp))
    }

    /// Starts polling (no-op while running).
    public func start() {
        guard loop == nil else { return }
        generation += 1
        let gen = generation
        loop = Task { [weak self] in
            await self?.run(gen)
        }
    }

    /// Stops polling. `updates` stays open; `start()` resumes.
    public func stop() {
        generation += 1
        loop?.cancel()
        loop = nil
    }

    public var isRunning: Bool { loop != nil }

    /// The last page (with local removals applied).
    public var currentPage: PendingPage? { lastPage }

    /// Decides through the API. When the request is settled either way (200, 410 decided
    /// elsewhere, 404 gone) the row is dropped at once and a `.page` without it is emitted, so the
    /// app removes the row and its banner without an error.
    @discardableResult
    public func decide(id: String, _ decision: Decision, device: String) async throws -> DecideResult {
        let result = try await api.decide(id: id, decision, device: device)
        switch result {
        case .ok, .alreadyDecided, .notFound:
            remove(id: id)
        case .refused:
            break
        }
        return result
    }

    /// Drops a row locally and emits the page without it (no-op if it is not shown).
    public func remove(id: String) {
        guard var page = lastPage, page.requests.contains(where: { $0.id == id }) else { return }
        page.requests.removeAll { $0.id == id }
        lastPage = page
        notifiedIDs.remove(id)
        continuation.yield(.page(page))
    }

    // MARK: - Loop

    private func run(_ gen: Int) async {
        defer {
            if generation == gen {
                loop = nil
            }
        }
        var attempt = 0
        while !Task.isCancelled {
            do {
                // After an error, ask for an immediate answer so recovery shows at once.
                let recovering = !reachable
                let page = try await api.pending(since: lastPage?.version, wait: recovering ? 0 : waitSeconds)
                if Task.isCancelled || generation != gen { return }
                attempt = 0
                reachable = true
                accept(page, force: recovering)     // "reachable again" even if nothing changed
                if let pause = page.retryAfter, pause > 0 {
                    try await sleeper(pause)          // waiter cap: the broker asked for a pause
                }
            } catch {
                if Task.isCancelled || generation != gen || error is CancellationError { return }
                if (error as? OIDCError) == .signInRequired {
                    continuation.yield(.signInRequired)
                    return
                }
                if reachable {
                    reachable = false
                    continuation.yield(.unreachable)
                }
                var delay = Self.backoff(attempt: attempt)
                attempt += 1
                if let asked = (error as? APIError)?.retryAfter {
                    delay = max(delay, asked)       // 429: 60 s, 503: 30 s
                }
                do {
                    try await sleeper(delay)
                } catch {
                    return
                }
            }
        }
    }

    /// Emits the page when it changed, or always with `force` (the first success after an outage).
    private func accept(_ incoming: PendingPage, force: Bool = false) {
        var page = incoming
        page.retryAfter = nil
        if !force, let last = lastPage, last.version == page.version, last.requests == page.requests {
            return
        }
        lastPage = page
        continuation.yield(.page(page))
        let newly = page.requests.filter { $0.notified && !notifiedIDs.contains($0.id) }
        notifiedIDs = Set(page.requests.filter { $0.notified }.map { $0.id })
        if !newly.isEmpty {
            continuation.yield(.newlyNotified(newly))
        }
    }
}
