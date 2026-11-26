import AppKit
import AuthenticationServices
import Foundation
import Observation
import ASBApproverKit

/// The app's state: the broker session, the pending list, and the decisions sent from the popover
/// and from banners. One instance (`AppModel.shared`), on the main actor.
@MainActor
@Observable
final class AppModel {
    enum State: Equatable {
        /// No session (first run, signed out, or a refresh that failed: "Sign in again").
        case signedOut
        /// The feed is answering.
        case ready
        /// The broker could not be reached; the feed keeps retrying with backoff.
        case unreachable
    }

    static let shared = AppModel()

    var state: State = .signedOut
    /// Pending requests, oldest first, as the broker sent them.
    var requests: [PendingRequest] = []
    /// What the user typed as the broker's client URL (persisted in UserDefaults).
    var brokerURLText: String = ""
    var isSigningIn = false
    var signInError: String?
    /// The session existed and could not be refreshed.
    var needsSignInAgain = false
    /// The last decision that did not go through (shown at the top of the list).
    var decideError: String?
    var notificationsDenied = false
    /// Rows shown expanded.
    var expandedIDs: Set<String> = []
    /// A banner was tapped: the popover scrolls to this row.
    var focusedRequestID: String?
    /// Requests with a decision in flight (their buttons are disabled).
    var busyIDs: Set<String> = []

    @ObservationIgnored private(set) var api: APIClient?
    @ObservationIgnored private(set) var oidc: OIDCClient?
    @ObservationIgnored private var feed: PendingFeed?
    @ObservationIgnored private var feedTask: Task<Void, Never>?
    @ObservationIgnored private var signInTask: Task<Void, Never>?
    private let webAuth = WebAuthSession()
    @ObservationIgnored private var workspaceObservers: [NSObjectProtocol] = []
    @ObservationIgnored private var launched = false
    /// False until the current feed delivers its first page. Banner actions that arrive before
    /// then (the app relaunched by a banner button, or any launch race) wait in
    /// `queuedBannerActions` and are checked against that page.
    @ObservationIgnored private var receivedFirstPage = false
    @ObservationIgnored private var queuedBannerActions: [(id: String, decision: Decision)] = []

    let notifications: Notifications
    let presence: PresenceReporter
    let loginItem: LoginItem
    /// The `device` label sent with decisions and presence: this Mac's name, sanitized.
    let device: String

    private init() {
        notifications = Notifications()
        presence = PresenceReporter()
        loginItem = LoginItem()
        device = Self.deviceLabel(Host.current().localizedName)
        brokerURLText = UserDefaults.standard.string(forKey: Self.brokerURLKey) ?? ""
        // Wired here rather than in `launch()`: the model is created in
        // `applicationWillFinishLaunching`, before any notification response can be delivered.
        notifications.onAction = { [weak self] id, decision in
            self?.decideFromBanner(id: id, decision)
        }
        notifications.onOpen = { [weak self] id in
            self?.focus(id)
        }
    }

    // MARK: - Launch

    /// Called from `applicationDidFinishLaunching`. The notification delegate and the banner
    /// handlers are set earlier (`applicationWillFinishLaunching`), so a banner action that launched
    /// the app reaches the model; it is queued until the first page and validated against it.
    func launch() {
        guard !launched else { return }
        launched = true
        presence.send = { [weak self] active in
            await self?.sendPresence(active)
        }
        Task { [weak self] in
            _ = await Notifications.requestAuthorization()
            self?.refreshNotificationAuthorization()
        }
        observeSleep()
        observeActivation()

        if let saved = SavedBroker.load() {
            let client = install(saved)
            Task { [weak self] in
                guard let self else { return }
                if await client.isSignedIn() {
                    self.state = .ready
                    self.startFeed()
                } else {
                    self.state = .signedOut
                    // No session: this feed never starts, so later banner actions are dropped
                    // at once (`feed == nil`) instead of queuing for a page that never comes.
                    self.feedTask?.cancel()
                    self.feedTask = nil
                    self.feed = nil
                    self.api = nil
                    self.dropQueuedBannerActions()
                }
            }
        } else {
            dropQueuedBannerActions()       // no session: nothing can decide them
        }
    }

    // MARK: - Sign-in

    func beginSignIn() {
        guard !isSigningIn else { return }
        signInTask = Task { [weak self] in
            await self?.signIn()
        }
    }

    private func signIn() async {
        signInError = nil
        guard let url = Self.parseBrokerURL(brokerURLText) else {
            signInError = "Enter the broker's client URL, for example https://broker.example:8800."
            return
        }
        isSigningIn = true
        defer { isSigningIn = false }
        do {
            let config = try await APIClient.fetchConfig(baseURL: url)
            let endpoints = try await OIDCClient.discover(issuer: config.issuer)
            let saved = SavedBroker(brokerURL: url, config: config, endpoints: endpoints)
            // A client only to build the authorize URL; its token state is replaced on exchange.
            let pkce = PKCE.make()
            let stateParam = PKCE.randomURLSafe()
            let probe = OIDCClient(config: config, endpoints: endpoints, store: MemoryTokenStore())
            let callback = try await webAuth.authenticate(url: probe.authorizeURL(state: stateParam, pkce: pkce),
                                                          callbackScheme: Self.callbackScheme)
            let code = try OIDCClient.authorizationCode(from: callback, expectedState: stateParam)

            // Only now end the previous session: a cancelled sign-in leaves it alone.
            await endSession()
            let client = install(saved)
            try await client.exchange(code: code, pkce: pkce)
            saved.store()
            UserDefaults.standard.set(brokerURLText, forKey: Self.brokerURLKey)
            needsSignInAgain = false
            decideError = nil
            state = .ready
            startFeed()
        } catch {
            if let e = error as? ASWebAuthenticationSessionError, e.code == .canceledLogin {
                return
            }
            signInError = Self.describe(error)
        }
    }

    func signOut() {
        Task { [weak self] in
            guard let self else { return }
            if self.state != .signedOut {
                await self.presence.stopSendingInactive()
            }
            await self.endSession()
            self.needsSignInAgain = false
            self.state = .signedOut
        }
    }

    /// Stops the feed and presence, forgets the tokens (Keychain item too), clears the list and banners.
    private func endSession() async {
        presence.stop()
        feedTask?.cancel()
        feedTask = nil
        if let feed {
            await feed.stop()
        }
        if let oidc {
            await oidc.signOut()
        }
        feed = nil
        api = nil
        oidc = nil
        dropQueuedBannerActions()
        requests = []
        expandedIDs = []
        busyIDs = []
        notifications.removeAllDelivered()
    }

    /// Builds the clients for a broker. Tokens come from the Keychain item, if any.
    @discardableResult
    private func install(_ saved: SavedBroker) -> OIDCClient {
        let client = OIDCClient(config: saved.config, endpoints: saved.endpoints, store: KeychainTokenStore())
        let api = APIClient(baseURL: saved.brokerURL, tokens: client)
        let feed = PendingFeed(api: api)
        self.oidc = client
        self.api = api
        self.feed = feed
        receivedFirstPage = false
        feedTask?.cancel()
        feedTask = Task { [weak self] in
            for await event in feed.updates {
                self?.handle(event)
            }
        }
        return client
    }

    private func startFeed() {
        guard let feed else { return }
        Task { await feed.start() }
        presence.start()
    }

    // MARK: - Feed

    private func handle(_ event: FeedEvent) {
        switch event {
        case .page(let page):
            guard state != .signedOut else { return }
            let ids = Set(page.requests.map(\.id))
            let gone = requests.map(\.id).filter { !ids.contains($0) }
            requests = page.requests
            expandedIDs.formIntersection(ids)
            busyIDs.formIntersection(ids)
            state = .ready
            if !gone.isEmpty {
                notifications.removeDelivered(gone)
            }
            // Also banners left over from an earlier run, or posted for rows that vanished meanwhile.
            notifications.removeDelivered(notIn: ids)
            if !receivedFirstPage {
                receivedFirstPage = true
                applyQueuedBannerActions()
            }
        case .newlyNotified(let notified):
            guard state != .signedOut else { return }
            for request in notified {
                notifications.post(request)
            }
        case .unreachable:
            // Kept until the next `.page`; `PendingFeed.stop()`/`start()` (sleep and wake) do not
            // reset it, and neither does this model.
            if state != .signedOut {
                state = .unreachable
            }
        case .signInRequired:
            presence.stop()
            if let feed {
                Task { await feed.stop() }      // already stopped when the feed reported it
            }
            needsSignInAgain = true
            state = .signedOut
            requests = []
            expandedIDs = []
            busyIDs = []
            dropQueuedBannerActions()
            receivedFirstPage = true        // stopped feed: later banner actions find no row and are dropped
            notifications.removeAllDelivered()
        }
    }

    // MARK: - Decisions

    /// Sends a decision from the popover. Only decisions the request offers are sent.
    func decide(_ request: PendingRequest, _ decision: Decision) {
        guard request.actions.contains(decision) else { return }
        send(id: request.id, decision)
    }

    /// A banner button. The banner offered only the request's `banner_actions`. Before the first
    /// page the list is not known yet, so the action is queued (never sent unchecked).
    private func decideFromBanner(id: String, _ decision: Decision) {
        if launched && feed == nil {
            notifications.removeDelivered([id])     // signed out: no page will come
            return
        }
        guard receivedFirstPage else {
            queuedBannerActions.append((id: id, decision: decision))
            return
        }
        guard let request = requests.first(where: { $0.id == id }),
              request.bannerActions.contains(decision), request.actions.contains(decision) else {
            // Not shown any more (decided elsewhere, expired): drop the stale banner.
            notifications.removeDelivered([id])
            return
        }
        send(id: id, decision)
    }

    /// The first page arrived: each queued action is sent only if its request is in the page and
    /// the decision is in that request's `banner_actions` and `actions`; otherwise its banner is
    /// removed and nothing is sent.
    private func applyQueuedBannerActions() {
        let queued = queuedBannerActions
        queuedBannerActions = []
        for action in queued {
            decideFromBanner(id: action.id, action.decision)
        }
    }

    /// No session will deliver a page: forget queued actions and remove their banners.
    private func dropQueuedBannerActions() {
        let ids = queuedBannerActions.map { $0.id }
        queuedBannerActions = []
        notifications.removeDelivered(ids)
    }

    private func send(id: String, _ decision: Decision) {
        guard let feed, !busyIDs.contains(id) else { return }
        busyIDs.insert(id)
        decideError = nil
        let device = self.device
        Task { [weak self] in
            do {
                let result = try await feed.decide(id: id, decision, device: device)
                guard let self else { return }
                self.busyIDs.remove(id)
                switch result {
                case .ok, .alreadyDecided, .notFound:
                    // Settled either way; the feed already dropped the row. No error for 410.
                    self.notifications.removeDelivered([id])
                case .refused:
                    self.decideError = "The broker refused that decision (it no longer offers it)."
                }
            } catch {
                guard let self else { return }
                self.busyIDs.remove(id)
                if (error as? OIDCError) == .signInRequired {
                    self.handle(.signInRequired)
                } else {
                    self.decideError = "The decision may not have reached the broker: " + Self.describe(error)
                }
            }
        }
    }

    func toggleExpanded(_ id: String) {
        if expandedIDs.contains(id) {
            expandedIDs.remove(id)
        } else {
            expandedIDs.insert(id)
        }
    }

    /// A banner was tapped: open the popover on that request.
    func focus(_ id: String) {
        if requests.contains(where: { $0.id == id }) {
            expandedIDs.insert(id)
            focusedRequestID = id
        } else {
            notifications.removeDelivered([id])
        }
        StatusItemOpener.open()
    }

    func openInBrowser(_ request: PendingRequest) {
        guard let url = request.browserUrl, let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http" else { return }
        NSWorkspace.shared.open(url)
    }

    // MARK: - Presence

    /// Re-reads the notification authorization (the user can change it in System Settings at any
    /// time). Presence is reported as active only while banners can be shown: a Mac whose banners
    /// are off must not hold back the phone push. Called at launch, when the popover opens and when
    /// the app becomes active.
    func refreshNotificationAuthorization() {
        Task { [weak self] in
            let allowed = await Notifications.bannersAllowed()
            guard let self else { return }
            self.notificationsDenied = !allowed
            self.presence.bannersAllowed = allowed
        }
    }

    private func observeActivation() {
        workspaceObservers.append(NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.refreshNotificationAuthorization()
            }
        })
    }

    private func sendPresence(_ active: Bool) async {
        guard let api else { return }
        do {
            try await api.presence(active: active, device: device)
        } catch {
            // Best effort: a lapsed beat only means the phone may get a push. The feed reports
            // sign-in and reachability problems.
        }
    }

    // MARK: - Sleep and wake

    private func observeSleep() {
        let nc = NSWorkspace.shared.notificationCenter
        workspaceObservers.append(nc.addObserver(forName: NSWorkspace.willSleepNotification, object: nil,
                                                 queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let feed = self.feed else { return }
                Task { await feed.stop() }
            }
        })
        workspaceObservers.append(nc.addObserver(forName: NSWorkspace.didWakeNotification, object: nil,
                                                 queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                // Resume at once rather than waiting out a backoff from the dead connection.
                // `state` is left as it is: an outage shown before sleep stays shown until a page.
                guard let self, self.state != .signedOut, let feed = self.feed else { return }
                Task { await feed.start() }
            }
        })
    }

    // MARK: - Helpers

    static let callbackScheme = "asb-approver"
    static let brokerURLKey = "brokerURL"

    /// `https://` is assumed when no scheme is typed. Only http and https are accepted.
    static func parseBrokerURL(_ text: String) -> URL? {
        var s = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if !s.contains("://") {
            s = "https://" + s
        }
        guard let url = URL(string: s), let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http", let host = url.host, !host.isEmpty else { return nil }
        return url
    }

    /// `notify.DEVICE_RE`: 1-64 of `A-Za-z0-9_.:-`. Other characters become `-`.
    static func deviceLabel(_ name: String?) -> String {
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-")
        var out = String((name ?? "").map { allowed.contains($0) ? $0 : "-" })
        while out.contains("--") {
            out = out.replacingOccurrences(of: "--", with: "-")
        }
        out = out.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        if out.count > 64 {
            out = String(out.prefix(64))
        }
        return out.isEmpty ? "mac" : out
    }

    /// A fixed, short message for the user. Never includes response bodies.
    static func describe(_ error: Error) -> String {
        if let e = error as? APIError {
            switch e {
            case .http(let status) where status == 404:
                return "This broker has no approver API. Add approver_api to its config and restart it."
            case .http(let status):
                return "The broker answered HTTP \(status)."
            case .rateLimited:
                return "The broker is rate-limiting this app. Try again in a minute."
            case .unavailable:
                return "The broker can't reach its identity provider right now. Try again shortly."
            case .invalidResponse:
                return "The broker's answer was not what this app expects."
            }
        }
        if let e = error as? OIDCError {
            switch e {
            case .signInRequired:
                return "Sign in again."
            case .discoveryFailed:
                return "The identity provider's discovery document is missing or invalid."
            case .stateMismatch:
                return "The sign-in answer did not match this sign-in. Try again."
            case .authorizationFailed(let code):
                return "The identity provider refused the sign-in (" + String(code.prefix(64)) + ")."
            case .tokenRequestFailed(let status):
                return "The identity provider's token endpoint answered HTTP \(status)."
            case .invalidResponse:
                return "The identity provider's answer was not what this app expects."
            }
        }
        if error is URLError {
            return "Can't reach the server."
        }
        if error is ASWebAuthenticationSessionError {
            return "The sign-in window could not be shown."
        }
        return "Something went wrong."
    }
}

/// The broker and identity-provider settings kept between launches (no secrets: the tokens live
/// only in the Keychain).
struct SavedBroker: Codable {
    var brokerURL: URL
    var config: ApproverConfig
    var endpoints: OIDCEndpoints

    static let key = "savedBroker"

    static func load() -> SavedBroker? {
        guard let data = UserDefaults.standard.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(SavedBroker.self, from: data)
    }

    func store() {
        if let data = try? JSONEncoder().encode(self) {
            UserDefaults.standard.set(data, forKey: Self.key)
        }
    }
}

/// `ASWebAuthenticationSession` as one async call. Not main-actor isolated as a whole so that the
/// presentation-context callback (an Objective-C protocol method) needs no isolation tricks;
/// `authenticate` itself runs on the main actor.
final class WebAuthSession: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var session: ASWebAuthenticationSession?

    @MainActor
    func authenticate(url: URL, callbackScheme: String) async throws -> URL {
        session?.cancel()
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
            let once = ResumeOnce(continuation)
            let s = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme) { callback, error in
                if let callback {
                    once.resume(.success(callback))
                } else {
                    once.resume(.failure(error ?? OIDCError.invalidResponse))
                }
            }
            s.presentationContextProvider = self
            // Share the browser's sign-in cookies with the identity provider (single sign-on).
            s.prefersEphemeralWebBrowserSession = false
            session = s
            if !s.start() {
                once.resume(.failure(ASWebAuthenticationSessionError(.presentationContextInvalid)))
            }
        }
    }

    /// Called on the main thread. A menu bar app may have no key window when the popover closed.
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        NSApplication.shared.keyWindow
            ?? NSApplication.shared.windows.first(where: { $0.isVisible })
            ?? ASPresentationAnchor()
    }
}

/// Resumes a continuation at most once (the session's handler and a failed `start()` could both try).
private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<URL, Error>?

    init(_ continuation: CheckedContinuation<URL, Error>) {
        self.continuation = continuation
    }

    func resume(_ result: Result<URL, Error>) {
        lock.lock()
        let c = continuation
        continuation = nil
        lock.unlock()
        c?.resume(with: result)
    }
}
