import AppKit
import CoreGraphics
import Foundation

/// Tells the broker when the user is really at this Mac, so the phone push can wait.
///
/// Active means: this app's banners can be shown (notification authorization is granted; see
/// `bannersAllowed`), the screen is unlocked (and not asleep, and this login session is the one on
/// the console) and there was keyboard or mouse input within the last 120 s. While active it sends
/// `presence(active: true)` every 10 s (the broker's presence `ttl_s` defaults to 25 s); on the
/// transition to inactive it sends `active: false` once, at once, and then nothing until active again.
///
/// Sending: at most one beat is in flight and at most one waits behind it. A newer state replaces
/// the waiting beat (so an `active: false` always replaces a waiting `true`), and a waiting `true`
/// older than `staleLimit` is dropped when its turn comes. An outage therefore never piles beats up
/// to burst out on recovery.
@MainActor
final class PresenceReporter {
    static let interval: TimeInterval = 10
    static let idleLimit: TimeInterval = 120
    /// A waiting `active: true` older than this is not sent (it would claim presence after the fact).
    static let staleLimit: TimeInterval = 10

    /// Sends one presence beat (set by the model).
    var send: ((Bool) async -> Void)?

    /// Whether this app's banners can be seen (notification authorization `.authorized` or
    /// `.provisional`). Set by the model; while false, presence is never reported as active.
    var bannersAllowed = false {
        didSet {
            if bannersAllowed != oldValue {
                tick()
            }
        }
    }

    private var locked = false
    private var asleep = false
    private var sessionInactive = false
    private var lastActive: Bool?
    private var loop: Task<Void, Never>?
    /// The beat being sent, if any.
    private var inFlight: Task<Void, Never>?
    /// The one beat waiting behind `inFlight`: the latest state, and when it was queued.
    private var waiting: (active: Bool, queuedAt: Date)?
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []

    init() {
        locked = Self.screenLockedNow()
        let dnc = DistributedNotificationCenter.default()
        observe(dnc, "com.apple.screenIsLocked") { $0.locked = true }
        observe(dnc, "com.apple.screenIsUnlocked") { $0.locked = false }
        let ws = NSWorkspace.shared.notificationCenter
        observe(ws, NSWorkspace.screensDidSleepNotification.rawValue) { $0.asleep = true }
        observe(ws, NSWorkspace.willSleepNotification.rawValue) { $0.asleep = true }
        observe(ws, NSWorkspace.screensDidWakeNotification.rawValue) { $0.asleep = false }
        observe(ws, NSWorkspace.didWakeNotification.rawValue) { $0.asleep = false }
        // Fast user switching: another user on the console.
        observe(ws, NSWorkspace.sessionDidResignActiveNotification.rawValue) { $0.sessionInactive = true }
        observe(ws, NSWorkspace.sessionDidBecomeActiveNotification.rawValue) { $0.sessionInactive = false }
    }

    /// Starts the 10 s beat (no-op while running).
    func start() {
        guard loop == nil else { return }
        lastActive = nil
        loop = Task { [weak self] in
            while !Task.isCancelled {
                self?.tick()
                try? await Task.sleep(nanoseconds: UInt64(PresenceReporter.interval * 1_000_000_000))
            }
        }
    }

    /// Stops beating and forgets a waiting beat. Sends nothing (see `stopSendingInactive`).
    func stop() {
        loop?.cancel()
        loop = nil
        lastActive = nil
        waiting = nil
    }

    /// Stops beating, waits for a beat in flight, then sends `active: false` (sign-out), so the
    /// `false` is not overtaken by an earlier `true`.
    func stopSendingInactive() async {
        stop()
        let current = inFlight
        await current?.value
        if let send {
            await send(false)
        }
    }

    var isActive: Bool {
        bannersAllowed && !locked && !asleep && !sessionInactive
            && Self.secondsSinceLastInput() < Self.idleLimit
    }

    private func tick() {
        guard loop != nil else { return }
        let active = isActive
        if active {
            enqueue(true)                       // every beat while active
        } else if lastActive != false {
            enqueue(false)                      // once, on the transition
        }
        lastActive = active
    }

    private func enqueue(_ active: Bool) {
        guard send != nil else { return }
        waiting = (active: active, queuedAt: Date())     // the latest state replaces a waiting beat
        pump()
    }

    /// Starts the waiting beat when nothing is in flight.
    private func pump() {
        guard inFlight == nil, let next = waiting, let send else { return }
        waiting = nil
        if next.active && Date().timeIntervalSince(next.queuedAt) > Self.staleLimit {
            return                              // stale presence: the next tick sends a fresh one
        }
        inFlight = Task { [weak self] in
            await send(next.active)
            guard let self else { return }
            self.inFlight = nil
            self.pump()
        }
    }

    private func observe(_ center: NotificationCenter, _ name: String,
                         _ change: @escaping @MainActor (PresenceReporter) -> Void) {
        let token = center.addObserver(forName: Notification.Name(name), object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                change(self)
                self.tick()                     // report a lock or unlock at once, not on the next beat
            }
        }
        observers.append((center, token))
    }

    // MARK: - System state

    /// The "any input event" type. `CGEventType.null` (0) is NOT "any event": it is the null event
    /// type and its idle time is unrelated to input. `kCGAnyInputEventType` is `~0` in C and has no
    /// Swift case, so it is built from its raw value (imported C enums accept any raw value).
    private static let anyInputEventType: CGEventType? = CGEventType(rawValue: ~UInt32(0))

    private static let inputEventTypes: [CGEventType] = [
        .keyDown, .flagsChanged, .mouseMoved, .leftMouseDown, .rightMouseDown, .otherMouseDown,
        .leftMouseDragged, .rightMouseDragged, .scrollWheel,
    ]

    /// Seconds since the last keyboard or mouse input in this login session.
    static func secondsSinceLastInput() -> TimeInterval {
        if let any = anyInputEventType {
            return CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: any)
        }
        // Fallback (not expected): the least idle time over the common input types.
        return inputEventTypes
            .map { CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: $0) }
            .min() ?? .infinity
    }

    /// Whether the screen is locked right now (for the state at launch, before any notification).
    private static func screenLockedNow() -> Bool {
        guard let dict = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return (dict["CGSSessionScreenIsLocked"] as? Bool) ?? false
    }
}
