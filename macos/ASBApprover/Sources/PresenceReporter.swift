import AppKit
import CoreGraphics
import Foundation

/// Tells the broker when the user is really at this Mac, so the phone push can wait.
///
/// Active means: the screen is unlocked (and not asleep, and this login session is the one on the
/// console) and there was keyboard or mouse input within the last 120 s. While active it sends
/// `presence(active: true)` every 10 s (the broker's presence `ttl_s` defaults to 25 s); on the
/// transition to inactive it sends `active: false` once, at once.
@MainActor
final class PresenceReporter {
    static let interval: TimeInterval = 10
    static let idleLimit: TimeInterval = 120

    /// Sends one presence beat (set by the model).
    var send: ((Bool) async -> Void)?

    private var locked = false
    private var asleep = false
    private var sessionInactive = false
    private var lastActive: Bool?
    private var loop: Task<Void, Never>?
    /// Beats go out one after another, so an `active: false` never overtakes an earlier `true`.
    private var sending: Task<Void, Never>?
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

    /// Stops beating. Sends nothing (the caller sends `active: false` first when it still can).
    func stop() {
        loop?.cancel()
        loop = nil
        lastActive = nil
    }

    var isActive: Bool {
        !locked && !asleep && !sessionInactive && Self.secondsSinceLastInput() < Self.idleLimit
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
        guard let send else { return }
        let previous = sending
        sending = Task {
            await previous?.value
            await send(active)
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
