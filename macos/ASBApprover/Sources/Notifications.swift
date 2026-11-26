import Foundation
import UserNotifications
import ASBApproverKit

/// Local banners for requests that need a human. A banner's identifier is the request id; its
/// category (and so its buttons) comes from the request's `banner_actions`.
///
/// Banner text approximates the Web Push title and text line, composed from the request view
/// (the broker does not send the push text): title "Secret request [RISK]", body "<credentials>
/// from <client>". Never the summary, target or details.
@MainActor
final class Notifications: NSObject, UNUserNotificationCenterDelegate {
    static let approveDenyCategory = "ASB_APPROVE_DENY"
    static let denyCategory = "ASB_DENY"
    static let noneCategory = "ASB_NONE"

    /// A banner button was pressed: (request id, decision).
    var onAction: ((String, Decision) -> Void)?
    /// The banner itself was clicked: request id.
    var onOpen: ((String) -> Void)?

    private var center: UNUserNotificationCenter { UNUserNotificationCenter.current() }

    /// Sets the delegate and the categories. Call from `applicationWillFinishLaunching`, so a
    /// response that launched the app is delivered.
    func configure() {
        center.delegate = self
        let approve = UNNotificationAction(identifier: Decision.approve.actionID, title: "Approve", options: [])
        let deny = UNNotificationAction(identifier: Decision.deny.actionID, title: "Deny", options: [.destructive])
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Self.approveDenyCategory, actions: [approve, deny],
                                   intentIdentifiers: [], options: []),
            UNNotificationCategory(identifier: Self.denyCategory, actions: [deny],
                                   intentIdentifiers: [], options: []),
            UNNotificationCategory(identifier: Self.noneCategory, actions: [],
                                   intentIdentifiers: [], options: []),
        ])
    }

    /// Asks once for permission to show banners. False when the user said no.
    static func requestAuthorization() async -> Bool {
        do {
            return try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
        } catch {
            return false
        }
    }

    // MARK: - Content

    static func category(for request: PendingRequest) -> String {
        let offered = request.bannerActions
        if offered.contains(.approve) && offered.contains(.deny) {
            return approveDenyCategory
        }
        if offered.contains(.deny) {
            return denyCategory
        }
        return noneCategory
    }

    static func title(for request: PendingRequest) -> String {
        if let level = request.risk?.level, !level.isEmpty {
            return "Secret request [\(level.uppercased())]"
        }
        return "Secret request"
    }

    static func body(for request: PendingRequest) -> String {
        let names = request.credentials.isEmpty ? request.mode : request.credentials.joined(separator: ", ")
        let client = request.client.name ?? request.client.id ?? "an unknown client"
        return "\(names) from \(client)"
    }

    // MARK: - Posting and removing

    func post(_ request: PendingRequest) {
        let content = UNMutableNotificationContent()
        content.title = Self.title(for: request)
        content.body = Self.body(for: request)
        content.categoryIdentifier = Self.category(for: request)
        content.sound = .default
        let id = request.id
        let note = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        // After a relaunch every notified request is "new" to the feed: do not alert twice for a
        // banner that is still on screen.
        center.getDeliveredNotifications { delivered in
            let shown = delivered.contains { $0.request.identifier == id }
            guard !shown else { return }
            Task { @MainActor [weak self] in
                self?.center.add(note) { _ in }
            }
        }
    }

    func removeDelivered(_ ids: [String]) {
        guard !ids.isEmpty else { return }
        center.removeDeliveredNotifications(withIdentifiers: ids)
        center.removePendingNotificationRequests(withIdentifiers: ids)
    }

    /// Removes delivered banners whose request is no longer pending.
    func removeDelivered(notIn pending: Set<String>) {
        center.getDeliveredNotifications { delivered in
            let stale = delivered.map { $0.request.identifier }.filter { !pending.contains($0) }
            guard !stale.isEmpty else { return }
            Task { @MainActor [weak self] in
                self?.removeDelivered(stale)
            }
        }
    }

    func removeAllDelivered() {
        center.removeAllDeliveredNotifications()
        center.removeAllPendingNotificationRequests()
    }

    // MARK: - UNUserNotificationCenterDelegate

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler:
                                            @escaping (UNNotificationPresentationOptions) -> Void) {
        // Show the banner even while the popover (and so the app) is active.
        completionHandler([.banner, .list, .sound])
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let id = response.notification.request.identifier
        let action = response.actionIdentifier
        Task { @MainActor [weak self] in
            self?.handleResponse(id: id, action: action)
        }
        completionHandler()
    }

    private func handleResponse(id: String, action: String) {
        switch action {
        case UNNotificationDefaultActionIdentifier:
            onOpen?(id)
        case UNNotificationDismissActionIdentifier:
            break
        default:
            // Only the two buttons the categories define; anything else is ignored.
            guard let decision = Decision(actionID: action), decision == .approve || decision == .deny else { return }
            onAction?(id, decision)
        }
    }
}
