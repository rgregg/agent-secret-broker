import Foundation
import Observation
import ServiceManagement

/// "Start at login" through `SMAppService.mainApp` (macOS 13+). The system owns the state; this
/// reads it back after every change and when the popover opens.
@MainActor
@Observable
final class LoginItem {
    private(set) var isEnabled = false
    /// The user must allow it in System Settings > General > Login Items.
    private(set) var needsApproval = false
    private(set) var lastError: String?

    init() {
        refresh()
    }

    func refresh() {
        let status = SMAppService.mainApp.status
        isEnabled = status == .enabled
        needsApproval = status == .requiresApproval
    }

    func set(_ enabled: Bool) {
        lastError = nil
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            lastError = "Couldn't change the login item."
        }
        refresh()
    }

    func openSystemSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }
}
