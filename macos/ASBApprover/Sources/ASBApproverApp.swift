import AppKit
import Observation
import SwiftUI

@main
struct ASBApproverApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    // The UI is an AppKit status item with a popover (StatusBarController), not a MenuBarExtra:
    // SwiftUI has no public way to open a MenuBarExtra window from code, and a banner click must.
    // A scene is still required; an empty Settings scene shows nothing.
    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}

/// Sets the notification delegate before launch finishes (a banner action can launch the app),
/// then builds the status item and starts the model.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        AppModel.shared.notifications.configure()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        StatusBarController.shared.install(model: AppModel.shared)
        AppModel.shared.launch()
    }
}

/// The menu bar icon (with the pending count) and the popover that holds MenuContent.
@MainActor
final class StatusBarController: NSObject, NSPopoverDelegate {
    static let shared = StatusBarController()

    private var statusItem: NSStatusItem?
    private let popover = NSPopover()
    private var model: AppModel?

    func install(model: AppModel) {
        guard statusItem == nil else { return }
        self.model = model
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            let image = NSImage(named: "MenuBarIcon")
            image?.isTemplate = true
            button.image = image
            button.imagePosition = .imageLeading
            button.target = self
            button.action = #selector(toggle(_:))
        }
        statusItem = item
        popover.behavior = .transient
        popover.animates = true
        popover.delegate = self
        observeCount()
    }

    /// Opens the popover (a banner was clicked). Does nothing if it is already open.
    func open() {
        guard let button = statusItem?.button, !popover.isShown, let model else { return }
        // A fresh hosting controller each time, so MenuContent's onAppear runs on every open.
        let host = NSHostingController(rootView: MenuContent(model: model))
        host.sizingOptions = [.preferredContentSize]
        popover.contentViewController = host
        NSApplication.shared.activate()
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        popover.contentViewController?.view.window?.makeKey()
    }

    func close() {
        popover.performClose(nil)
    }

    @objc private func toggle(_ sender: Any?) {
        if popover.isShown {
            close()
        } else {
            open()
        }
    }

    nonisolated func popoverDidClose(_ notification: Notification) {
        Task { @MainActor in
            // Drop the content so its onDisappear runs and nothing keeps polling the view.
            self.popover.contentViewController = nil
        }
    }

    /// Keeps the pending count beside the icon, re-arming the observation after each change.
    private func observeCount() {
        guard let model else { return }
        let count = withObservationTracking {
            model.requests.count
        } onChange: {
            Task { @MainActor [weak self] in
                self?.observeCount()
            }
        }
        guard let button = statusItem?.button else { return }
        button.title = count > 0 ? " \(count)" : ""
        button.setAccessibilityLabel(count > 0 ? "ASB Approver, \(count) pending" : "ASB Approver")
    }
}
