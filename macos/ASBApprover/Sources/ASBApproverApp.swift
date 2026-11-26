import AppKit
import SwiftUI

@main
struct ASBApproverApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        MenuBarExtra {
            MenuContent(model: AppModel.shared)
        } label: {
            MenuBarLabel(model: AppModel.shared)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Sets the notification delegate before launch finishes (a banner action can launch the app),
/// then starts the model.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        AppModel.shared.notifications.configure()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppModel.shared.launch()
    }
}

/// Opens the menu bar window, as if the user clicked the status item. SwiftUI has no public API
/// for this, so it clicks the status item's button (found by walking the status bar window's
/// views; no private keys are read). If that fails, nothing happens.
@MainActor
enum StatusItemOpener {
    static func open() {
        NSApplication.shared.activate()
        let windows = NSApplication.shared.windows
        if windows.contains(where: { $0.isVisible && className(of: $0).contains("MenuBarExtraWindow") }) {
            return      // already open
        }
        for window in windows where className(of: window).contains("StatusBarWindow") {
            if let button = findButton(in: window.contentView) {
                button.performClick(nil)
                return
            }
        }
    }

    private static func className(of window: NSWindow) -> String {
        String(describing: type(of: window))
    }

    private static func findButton(in view: NSView?) -> NSButton? {
        guard let view else { return nil }
        if let button = view as? NSButton {
            return button
        }
        for sub in view.subviews {
            if let button = findButton(in: sub) {
                return button
            }
        }
        return nil
    }
}
