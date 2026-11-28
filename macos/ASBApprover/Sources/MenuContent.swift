import AppKit
import SwiftUI
import ASBApproverKit

/// The popover's content (StatusBarController): sign-in, or the pending list.
struct MenuContent: View {
    let model: AppModel
    /// The measured height of the request rows; the list is this tall up to `listMaxHeight`.
    @State private var listHeight: CGFloat = 0
    static let listMaxHeight: CGFloat = 480

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            switch model.state {
            case .signedOut:
                SignInView(model: model)
                    .padding(12)
            case .ready, .unreachable:
                if model.state == .unreachable {
                    notice("Can't reach the broker. Retrying…", systemImage: "wifi.exclamationmark")
                }
                if model.notificationsDenied {
                    notice("Notifications are off for ASB Approver; turn them on in System Settings to get banners.",
                           systemImage: "bell.slash")
                }
                if let error = model.decideError {
                    notice(error, systemImage: "exclamationmark.triangle")
                }
                requestList
            }
            Divider()
            footer
        }
        .frame(width: 400)
        // The popover (sizingOptions .preferredContentSize) takes its size from this view's ideal size. Every part below has a
        // definite height, and fixedSize makes the window follow it (shrinking after sign-in or when
        // the list empties) instead of keeping an old, taller size with the content centered in it.
        .fixedSize(horizontal: false, vertical: true)
        .onAppear {
            model.loginItem.refresh()
            model.refreshNotificationAuthorization()
        }
    }

    private var header: some View {
        HStack {
            Text("ASB Approver")
                .font(.headline)
            Spacer()
            if model.state != .signedOut && !model.requests.isEmpty {
                Text(verbatim: "\(model.requests.count) pending")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private func notice(_ text: String, systemImage: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: systemImage)
            Text(verbatim: text)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.08))
    }

    @ViewBuilder
    private var requestList: some View {
        if model.requests.isEmpty {
            Text("Nothing is waiting for you.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 24)
        } else {
            ScrollViewReader { proxy in
                ScrollView {
                    // A plain VStack (the list is short) so its full height is known; the ScrollView
                    // is exactly that tall, up to listMaxHeight, and scrolls beyond it.
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(model.requests) { request in
                            RequestRow(request: request, model: model)
                                .id(request.id)
                            if request.id != model.requests.last?.id {
                                Divider()
                            }
                        }
                    }
                    .background(GeometryReader { geo in
                        Color.clear.preference(key: ListHeightKey.self, value: geo.size.height)
                    })
                }
                .frame(height: min(max(listHeight, 1), Self.listMaxHeight))
                .onPreferenceChange(ListHeightKey.self) { listHeight = $0 }
                .onAppear {
                    scroll(proxy, to: model.focusedRequestID)
                }
                .onChange(of: model.focusedRequestID) { _, id in
                    scroll(proxy, to: id)
                }
                .onDisappear {
                    model.focusedRequestID = nil
                }
            }
        }
    }

    private func scroll(_ proxy: ScrollViewProxy, to id: String?) {
        guard let id else { return }
        DispatchQueue.main.async {
            withAnimation {
                proxy.scrollTo(id, anchor: .top)
            }
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Toggle("Launch at login", isOn: Binding(
                    get: { model.loginItem.isEnabled },
                    set: { model.loginItem.set($0) }))
                    .toggleStyle(.checkbox)
                if model.loginItem.needsApproval {
                    Button("Allow in Settings…") {
                        model.loginItem.openSystemSettings()
                    }
                    .buttonStyle(.link)
                }
                Spacer()
                if model.state != .signedOut {
                    Button("Sign out") {
                        model.signOut()
                    }
                }
                Button("Quit") {
                    NSApplication.shared.terminate(nil)
                }
            }
            if let error = model.loginItem.lastError {
                Text(verbatim: error)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

/// Carries the request rows' measured height up to the list's frame.
private struct ListHeightKey: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}
