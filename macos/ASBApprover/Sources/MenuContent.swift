import AppKit
import SwiftUI
import ASBApproverKit

/// The menu bar icon, plus the pending count when there is any.
struct MenuBarLabel: View {
    let model: AppModel

    var body: some View {
        let count = model.requests.count
        HStack(spacing: 3) {
            Image("MenuBarIcon")
            if count > 0 {
                Text(verbatim: String(count))
            }
        }
        .accessibilityLabel(Text(verbatim: count > 0 ? "ASB Approver, \(count) pending" : "ASB Approver"))
    }
}

/// The menu bar window: sign-in, or the pending list.
struct MenuContent: View {
    let model: AppModel

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
        .onAppear {
            model.loginItem.refresh()
        }
    }

    private var header: some View {
        HStack {
            Text("ASB Approver")
                .font(.headline)
            Spacer()
            if model.state != .signedOut {
                Text(verbatim: model.requests.isEmpty ? "No pending requests" : "\(model.requests.count) pending")
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
                .frame(maxWidth: .infinity, minHeight: 80)
        } else {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(model.requests) { request in
                            RequestRow(request: request, model: model)
                                .id(request.id)
                            Divider()
                        }
                    }
                }
                .frame(minHeight: 120, maxHeight: 480)
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
