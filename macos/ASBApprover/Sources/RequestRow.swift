import SwiftUI
import ASBApproverKit

/// One pending request. Collapsed: credential names, client, risk badge and summary. Expanded:
/// also the target, the risk reasons and the masked details.
///
/// Every string that comes from the request is attacker-influenced and is shown with
/// `Text(verbatim:)` only: never Markdown, attributed or HTML text.
struct RequestRow: View {
    let request: PendingRequest
    let model: AppModel

    /// The "Always" variant waiting for confirmation, if any.
    @State private var pendingAlways: Decision?

    private var expanded: Bool { model.expandedIDs.contains(request.id) }
    private var busy: Bool { model.busyIDs.contains(request.id) }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                model.toggleExpanded(request.id)
            } label: {
                summaryBlock
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                expandedBlock
            }

            actionBar
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(model.focusedRequestID == request.id ? Color.accentColor.opacity(0.08) : Color.clear)
        .confirmationDialog(Text("Always approve?"),
                            isPresented: Binding(get: { pendingAlways != nil },
                                                 set: { if !$0 { pendingAlways = nil } }),
                            titleVisibility: .visible,
                            presenting: pendingAlways) { decision in
            Button("Always approve") {
                model.decide(request, decision)
                pendingAlways = nil
            }
            Button("Cancel", role: .cancel) {
                pendingAlways = nil
            }
        } message: { decision in
            Text(verbatim: Self.alwaysMessage(request, decision))
        }
    }

    // MARK: - Pieces

    private var summaryBlock: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: expanded ? "chevron.down" : "chevron.right")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 10)
                .padding(.top, 3)
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline) {
                    Text(verbatim: Self.credentialLine(request))
                        .font(.headline)
                        .lineLimit(expanded ? nil : 1)
                    Spacer(minLength: 4)
                    RiskBadge(level: request.risk?.level)
                }
                HStack(spacing: 4) {
                    Text(verbatim: "from " + Self.clientName(request))
                    Text(verbatim: "·")
                    Text(request.createdDate, style: .relative)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                if !request.notified {
                    Text("Assessing…")
                        .font(.caption)
                        .italic()
                        .foregroundStyle(.secondary)
                }
                if let summary = request.summary, !summary.isEmpty {
                    Text(verbatim: summary)
                        .font(.callout)
                        .lineLimit(expanded ? nil : 2)
                        .fixedSize(horizontal: false, vertical: true)
                    if request.summarySource == "model" {
                        Text("Summary written by a model; not verified.")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var expandedBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let target = request.target, !target.isEmpty {
                Text(verbatim: target)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let reasons = request.risk?.reasons, !reasons.isEmpty {
                Text(verbatim: "Why: " + reasons.joined(separator: "; "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let details = request.details, details != .null {
                Text(verbatim: DetailsText.render(details))
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
            }
            Text(verbatim: "Mode: \(request.mode)")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.leading, 18)
    }

    /// Buttons for exactly the request's `actions`, plus "Open in browser".
    private var actionBar: some View {
        let actions = request.actions
        let grants = Self.grantMinutes(actions)
        return HStack(spacing: 6) {
            if actions.contains(.deny) {
                Button("Deny", role: .destructive) {
                    model.decide(request, .deny)
                }
            }
            if actions.contains(.approve) {
                Button("Approve") {
                    model.decide(request, .approve)
                }
            }
            if !grants.isEmpty {
                Menu("For…") {
                    ForEach(grants, id: \.self) { minutes in
                        Button(Self.durationLabel(minutes)) {
                            model.decide(request, .grant(minutes: minutes))
                        }
                    }
                }
                .fixedSize()
            }
            if actions.contains(.always) {
                Button("Always…") {
                    pendingAlways = .always
                }
            }
            if actions.contains(.alwaysScript) {
                Button("Always (script)…") {
                    pendingAlways = .alwaysScript
                }
            }
            Spacer(minLength: 0)
            if request.browserUrl != nil {
                Button("Open in browser") {
                    model.openInBrowser(request)
                }
                .buttonStyle(.link)
            }
        }
        .controlSize(.small)
        .disabled(busy)
        .padding(.leading, 18)
    }

    // MARK: - Text

    static func credentialLine(_ r: PendingRequest) -> String {
        r.credentials.isEmpty ? r.mode : r.credentials.joined(separator: ", ")
    }

    static func clientName(_ r: PendingRequest) -> String {
        r.client.name ?? r.client.id ?? "an unknown client"
    }

    static func grantMinutes(_ actions: [Decision]) -> [Int] {
        actions.compactMap { d -> Int? in
            if case .grant(let minutes) = d {
                return minutes
            }
            return nil
        }
    }

    static func durationLabel(_ minutes: Int) -> String {
        if minutes % 1440 == 0 {
            let days = minutes / 1440
            return days == 1 ? "1 day" : "\(days) days"
        }
        if minutes % 60 == 0 {
            let hours = minutes / 60
            return hours == 1 ? "1 hour" : "\(hours) hours"
        }
        return minutes == 1 ? "1 minute" : "\(minutes) minutes"
    }

    static func alwaysMessage(_ r: PendingRequest, _ d: Decision) -> String {
        let what = credentialLine(r)
        let who = clientName(r)
        if d == .alwaysScript {
            return "Approve \(what) for \(who) now, and every later request from this script, without asking?"
        }
        return "Approve \(what) for \(who) now, and every later matching request, without asking?"
    }
}

/// The risk level as a small colored badge.
struct RiskBadge: View {
    let level: String?

    var body: some View {
        if let level, !level.isEmpty {
            Text(verbatim: level.uppercased())
                .font(.caption2.weight(.semibold))
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .foregroundStyle(.white)
                .background(Capsule().fill(color(level)))
        }
    }

    private func color(_ level: String) -> Color {
        switch level.lowercased() {
        case "low": return .green
        case "medium": return .orange
        case "high", "critical": return .red
        default: return .gray
        }
    }
}

/// The masked `details` object as indented plain text.
enum DetailsText {
    static let maxLength = 4000

    static func render(_ value: JSONValue) -> String {
        var out = ""
        write(value, indent: 0, into: &out)
        if out.count > maxLength {
            out = String(out.prefix(maxLength)) + "\n…"
        }
        return out
    }

    private static func write(_ value: JSONValue, indent: Int, into out: inout String) {
        let pad = String(repeating: "  ", count: indent)
        switch value {
        case .object(let o):
            for key in o.keys.sorted() {
                guard let v = o[key] else { continue }
                if isScalar(v) {
                    out += pad + key + ": " + scalar(v) + "\n"
                } else {
                    out += pad + key + ":\n"
                    write(v, indent: indent + 1, into: &out)
                }
            }
        case .array(let a):
            for v in a {
                if isScalar(v) {
                    out += pad + "- " + scalar(v) + "\n"
                } else if case .array(let inner) = v, inner.allSatisfy(isScalar) {
                    out += pad + "- " + inner.map(scalar).joined(separator: ": ") + "\n"   // header pairs
                } else {
                    out += pad + "-\n"
                    write(v, indent: indent + 1, into: &out)
                }
            }
        default:
            out += pad + scalar(value) + "\n"
        }
    }

    private static func isScalar(_ v: JSONValue) -> Bool {
        switch v {
        case .object, .array: return false
        default: return true
        }
    }

    private static func scalar(_ v: JSONValue) -> String {
        switch v {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .number(let n):
            if n.rounded() == n, abs(n) < 1e15 {
                return String(Int64(n))
            }
            return String(n)
        case .string(let s): return s
        case .object, .array: return ""
        }
    }
}
