import SwiftUI

/// First run and "Sign in again": the broker's client URL, then the identity provider's sign-in
/// in an `ASWebAuthenticationSession` (authorization code + PKCE).
struct SignInView: View {
    @Bindable var model: AppModel

    /// Shown verbatim on the sign-in screen (docs/reference.md, "Approver app API", Security).
    static let warning =
        "Anything running as you on this Mac can use this app to approve requests. Don't run agents on a Mac where you approve."

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(model.needsSignInAgain ? "Sign in again" : "Sign in to your broker")
                .font(.title3.weight(.semibold))

            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.shield")
                    .foregroundStyle(.orange)
                Text(verbatim: Self.warning)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .font(.callout)
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 6).fill(Color.orange.opacity(0.12)))

            VStack(alignment: .leading, spacing: 4) {
                Text("Broker client URL")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextField("https://broker.example:8800", text: $model.brokerURLText)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .onSubmit {
                        model.beginSignIn()
                    }
            }

            if let error = model.signInError {
                Text(verbatim: error)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                if model.isSigningIn {
                    ProgressView()
                        .controlSize(.small)
                }
                Button(model.isSigningIn ? "Signing in…" : "Sign in") {
                    model.beginSignIn()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(model.isSigningIn
                          || model.brokerURLText.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }
}
