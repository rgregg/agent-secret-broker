import XCTest
@testable import ASBApproverKit

final class ModelsTests: XCTestCase {
    /// Fixtures/pending.json is a real `/v1/approver/pending` body, dumped from the broker's
    /// `request_view` (an http low-risk notified request, a credential request, and an http
    /// request offering grants and Always).
    func testDecodesRecordedPending() throws {
        let page = try JSONDecoder.approverAPI().decode(PendingPage.self, from: Fixtures.data("pending"))
        XCTAssertEqual(page.version, 3)
        XCTAssertNil(page.retryAfter)
        XCTAssertEqual(page.requests.count, 3)

        let low = page.requests[0]
        XCTAssertEqual(low.id, "Kj1GZvGJdOU3JxoV_aTa2g")
        XCTAssertEqual(low.mode, "http")
        XCTAssertEqual(low.credentials, ["svc"])
        XCTAssertEqual(low.client, PendingRequest.Client(name: "shared key (legacy)", id: "legacy"))
        XCTAssertEqual(low.summary, "Lists the files in a bucket")
        XCTAssertNil(low.summarySource)
        XCTAssertEqual(low.risk?.level, "low")
        XCTAssertEqual(low.risk?.reasons, ["model rated it low"])
        XCTAssertEqual(low.target, "GET http://api.example.test/v1/files")
        XCTAssertTrue(low.notified)
        XCTAssertEqual(low.bannerActions, [.deny, .approve])
        XCTAssertEqual(low.actions, [.deny, .approve, .grant(minutes: 15), .grant(minutes: 60), .always])
        XCTAssertEqual(low.browserUrl, URL(string: "https://secrets.example/a/j4pdMDApbb-zmWQOJ4pfquJFfgqXbJ8b"))
        XCTAssertEqual(low.created, 1795719249.4102335, accuracy: 0.001)
        XCTAssertGreaterThan(low.expiresDate, low.createdDate)
        guard case .array(let headers)? = low.details?["headers"] else {
            return XCTFail("details.headers should be a list")
        }
        XCTAssertEqual(headers.first, .array([.string("Authorization"), .string("Bearer {{SVC_TOKEN}}")]))

        let cred = page.requests[1]
        XCTAssertEqual(cred.mode, "credential")
        XCTAssertEqual(cred.credentials, ["newapi"])
        XCTAssertNil(cred.summary)
        XCTAssertNil(cred.details)
        XCTAssertEqual(cred.risk?.level, "high")
        XCTAssertTrue(cred.notified)
        XCTAssertEqual(cred.bannerActions, [])
        XCTAssertEqual(cred.actions, [.deny])           // browser-only: deny plus browser_url
        XCTAssertNotNil(cred.browserUrl)

        let medium = page.requests[2]
        XCTAssertEqual(medium.risk?.level, "medium")
        XCTAssertTrue(medium.actions.contains(.always))
        XCTAssertTrue(medium.actions.contains(.grant(minutes: 60)))
    }

    func testDecisionParsesActionIDs() {
        XCTAssertEqual(Decision(actionID: "approve"), .approve)
        XCTAssertEqual(Decision(actionID: "deny"), .deny)
        XCTAssertEqual(Decision(actionID: "grant:15"), .grant(minutes: 15))
        XCTAssertEqual(Decision(actionID: "always"), .always)
        XCTAssertEqual(Decision(actionID: "always_script"), .alwaysScript)
        for bad in ["grant:", "grant:x", "grant:-5", "grant:0", "grant:1.5", "grant: 5", "Approve", "", "ssh_rule"] {
            XCTAssertNil(Decision(actionID: bad), bad)
        }
        for d: Decision in [.approve, .deny, .grant(minutes: 240), .always, .alwaysScript] {
            XCTAssertEqual(Decision(actionID: d.actionID), d)
        }
    }

    func testUnknownActionsAreSkippedNotFatal() throws {
        var row = Fixtures.row("r1", notified: false, actions: ["deny", "approve", "teleport", "grant:30"])
        row["summary"] = NSNull()
        row["risk"] = NSNull()
        let data = try JSONSerialization.data(withJSONObject: Fixtures.page(7, [row]))
        let page = try JSONDecoder.approverAPI().decode(PendingPage.self, from: data)
        let r = try XCTUnwrap(page.requests.first)
        XCTAssertEqual(r.actions, [.deny, .approve, .grant(minutes: 30)])
        XCTAssertFalse(r.notified)
        XCTAssertEqual(r.bannerActions, [])
        XCTAssertNil(r.risk)
        XCTAssertNil(r.summary)
        XCTAssertEqual(r.summarySource, "model")
    }

    func testConfigDecodes() throws {
        let json = #"{"issuer": "https://idp.example.test/application/o/asb-approver/", "client_id": "abc", "scopes": ["openid", "profile", "offline_access"], "api_version": 1}"#
        let cfg = try JSONDecoder.approverAPI().decode(ApproverConfig.self, from: Data(json.utf8))
        XCTAssertEqual(cfg, ApproverConfig(issuer: URL(string: "https://idp.example.test/application/o/asb-approver/")!,
                                           clientId: "abc", scopes: ["openid", "profile", "offline_access"],
                                           apiVersion: 1))
    }
}
