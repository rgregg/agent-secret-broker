import XCTest
@testable import ASBApproverKit

final class PKCETests: XCTestCase {
    /// RFC 7636 Appendix B.
    func testPKCEChallengeIsS256OfVerifier() {
        let p = PKCE(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        XCTAssertEqual(p.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        XCTAssertEqual(p.method, "S256")
    }

    func testMakeIsValidAndRandom() {
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        let a = PKCE.make()
        let b = PKCE.make()
        XCTAssertNotEqual(a.verifier, b.verifier)
        for p in [a, b] {
            XCTAssertTrue((43...128).contains(p.verifier.count), "\(p.verifier.count)")
            XCTAssertTrue(p.verifier.allSatisfy { allowed.contains($0) })
            XCTAssertEqual(p.challenge, PKCE(verifier: p.verifier).challenge)
            XCTAssertEqual(p.challenge.count, 43)       // 32-byte digest, unpadded base64url
            XCTAssertFalse(p.challenge.contains("="))
        }
    }

    func testRandomURLSafe() {
        let s = PKCE.randomURLSafe(bytes: 16)
        XCTAssertEqual(s.count, 22)
        XCTAssertFalse(s.contains { "+/=".contains($0) })
    }
}
