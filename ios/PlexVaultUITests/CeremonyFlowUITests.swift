import XCTest
import VaultKit

/// Walks the entire provisioning ceremony in the real app against the simulated
/// card.
///
/// This exists because every step-transition bug found so far had the same shape:
/// a step produced something the operator needed to read, and the next screen
/// replaced it in the same render pass. The reported symptom was an empty
/// mnemonic list; the same defect had silently swallowed the card inventory, the
/// entropy commitment, the derived address, the read-back comparison, the pairing
/// QR and the counter value. None of that is visible from unit tests, which is
/// why this test drives the actual screens.
///
/// Scrolling to a control is done with `tapWhenVisible`, from `UITestSupport`.
final class CeremonyFlowUITests: XCTestCase {

    /// All-zero entropy produces a known mnemonic, which lets the test complete
    /// the transcription back-fill.
    private static let zeroEntropyHex = String(repeating: "00", count: 32)
    private static let userPIN = "246810"
    private static let adminPIN = "87654321"

    private func launchForCeremony() -> XCUIApplication {
        let app = launchApp(
            deviceChoice: "simulated",
            arguments: ["-deterministic-entropy", Self.zeroEntropyHex]
        )
        // The app opens on its home screen; the ceremony screens are behind it.
        openProvisioningFlow(app)
        return app
    }

    private func button(_ label: String, in app: XCUIApplication) -> XCUIElement {
        app.buttons[label]
    }

    /// The regression test for the reported bug: after the entropy step, the
    /// mnemonic step must show 24 words.
    func testMnemonicStepShowsTwentyFourWords() throws {
        let app = launchForCeremony()
        advanceToMnemonicStep(app, userPIN: Self.userPIN, adminPIN: Self.adminPIN)

        // Nothing is shown until the operator asks for it.
        XCTAssertFalse(app.staticTexts["abandon"].exists, "words must not be on screen before revealing")

        tapWhenVisible(app.buttons["reveal-mnemonic"], in: app)

        // All 24 words must actually be rendered, not just the container.
        let expected = try BIP39.mnemonic(fromEntropy: [UInt8](repeating: 0, count: 32))
        XCTAssertEqual(expected.count, 24)
        XCTAssertEqual(expected.last, "art", "fixture assumption changed")

        for (index, word) in expected.enumerated() {
            let cell = app.staticTexts[word]
            XCTAssertTrue(
                cell.waitForExistence(timeout: 5),
                "word \(index + 1) (\(word)) is missing from the revealed list:\n\(app.debugDescription)"
            )
        }
        XCTAssertTrue(app.staticTexts["24."].exists || app.staticTexts["24"].exists, "numbering missing")

        // And the transcription gate still works.
        XCTAssertFalse(button("Confirm transcription", in: app).isEnabled)
    }

    /// Completing the back-fill must actually advance the ceremony, which is what
    /// proves the mnemonic the user sees is the one the ceremony derived.
    func testBackfillAdvancesToDerivation() throws {
        let app = launchForCeremony()
        advanceToMnemonicStep(app, userPIN: Self.userPIN, adminPIN: Self.adminPIN)
        try revealAndConfirmMnemonic(app, entropy: [UInt8](repeating: 0, count: 32))

        XCTAssertTrue(
            button("Derive keys", in: app).waitForExistence(timeout: 10),
            "the ceremony must advance to derivation:\n\(app.debugDescription)"
        )
    }

}
