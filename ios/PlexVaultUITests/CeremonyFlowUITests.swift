import XCTest
import VaultKit

/// Walks the entire provisioning ceremony in the real app against the simulated
/// card.
///
/// This exists because every step-transition bug found so far had the same shape:
/// a step produced something the operator needed to read, and the next screen
/// replaced it in the same render pass. The reported symptom was an empty
/// mnemonic list; the same defect had silently swallowed the card inventory, the
/// entropy commitment, the derived address, the read-back comparison and the pairing
/// QR. None of that is visible from unit tests, which is
/// why this test drives the actual screens.
///
/// Scrolling to a control is done with `tapWhenVisible`, from `UITestSupport`.
final class CeremonyFlowUITests: XCTestCase {

    /// All-zero entropy produces a known mnemonic, which lets the test complete
    /// the transcription back-fill.
    private static let zeroEntropyHex = String(repeating: "00", count: 32)
    private static let userPIN = "246810"
    private static let adminPIN = "87654321"

    private func launchForCeremony(cards: Int = 1) -> XCUIApplication {
        var arguments = ["-deterministic-entropy", Self.zeroEntropyHex]
        if cards > 1 { arguments += ["-simulated-cards", "\(cards)"] }
        let app = launchApp(deviceChoice: "simulated", arguments: arguments)
        // The app opens on its home screen; the ceremony screens are behind it.
        openProvisioningFlow(app)
        return app
    }

    private func button(_ label: String, in app: XCUIApplication) -> XCUIElement {
        app.buttons[label]
    }

    /// Two YubiKeys in one run: each is read, reset, given its own PINs and written, and the
    /// record names both.
    ///
    /// This is the regression test for the defect a hardware run found with the card count at 2:
    /// the second card was reset, its write screen showed the **first** card's read-back and a
    /// Continue button, and tapping it carried the ceremony on without writing anything — so the
    /// run reported two cards and only one of them held the keys (amendment 41). The assertion is
    /// behavioural: the second card's write step must ask to be written.
    func testASecondYubiKeyIsWrittenInTheSameRun() throws {
        let app = launchForCeremony(cards: 2)
        advanceToMnemonicStep(app, userPIN: Self.userPIN, adminPIN: Self.adminPIN)
        try revealAndConfirmMnemonic(app, entropy: [UInt8](repeating: 0, count: 32))

        tapStepAction("Derive keys", in: app)
        tapStepAction("Continue", in: app)

        // Two YubiKeys, chosen after the keys exist and before the first card is touched.
        let count = app.steppers["card-count"]
        XCTAssertTrue(count.waitForExistence(timeout: 10),
                      "the card-count step is missing:\n\(app.debugDescription)")
        count.buttons.element(boundBy: 1).tap()
        tapStepAction("Continue", in: app)

        // Card 1. `provisionTheCard` asserts the write action by name, so a write step that had
        // already been closed by the previous card's results fails here rather than passing.
        provisionTheCard(app, userPIN: Self.userPIN, adminPIN: Self.adminPIN)
        XCTAssertTrue(app.buttons["Read YubiKey"].waitForExistence(timeout: 15),
                      "the second card's inventory is due:\n\(app.debugDescription)")
        provisionTheCard(app, userPIN: Self.userPIN, adminPIN: Self.adminPIN)

        // The wipe ends the provisioning process and produces its record, which names both cards.
        // Pairing is a separate process with its own record (amendment 43), so this test stops at
        // the record the run that wrote the cards produced.
        wipeSecrets(app, exit: false)

        XCTAssertTrue(app.staticTexts["YubiKey 1 of 2 serial"].waitForExistence(timeout: 10),
                      "the record must name the first card:\n\(app.debugDescription)")
        XCTAssertTrue(app.staticTexts["YubiKey 2 of 2 serial"].exists)
    }

    /// The wipe closes the app, and the next launch goes straight to pairing it (amendment 43).
    ///
    /// This is the behaviour an operator asked for: wipe the secrets, let the app end, reopen it
    /// later and carry on with the wallet. The second process writes nothing and holds no secret —
    /// it reads the pairing codes back out of the card's stored manifest — so it is not gated on the
    /// setup screen the provisioning process has to pass.
    func testTheWipeClosesTheAppAndTheNextLaunchResumesPairing() throws {
        // No `-reset-pending-pairing`: the value the wipe stores is the subject of the test, and the
        // second launch has to read it back.
        let app = launchApp(
            deviceChoice: "simulated",
            arguments: ["-deterministic-entropy", Self.zeroEntropyHex],
            resetPendingPairing: false
        )
        openProvisioningFlow(app)
        advanceToMnemonicStep(app, userPIN: Self.userPIN, adminPIN: Self.adminPIN)
        try revealAndConfirmMnemonic(app, entropy: [UInt8](repeating: 0, count: 32))
        tapStepAction("Derive keys", in: app)
        tapStepAction("Continue", in: app)
        tapStepAction("Continue", in: app)   // one YubiKey
        provisionTheCard(app, userPIN: Self.userPIN, adminPIN: Self.adminPIN)

        // The wipe produces the record; the record screen's own "Quit & Reopen App", behind its
        // confirmation, is what actually ends this process.
        wipeSecrets(app, exit: true)

        // Reopening it lands in the pairing process, not on the home screen and not on the setup
        // screen.
        app.launch()
        XCTAssertTrue(
            app.staticTexts["Pairing is still pending"].waitForExistence(timeout: 20),
            "the app must open on the pairing process:\n\(app.debugDescription)"
        )
        XCTAssertFalse(app.buttons["Sign a transaction"].exists, "the home screen must not be the first screen")
        XCTAssertFalse(app.buttons["begin-ceremony"].exists, "this process generates nothing, so it has no posture gate")

        // And it is the read-only route: the card is read, the manifest is checked, and there is no
        // reset step anywhere near it.
        tapStepAction("Read YubiKey", in: app)
        tapStepAction("Continue", in: app)
        XCTAssertTrue(app.buttons["Read pairing manifest"].waitForExistence(timeout: 10),
                      "the pairing process reads the manifest:\n\(app.debugDescription)")
        XCTAssertFalse(app.buttons["Reset applet"].exists, "pairing must never offer the reset")
        XCTAssertFalse(app.buttons["Wipe secrets"].exists, "there is nothing to wipe in this process")
    }

    /// The address the deterministic (all-zero entropy) mnemonic derives, computed by the same
    /// library the app uses, so the test asserts the wiring rather than re-deriving the crypto.
    private static let expectedEVMAddress = "0x1CDE9225FfE472d7426a0e18A3407635F9fA8FDb"

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
