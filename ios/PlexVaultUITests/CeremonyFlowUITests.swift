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
final class CeremonyFlowUITests: XCTestCase {

    /// All-zero entropy produces a known mnemonic, which lets the test complete
    /// the transcription back-fill.
    private static let zeroEntropyHex = String(repeating: "00", count: 32)
    private static let userPIN = "246810"
    private static let adminPIN = "87654321"

    private func launchApp() -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-deterministic-entropy", Self.zeroEntropyHex]
        app.launch()
        XCTAssertTrue(app.buttons["begin-ceremony"].waitForExistence(timeout: 15), app.debugDescription)
        return app
    }

    private func tap(_ element: XCUIElement, in app: XCUIApplication,
                     file: StaticString = #filePath, line: UInt = #line) {
        var attempts = 0
        while attempts < 12 {
            let frame = element.frame
            let visible = app.windows.firstMatch.frame.insetBy(dx: 0, dy: 140)
            if visible.contains(CGPoint(x: frame.midX, y: frame.midY)) { break }
            if frame.midY > visible.midY { app.swipeUp() } else { app.swipeDown() }
            attempts += 1
        }
        XCTAssertTrue(element.waitForExistence(timeout: 5), "\\(element) never appeared", file: file, line: line)
        element.tap()
    }

    private func button(_ label: String, in app: XCUIApplication) -> XCUIElement {
        app.buttons[label]
    }

    /// Types into the n-th secure field on screen. The PIN fields are `SecureField`s
    /// rendered in order, and are never revealed.
    private func typeSecret(_ text: String, into title: String, in app: XCUIApplication,
                            file: StaticString = #filePath, line: UInt = #line) {
        let field = app.secureTextFields["secret-\(title)"]
        XCTAssertTrue(field.waitForExistence(timeout: 5), "secret field '\(title)' missing", file: file, line: line)

        // The keyboard is dismissed after every field, so the layout is stable and
        // each field keeps its position — the earlier flakiness came from focus
        // being lost while the keyboard animated over the target.
        field.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
        Thread.sleep(forTimeInterval: 0.3)   // let focus and the keyboard animation settle
        field.typeText(text)

        // Dismiss the keyboard so the next field is not covered by it. This also
        // exercises the app's own Done button, which the numeric PIN pads need.
        let done = app.buttons["dismiss-keyboard"]
        if done.exists { done.tap() }
        Thread.sleep(forTimeInterval: 0.2)
    }

    private func acknowledgePosture(in app: XCUIApplication) {
        for index in 0..<app.switches.count {
            let toggle = app.switches.element(boundBy: index)
            if (toggle.value as? String) == "0" { toggle.tap() }
        }
    }

    /// The regression test for the reported bug: after the entropy step, the
    /// mnemonic step must show 24 words.
    func testMnemonicStepShowsTwentyFourWords() throws {
        let app = launchApp()
        advanceToMnemonicStep(app)

        // Nothing is shown until the operator asks for it.
        XCTAssertFalse(app.staticTexts["abandon"].exists, "words must not be on screen before revealing")

        tap(app.buttons["reveal-mnemonic"], in: app)

        // All 24 words must actually be rendered, not just the container.
        let expected = try BIP39.mnemonic(fromEntropy: [UInt8](repeating: 0, count: 32))
        XCTAssertEqual(expected.count, 24)
        XCTAssertEqual(expected.last, "art", "fixture assumption changed")

        for (index, word) in expected.enumerated() {
            let cell = app.staticTexts[word]
            XCTAssertTrue(
                cell.waitForExistence(timeout: 5),
                "word \\(index + 1) (\\(word)) is missing from the revealed list:\n\\(app.debugDescription)"
            )
        }
        XCTAssertTrue(app.staticTexts["24."].exists || app.staticTexts["24"].exists, "numbering missing")

        // And the transcription gate still works.
        XCTAssertFalse(button("Confirm transcription", in: app).isEnabled)
    }

    /// Completing the back-fill must actually advance the ceremony, which is what
    /// proves the mnemonic the user sees is the one the ceremony derived.
    func testBackfillAdvancesToDerivation() throws {
        let app = launchApp()
        advanceToMnemonicStep(app)
        tap(app.buttons["reveal-mnemonic"], in: app)

        let challenge = try BIP39.mnemonic(fromEntropy: [UInt8](repeating: 0, count: 32))
        let digest = SHA256.hash(challenge.joined(separator: " "))
        var indices: [Int] = []
        var cursor = 0
        while indices.count < 3 && cursor < digest.count {
            let candidate = Int(digest[cursor]) % challenge.count
            if !indices.contains(candidate) { indices.append(candidate) }
            cursor += 1
        }

        for (position, index) in indices.sorted().enumerated() {
            let field = app.textFields.element(boundBy: position)
            XCTAssertTrue(field.waitForExistence(timeout: 5), "back-fill field \\(position) missing")
            tap(field, in: app)
            field.typeText(challenge[index])
        }

        let confirm = button("Confirm transcription", in: app)
        XCTAssertTrue(confirm.isEnabled, "a correct back-fill must enable confirmation")
        tap(confirm, in: app)

        XCTAssertTrue(
            button("Derive key", in: app).waitForExistence(timeout: 10),
            "the ceremony must advance to derivation:\n\\(app.debugDescription)"
        )
    }

    /// Drives setup, inventory, reset, PINs, policy and entropy so the caller lands
    /// on the mnemonic step.
    private func advanceToMnemonicStep(_ app: XCUIApplication,
                                       file: StaticString = #filePath, line: UInt = #line) {
        tap(app.buttons["choice-Simulated (debug)"], in: app)
        acknowledgePosture(in: app)
        tap(app.buttons["begin-ceremony"], in: app)

        // Card inventory: read, look at it, then continue.
        let read = button("Read YubiKey", in: app)
        XCTAssertTrue(read.waitForExistence(timeout: 10), "inventory step missing:\n\(app.debugDescription)")
        tap(read, in: app)
        XCTAssertTrue(app.staticTexts["Factory fresh"].waitForExistence(timeout: 10),
                      "inventory output must stay on screen:\n\(app.debugDescription)")
        tap(button("Continue", in: app), in: app)

        // Reset with the factory default Admin PIN.
        typeSecret("12345678", into: "Admin PIN (PW3)", in: app)
        tap(button("Reset applet", in: app), in: app)
        let confirmReset = app.buttons["Reset and erase"]
        XCTAssertTrue(confirmReset.waitForExistence(timeout: 5), "reset confirmation missing")
        confirmReset.tap()

        // PINs: user, repeat, admin, repeat.
        XCTAssertTrue(app.staticTexts["User PIN (PW1) — at least 6 digits"].waitForExistence(timeout: 10),
                      "PIN step missing:\n\(app.debugDescription)")
        typeSecret(Self.userPIN, into: "User PIN", in: app)
        typeSecret(Self.userPIN, into: "Repeat User PIN", in: app)
        typeSecret(Self.adminPIN, into: "Admin PIN", in: app)
        typeSecret(Self.adminPIN, into: "Repeat Admin PIN", in: app)
        tap(button("Set PINs", in: app), in: app)

        // Policy.
        let applyPolicy = button("Apply policy", in: app)
        XCTAssertTrue(applyPolicy.waitForExistence(timeout: 10), "policy step missing")
        tap(applyPolicy, in: app)

        // Entropy: generate, record the commitment, then continue.
        let generate = button("Generate entropy", in: app)
        XCTAssertTrue(generate.waitForExistence(timeout: 10), "entropy step missing")
        tap(generate, in: app)

        let commitment = app.staticTexts["Entropy commitment (first 8 hex of SHA-256)"]
        XCTAssertTrue(commitment.waitForExistence(timeout: 10),
                      "the commitment must stay on screen after generating:\n\(app.debugDescription)")

        let recorded = app.switches["I have written down the entropy commitment"]
        XCTAssertTrue(recorded.waitForExistence(timeout: 5))
        tap(recorded, in: app)

        let reveal = button("Reveal the mnemonic", in: app)
        XCTAssertTrue(reveal.waitForExistence(timeout: 5), "cannot proceed to the mnemonic")
        tap(reveal, in: app)

        XCTAssertTrue(app.buttons["reveal-mnemonic"].waitForExistence(timeout: 10),
                      "mnemonic step missing:\n\(app.debugDescription)")
    }
}
