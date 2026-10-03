import XCTest
import VaultKit

/// Shared helpers for driving the real app in a simulator.
///
/// Scrolling was the flakiest thing in this suite, and the reason is worth
/// recording: the original helper used `swipeUp()`/`swipeDown()`, which flick with
/// momentum. A flick overshoots the target, the correction flicks back past it,
/// and the loop oscillates — so whether the row ended up inside the tappable band
/// came down to luck. A slow press-and-drag has no momentum and settles.
///
/// The band exists because `isHittable` is not sufficient: an element underneath
/// the pinned bottom bar still reports `isHittable` while the tap is intercepted by
/// the bar. That is not hypothetical — it is how the posture toggles came to be
/// silently left unticked, with the primary action then disabled.
extension XCTestCase {

    /// The area in which a tap is reliable: below the navigation bar and above the
    /// pinned primary action.
    ///
    /// Measured from the real chrome rather than a fixed inset, because both edges
    /// move with the device and with Dynamic Type.
    func visibleBand(in app: XCUIApplication) -> CGRect {
        let window = app.windows.firstMatch.frame
        // `.frame` on a query with no matches records a failure, so existence is
        // checked first: the ceremony's running phase has a navigation bar but no
        // pinned `begin-ceremony`.
        let navBar = app.navigationBars.firstMatch
        let top = (navBar.exists ? navBar.frame.maxY : window.minY) + 8
        let primaryAction = app.buttons["begin-ceremony"]
        // With no pinned action on screen (the running phase puts each step's
        // action inside the scroll view) fall back to clearing the toolbar and the
        // privacy footer.
        let bottom = (primaryAction.exists ? primaryAction.frame.minY : window.maxY - 140) - 12
        return CGRect(x: window.minX, y: top, width: window.width,
                      height: max(1, bottom - top))
    }

    /// Scrolls by a bounded amount; positive `delta` reveals content further down.
    /// The ceremony's PIN fields use `.numberPad`, which has no return key, so the
    /// only way to close the keyboard is the toolbar's Done button. A step whose
    /// action sits at the bottom of a tall page is behind the keyboard until then —
    /// the retry-limit step is the first one whose action is that low.
    func dismissKeyboard(in app: XCUIApplication) {
        let done = app.buttons["dismiss-keyboard"]
        if done.exists { done.tap() }
    }

    func scroll(_ app: XCUIApplication, by delta: CGFloat) {
        let clamped = max(-200, min(200, delta))
        guard abs(clamped) >= 1 else { return }
        // x=0.02 keeps the touch in the scroll view's side padding, clear of the
        // rows, so press-and-drag cannot be picked up by a button or a toggle.
        let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.02, dy: 0.5))
        start.press(forDuration: 0.25, thenDragTo: start.withOffset(CGVector(dx: 0, dy: -clamped)))
    }

    /// Brings `element` into the tappable band, then taps it.
    func tapWhenVisible(_ element: XCUIElement, in app: XCUIApplication,
                        file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(element.waitForExistence(timeout: 10), "\(element) never appeared",
                      file: file, line: line)

        var midY = element.frame.midY
        var landed = false
        for _ in 0..<12 {
            let band = visibleBand(in: app)
            let frame = element.frame
            midY = frame.midY
            if band.contains(CGPoint(x: frame.midX, y: midY)) { landed = true; break }
            scroll(app, by: midY - band.midY)
        }
        // Asserted on the value measured inside the loop: re-reading the frame
        // afterwards races with a scroll that is still settling.
        XCTAssertTrue(
            landed,
            "\(element) could not be brought into the visible area (midY=\(midY))",
            file: file, line: line
        )
        element.tap()
    }

    /// Taps the pinned primary action, which must be reachable without scrolling.
    func tapPinnedPrimaryAction(_ app: XCUIApplication,
                                file: StaticString = #filePath, line: UInt = #line) {
        let begin = app.buttons["begin-ceremony"]
        XCTAssertTrue(begin.waitForExistence(timeout: 15),
                      "the primary action never appeared", file: file, line: line)
        XCTAssertTrue(begin.isHittable,
                      "the primary action must be hittable without scrolling",
                      file: file, line: line)
        begin.tap()
    }

    /// Ticks both posture acknowledgements, scrolling each into view first.
    ///
    /// Addressed by label rather than by index: `app.switches` also matches the
    /// decorative knob inside each SwiftUI `Toggle`, so an index-based loop visits
    /// four elements instead of two.
    func acknowledgePosture(in app: XCUIApplication,
                            file: StaticString = #filePath, line: UInt = #line) {
        for label in ["This iPhone is factory-reset, has no SIM, and is in airplane mode",
                      "No cameras or other people can see this screen"] {
            let toggle = app.switches[label]
            XCTAssertTrue(toggle.waitForExistence(timeout: 5),
                          "posture toggle missing: \(label)", file: file, line: line)
            if (toggle.value as? String) == "0" {
                tapWhenVisible(toggle, in: app, file: file, line: line)
            }
        }
    }
}

// MARK: - Typing secrets

extension XCTestCase {
    /// Types into the n-th secure field on screen. The PIN fields are `SecureField`s
    /// rendered in order, and are never revealed.
    func typeSecret(_ text: String, into title: String, in app: XCUIApplication,
                            file: StaticString = #filePath, line: UInt = #line) {
        let field = app.secureTextFields["secret-\(title)"]
        XCTAssertTrue(field.waitForExistence(timeout: 5), "secret field '\(title)' missing", file: file, line: line)

        // The keyboard is dismissed after every field, so the layout is stable and
        // each field keeps its position — the earlier flakiness came from focus
        // being lost while the keyboard animated over the target.
        tapWhenVisible(field, in: app, file: file, line: line)
        Thread.sleep(forTimeInterval: 0.3)   // let focus and the keyboard animation settle
        field.typeText(text)

        // Dismiss the keyboard so the next field is not covered by it. This also
        // exercises the app's own Done button, which the numeric PIN pads need.
        let done = app.buttons["dismiss-keyboard"]
        if done.exists { done.tap() }
        Thread.sleep(forTimeInterval: 0.2)
    }
}

extension XCTestCase {
    /// Opens the provisioning flow from the app's home screen.
    ///
    /// The app has two routes — provisioning and signing — so the ceremony screens
    /// are no longer what `launch()` lands on. Tolerant of being called when the
    /// flow is already open, so a test can call it without knowing how it got there.
    func openProvisioningFlow(
        _ app: XCUIApplication,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let route = app.buttons["route-provisioning"]
        if route.waitForExistence(timeout: 10) {
            tapWhenVisible(route, in: app, file: file, line: line)
        }
        XCTAssertTrue(
            app.buttons["choice-NFC"].waitForExistence(timeout: 15),
            "the provisioning setup screen did not appear:\n\(app.debugDescription)",
            file: file, line: line
        )
    }

    /// Taps a ceremony step's primary action by its label, scrolling it into view
    /// first.
    ///
    /// This is not `tapWhenVisible`, and the difference is measured rather than
    /// stylistic. A step action is the last element of the step's content, and the
    /// tall steps (derivation, import, read-back) put it below the fold. Scrolled
    /// to the end, it settles ~5pt below the band `visibleBand(in:)` reserves for
    /// the privacy footer — the band would refuse to tap a button that is on
    /// screen and unobstructed. `isHittable` asks the question that matters here
    /// (is anything in the way?), and unlike the posture toggles, nothing overlays
    /// a step action.
    func tapStepAction(
        _ title: String,
        in app: XCUIApplication,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        tapScrolling(app.buttons[title], named: "step action '\(title)'", in: app, file: file, line: line)
    }

    /// Taps an element that may sit below the fold, scrolling until it is hittable.
    ///
    /// The band-based `tapWhenVisible` is the right helper for controls near the top
    /// of a screen, but an action that is the last element of a tall page settles a
    /// few points below the band it reserves for the privacy footer, and the band
    /// then refuses to tap a button that is plainly on screen and unobstructed.
    /// `isHittable` asks the question that matters for those.
    func tapScrolling(
        _ element: XCUIElement,
        named description: String,
        in app: XCUIApplication,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertTrue(
            element.waitForExistence(timeout: 15),
            "\(description) never appeared:\n\(app.debugDescription)",
            file: file, line: line
        )
        for _ in 0..<16 where !element.isHittable {
            scroll(app, by: 220)
        }
        XCTAssertTrue(
            element.isHittable,
            "\(description) is not tappable (midY=\(element.frame.midY)):\n\(app.debugDescription)",
            file: file, line: line
        )
        element.tap()
    }
}

// MARK: - Driving the whole ceremony

/// The walk helpers live here rather than in one test file because two suites
/// need them now: the ceremony walk, and the read-only re-pair that has to be
/// preceded by a real provisioning pass to have anything to read.
extension XCTestCase {

    /// Steps 1-6: setup, inventory, reset, PINs, policy, entropy — landing on the
    /// mnemonic step with the words still hidden.
    func advanceToMnemonicStep(
        _ app: XCUIApplication,
        userPIN: String,
        adminPIN: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        openProvisioningFlow(app, file: file, line: line)
        tapWhenVisible(app.buttons["choice-Simulated (debug)"], in: app, file: file, line: line)
        acknowledgePosture(in: app, file: file, line: line)
        tapPinnedPrimaryAction(app, file: file, line: line)

        // Card inventory: read, look at it, then continue.
        let read = app.buttons["Read YubiKey"]
        XCTAssertTrue(read.waitForExistence(timeout: 10), "inventory step missing", file: file, line: line)
        tapWhenVisible(read, in: app, file: file, line: line)
        XCTAssertTrue(app.staticTexts["Factory fresh"].waitForExistence(timeout: 10),
                      "inventory output must stay on screen", file: file, line: line)
        tapStepAction("Continue", in: app, file: file, line: line)

        // Reset with the factory default Admin PIN.
        typeSecret("12345678", into: "Admin PIN (PW3)", in: app, file: file, line: line)
        tapWhenVisible(app.buttons["Reset applet"], in: app, file: file, line: line)
        let confirmReset = app.buttons["Reset and erase"]
        XCTAssertTrue(confirmReset.waitForExistence(timeout: 5), "reset confirmation missing", file: file, line: line)
        confirmReset.tap()

        // PINs: user, repeat, admin, repeat.
        XCTAssertTrue(app.staticTexts["User PIN (PW1) — at least 6 digits"].waitForExistence(timeout: 10),
                      "PIN step missing", file: file, line: line)
        typeSecret(userPIN, into: "User PIN", in: app, file: file, line: line)
        typeSecret(userPIN, into: "Repeat User PIN", in: app, file: file, line: line)
        typeSecret(adminPIN, into: "Admin PIN", in: app, file: file, line: line)
        typeSecret(adminPIN, into: "Repeat Admin PIN", in: app, file: file, line: line)
        tapWhenVisible(app.buttons["Set PINs"], in: app, file: file, line: line)

        // PIN retry limits: the step exists so the operator makes this choice
        // deliberately, with the consequences in front of them.
        XCTAssertTrue(
            app.staticTexts["If every attempt is used up"].waitForExistence(timeout: 10),
            "the retry-limit step must state what happens when the attempts run out",
            file: file, line: line
        )
        let retryLimit = app.steppers["pin-retry-limit"]
        XCTAssertTrue(retryLimit.waitForExistence(timeout: 5), "retry-limit picker missing", file: file, line: line)
        // Raise it once, which exercises the write and the read-back with a value
        // that is not the card's factory default.
        retryLimit.buttons.element(boundBy: 1).tap()
        // The PIN fields use a number pad with no return key, so the keyboard is
        // still up from the previous step and covers the action at the bottom.
        dismissKeyboard(in: app)
        tapStepAction("Set PIN retry limits", in: app, file: file, line: line)

        // Entropy: generate, record the commitment, then continue.
        let generate = app.buttons["Generate entropy"]
        XCTAssertTrue(
            generate.waitForExistence(timeout: 10),
            "entropy step missing; hierarchy:\n\(app.debugDescription)",
            file: file, line: line
        )
        tapWhenVisible(generate, in: app, file: file, line: line)

        let commitment = app.staticTexts["Entropy commitment (first 8 hex of SHA-256)"]
        XCTAssertTrue(commitment.waitForExistence(timeout: 10),
                      "the commitment must stay on screen after generating", file: file, line: line)
        let recorded = app.switches["I have written down the entropy commitment"]
        XCTAssertTrue(recorded.waitForExistence(timeout: 5), file: file, line: line)
        tapWhenVisible(recorded, in: app, file: file, line: line)

        let reveal = app.buttons["Reveal the mnemonic"]
        XCTAssertTrue(reveal.waitForExistence(timeout: 5), "cannot proceed to the mnemonic", file: file, line: line)
        tapWhenVisible(reveal, in: app, file: file, line: line)

        XCTAssertTrue(app.buttons["reveal-mnemonic"].waitForExistence(timeout: 10),
                      "mnemonic step missing", file: file, line: line)
    }

    /// Reveals the words, back-fills the challenge from the entropy the app was
    /// launched with, and confirms the transcription.
    func revealAndConfirmMnemonic(
        _ app: XCUIApplication,
        entropy: [UInt8],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        tapWhenVisible(app.buttons["reveal-mnemonic"], in: app, file: file, line: line)

        let words = try BIP39.mnemonic(fromEntropy: entropy)
        let digest = SHA256.hash(words.joined(separator: " "))
        var indices: [Int] = []
        var cursor = 0
        while indices.count < 3 && cursor < digest.count {
            let candidate = Int(digest[cursor]) % words.count
            if !indices.contains(candidate) { indices.append(candidate) }
            cursor += 1
        }

        for (position, index) in indices.sorted().enumerated() {
            let field = app.textFields.element(boundBy: position)
            XCTAssertTrue(field.waitForExistence(timeout: 5), "back-fill field \(position) missing",
                          file: file, line: line)
            tapWhenVisible(field, in: app, file: file, line: line)
            field.typeText(words[index])
        }

        let done = app.buttons["dismiss-keyboard"]
        if done.exists { done.tap() }
        Thread.sleep(forTimeInterval: 0.3)

        let confirm = app.buttons["Confirm transcription"]
        XCTAssertTrue(confirm.isEnabled, "a correct back-fill must enable confirmation", file: file, line: line)
        tapWhenVisible(confirm, in: app, file: file, line: line)
    }

    /// Everything after the mnemonic: derivation, import, read-back, the manifest
    /// write, the pairing codes, the counter and the teardown. Returns once the
    /// record is on screen.
    ///
    /// `expectedEVMAddress` is asserted against the address the pairing screen
    /// shows, so the codes are checked against the address derived independently
    /// of the app.
    func completeCeremonyAfterMnemonic(
        _ app: XCUIApplication,
        expectedEVMAddress: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        // Every step action goes through `tapStepAction`: on these tall steps the
        // action sits at the end of the content, where the band-based helper refuses
        // to tap it. The labels are still asserted, so a step whose action loses its
        // name fails here rather than silently tapping the wrong control.

        // Derivation: derive, then continue.
        tapStepAction("Derive keys", in: app, file: file, line: line)
        tapStepAction("Continue", in: app, file: file, line: line)

        // Import.
        tapStepAction("Import keys into YubiKey", in: app, file: file, line: line)

        // Read-back: verify, then continue.
        tapStepAction("Verify read-back", in: app, file: file, line: line)
        tapStepAction("Continue", in: app, file: file, line: line)

        // Policy: last, because writing a slot's algorithm attributes resets that
        // slot and the applet drops its touch policy with it (amendment 26). The
        // step reads both policies back off the card, so reaching the manifest step
        // at all means the card reported them.
        tapStepAction("Apply policy", in: app, file: file, line: line)

        // The manifest write is new in this version: assert it actually happened,
        // because every later re-pair depends on it.
        tapStepAction("Store pairing manifest", in: app, file: file, line: line)
        XCTAssertTrue(
            app.staticTexts["Stored on the YubiKey and read back byte-for-byte."].waitForExistence(timeout: 10),
            "the manifest must be stored and read back", file: file, line: line
        )
        tapStepAction("Continue", in: app, file: file, line: line)

        // Pairing: acknowledge the chain code, build the codes, check the address,
        // then continue.
        let acknowledge = app.switches["I understand that only the address shown here can be signed for"]
        XCTAssertTrue(acknowledge.waitForExistence(timeout: 10), "chain-code acknowledgement missing",
                      file: file, line: line)
        tapWhenVisible(acknowledge, in: app, file: file, line: line)
        tapStepAction("Prepare pairing codes", in: app, file: file, line: line)

        XCTAssertTrue(
            app.staticTexts[expectedEVMAddress].waitForExistence(timeout: 10),
            "the pairing screen must show the derived EVM address", file: file, line: line
        )
        let confirmed = app.switches["I confirmed my desktop wallet shows these exact values"]
        XCTAssertTrue(confirmed.waitForExistence(timeout: 5), file: file, line: line)
        tapWhenVisible(confirmed, in: app, file: file, line: line)
        tapStepAction("Continue", in: app, file: file, line: line)

        // Counter, then teardown.
        tapStepAction("Read counter", in: app, file: file, line: line)
        tapStepAction("Continue", in: app, file: file, line: line)
        tapStepAction("Wipe secrets and finish", in: app, file: file, line: line)

        XCTAssertTrue(app.buttons["Provision another wallet"].waitForExistence(timeout: 10),
                      "the record must be shown when the ceremony finishes", file: file, line: line)
    }
}
