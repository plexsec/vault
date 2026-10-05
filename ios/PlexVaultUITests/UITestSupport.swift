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
        // action inside the scroll view) the band reaches the bottom of the
        // window: nothing is pinned down there any more, and a margin large
        // enough to clear the footer that used to be left the last control of a
        // short page — "Confirm transcription" — a few points below the band.
        let bottom = (primaryAction.exists ? primaryAction.frame.minY : window.maxY - 12) - 12
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
    ///
    /// The identifier is a parameter because the same shape is used by more than one
    /// screen (the ceremony's setup, the device screen); what they share is the claim
    /// being made — an action pinned to the bottom of the screen is on screen and
    /// unobstructed, so it must be tappable without scrolling. `tapWhenVisible` cannot
    /// check that: its `visibleBand` stops short of the bottom precisely because a
    /// pinned action lives there.
    func tapPinnedPrimaryAction(_ app: XCUIApplication,
                                identifier: String = "begin-ceremony",
                                file: StaticString = #filePath, line: UInt = #line) {
        let begin = app.buttons[identifier]
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
                          "posture toggle missing: \(label)\n\(app.debugDescription)", file: file, line: line)
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
        closeKeyboard(in: app, file: file, line: line)
        Thread.sleep(forTimeInterval: 0.2)
    }

    /// Types into a field, and does not start typing until that field really holds
    /// the keyboard's focus.
    ///
    /// `typeText` does not type into the element it is called on: it types into
    /// whatever holds the keyboard's focus, and when it cannot establish which
    /// element that is it synthesizes nothing and fails with "Neither element nor
    /// any descendant has keyboard focus". The condition is read from the same
    /// `hasKeyboardFocus` attribute `typeText`'s own lookup uses, because that is
    /// the only signal that says what the keyboard is attached to — a sleep is not:
    /// `typeSecret`'s fixed 0.3s settle was measured to be enough on the PIN fields
    /// and is not enough here.
    ///
    /// The tap is repeated until the focus arrives because of the keyboard's own
    /// input-accessory toolbar: it holds this suite's `dismiss-keyboard`, it sits
    /// exactly over the second and third back-fill fields on this page, and the page
    /// is too short to scroll them out from under it. A tap delivered while that
    /// toolbar is on screen lands on the toolbar, and the field keeps whatever focus
    /// it had — which is why the field that does not take focus is always the second
    /// one, and why `closeKeyboard` is called before the first tap.
    func tapAndType(_ text: String, into field: XCUIElement, in app: XCUIApplication,
                    file: StaticString = #filePath, line: UInt = #line) {
        closeKeyboard(in: app, file: file, line: line)
        let focused = app.textFields.matching(NSPredicate(format: "hasKeyboardFocus == true"))
        var ready = false
        for _ in 0..<4 {
            let holders = focused.allElementsBoundByIndex
            // By position rather than by identity: the query returns the field the
            // keyboard is on, and the element the test holds is a fresh lookup of
            // the same field.
            if holders.count == 1, abs(holders[0].frame.midY - field.frame.midY) < 2 {
                ready = true
                break
            }
            tapWhenVisible(field, in: app, file: file, line: line)
            Thread.sleep(forTimeInterval: 0.3)
        }
        XCTAssertTrue(
            ready,
            "the keyboard never focused \(field) — typing would have gone elsewhere:\n"
                + app.debugDescription,
            file: file, line: line
        )
        field.typeText(text)
    }

    /// Closes the keyboard and waits until its accessory toolbar is really gone.
    ///
    /// Tapping Done is not enough on its own. The toolbar stays on screen while it
    /// animates away, and a tap that arrives in that window is swallowed by it — the
    /// field under it never takes focus, which surfaces later as `typeText` failing
    /// with "Neither element nor any descendant has keyboard focus".
    func closeKeyboard(in app: XCUIApplication,
                       file: StaticString = #filePath, line: UInt = #line) {
        let done = app.buttons["dismiss-keyboard"]
        guard done.exists else { return }
        done.tap()
        XCTAssertTrue(
            done.waitForNonExistence(timeout: 3),
            "the keyboard's toolbar did not close, so it would swallow the next tap",
            file: file, line: line
        )
    }
}

extension XCTestCase {
    /// Launches the app, with the card connection already answered.
    ///
    /// The app asks how the YubiKey is connected on first launch and stores the answer,
    /// so a test that is about something else seeds it rather than tapping through the
    /// screen — and a test that *is* about that screen starts from `firstRun: true`,
    /// which clears the stored value so the gate really appears. Both hooks are DEBUG-only
    /// (`DeviceChoiceStore.applyLaunchArguments`).
    ///
    /// - Parameters:
    ///   - deviceChoice: raw value of the connection to store before the first screen
    ///     (`"nfc"`, `"usbC"`, `"simulated"`).
    ///   - firstRun: start with no stored choice, which is what puts the device screen in
    ///     front of the app.
    ///   - arguments: further launch arguments, e.g. `-deterministic-entropy`.
    func launchApp(
        deviceChoice: String = "nfc",
        firstRun: Bool = false,
        arguments: [String] = []
    ) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = arguments
        app.launchArguments += firstRun
            ? ["-reset-device-choice"]
            : ["-device-choice", deviceChoice]
        app.launch()
        return app
    }

    /// Opens the provisioning flow from the app's home screen.
    ///
    /// The app has two routes — provisioning and signing — and the provisioning
    /// modes now live on the home screen behind the collapsed "Wallet & Key
    /// Management" section. Tolerant of being called when the flow is already
    /// open, so a test can call it without knowing how it got there.
    func openProvisioningFlow(
        _ app: XCUIApplication,
        mode: String = "Generate a new wallet",
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let section = app.buttons["wallet-key-management"]
        if section.waitForExistence(timeout: 10) {
            // The home screen is showing: expand the collapsed section and pick the
            // requested mode. If the flow is already open, the section is absent and
            // this step is skipped.
            tapWhenVisible(section, in: app, file: file, line: line)
            let entry = app.buttons["wallet-mode-\(mode)"]
            XCTAssertTrue(
                entry.waitForExistence(timeout: 10),
                "wallet mode entry '\(mode)' did not appear:\n\(app.debugDescription)",
                file: file, line: line
            )
            tapWhenVisible(entry, in: app, file: file, line: line)
        }
        // The setup screen's own pinned action: the transport rows that used to
        // identify this screen now live on the device screen, which is a separate
        // route and must not be mistaken for this one.
        XCTAssertTrue(
            app.buttons["begin-ceremony"].waitForExistence(timeout: 15),
            "the provisioning setup screen did not appear:\n\(app.debugDescription)",
            file: file, line: line
        )
    }

    /// Taps a ceremony step's primary action by its label, scrolling it into view
    /// first.
    ///
    /// This is not `tapWhenVisible`, and the difference is measured rather than
    /// stylistic. A step action is the last element of the step's content, and the
    /// tall steps (derivation, import, read-back) put it below the fold. When the
    /// page cannot scroll any further the action settles wherever it lands, which
    /// need not be inside the band `visibleBand(in:)` measures — the band would
    /// refuse to tap a button that is on screen and unobstructed. `isHittable`
    /// asks the question that matters here (is anything in the way?), and unlike
    /// the posture toggles, nothing overlays a step action.
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
    /// of a screen, but an action that is the last element of a page can settle
    /// outside the band when the page has no room left to scroll, and the band then
    /// refuses to tap a button that is plainly on screen and unobstructed.
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

    /// Steps 1-6: setup, inventory, reset, PINs, the retry limits, entropy — landing on
    /// the mnemonic step with the words still hidden.
    func advanceToMnemonicStep(
        _ app: XCUIApplication,
        userPIN: String,
        adminPIN: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        openProvisioningFlow(app, file: file, line: line)
        // The connection was seeded at launch: this walk is about the ceremony, and the
        // simulated card is what a simulator can reach (`launchApp(deviceChoice:)`).
        acknowledgePosture(in: app, file: file, line: line)
        tapPinnedPrimaryAction(app, file: file, line: line)

        // Card inventory: read, look at it, then continue.
        let read = app.buttons["Read YubiKey"]
        XCTAssertTrue(read.waitForExistence(timeout: 10), "inventory step missing", file: file, line: line)
        tapWhenVisible(read, in: app, file: file, line: line)
        XCTAssertTrue(app.staticTexts["Factory fresh"].waitForExistence(timeout: 10),
                      "inventory output must stay on screen", file: file, line: line)
        tapStepAction("Continue", in: app, file: file, line: line)

        // Reset: no PIN. The app blocks both PINs itself and then terminates the
        // applet, which is `ykman openpgp reset`'s sequence, so the button is live
        // as soon as the inventory has been acknowledged.
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
        let userRetry = app.steppers["pin-retry-limit-user"]
        XCTAssertTrue(userRetry.waitForExistence(timeout: 5), "the User PIN's picker is missing", file: file, line: line)
        let adminRetry = app.steppers["pin-retry-limit-admin"]
        XCTAssertTrue(adminRetry.waitForExistence(timeout: 5), "the Admin PIN's picker is missing", file: file, line: line)
        // Raise each once, to different numbers: that exercises the write and the
        // read-back with values that are neither the card's factory default nor each
        // other, so a write that put one number on both passwords fails the walk.
        userRetry.buttons.element(boundBy: 1).tap()
        adminRetry.buttons.element(boundBy: 1).tap()
        adminRetry.buttons.element(boundBy: 1).tap()
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
            tapAndType(words[index], into: field, in: app, file: file, line: line)
        }

        closeKeyboard(in: app, file: file, line: line)
        Thread.sleep(forTimeInterval: 0.3)

        let confirm = app.buttons["Confirm transcription"]
        XCTAssertTrue(confirm.isEnabled, "a correct back-fill must enable confirmation", file: file, line: line)
        tapWhenVisible(confirm, in: app, file: file, line: line)
    }

    /// Everything after the mnemonic: derivation, the card, the pairing codes, the
    /// counter and the teardown. Returns once the record is on screen.
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

        // The card: one action writes the keys, the policy and the pairing manifest,
        // and reads all of it back. The step only shows "Continue" once the card has
        // reported everything back, so reaching it is the assertion that the writes
        // happened and were verified (amendment 37).
        tapStepAction("Write and verify the YubiKey", in: app, file: file, line: line)
        XCTAssertTrue(
            app.staticTexts["The pairing manifest is stored on the YubiKey and read back byte-for-byte."]
                .waitForExistence(timeout: 20),
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
