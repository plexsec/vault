import XCTest

/// Drives the real app in a simulator.
///
/// The setup screen is where a user can get stuck, so it is covered by
/// automation rather than by eye. Two behaviours are locked in here because both
/// were wrong at some point:
///
/// 1. Selecting a mode (or transport) must be a real tappable control.
///    An earlier version used `Picker(.inline)`, which iOS 26 renders as a wheel
///    whose default is already selected — so tapping "Generate a new wallet" did
///    nothing and the screen looked broken.
/// 2. The primary action must be reachable without scrolling and must say why it
///    is disabled, instead of appearing to ignore taps.
///
/// Scrolling to a control is done with `tapWhenVisible`, from `UITestSupport`.
final class SetupFlowUITests: XCTestCase {

    private func launch() -> XCUIApplication {
        let app = XCUIApplication()
        app.launch()
        openProvisioningFlow(app)
        return app
    }

    /// The headline regression: the mode rows must be tappable and must change
    /// the selection.
    func testModeRowsAreTappableAndSelectable() {
        let app = launch()

        let generate = app.buttons["choice-Generate a new wallet"]
        let restore = app.buttons["choice-Restore from a mnemonic"]
        XCTAssertTrue(generate.exists, app.debugDescription)
        XCTAssertTrue(restore.exists, app.debugDescription)

        // Regression for the reported bug: the mode rows must be on screen and
        // unobscured on launch. Previously this was a wheel-based picker whose
        // default was already selected, so tapping it appeared to do nothing.
        XCTAssertTrue(
            visibleBand(in: app).contains(CGPoint(x: generate.frame.midX, y: generate.frame.midY)),
            "Generate a new wallet must be visible without scrolling (y=\(generate.frame.midY))"
        )

        // Generate is the default.
        XCTAssertTrue(generate.isSelected, "Generate a new wallet should start selected")
        XCTAssertFalse(restore.isSelected)

        tapWhenVisible(restore, in: app)
        XCTAssertTrue(restore.isSelected, "tapping a mode row must select it")
        XCTAssertFalse(generate.isSelected, "selection must move, not accumulate")

        tapWhenVisible(generate, in: app)
        XCTAssertTrue(generate.isSelected)
        XCTAssertFalse(restore.isSelected)
    }

    func testTransportRowIsSelectableAndChainPickerIsGone() {
        let app = launch()

        let usbC = app.buttons["choice-USB-C"]
        XCTAssertTrue(usbC.exists, app.debugDescription)
        XCTAssertFalse(usbC.isSelected)
        tapWhenVisible(usbC, in: app)
        XCTAssertTrue(usbC.isSelected)

        // There is no chain picker any more: one ceremony always writes both
        // algorithms. Asserted by identifier count rather than by a negative
        // `.exists` lookup, which XCTest reports as a snapshot error even when the
        // element is legitimately absent.
        XCTAssertEqual(app.buttons.matching(identifier: "choice-Bitcoin (native segwit)").count, 0)
        XCTAssertEqual(app.buttons.matching(identifier: "choice-Ethereum (EVM)").count, 0)
    }

    /// The gate: the ceremony must not start until the posture checks are ticked,
    /// must be startable without scrolling to the bottom, and must advance.
    func testCeremonyCannotBeginUntilPostureIsAcknowledged() {
        let app = launch()
        let begin = app.buttons["begin-ceremony"]

        XCTAssertTrue(begin.isHittable, "the primary action must be reachable without scrolling")
        XCTAssertFalse(begin.isEnabled, "the ceremony must not start before the checks are acknowledged")
        XCTAssertTrue(
            app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'see this screen'")).firstMatch.exists,
            "a disabled action must explain itself"
        )

        acknowledgePosture(in: app)

        XCTAssertTrue(begin.isEnabled, "acknowledging both checks must enable the action")
        tapPinnedPrimaryAction(app)

        XCTAssertTrue(
            app.buttons["Read YubiKey"].waitForExistence(timeout: 10),
            "Begin ceremony must advance to the card-inventory step:\n\(app.debugDescription)"
        )
    }

    /// Choosing a mode must actually reach the ceremony: restore mode is
    /// observable because it is recorded in the step flow.
    func testRestoreModeReachesTheCeremony() {
        let app = launch()
        tapWhenVisible(app.buttons["choice-Restore from a mnemonic"], in: app)
        acknowledgePosture(in: app)
        tapPinnedPrimaryAction(app)
        XCTAssertTrue(
            app.buttons["Read YubiKey"].waitForExistence(timeout: 10),
            "restore mode must also reach the ceremony:\n\(app.debugDescription)"
        )
    }
}
