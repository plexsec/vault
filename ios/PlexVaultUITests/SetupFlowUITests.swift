import XCTest

/// Drives the real app in a simulator.
///
/// The setup screen is where a user can get stuck, so it is covered by
/// automation rather than by eye. Two behaviours are locked in here because both
/// were wrong at some point:
///
/// 1. Selecting a mode (or transport, or chain) must be a real tappable control.
///    An earlier version used `Picker(.inline)`, which iOS 26 renders as a wheel
///    whose default is already selected — so tapping "Generate a new wallet" did
///    nothing and the screen looked broken.
/// 2. The primary action must be reachable without scrolling and must say why it
///    is disabled, instead of appearing to ignore taps.
final class SetupFlowUITests: XCTestCase {

    /// Brings an element into the *visible* part of the window before tapping it.
    ///
    /// Deliberately not `isHittable`-based: for an element underneath the pinned
    /// bottom bar, `isHittable` still reports true while the tap is intercepted by
    /// the bar. The band below keeps clear of the bar and the navigation bar.
    private func tap(_ element: XCUIElement, in app: XCUIApplication,
                     file: StaticString = #filePath, line: UInt = #line) {
        let window = app.windows.firstMatch
        var attempts = 0
        while attempts < 12 {
            let frame = element.frame
            let visible = window.frame.insetBy(dx: 0, dy: 140)
            if visible.contains(CGPoint(x: frame.midX, y: frame.midY)) { break }
            if frame.midY > visible.midY {
                app.swipeUp()
            } else {
                app.swipeDown()
            }
            attempts += 1
        }
        XCTAssertTrue(
            window.frame.insetBy(dx: 0, dy: 140).contains(CGPoint(x: element.frame.midX, y: element.frame.midY)),
            "\(element) could not be brought into the visible area",
            file: file, line: line
        )
        element.tap()
    }

    /// The pinned primary action needs no scrolling, and must be tappable from a
    /// cold launch — that is the property being locked in.
    private func tapPinnedPrimaryAction(_ app: XCUIApplication,
                                        file: StaticString = #filePath, line: UInt = #line) {
        let begin = app.buttons["begin-ceremony"]
        XCTAssertTrue(begin.isHittable, "the primary action must be hittable without scrolling",
                      file: file, line: line)
        begin.tap()
    }

    private func launch() -> XCUIApplication {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(
            app.buttons["begin-ceremony"].waitForExistence(timeout: 15),
            "setup screen did not appear:\n\(app.debugDescription)"
        )
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
        let visibleBand = app.windows.firstMatch.frame.insetBy(dx: 0, dy: 140)
        XCTAssertTrue(
            visibleBand.contains(CGPoint(x: generate.frame.midX, y: generate.frame.midY)),
            "Generate a new wallet must be visible without scrolling (y=\(generate.frame.midY))"
        )

        // Generate is the default.
        XCTAssertTrue(generate.isSelected, "Generate a new wallet should start selected")
        XCTAssertFalse(restore.isSelected)

        tap(restore, in: app)
        XCTAssertTrue(restore.isSelected, "tapping a mode row must select it")
        XCTAssertFalse(generate.isSelected, "selection must move, not accumulate")

        tap(generate, in: app)
        XCTAssertTrue(generate.isSelected)
        XCTAssertFalse(restore.isSelected)
    }

    func testTransportAndChainRowsAreSelectable() {
        let app = launch()

        let usbC = app.buttons["choice-USB-C"]
        XCTAssertTrue(usbC.exists, app.debugDescription)
        XCTAssertFalse(usbC.isSelected)
        tap(usbC, in: app)
        XCTAssertTrue(usbC.isSelected)

        let bitcoin = app.buttons["choice-Bitcoin (native segwit)"]
        XCTAssertTrue(bitcoin.exists)
        tap(bitcoin, in: app)
        XCTAssertTrue(bitcoin.isSelected)
        XCTAssertFalse(app.buttons["choice-Ethereum (EVM)"].isSelected)
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

        for index in 0..<app.switches.count {
            let toggle = app.switches.element(boundBy: index)
            if (toggle.value as? String) == "0" { toggle.tap() }
        }

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
        tap(app.buttons["choice-Restore from a mnemonic"], in: app)
        for index in 0..<app.switches.count {
            let toggle = app.switches.element(boundBy: index)
            if (toggle.value as? String) == "0" { toggle.tap() }
        }
        tapPinnedPrimaryAction(app)
        XCTAssertTrue(
            app.buttons["Read YubiKey"].waitForExistence(timeout: 10),
            "restore mode must also reach the ceremony"
        )
    }
}
