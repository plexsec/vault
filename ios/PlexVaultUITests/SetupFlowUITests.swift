import XCTest

/// Drives the real app in a simulator.
///
/// The setup screen is where a user can get stuck, so it is covered by
/// automation rather than by eye. Two behaviours are locked in here because both
/// were wrong at some point:
///
/// 1. The three provisioning modes must be reachable from the home screen as
///    real tappable entries behind a collapsed section. An earlier version used a
///    `Picker(.inline)` on the setup screen, which iOS 26 renders as a wheel
///    whose default is already selected — so tapping "Generate a new wallet" did
///    nothing and the screen looked broken.
/// 2. The primary action must be reachable without scrolling and must say why it
///    is disabled, instead of appearing to ignore taps.
/// 3. A Cancel button must leave the flow it is on. The signing flow's toolbar
///    button called the view model's `abort()` in every phase, which on its old
///    setup screen reset state that was already empty: the button did nothing, and
///    the screen was a one-way door. The signing flow now opens on the scanner and
///    cancels from there.
///
/// Scrolling to a control is done with `tapWhenVisible`, from `UITestSupport`.
final class SetupFlowUITests: XCTestCase {

    private func launch() -> XCUIApplication {
        // The connection is seeded: it is chosen once on the device screen, and these
        // tests are about the provisioning setup screen behind it.
        let app = launchApp()
        openProvisioningFlow(app)
        return app
    }

    /// The three mode entries live on the home screen, collapsed by default, and
    /// expand when the section is tapped.
    func testWalletKeyManagementSectionIsCollapsedByDefaultAndExpands() {
        let app = launchApp()

        let section = app.buttons["wallet-key-management"]
        XCTAssertTrue(section.waitForExistence(timeout: 10), app.debugDescription)

        // Collapsed by default: the three entries are not in the hierarchy.
        XCTAssertEqual(app.buttons.matching(identifier: "wallet-mode-Generate a new wallet").count, 0)
        XCTAssertEqual(app.buttons.matching(identifier: "wallet-mode-Restore from a mnemonic").count, 0)
        XCTAssertEqual(app.buttons.matching(identifier: "wallet-mode-Pair a wallet").count, 0)

        tapWhenVisible(section, in: app)

        XCTAssertTrue(
            app.buttons["wallet-mode-Generate a new wallet"].waitForExistence(timeout: 5),
            "the section must reveal its entries:\n\(app.debugDescription)"
        )
        XCTAssertTrue(app.buttons["wallet-mode-Restore from a mnemonic"].exists)
        XCTAssertTrue(app.buttons["wallet-mode-Pair a wallet"].exists)
    }

    /// Neither flow offers a connection picker any more, and neither repeats the choice as
    /// read-only prose: it is one setting for the phone, chosen on the device screen and
    /// shown on the home screen. The chain picker is gone for a different reason — one
    /// ceremony always writes both algorithms.
    func testTheSetupScreenHasNoConnectionOrChainPicker() {
        let app = launch()

        // Asserted by identifier count rather than by a negative `.exists` lookup, which
        // XCTest reports as a snapshot error even when the element is legitimately absent.
        XCTAssertEqual(app.buttons.matching(identifier: "device-choice-NFC").count, 0,
                       "the connection is chosen once, on the device screen")
        XCTAssertEqual(app.buttons.matching(identifier: "device-choice-USB-C").count, 0)
        XCTAssertEqual(app.buttons.matching(identifier: "choice-Bitcoin (native segwit)").count, 0)
        XCTAssertEqual(app.buttons.matching(identifier: "choice-Ethereum (EVM)").count, 0)
        XCTAssertEqual(app.staticTexts.matching(NSPredicate(format: "label == %@", "Card connection")).count, 0,
                       "the setup screen does not summarise the connection either")
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
            app.buttons["Generate entropy"].waitForExistence(timeout: 10),
            "Begin ceremony must advance to the entropy step — the keys come before any card:\n\(app.debugDescription)"
        )
    }

    /// Cancel on the signing setup screen leaves the flow.
    ///
    /// It used to do nothing at all: the toolbar button called `abort()` in every
    /// phase, and on this screen that only reset state which was already empty, so
    /// the only way out was to kill the app. The provisioning flow's Cancel already
    /// exits — the two now behave the same, down to the identifier.
    /// The signing flow opens on the scanner, and its Cancel leaves the flow.
    ///
    /// There is no setup screen any more: tapping the home screen's entry opens the camera,
    /// because the request is what names the key and nothing has to be decided first. The
    /// button being a real way out is the part worth locking in — it once called `abort()`
    /// in every phase, which on the setup screen reset state that was already empty.
    func testTheSigningFlowOpensOnTheScannerAndCancelsHome() {
        let app = launchApp()

        tapWhenVisible(app.buttons["route-signing"], in: app)
        XCTAssertTrue(
            app.buttons["use-sample-request"].waitForExistence(timeout: 10),
            "the signing flow must open on the scanner:\(app.debugDescription)"
        )
        let cancel = app.buttons["cancel-scanning"]
        XCTAssertTrue(cancel.waitForExistence(timeout: 10), app.debugDescription)
        // Tapped directly rather than with `tapWhenVisible`: the helper scrolls until
        // an element lands in `visibleBand`, which deliberately starts below the
        // navigation bar, so a toolbar button can never be brought into it.
        XCTAssertTrue(cancel.isHittable, "the Cancel button must be tappable")
        cancel.tap()

        XCTAssertTrue(
            app.buttons["route-signing"].waitForExistence(timeout: 10),
            "cancelling the scanner must return to the home screen:\(app.debugDescription)"
        )
    }

    /// Choosing a mode must actually reach the ceremony: restore mode is
    /// observable because it is recorded in the step flow.
    func testRestoreModeReachesTheCeremony() {
        let app = launchApp(deviceChoice: "simulated")
        openProvisioningFlow(app, mode: "Restore from a mnemonic")
        acknowledgePosture(in: app)
        tapPinnedPrimaryAction(app)
        XCTAssertTrue(
            app.textViews.firstMatch.waitForExistence(timeout: 10),
            "restore mode must open on the words themselves:\n\(app.debugDescription)"
        )
    }
}
