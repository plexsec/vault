import XCTest

/// The device choice: how the iPhone reaches the YubiKey, asked once and remembered.
///
/// It exists because the connection is the one thing the app cannot work out for itself —
/// both real transports reach the same card — and because it used to be asked *inside*
/// each flow, which made it two sources of truth and let it be changed between the read
/// and the signature. These tests hold the three properties that came out of that: the
/// app asks before it does anything else, the answer survives a relaunch, and the home
/// screen both shows it and provides the only way to change it.
final class DeviceChoiceUITests: XCTestCase {

    /// The home screen's YubiKey button, which is the only place the connection is shown.
    private func deviceButton(in app: XCUIApplication) -> XCUIElement {
        app.buttons["device-button"]
    }

    /// On a first run the device screen is the way in, it cannot be left without an
    /// answer, and the answer is what the home screen then shows.
    func testFirstLaunchAsksBeforeAnythingElse() {
        let app = launchApp(firstRun: true)

        XCTAssertTrue(
            app.buttons["device-choice-NFC"].waitForExistence(timeout: 15),
            "a first run must ask which connection to use:\n\(app.debugDescription)"
        )
        XCTAssertFalse(
            app.buttons["route-signing"].exists,
            "the home screen must not be reachable before the question is answered"
        )
        XCTAssertFalse(
            app.buttons["wallet-key-management"].exists,
            "neither route may be reachable before the question is answered"
        )

        // Nothing is chosen yet, and the disabled action says why — the same pattern the
        // ceremony's setup screen uses, rather than a button that looks tappable and is not.
        let done = app.buttons["device-done"]
        XCTAssertTrue(done.waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertFalse(done.isEnabled, "Continue must wait for a choice")
        XCTAssertTrue(
            app.staticTexts.containing(
                NSPredicate(format: "label CONTAINS 'Choose the connection'")
            ).firstMatch.exists,
            "a disabled action must explain itself:\n\(app.debugDescription)"
        )

        tapWhenVisible(app.buttons["device-choice-USB-C"], in: app)
        XCTAssertTrue(app.buttons["device-choice-USB-C"].isSelected)
        XCTAssertTrue(done.isEnabled, "a choice must enable Continue")

        tapPinnedPrimaryAction(app, identifier: "device-done")

        // Home, showing the connection it was given: the top-right button names it, and that
        // label is the only place the choice is visible.
        XCTAssertTrue(
            app.buttons["route-signing"].waitForExistence(timeout: 15),
            "Continue must reach the home screen:\n\(app.debugDescription)"
        )
        let device = deviceButton(in: app)
        XCTAssertTrue(device.waitForExistence(timeout: 10), "the home screen must show the connection")
        XCTAssertTrue(
            device.label.hasPrefix("Card connection: USB-C"),
            "the button must name the connection in use, got '\(device.label)'"
        )
    }

    /// On USB-C the app can tell whether the key is plugged in, and says so: the icon turns
    /// green when it is and grey when it is not.
    ///
    /// A simulator has no smart-card slot to ask, so the assertion is that the presence
    /// *clause* arrives — either reading is a passed check that the poll reached the reader
    /// and reported something, which is the part that can break.
    func testTheUsbCConnectionReportsWhetherTheKeyIsPluggedIn() {
        let app = launchApp(firstRun: true)
        tapWhenVisible(app.buttons["device-choice-USB-C"], in: app)
        tapPinnedPrimaryAction(app, identifier: "device-done")

        let device = deviceButton(in: app)
        XCTAssertTrue(device.waitForExistence(timeout: 10), app.debugDescription)
        let reported = NSPredicate(
            format: "label CONTAINS 'YubiKey inserted' OR label CONTAINS 'no YubiKey detected'"
        )
        expectation(for: reported, evaluatedWith: device)
        waitForExpectations(timeout: 15)
    }

    /// The choice is remembered across launches, and the home screen's button is how it
    /// changes — including that the new value *replaces* the old one.
    func testTheChoiceIsRememberedAndReplacedWhenChanged() {
        let app = launchApp(firstRun: true)
        tapWhenVisible(app.buttons["device-choice-USB-C"], in: app)
        tapPinnedPrimaryAction(app, identifier: "device-done")
        XCTAssertTrue(app.buttons["route-signing"].waitForExistence(timeout: 15), app.debugDescription)

        // Relaunch with no hooks at all: whatever comes back is what was stored.
        app.terminate()
        app.launchArguments = []
        app.launch()

        XCTAssertTrue(
            app.buttons["route-signing"].waitForExistence(timeout: 15),
            "a stored choice must skip the question:\n\(app.debugDescription)"
        )
        XCTAssertEqual(
            app.buttons.matching(identifier: "device-choice-NFC").count, 0,
            "the device screen must not reappear once a choice is stored"
        )
        XCTAssertTrue(
            deviceButton(in: app).label.hasPrefix("Card connection: USB-C"),
            "the stored choice must be what comes back, got '\(deviceButton(in: app).label)'"
        )

        // Change it, from the title-line button only.
        tapWhenVisible(app.buttons["device-button"], in: app)
        let nfc = app.buttons["device-choice-NFC"]
        XCTAssertTrue(nfc.waitForExistence(timeout: 15), app.debugDescription)
        XCTAssertTrue(
            app.buttons["device-choice-USB-C"].isSelected,
            "the screen must open on the stored choice, not on a default"
        )
        XCTAssertFalse(nfc.isSelected)

        tapWhenVisible(nfc, in: app)
        XCTAssertTrue(nfc.isSelected)
        let done = app.buttons["device-done"]
        XCTAssertTrue(done.isEnabled, "leaving the change screen is always allowed")
        tapPinnedPrimaryAction(app, identifier: "device-done")

        XCTAssertTrue(
            app.buttons["route-signing"].waitForExistence(timeout: 15),
            "Done must return to the home screen:\n\(app.debugDescription)"
        )
        XCTAssertTrue(deviceButton(in: app).waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertEqual(
            deviceButton(in: app).label, "Card connection: NFC",
            "the new choice must replace the stored one, not sit beside it"
        )

        // And the replacement is what is stored: relaunch again.
        app.terminate()
        app.launch()
        XCTAssertTrue(app.buttons["route-signing"].waitForExistence(timeout: 15), app.debugDescription)
        XCTAssertEqual(deviceButton(in: app).label, "Card connection: NFC",
                       "the change must survive a relaunch")
    }

    /// The button sits on the title line, not in a navigation bar.
    ///
    /// It started life as a `.topBarTrailing` toolbar item, which put it in the empty strip
    /// *above* the "PlexVault" title — visibly higher than everything it belongs to. This
    /// pins the fix: the two are centred on each other.
    func testTheDeviceButtonSitsOnTheTitleLine() {
        let app = launchApp()

        let title = app.staticTexts["PlexVault"]
        let device = deviceButton(in: app)
        XCTAssertTrue(title.waitForExistence(timeout: 10), app.debugDescription)
        XCTAssertTrue(device.waitForExistence(timeout: 10), app.debugDescription)

        XCTAssertEqual(
            title.frame.midY, device.frame.midY, accuracy: 6,
            "the button must be centred on the title's line, not on the top of the screen "
                + "(title \(title.frame), button \(device.frame))"
        )
        // And it is in a corner of the title's row, not in the content column.
        XCTAssertGreaterThan(device.frame.minX, title.frame.maxX, "the button belongs on the right")
    }

    /// What the device screen stores is what the ceremony then uses.
    ///
    /// The connection is not echoed on any screen inside the flow — that is the point of
    /// asking once — so the proof is behavioural: the simulated card answers. A real NFC
    /// read in a simulator cannot, so reaching the step that talks to the card is evidence the
    /// choice travelled from the device screen through the store into the ceremony. That step
    /// is the inventory now, and it comes after the keys (amendment 40), so this walk reads
    /// the card the first time the ceremony asks for it: the entropy step's `randomBytes`
    /// proves the transport works, and the inventory proves *which* card answered.
    func testTheChoiceMadeOnTheDeviceScreenReachesTheCeremony() throws {
        let app = launchApp(firstRun: true)

        tapWhenVisible(app.buttons["device-choice-Simulated (debug)"], in: app)
        tapPinnedPrimaryAction(app, identifier: "device-done")
        XCTAssertEqual(
            deviceButton(in: app).label, "Card connection: Simulated (debug)",
            "the home screen must show the choice just made:\n\(app.debugDescription)"
        )

        openProvisioningFlow(app)
        acknowledgePosture(in: app)
        tapPinnedPrimaryAction(app)

        // The ceremony's first step reads the card's own RNG, so the simulated card answering
        // here is the transport proving itself.
        tapWhenVisible(app.buttons["Generate entropy"], in: app)
        XCTAssertTrue(
            app.staticTexts["Entropy commitment (first 8 hex of SHA-256)"].waitForExistence(timeout: 15),
            "the simulated card must be the one the ceremony read:\n\(app.debugDescription)"
        )
    }
}
