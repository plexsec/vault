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

    /// Counts the static texts whose label is exactly `label`: `app.staticTexts[x]` is a
    /// single element, and a negative assertion needs "none on screen".
    private func staticTextCount(_ label: String, in app: XCUIApplication) -> Int {
        app.staticTexts.matching(NSPredicate(format: "label == %@", label)).count
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

        // Home, showing the connection it was given.
        XCTAssertTrue(
            app.buttons["route-signing"].waitForExistence(timeout: 15),
            "Continue must reach the home screen:\n\(app.debugDescription)"
        )
        XCTAssertTrue(app.staticTexts["Card connection"].exists, "the home screen must summarise it")
        XCTAssertTrue(app.staticTexts["USB-C"].exists, "and show which one was chosen")
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
        XCTAssertTrue(app.staticTexts["USB-C"].exists, "the stored choice must be what comes back")

        // Change it, from the home screen only.
        tapWhenVisible(app.buttons["change-device"], in: app)
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
        XCTAssertTrue(app.staticTexts["NFC"].waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertEqual(
            staticTextCount("USB-C", in: app), 0,
            "the new choice must replace the stored one, not sit beside it"
        )

        // And the replacement is what is stored: relaunch again.
        app.terminate()
        app.launch()
        XCTAssertTrue(app.buttons["route-signing"].waitForExistence(timeout: 15), app.debugDescription)
        XCTAssertTrue(app.staticTexts["NFC"].exists, "the change must survive a relaunch")
        XCTAssertEqual(staticTextCount("USB-C", in: app), 0)
    }

    /// What the device screen stores is what the ceremony then uses.
    ///
    /// The connection is not echoed on any screen inside the flow — that is the point of
    /// asking once — so the proof is behavioural: the simulated card answers. A real NFC
    /// read in a simulator cannot, so reaching the inventory is evidence the choice
    /// travelled from the device screen through the store into the ceremony.
    func testTheChoiceMadeOnTheDeviceScreenReachesTheCeremony() {
        let app = launchApp(firstRun: true)

        tapWhenVisible(app.buttons["device-choice-Simulated (debug)"], in: app)
        tapPinnedPrimaryAction(app, identifier: "device-done")
        XCTAssertTrue(
            app.staticTexts["Simulated (debug)"].waitForExistence(timeout: 10),
            "the home screen must show the choice just made:\n\(app.debugDescription)"
        )

        openProvisioningFlow(app)
        acknowledgePosture(in: app)
        tapPinnedPrimaryAction(app)

        tapWhenVisible(app.buttons["Read YubiKey"], in: app)
        XCTAssertTrue(
            app.staticTexts["Factory fresh"].waitForExistence(timeout: 15),
            "the simulated card must be the one the ceremony read:\n\(app.debugDescription)"
        )
    }
}
