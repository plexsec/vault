import XCTest
import VaultKit

/// The read-only re-pair mode, driven through the real screens.
///
/// The unit tests already hold the logic to a hard bar; this covers what they
/// cannot see — that choosing the mode reaches a non-destructive path at all. The
/// failure worth catching here is a mode that quietly routes into the reset screen,
/// which would erase the keys an operator chose this mode to keep.
final class RePairUITests: XCTestCase {

    private func launchApp() -> XCUIApplication {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.buttons["begin-ceremony"].waitForExistence(timeout: 15), app.debugDescription)
        return app
    }

    func testRePairModeIsSelectableAndReadsWithoutErasing() throws {
        let app = launchApp()

        // Choice rows carry an identifier built from their title, so this selects
        // the mode without matching on typography.
        let mode = app.buttons["choice-Re-pair this YubiKey"]
        XCTAssertTrue(mode.waitForExistence(timeout: 10), "the mode must be offered:\n\(app.debugDescription)")
        tapWhenVisible(mode, in: app)

        // The simulated card, as in the ceremony walk: the default transport is NFC,
        // which a simulator cannot provide.
        tapWhenVisible(app.buttons["choice-Simulated (debug)"], in: app)
        acknowledgePosture(in: app)
        tapPinnedPrimaryAction(app)

        // Inventory: the shared first screen, with the destructive warning gone.
        let read = app.buttons["Read YubiKey"]
        XCTAssertTrue(read.waitForExistence(timeout: 10), "inventory step missing:\n\(app.debugDescription)")
        XCTAssertFalse(
            app.staticTexts["This YubiKey already holds a key. Continuing will erase it."].exists,
            "re-pair must not warn about erasing a key it is not going to touch"
        )
        tapWhenVisible(read, in: app)

        let nonDestructive = app.staticTexts["Check the serial number against the card you intend to re-pair. Nothing will be written to it."]
        XCTAssertTrue(nonDestructive.waitForExistence(timeout: 10),
                      "the inventory step must say nothing is written:\n\(app.debugDescription)")
        tapWhenVisible(app.buttons["Continue"], in: app)

        // The read-only step, and no reset screen anywhere near it.
        let readManifest = app.buttons["Read pairing manifest"]
        XCTAssertTrue(readManifest.waitForExistence(timeout: 10),
                      "re-pair step missing:\n\(app.debugDescription)")
        XCTAssertFalse(app.buttons["Reset applet"].exists, "re-pair must never offer the reset")

        // A simulated card that was never provisioned has nothing to pair from, so
        // the read must refuse rather than produce codes from an empty object.
        tapWhenVisible(readManifest, in: app)
        let refusal = app.staticTexts.containing(
            NSPredicate(format: "label CONTAINS %@", "no pairing manifest")
        ).firstMatch
        XCTAssertTrue(refusal.waitForExistence(timeout: 10),
                      "an empty card must be refused with a reason:\n\(app.debugDescription)")

        // And the gate held: there is still no way forward to a QR code.
        XCTAssertFalse(app.buttons["Prepare pairing codes"].exists)
    }
}
