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

    /// The regression test for the reported defect: after reading the manifest, the
    /// pairing step showed no QR code and no addresses, so there was nothing to
    /// import into a wallet.
    ///
    /// The cause was that the pairing screen rendered its codes from `derivedKeys`,
    /// which only exists when a mnemonic was entered — and a re-pair deliberately
    /// has none. The screen now renders from the ceremony record, which both routes
    /// fill in. This test therefore provisions a card the whole way through (which
    /// also proves the complete ceremony finishes in the app, previously untested),
    /// then re-pairs it and asserts the codes and the address are on screen.
    func testRePairingAProvisionedCardShowsTheCodesAndTheAddress() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-deterministic-entropy", Self.zeroEntropyHex]
        app.launch()
        XCTAssertTrue(app.buttons["begin-ceremony"].waitForExistence(timeout: 15), app.debugDescription)

        // The address an independent implementation derives from the same mnemonic
        // the app was given: the pairing screen has to show this exact string.
        let entropy = [UInt8](repeating: 0, count: 32)
        let words = try BIP39.mnemonic(fromEntropy: entropy)
        let seed = try BIP39.seed(mnemonic: words)
        let master = try ExtendedPrivateKey.master(seed: seed)
        let leaf = try master.derived(try DerivationPath("m/44'/0'/0'/0/0"))
        let expectedEVM = try EVMAddress.checksummed(fromPublicKey: try leaf.publicKey())

        // Provision for real, so the card on the other side of the APDU layer holds
        // keys and the manifest that describes them.
        advanceToMnemonicStep(app, userPIN: Self.userPIN, adminPIN: Self.adminPIN)
        try revealAndConfirmMnemonic(app, entropy: entropy)
        completeCeremonyAfterMnemonic(app, expectedEVMAddress: expectedEVM)

        // Back to setup for the read-only pass. The card is a process-wide mock, so
        // it is still provisioned — which is exactly the state this mode is for.
        tapStepAction("Provision another wallet", in: app)
        let mode = app.buttons["choice-Re-pair this YubiKey"]
        XCTAssertTrue(mode.waitForExistence(timeout: 10), app.debugDescription)
        tapWhenVisible(mode, in: app)
        tapWhenVisible(app.buttons["choice-Simulated (debug)"], in: app)
        acknowledgePosture(in: app)
        tapPinnedPrimaryAction(app)

        tapStepAction("Read YubiKey", in: app)
        tapStepAction("Continue", in: app)
        tapStepAction("Read pairing manifest", in: app)
        XCTAssertTrue(
            app.staticTexts["The stored manifest matches the keys in this YubiKey."].waitForExistence(timeout: 10),
            "the manifest must be checked against the card:\n\(app.debugDescription)"
        )
        tapStepAction("Continue", in: app)

        // The defect: this screen had no codes on it.
        let acknowledge = app.switches["I understand that only the address shown here can be signed for"]
        XCTAssertTrue(acknowledge.waitForExistence(timeout: 10), "pairing step missing:\n\(app.debugDescription)")
        tapWhenVisible(acknowledge, in: app)
        tapStepAction("Prepare pairing codes", in: app)

        XCTAssertTrue(
            app.images["QR code"].waitForExistence(timeout: 10),
            "the re-pair must show a QR code to import:\n\(app.debugDescription)"
        )
        XCTAssertTrue(
            app.staticTexts[expectedEVM].waitForExistence(timeout: 10),
            "the re-pair must show the address to check against the wallet:\n\(app.debugDescription)"
        )
        // Both keys, so a wallet can import the pair.
        XCTAssertGreaterThanOrEqual(
            app.images.matching(identifier: "QR code").count, 2,
            "both keys need a code:\n\(app.debugDescription)"
        )
    }

    private static let userPIN = "246810"
    private static let adminPIN = "87654321"
    private static let zeroEntropyHex = String(repeating: "00", count: 32)
}
