import VaultKit
import XCTest

/// The signing flow, driven end to end in the simulator.
///
/// The camera cannot be used in a simulator, so the request arrives through the
/// DEBUG-only sample button, which goes through the same decoder and the same
/// ceremony as a scanned one. Everything else is the real flow: a card provisioned
/// by the provisioning flow in the same app session, the real manifest check, the
/// real approval gate, a signature from the simulated card, verification, and the
/// `eth-signature` QR.
final class SigningFlowUITests: XCTestCase {
    private static let userPIN = "246810"
    private static let adminPIN = "87654321"
    private static let entropy = [UInt8](repeating: 0, count: 32)

    /// The address the deterministic (all-zero entropy) mnemonic derives, computed
    /// here rather than copied: the card signs for it, `tools/derive` agrees, and
    /// the screen has to match both.
    private static func expectedAddress() throws -> String {
        let words = try BIP39.mnemonic(fromEntropy: entropy)
        let seed = try BIP39.seed(mnemonic: words)
        let master = try ExtendedPrivateKey.master(seed: seed)
        let leaf = try master.derived(try DerivationPath("m/44'/0'/0'/0/0"))
        return try EVMAddress.checksummed(fromPublicKey: try leaf.publicKey())
    }

    override func setUp() {
        continueAfterFailure = false
    }

    func testSigningAProvisionedCardProducesAScannableSignature() throws {
        let expectedAddress = try Self.expectedAddress()
        // The simulated card, seeded as the connection: a simulator cannot do NFC, and the
        // choice is made once on the device screen rather than per flow.
        let app = launchApp(
            deviceChoice: "simulated",
            arguments: ["-deterministic-entropy", String(repeating: "00", count: 32)]
        )

        // 1. Provision the simulated card through the real ceremony, so the card
        //    carries a key and a pairing manifest.
        openProvisioningFlow(app)
        try advanceToMnemonicStep(app, userPIN: Self.userPIN, adminPIN: Self.adminPIN)
        try revealAndConfirmMnemonic(app, entropy: Self.entropy)
        completeCeremonyAfterMnemonic(app, expectedEVMAddress: expectedAddress)
        tapStepAction("Provision another wallet", in: app)

        // 2. Back at the home screen, choose the signing flow.
        let signingRoute = app.buttons["route-signing"]
        XCTAssertTrue(signingRoute.waitForExistence(timeout: 10), "the app must return to the home screen")
        tapWhenVisible(signingRoute, in: app)

        // 3. Scan the request **first**: the DEBUG sample stands in for the camera. No
        //    card has been touched at this point, which is the point of the order — the
        //    request names the one key the card will be asked for.
        tapWhenVisible(app.buttons["scan-request"], in: app)
        XCTAssertFalse(
            app.staticTexts["signing-address"].exists,
            "the card's address cannot be on screen before the card has been read"
        )
        tapScrolling(app.buttons["use-sample-request"], named: "sample request", in: app)

        // 4. Now the card is read (read-only; no PIN), for the key the request named.
        tapScrolling(app.buttons["read-card"], named: "read the card", in: app)

        // The address on screen is derived from the card's own key, and must be the
        // account the provisioning ceremony exported.
        let address = app.staticTexts["signing-address"]
        XCTAssertTrue(address.waitForExistence(timeout: 15), "the signing address must be shown")
        XCTAssertEqual(address.label, expectedAddress)

        // 5. The summary: this is the screen the defect report was about.
        let headline = app.staticTexts["summary-headline"]
        XCTAssertTrue(headline.waitForExistence(timeout: 15), "the transaction summary must be shown")
        XCTAssertTrue(headline.label.contains("Send"), headline.label)
        XCTAssertTrue(app.staticTexts["1 ETH"].exists || app.staticTexts.containing(
            NSPredicate(format: "label CONTAINS %@", "1 ETH")
        ).firstMatch.exists, "the value must be on the summary")
        XCTAssertTrue(
            app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "0x3535353535353535353535353535353535353535"))
                .firstMatch.exists,
            "the recipient must be on the summary"
        )

        // The chain id is unconfirmed in this session, so the flow asks first — and
        // approval is not offered until it is answered.
        XCTAssertTrue(
            app.buttons["confirm-chain"].waitForExistence(timeout: 5),
            "an unconfirmed chain id must be asked about explicitly"
        )
        XCTAssertFalse(
            app.buttons["approve-transaction"].exists,
            "approval must not be offered before the chain id is confirmed"
        )
        tapScrolling(app.buttons["confirm-chain"], named: "chain confirmation", in: app)
        XCTAssertTrue(
            app.buttons["approve-transaction"].waitForExistence(timeout: 5),
            "confirmation must unblock approval"
        )

        // 6. Approve, then sign with one touch.
        tapScrolling(app.buttons["approve-transaction"], named: "approval", in: app)
        let acknowledge = app.switches["acknowledge-touch-rule"]
        XCTAssertTrue(acknowledge.waitForExistence(timeout: 10), "the one-touch rule must be stated before signing")
        tapScrolling(acknowledge, named: "one-touch acknowledgement", in: app)
        typeSecret(Self.userPIN, into: "User PIN", in: app)
        tapScrolling(app.buttons["sign-transaction"], named: "sign action", in: app)

        // 7. The signature QR, and a record that says what happened.
        let qr = app.images["QR code"]
        if !qr.waitForExistence(timeout: 20) {
            let banner = app.staticTexts["signing-error"].exists
                ? app.staticTexts["signing-error"].label
                : "(no error banner on screen)"
            XCTFail("the signature QR must be shown. Error shown: \(banner)\n\(app.debugDescription)")
        }
        XCTAssertTrue(
            app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "Signature verified"))
                .firstMatch.waitForExistence(timeout: 10),
            "the record must say the signature was verified"
        )
        XCTAssertTrue(
            app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "1 (one signature)"))
                .firstMatch.exists,
            "the counter change must be recorded: one signature, not more"
        )
    }

}
