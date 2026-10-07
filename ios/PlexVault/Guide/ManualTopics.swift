import SwiftUI

/// The manual's entries: one procedure per row of the guide's table, one page each.
///
/// A procedure is looked up on its own — a card is replaced, a card is reset, a wallet is paired —
/// so each is a page rather than a section of one long document. The order is the order the work is
/// done in, and the two provisioning procedures share everything after the keys exist.
enum ManualTopic: String, CaseIterable, Identifiable, Hashable {
    case beforeYouStart
    case createWallet
    case restoreWallet
    case pairWithMetaMask
    case signWithMetaMask
    case whenSomethingGoesWrong

    var id: String { rawValue }

    var title: String {
        switch self {
        case .beforeYouStart: return "Before you start"
        case .createWallet: return "Create a YubiKey wallet"
        case .restoreWallet: return "Restore from your 24 words"
        case .pairWithMetaMask: return "Pair a wallet (MetaMask)"
        case .signWithMetaMask: return "Sign a transaction (MetaMask)"
        case .whenSomethingGoesWrong: return "When something goes wrong"
        }
    }

    var subtitle: String {
        switch self {
        case .beforeYouStart:
            return "The card, the app, the backup and the wallet you will pair with."
        case .createWallet:
            return "From entropy to two records and a paired wallet."
        case .restoreWallet:
            return "The same run, with the keys coming from your words instead of the card."
        case .pairWithMetaMask:
            return "The app shows the code; MetaMask scans it."
        case .signWithMetaMask:
            return "MetaMask shows the request; this app scans it."
        case .whenSomethingGoesWrong:
            return "The messages you may see, and which of them mean stop."
        }
    }
}

/// The page one manual entry pushes.
struct ManualTopicPage: View {
    let topic: ManualTopic

    var body: some View {
        ScrollView {
            Group {
                switch topic {
                case .beforeYouStart: BeforeYouStartTopic()
                case .createWallet: CreateWalletTopic()
                case .restoreWallet: RestoreWalletTopic()
                case .pairWithMetaMask: PairWithMetaMaskTopic()
                case .signWithMetaMask: SignWithMetaMaskTopic()
                case .whenSomethingGoesWrong: WhenSomethingGoesWrongTopic()
                }
            }
            .padding()
        }
        .navigationTitle(topic.title)
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Before you start

private struct BeforeYouStartTopic: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GuideCard(title: "You need", systemImage: "checklist") {
                GuideBullet(
                    "A YubiKey 5 series card (firmware 5.2.3 or later). One is enough; up to five can "
                        + "be written in one run, all holding the same keys."
                )
                GuideBullet(
                    "This app on the iPhone. It needs no network connection at any point — "
                        + "provisioning and signing both work with the phone offline."
                )
                GuideBullet(
                    "Something durable for the 24 words, ideally two steel plates kept in separate "
                        + "places, and a password manager for the PINs."
                )
                GuideBullet(
                    "A wallet to pair with: MetaMask in the browser, or MetaMask Mobile. The account "
                        + "it shows after pairing is the one this card can sign for."
                )
            }

            GuideCard(title: "Two things to decide first", systemImage: "questionmark.circle") {
                GuideText(
                    "How many cards this run will write. Every card gets the same two keys, so any of "
                        + "them can sign for the wallet; each gets its own PINs. More than one card "
                        + "means losing one is not losing the wallet."
                )
                GuideText(
                    "Whether the 24 words get written down. The app does not force it: with several "
                        + "cards you may continue without, and the record then says so. With a single "
                        + "card the words are the only thing that survives losing it."
                )
            }
        }
    }
}

// MARK: - Create

private struct CreateWalletTopic: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GuideCard(title: "Getting to the ceremony", systemImage: "sparkles") {
                GuideSteps(steps: [
                    GuideStep(
                        "Choose how the YubiKey is read",
                        "On the first launch: NFC — hold the phone against the key when asked — or "
                            + "USB-C, which you leave plugged in. The choice is remembered, and the "
                            + "button on the home screen shows it."
                    ),
                    GuideStep(
                        "Open the provisioning flow",
                        "Home → Wallet & Key Management → Generate a new wallet."
                    ),
                    GuideStep(
                        "Read the posture and the rules",
                        "The app states the one-touch rule and asks you to confirm the state of the "
                            + "device. Nothing has been written yet."
                    ),
                ])
            }

            GuideCard(title: "Keys, words and addresses", systemImage: "key.horizontal.fill") {
                GuideSteps(steps: [
                    GuideStep(
                        "Record the entropy commitment",
                        "The app draws randomness from the card's hardware generator and shows a "
                            + "commitment to it — a receipt for this run. Write it down if you keep "
                            + "records, and tick that you have."
                    ),
                    GuideStep(
                        "Write down the 24 words",
                        "Hold the screen to reveal them. Transcribe them onto steel, twice, and pass "
                            + "the back-fill check. The app will not show them again: after the wipe "
                            + "they exist only on your plates."
                    ),
                    GuideStep(
                        "Check the derived addresses",
                        "Both keys are derived and their addresses shown. These are the addresses "
                            + "your wallet will show once it is paired."
                    ),
                    GuideStep(
                        "Say how many YubiKeys",
                        "One to five. Every card gets the same two keys, so any of them can sign for "
                            + "the wallet; each card gets its own PINs."
                    ),
                ])
            }

            GuideCard(title: "Per card, in the order the app asks", systemImage: "creditcard") {
                GuideSteps(steps: [
                    GuideStep(
                        "Read its inventory",
                        "The serial is shown. Check it is not a card this run has already written — "
                            + "the app refuses those rather than resetting a card that now holds the "
                            + "keys."
                    ),
                    GuideStep(
                        "Reset it",
                        "No PIN is asked for; this erases the whole applet, exactly as a factory "
                            + "reset does. Do not interrupt the tap. If it stops halfway the card is "
                            + "left with both PINs blocked and the old keys in place — tapping reset "
                            + "again finishes the job."
                    ),
                    GuideStep(
                        "Choose both PINs",
                        "A 6-digit User PIN, typed for every signature, and an Admin PIN, typed "
                            + "almost never. Record both in your password manager, keyed by the "
                            + "card's serial."
                    ),
                    GuideStep(
                        "Set the retry limits",
                        "How many wrong entries each PIN tolerates before the card blocks. Three is "
                            + "the factory value and the smallest brute-force budget; using them up "
                            + "means rebuilding the card from the 24 words."
                    ),
                    GuideStep(
                        "Write and verify in one step",
                        "One action writes both keys, then the touch policy — which has to be last, "
                            + "because writing a slot's keys discards it — then the pairing manifest, "
                            + "and reads all of it back off the card. Continue appears only once "
                            + "every value has come back."
                    ),
                    GuideStep("Repeat the last five steps for each card"),
                ])
            }

            GuideCard(title: "Ending the first process", systemImage: "trash") {
                GuideSteps(steps: [
                    GuideStep(
                        "Wipe secrets",
                        "The mnemonic, the seed and both keys leave the app's memory and the "
                            + "provisioning record appears. Save it — Save to Photos or Copy. It says "
                            + "what was written into which card, and it is the only thing that can."
                    ),
                    GuideStep(
                        "Quit & Reopen App",
                        "Confirm the alert. Nothing else closes the app, and the record is gone once "
                            + "you leave it."
                    ),
                ])
            }

            GuideCard(title: "The second process", systemImage: "link") {
                GuideSteps(steps: [
                    GuideStep(
                        "Reopen the app",
                        "It opens straight on the pairing flow. Hold the card against the phone and "
                            + "read it: no PIN, and nothing is written."
                    ),
                    GuideStep(
                        "Pair the wallet",
                        "Follow \"Pair a wallet (MetaMask)\" — the app shows the codes and the wallet "
                            + "scans them."
                    ),
                    GuideStep(
                        "Save the pairing record, then finish",
                        "This step is the pairing process's own record. Finishing returns to the home "
                            + "screen, and no restart is needed before the next ceremony."
                    ),
                ])
            }

            GuideNote(
                title: "The paper backup is not forced",
                text: "If several cards will hold the keys you may continue without writing the words "
                    + "down; the record then says so and the cards are the wallet. With a single card, "
                    + "the words are the only thing that survives losing it.",
                systemImage: "exclamationmark.triangle.fill"
            )
        }
    }
}

// MARK: - Restore

private struct RestoreWalletTopic: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GuideCard(title: "Restore from a mnemonic", systemImage: "arrow.clockwise") {
                GuideSteps(steps: [
                    GuideStep(
                        "Open the restore flow",
                        "Home → Wallet & Key Management → Restore from a mnemonic."
                    ),
                    GuideStep(
                        "Read the posture and the rules",
                        "The words enter this app's memory, so the device checks matter more here "
                            + "than anywhere else. Do this on a device you trust, never on a computer."
                    ),
                    GuideStep(
                        "Enter the 24 words",
                        "Type or paste them. The BIP39 checksum is verified before any key is "
                            + "derived, so a typo is refused here rather than after a card has been "
                            + "written."
                    ),
                    GuideStep(
                        "Compare the addresses",
                        "The app shows the addresses these words produce. Compare them with the ones "
                            + "you already hold. If they differ, stop: these are not the words this "
                            + "wallet was made from, and a card written with them cannot sign for your "
                            + "funds."
                    ),
                    GuideStep(
                        "Continue exactly as for a new wallet",
                        "The card count, the reset, the PINs, the retry limits, the write-and-verify "
                            + "step, the wipe and the pairing are all the same."
                    ),
                ])
            }

            GuideNote(
                title: "What a restore changes, and what it does not",
                text: "The same words produce the same keys, so the addresses are unchanged and a "
                    + "wallet already paired to them keeps working. What is new is the card: a "
                    + "different serial, and PINs you choose now. The old card is not erased by "
                    + "restoring onto a new one — reset it separately when you retire it.",
                systemImage: "info.circle.fill",
                tint: .blue
            )
        }
    }
}

// MARK: - Pair

private struct PairWithMetaMaskTopic: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GuideText(
                "MetaMask's QR hardware wallet speaks the Keystone protocol, which is what this app "
                    + "speaks. The app shows the code and MetaMask scans it with the camera — the "
                    + "opposite of the signing direction. Menu labels move between MetaMask versions; "
                    + "what you are looking for is the QR-based option among the hardware wallets."
            )

            GuideCard(title: "In MetaMask", systemImage: "laptopcomputer") {
                GuideSteps(steps: [
                    GuideStep(
                        "Account selector → Add account or hardware wallet → Add hardware wallet → "
                            + "QR-based → Continue"
                    ),
                    GuideStep("Allow camera access", "MetaMask opens its scanner."),
                ])
            }

            GuideCard(title: "In this app", systemImage: "iphone") {
                GuideSteps(steps: [
                    GuideStep(
                        "Wallet & Key Management → Pair a wallet",
                        "This is the read-only route: it does not reset the card and does not need the "
                            + "mnemonic."
                    ),
                    GuideStep(
                        "Read the YubiKey",
                        "Hold it against the phone, or leave it plugged in. No PIN is needed to read, "
                            + "and nothing is written."
                    ),
                    GuideStep(
                        "Prepare pairing codes",
                        "Two codes appear — secp256k1 and Ed25519 — each with the address your wallet "
                            + "must show for it."
                    ),
                    GuideStep(
                        "Tick the chain-code acknowledgement",
                        "The code carries a chain code, so a wallet is able to derive accounts this "
                            + "card cannot sign for. Reading the address back is what rules that out, "
                            + "which is what the acknowledgement says."
                    ),
                ])
            }

            GuideCard(title: "Back in MetaMask", systemImage: "qrcode") {
                GuideSteps(steps: [
                    GuideStep(
                        "Scan the secp256k1 code",
                        "Point the scanner at it and hold still while it animates — MetaMask is "
                            + "collecting a whole key, so it takes a moment. The Ed25519 code is for "
                            + "wallets that take a second key; MetaMask is not one of them."
                    ),
                    GuideStep(
                        "Compare the addresses",
                        "MetaMask must show the same address the app shows for secp256k1. If it "
                            + "differs, stop and do not pair."
                    ),
                    GuideStep(
                        "Confirm and pick the account",
                        "Every account index MetaMask offers is the same address, because the export "
                            + "is pinned to the one path this card signs for. Add one. MetaMask Mobile "
                            + "refuses a second index; the extension will duplicate the same account."
                    ),
                ])
            }

            GuideCard(title: "Finishing", systemImage: "checkmark") {
                GuideSteps(steps: [
                    GuideStep(
                        "Confirm the values in this app",
                        "Tick \"I confirmed my desktop wallet shows these exact values\"."
                    ),
                    GuideStep(
                        "Continue, save the pairing record, and finish",
                        "Finishing returns to the home screen."
                    ),
                ])
            }

            GuideNote(
                title: "Re-pairing is the same route",
                text: "Losing the pairing — a reinstalled wallet, a second desktop — costs a "
                    + "re-pairing, never a card. Pair a wallet, read the card, prepare the codes: no "
                    + "mnemonic and no PIN. The one thing that cannot be re-paired is a card whose "
                    + "applet has been reset, because the manifest is erased with the keys.",
                systemImage: "info.circle.fill",
                tint: .blue
            )
        }
    }
}

// MARK: - Sign

private struct SignWithMetaMaskTopic: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GuideText(
                "The direction reverses here: MetaMask shows the request and this app scans it. "
                    + "Nothing is written to the card, and the mnemonic is not needed — if any screen "
                    + "asks for the 24 words while signing, stop."
            )

            GuideCard(title: "In MetaMask", systemImage: "laptopcomputer") {
                GuideSteps(steps: [
                    GuideStep(
                        "Build the transaction and confirm it",
                        "Use as small a value as you can make it the first time."
                    ),
                    GuideStep(
                        "Leave the request code on screen",
                        "When MetaMask asks for the signature it shows an animated QR code."
                    ),
                ])
            }

            GuideCard(title: "In this app", systemImage: "iphone") {
                GuideSteps(steps: [
                    GuideStep(
                        "Sign a transaction, and aim the camera",
                        "The camera opens directly. The preview is frosted on purpose: the app reads "
                            + "the request from the camera stream, not from the picture, so a blurred "
                            + "image is not a fault."
                    ),
                    GuideStep(
                        "Read the YubiKey",
                        "Hold it against the phone, or leave it plugged in. No PIN is needed to read."
                    ),
                    GuideStep(
                        "Check the address",
                        "It must be the account in MetaMask. A request naming a key this card does not "
                            + "sign with is refused before the card is touched."
                    ),
                    GuideStep(
                        "Read the summary",
                        "To, Value, Warnings, and the decoded function. A token transfer shows Value 0 "
                            + "with the amount in raw units in the function's arguments. If the "
                            + "function is unrecognised the raw hex is shown: compare it with MetaMask, "
                            + "or cancel and rebuild the transaction from a dapp you trust."
                    ),
                    GuideStep(
                        "Confirm the chain",
                        "Compare both the name and the id with the network MetaMask is on: the name is "
                            + "a convenience, the id is the fact. Value and fees are shown in that "
                            + "chain's own coin, never assumed to be ETH."
                    ),
                    GuideStep("Approve", "The digest shown — keccak-256 — is what gets signed."),
                    GuideStep(
                        "Tick the one-touch rule and enter the User PIN",
                        "Then tap Sign with the YubiKey."
                    ),
                    GuideStep(
                        "Touch the gold contact",
                        "The app names the touch it is waiting for. Hold the key against the phone and "
                            + "touch it when it blinks; the signature appears as soon as the card "
                            + "answers."
                    ),
                ])
            }

            GuideCard(title: "Back in MetaMask", systemImage: "qrcode") {
                GuideSteps(steps: [
                    GuideStep(
                        "Scan the signature back and let MetaMask verify",
                        "MetaMask checks the signature against the account it holds before it "
                            + "broadcasts."
                    ),
                ])
            }

            GuideNote(
                title: "Nothing has happened until MetaMask verifies",
                text: "If MetaMask refuses the signature, do not retry here — start again from "
                    + "MetaMask, which generates a new request. One transaction is one signature "
                    + "attempt, and a second attempt for the same request is the thing to walk away "
                    + "from.",
                systemImage: "checkmark.shield.fill",
                tint: .blue
            )
        }
    }
}

// MARK: - When something goes wrong

private struct WhenSomethingGoesWrongTopic: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GuideCard(title: "Provisioning", systemImage: "exclamationmark.bubble") {
                GuideBullet(
                    "The reset was interrupted. The card is left with both PINs blocked and the old "
                        + "keys still in place. Tap reset again — it still needs no PIN — and let it "
                        + "finish."
                )
                GuideBullet(
                    "The app refuses a card as already written. That is the guard against resetting a "
                        + "card that now holds the keys. Use a different card, or continue with the "
                        + "ones already written."
                )
                GuideBullet(
                    "\"This YubiKey carries no pairing manifest.\" The card was reset, or was "
                        + "provisioned before the manifest existed. Provision it again — which resets "
                        + "it — before signing."
                )
            }

            GuideCard(title: "Signing", systemImage: "signature") {
                GuideBullet(
                    "\"The YubiKey rejected the PIN.\" Nothing was signed, and the message says how "
                        + "many attempts are left. After the last one the User PIN blocks, and only "
                        + "rebuilding the card from the 24 words clears it."
                )
                GuideBullet(
                    "The touch did not come through — a timeout, or the key moved away. The card may "
                        + "have signed, so this app does not retry and does not offer a second "
                        + "attempt. Start again from the wallet with a new request."
                )
                GuideBullet(
                    "\"The signature does not match this card's key.\" No code is shown and nothing "
                        + "can be scanned. Do not retry: treat the phone as suspect and consider "
                        + "moving the funds."
                )
                GuideBullet(
                    "\"The request is for a path this YubiKey does not sign.\" The wallet offered a "
                        + "sibling account of the same extended key. Select the paired account, or "
                        + "re-pair with the account you want."
                )
                GuideBullet(
                    "A second touch is requested. It should never be. Stop, and treat the app that "
                        + "asked as compromised."
                )
            }
        }
    }
}
