import SwiftUI

/// The first half of the guide page: what the app does, and how the three parts of the scheme fit
/// together.
///
/// The order is the order the questions come in — where the key is, what the app keeps, what the
/// wallet does, how they talk, and then what the app checks and refuses. Everything here is a
/// restatement of design.md §4–§5 and §6.4; the guide is where the operator reads it, not where it
/// is decided.
struct HowItWorksView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GuideHeading("The app, the YubiKey and your wallet")

            GuideText(
                "There are three parts to this wallet, and the private key lives in exactly one of "
                    + "them. Everything else on this page follows from that."
            )

            keyCard
            appCard
            walletCard
            channelCard
            pairingCard
            keysCard
            checksCard
            refusalsCard
            processesCard
        }
    }

    private var keyCard: some View {
        GuideCard(title: "The YubiKey holds the key", systemImage: "key.horizontal.fill") {
            GuideText(
                "The private key is written into the card's OpenPGP applet and cannot be read back "
                    + "out. The app can ask the card to sign something; it can never ask the card for "
                    + "the key."
            )
            GuideText(
                "Both signing-capable slots are written with a Fixed touch policy, so a signature "
                    + "needs the User PIN and a physical touch of the gold contact. The card will not "
                    + "sign while it is sitting in a drawer, and that is the point: a signature you "
                    + "did not ask for is the attack this stops."
            )
            GuideNote(
                title: "One transaction, one touch",
                text: "If any app asks for a second touch for the same transaction, stop and treat "
                    + "that app as compromised. A failed touch is not retried here — the card may "
                    + "already have signed — so the flow restarts from the wallet with a new request.",
                systemImage: "hand.raised.fill"
            )
        }
    }

    private var appCard: some View {
        GuideCard(title: "This app holds nothing", systemImage: "iphone") {
            GuideText(
                "The app generates the key from a 24-word mnemonic, writes it into the card, and "
                    + "then wipes the mnemonic, the seed and both private keys out of its memory. "
                    + "From that moment it holds no secret at all, and the wipe screen is where that "
                    + "happens rather than a claim about it."
            )
            GuideText(
                "It contains no networking code — the release audit checks that mechanically — so "
                    + "nothing it displays can leave the phone on its own. Its whole job afterwards "
                    + "is to show you what you are about to sign and to ask the card for the "
                    + "signature."
            )
        }
    }

    private var walletCard: some View {
        GuideCard(title: "The wallet is the watch-only side", systemImage: "laptopcomputer") {
            GuideText(
                "MetaMask, or any other Keystone-compatible wallet, holds the public address, builds "
                    + "the transaction, and verifies the signature before it broadcasts. It never "
                    + "holds the key and cannot sign on its own: a transaction this app has not "
                    + "answered stays unsigned."
            )
            GuideText(
                "The wallet is also the independent party. Its check that the signature verifies "
                    + "against the digest it sent and the account it holds is the control this app "
                    + "cannot provide about itself."
            )
        }
    }

    private var channelCard: some View {
        GuideCard(title: "The only channel is a QR code", systemImage: "qrcode") {
            GuideText(
                "The wallet shows the request as an animated QR code and the app reads it with the "
                    + "camera; the app answers with an animated QR code of its own and the wallet "
                    + "scans that back. The codes are fountain-coded in the Blockchain Commons UR "
                    + "format and split over many frames — which is why they move: a whole "
                    + "transaction does not fit in one frame of a QR code."
            )
            GuideText(
                "Nothing else is used. No cable, no Bluetooth, no server, no account: the phone can "
                    + "stay offline for its entire life, and the two devices never need to reach each "
                    + "other over a network."
            )
        }
    }

    private var pairingCard: some View {
        GuideCard(title: "Pairing shares two public codes", systemImage: "link") {
            GuideText(
                "Pairing shows the wallet one code per key — secp256k1 for EVM chains, Ed25519 as the "
                    + "second key. Each carries the public key, its derivation path, the master "
                    + "fingerprint and a chain code: public data only, never a private key. "
                    + "MetaMask's QR hardware-wallet import reads the secp256k1 code."
            )
            GuideText(
                "One YubiKey slot holds exactly one key, so the secp256k1 code is exported at the "
                    + "account level with its derivation pinned to the single path this card can sign "
                    + "for. That is why MetaMask offers the same address for every account index. It "
                    + "is deliberate: the alternative would be offering addresses this card could "
                    + "never sign for."
            )
        }
    }

    private var keysCard: some View {
        GuideCard(title: "Two keys, one backup", systemImage: "number") {
            GuideBullet("secp256k1, path m/44'/0'/0'/0/0 — the EVM signing key.")
            GuideBullet("Ed25519, path m/44'/501'/0'/0' — the second key for chains that are not secp256k1.")
            GuideText(
                "Both come from the same 24 words, which are the only backup. A YubiKey can be "
                    + "recreated from them at any time and will hold the same keys and the same "
                    + "addresses; nothing else can."
            )
            GuideNote(
                title: "What this version signs",
                text: "EVM transactions: Ethereum and any other chain whose id the request names. "
                    + "Bitcoin and Ed25519 signing are not implemented yet — the keys, the addresses "
                    + "and the pairing exist, the signing does not. Requests for them are refused "
                    + "rather than approximated.",
                systemImage: "signature",
                tint: .blue
            )
        }
    }

    private var checksCard: some View {
        GuideCard(title: "What the app checks before it touches the card", systemImage: "checkmark.shield") {
            GuideBullet(
                "The request's derivation path must be this card's pinned path. A request for "
                    + "another account is refused before the card is even read."
            )
            GuideBullet(
                "The bytes it hashes are the bytes it showed you: the transaction is rebuilt from the "
                    + "decoded fields and must reproduce the input exactly."
            )
            GuideBullet(
                "The chain id must agree between the request and the transaction inside it, and you "
                    + "confirm the chain by name before anything is signed."
            )
            GuideBullet("The digest it signs is recomputed from the transaction you approved.")
            GuideBullet(
                "The signature must recover this card's key. A signature that does not is never shown "
                    + "as a QR code at all."
            )
            GuideBullet(
                "Fields the app does not recognise are refused rather than ignored: a field it cannot "
                    + "read could be one that changes what gets signed."
            )
        }
    }

    private var refusalsCard: some View {
        GuideCard(title: "What the app will not do", systemImage: "nosign") {
            GuideBullet("Ask the card to sign twice for one transaction. One transaction, one touch.")
            GuideBullet(
                "Retry a signature after a failed touch. The card may already have signed, so the "
                    + "flow stops and the next attempt starts from the wallet with a new request."
            )
            GuideBullet(
                "Store anything about your wallet, your transactions or your keys. A release build "
                    + "remembers which reader the YubiKey is on and whether a pairing is still "
                    + "pending — nothing else."
            )
            GuideBullet(
                "Read the card's signature counter. A YubiKey is used with other applications too, "
                    + "so a count on the card says nothing about what this wallet asked for."
            )
        }
    }

    private var processesCard: some View {
        GuideCard(title: "Why it asks you to quit and reopen", systemImage: "arrow.clockwise") {
            GuideText(
                "Provisioning is two processes, and the split is the point. The first generates the "
                    + "keys, writes the card, wipes the secrets and produces the record; the wipe "
                    + "screen's \"Quit & Reopen App\" is what ends it."
            )
            GuideText(
                "The second starts when you open the app again. It reads the pairing keys back out of "
                    + "the card's own stored manifest and shows them to the wallet — no mnemonic, no "
                    + "PIN, nothing secret — which is why a provisioning run that has been wiped "
                    + "reopens straight on pairing instead of on the home screen."
            )
        }
    }
}
