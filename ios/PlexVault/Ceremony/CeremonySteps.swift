import SwiftUI
import VaultKit
import YubikeyKit

/// One algorithm's block inside a multi-key step.
///
/// The ceremony now produces two keys at once, so every step that used to show
/// "the key" shows two of these instead, labelled with the algorithm and the
/// slot it lands in.
struct KeySection: View {
    let title: String
    var subtitle: String?
    var identities: [(String, String)] = []
    var rows: [(String, String)] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.weight(.semibold))
                if let subtitle {
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
            }
            ForEach(Array(identities.enumerated()), id: \.offset) { _, entry in
                AddressDisplay(label: entry.0, value: entry.1)
            }
            if !rows.isEmpty { KeyValueRows(rows: rows) }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Step 2: card inventory

struct InventoryStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    private var hasInventory: Bool { viewModel.inventory != nil }

    private var isRePair: Bool { viewModel.mode == .rePair }

    var body: some View {
        StepScaffold(
            why: isRePair
                ? "Read the card before trusting anything on it. This records the applet version and serial number, and confirms both key slots are occupied — the manifest is only worth reading from a card that holds the keys it describes."
                : "Read the card before changing anything. This records the applet version, the serial number, which key slots are already occupied, and the signature-counter baseline in your provisioning record.",
            caution: !isRePair && viewModel.cardHoldsAnyKey
                ? "This YubiKey already holds a key. Continuing will erase it."
                : nil,
            actionTitle: hasInventory ? "Continue" : "Read YubiKey",
            isBusy: viewModel.busy,
            isEnabled: !viewModel.isUnsupportedApplet,
            action: {
                if hasInventory {
                    viewModel.advance()
                } else {
                    Task { await viewModel.inspectCard() }
                }
            }
        ) {
            if let inventory = viewModel.inventory {
                KeyValueRows(rows: viewModel.cardInventorySummary)

                if inventory.isDefinitelyUnsupported {
                    Label(
                        "This YubiKey's OpenPGP applet is version \(inventory.openPGPVersion) — too old to provision. Firmware 5.2.3 / applet 3.4 or newer is required, and the firmware cannot be upgraded.",
                        systemImage: "xmark.octagon.fill"
                    )
                    .font(.footnote)
                    .foregroundStyle(.red)
                } else if !inventory.likelySupportsSecp256k1 {
                    Label(
                        "This applet version may not support secp256k1 or Ed25519. YubiKey firmware 5.2.3 or newer is required.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .font(.footnote)
                    .foregroundStyle(.orange)
                }

                Text(isRePair
                     ? "Check the serial number against the card you intend to re-pair. Nothing will be written to it."
                     : "Check the serial number against the key you intend to provision, then continue.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text(viewModel.transportChoice == .usbC
                     ? "Plug the YubiKey into the USB-C port. OTP must be disabled (ykman config usb --disable OTP) or the keyboard will not appear."
                     : "Hold the YubiKey against the top of the iPhone when the reader appears.")
                    .font(.callout)
            }
        }
    }
}

// MARK: - Step 3: reset

struct ResetStepView: View {
    @Bindable var viewModel: CeremonyViewModel
    @State private var confirmReset = false

    var body: some View {
        StepScaffold(
            why: "Terminates and re-activates the OpenPGP applet, which clears the keys in every slot, resets the PINs to their factory defaults and sets the signature counter back to zero.",
            caution: "This erases everything already on the OpenPGP applet, in both the signature and authentication slots. Three wrong Admin PIN entries also make this card unusable for provisioning, so check the PIN before confirming.",
            actionTitle: "Reset applet",
            isBusy: viewModel.busy,
            isEnabled: viewModel.resetAdminPIN.count >= 8,
            action: { confirmReset = true }
        ) {
            if viewModel.cardHoldsAnyKey {
                Toggle(
                    "I understand this erases the existing key on this YubiKey",
                    isOn: $viewModel.acknowledgeDestructiveReset
                )
                .font(.footnote)
            }

            SecretEntryField(
                title: "Admin PIN (PW3)",
                prompt: "Factory default is 12345678",
                text: $viewModel.resetAdminPIN,
                isNumeric: true
            )

            Text("A factory-reset key uses 12345678. If this YubiKey was provisioned before, enter the Admin PIN you set then — and note that three wrong attempts permanently block this card for provisioning.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .confirmationDialog(
            "Reset the OpenPGP applet on this YubiKey?",
            isPresented: $confirmReset,
            titleVisibility: .visible
        ) {
            Button("Reset and erase", role: .destructive) {
                Task { await viewModel.resetCard() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("All keys on the applet are deleted and the PINs return to their factory defaults.")
        }
    }
}

// MARK: - Step 4: PINs

struct PINStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    private var pinsValid: Bool {
        viewModel.userPIN.count >= 6
            && viewModel.userPIN == viewModel.userPINConfirmation
            && viewModel.adminPIN.count >= 8
            && viewModel.adminPIN == viewModel.adminPINConfirmation
            && viewModel.userPIN != viewModel.adminPIN
    }

    var body: some View {
        StepScaffold(
            why: "The User PIN is required for every signature; the Admin PIN protects configuration and is needed if the card is ever reset.",
            caution: "Three wrong Admin PIN entries permanently block this card for provisioning. Record both PINs in your password manager before continuing.",
            actionTitle: "Set PINs",
            isBusy: viewModel.busy,
            isEnabled: pinsValid,
            action: { Task { await viewModel.provisionPINs() } }
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Text("User PIN (PW1) — at least 6 digits").font(.footnote.weight(.medium))
                SecretEntryField(title: "User PIN", prompt: "6+ digits", text: $viewModel.userPIN, isNumeric: true)
                SecretEntryField(title: "Repeat User PIN", prompt: "6+ digits", text: $viewModel.userPINConfirmation, isNumeric: true)
            }

            VStack(alignment: .leading, spacing: 12) {
                Text("Admin PIN (PW3) — at least 8 digits").font(.footnote.weight(.medium))
                SecretEntryField(title: "Admin PIN", prompt: "8+ digits", text: $viewModel.adminPIN, isNumeric: true)
                SecretEntryField(title: "Repeat Admin PIN", prompt: "8+ digits", text: $viewModel.adminPINConfirmation, isNumeric: true)
            }

            if !pinsValid {
                Text("Both PINs must meet the length rules, match their confirmation, and differ from each other.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 5: policy

struct PolicyStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Writes two permanent policies to both signing-capable slots: the key requires a physical touch for every use and cannot be relaxed later, and the User PIN must be re-entered for every signature.",
            caution: "These policies are the basis of the whole scheme's security. If the read-back check after this step reports a discrepancy, stop.",
            actionTitle: "Apply policy",
            isBusy: viewModel.busy,
            action: { Task { await viewModel.applyPolicy() } }
        ) {
            KeyValueRows(rows: [
                ("Signature slot touch policy (UIF 0xD6)", "Fixed — 02"),
                ("Authentication slot touch policy (UIF 0xD8)", "Fixed — 02"),
                ("PW1 status (0xC4[0])", "0x00 — PIN required per signature"),
                ("Expected APDUs", "00 DA 00 D6 02 02 20, 00 DA 00 D8 02 02 20"),
            ])
            Text("Touch policy is written to the authentication slot too, even though that key's signatures are not counted by the hardware counter.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - Step 6: entropy

struct EntropyStepView: View {
    @Bindable var viewModel: CeremonyViewModel
    @State private var commitmentRecorded = false

    private var hasCommitment: Bool { viewModel.entropyCommitment != nil }

    var body: some View {
        StepScaffold(
            why: "The 24 words are generated from 256 bits produced by the YubiKey's hardware random-number generator (GET CHALLENGE). One mnemonic backs up both signing keys. The commitment below lets you verify later that the mnemonic you wrote down is the one this device generated.",
            actionTitle: hasCommitment ? "Reveal the mnemonic" : "Generate entropy",
            isEnabled: !hasCommitment || commitmentRecorded,
            action: {
                if hasCommitment {
                    // Advancing here is also what derives the words, so the
                    // mnemonic step can never be reached empty.
                    viewModel.advance()
                } else {
                    Task { await viewModel.generateEntropy() }
                }
            }
        ) {
            if let commitment = viewModel.entropyCommitment {
                AddressDisplay(label: "Entropy commitment (first 8 hex of SHA-256)", value: commitment)
                Text("Write this on your provisioning record before continuing.")
                    .font(.caption).foregroundStyle(.secondary)

                Toggle("I have written down the entropy commitment", isOn: $commitmentRecorded)
                    .font(.footnote)
                    .padding(.top, 4)

                Divider().padding(.vertical, 4)

                Text("Optional dice ritual").font(.footnote.weight(.medium))
                Text("""
                Rolling dice does not change the generated words in this version — the \
                system CSPRNG is authoritative. You may still roll >= 99 times and record \
                the sequence as a ceremony witness, but it cannot be used to reproduce the \
                mnemonic afterwards.
                """)
                .font(.caption)
                .foregroundStyle(.secondary)

                HStack(spacing: 6) {
                    ForEach(1...6, id: \.self) { face in
                        Button("\(face)") { viewModel.recordDiceRoll(face) }
                            .buttonStyle(.bordered)
                    }
                }
                if !viewModel.diceRolls.isEmpty {
                    Text("Rolls recorded: \(viewModel.diceRolls.count)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("256 bits of entropy will be generated on this device and never leave it.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 7: mnemonic

struct MnemonicStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    private var backfillComplete: Bool {
        viewModel.transcriptionChallenge.allSatisfy { index in
            let expected = viewModel.mnemonic.indices.contains(index) ? viewModel.mnemonic[index] : nil
            return viewModel.backfillEntries[index]?.trimmingCharacters(in: .whitespaces).lowercased() == expected
        }
    }

    var body: some View {
        if viewModel.mode == .restoreFromMnemonic && viewModel.mnemonic.isEmpty {
            restoreView
        } else {
            generateView
        }
    }

    private var restoreView: some View {
        StepScaffold(
            why: "Enter the existing 24-word mnemonic. It is checked against the BIP39 checksum before any key is derived, and it stays in memory only for this ceremony. The same words re-derive both the secp256k1 and the Ed25519 key.",
            caution: "The words enter this app's memory. Only do this on a device you trust, and never on an online computer.",
            actionTitle: "Check and accept mnemonic",
            isEnabled: !viewModel.restoreWords.split(whereSeparator: \.isWhitespace).isEmpty,
            action: { viewModel.restoreMnemonic() }
        ) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Mnemonic words").font(.subheadline.weight(.medium))
                TextEditor(text: $viewModel.restoreWords)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 140)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.3)))
            }
        }
    }

    private var generateView: some View {
        StepScaffold(
            why: "Transcribe these 24 words onto your steel plate now. They are the only backup of the wallet; the YubiKey can be replaced, the words cannot. This one mnemonic restores both keys.",
            caution: viewModel.screenIsCaptured
                ? "Screen recording or mirroring is active. The words cannot be shown."
                : "No cameras, no screenshots. The words hide themselves again after \(CeremonyViewModel.revealWindowSeconds) seconds.",
            actionTitle: "Confirm transcription",
            isEnabled: backfillComplete,
            secondaryTitle: viewModel.mnemonicRevealed ? "Hide the words now" : nil,
            secondaryAction: viewModel.mnemonicRevealed ? { viewModel.hideMnemonic() } : nil,
            action: { viewModel.confirmTranscription() }
        ) {
            mnemonicPanel

            VStack(alignment: .leading, spacing: 10) {
                Text("Back-fill these words to prove the transcription")
                    .font(.subheadline.weight(.medium))
                ForEach(viewModel.transcriptionChallenge, id: \.self) { index in
                    HStack {
                        Text("Word \(index + 1)").font(.footnote.monospacedDigit()).frame(width: 70, alignment: .leading)
                        TextField("word", text: Binding(
                            get: { viewModel.backfillEntries[index] ?? "" },
                            set: { viewModel.backfillEntries[index] = $0 }
                        ))
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .textContentType(.oneTimeCode)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var mnemonicPanel: some View {
        if viewModel.mnemonic.isEmpty {
            // Unreachable by construction: the words are derived when the entropy
            // step completes. Kept as an explicit state so a future regression
            // shows a message instead of a blank panel (which is what the
            // "empty mnemonic list" bug looked like).
            Label("The mnemonic has not been generated. Go back to the entropy step and continue.", systemImage: "exclamationmark.triangle")
                .font(.footnote)
                .foregroundStyle(.orange)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.orange.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 10))
        } else if viewModel.mnemonicRevealed {
            VStack(alignment: .leading, spacing: 8) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 104), spacing: 8)], spacing: 8) {
                    ForEach(Array(viewModel.mnemonic.enumerated()), id: \.offset) { index, word in
                        HStack(spacing: 6) {
                            Text("\(index + 1).").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            Text(word).font(.system(.callout, design: .monospaced))
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.secondary.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
                Label("Hiding in \(viewModel.revealSecondsRemaining)s", systemImage: "timer")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        } else {
            Button {
                viewModel.revealMnemonic()
            } label: {
                VStack(spacing: 10) {
                    Image(systemName: "eye.fill").font(.largeTitle)
                    Text("Reveal the 24 words")
                        .font(.headline)
                    Text("They will hide again after \(CeremonyViewModel.revealWindowSeconds) seconds.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 28)
                .background(Color.accentColor.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .disabled(viewModel.screenIsCaptured)
            .accessibilityIdentifier("reveal-mnemonic")
        }
    }
}

// MARK: - Step 8: derivation

struct DerivationStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Derives both signing keys from the one mnemonic: secp256k1 at \(DerivationPath.secp256k1Default.description) via BIP32, and Ed25519 at \(DerivationPath.ed25519Default.description) via SLIP-0010. The private keys stay in memory until they are imported into the YubiKey.",
            actionTitle: viewModel.derivedKeys == nil ? "Derive keys" : "Continue",
            action: {
                if viewModel.derivedKeys == nil {
                    viewModel.deriveKeys()
                } else {
                    viewModel.advance()
                }
            }
        ) {
            if let keys = viewModel.derivedKeys {
                ForEach(keys.all, id: \.algorithm) { key in
                    KeySection(
                        title: key.algorithm.displayName,
                        subtitle: key.slot.displayName,
                        identities: identityRows(for: key),
                        rows: [
                            ("Path", key.path.description),
                            ("Public key", key.publicKeyHex),
                            ("Key fingerprint", key.fingerprintHex),
                            ("Parent fingerprint", key.parentFingerprintHex),
                            ("Master fingerprint", key.masterFingerprintHex),
                        ]
                    )
                }
                Text("These are the values the read-back check verifies against the YubiKey after import.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Deriving takes a moment: PBKDF2 with 2048 iterations, then BIP32 for secp256k1 and SLIP-0010 for Ed25519.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    /// secp256k1 yields two addresses from one key; Ed25519's identity is the key.
    private func identityRows(for key: DerivedKeySummary) -> [(String, String)] {
        var rows: [(String, String)] = []
        if let evm = key.evmAddress { rows.append(("EVM address", evm)) }
        if let btc = key.bitcoinAddress { rows.append(("Bitcoin address", btc)) }
        if rows.isEmpty { rows.append(("Identity (public key)", key.identity)) }
        return rows
    }
}

// MARK: - Step 9: import

struct ImportStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Writes both private keys into the YubiKey — secp256k1 into the signature slot, Ed25519 into the authentication slot — along with each key's algorithm attributes, fingerprint and creation time. This is the only step that puts key material on the card.",
            caution: "Do not remove the YubiKey during this step.",
            actionTitle: "Import keys into YubiKey",
            isBusy: viewModel.busy,
            action: { Task { await viewModel.importKeys() } }
        ) {
            if let keys = viewModel.derivedKeys {
                ForEach(keys.all, id: \.algorithm) { key in
                    KeySection(
                        title: key.algorithm.displayName,
                        subtitle: key.slot == .signature
                            ? "\(key.slot.displayName) (CRT B6) — counted by the hardware signature counter"
                            : "\(key.slot.displayName) (CRT A4) — no hardware signature counter",
                        rows: [
                            ("Algorithm", key.algorithm == .secp256k1
                                ? "ECDSA secp256k1 (1.3.132.0.10)"
                                : "EdDSA Ed25519 (1.3.6.1.4.1.11591.15.1)"),
                            ("Key", key.publicKeyHex),
                            ("Fingerprint", key.fingerprintHex),
                        ]
                    )
                }
                Text("Both keys are written in one pass; the card must accept each before the ceremony continues.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 10: read-back

struct ReadBackStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Reads each public key back out of the YubiKey and compares it byte-for-byte against the key derived on this device. This is the mandatory check that the card holds the keys you think it does; a mismatch on either key voids the whole procedure.",
            actionTitle: viewModel.readBack.isEmpty ? "Verify read-back" : "Continue",
            isBusy: viewModel.busy,
            action: {
                if viewModel.readBack.isEmpty {
                    Task { await viewModel.verifyReadBack() }
                } else {
                    viewModel.advance()
                }
            }
        ) {
            if !viewModel.readBack.isEmpty {
                ForEach(KeyAlgorithm.allCases, id: \.self) { algorithm in
                    if let result = viewModel.readBack[algorithm] {
                        KeySection(
                            title: algorithm.displayName,
                            subtitle: result.slot.displayName,
                            rows: [
                                ("Matches derived key", result.matches ? "yes" : "NO"),
                                ("Key from YubiKey", result.cardPublicKeyHex),
                                ("Derived key", result.derivedPublicKeyHex),
                                ("Identity from YubiKey key", result.identityFromCardKey),
                            ]
                        )
                    }
                }
                if viewModel.allReadBacksSucceeded {
                    Label("The YubiKey holds exactly the derived keys.", systemImage: "checkmark.seal.fill")
                        .font(.footnote)
                        .foregroundStyle(.green)
                }
            } else {
                Text("No PIN is required for this read. The card returns public keys, which are public data.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Re-pair: read the manifest off the card

/// The read-only mode's whole surface. No PIN, no mnemonic, no writes: the card
/// already holds everything a wallet needs, because the provisioning ceremony put
/// it there — and the codes are only shown after the manifest has been checked
/// against the keys the card reports for itself.
struct RepairStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Reads the pairing keys out of the YubiKey itself — the account-level public keys and chain codes a desktop wallet needs — and checks them against the keys the card reports for its own slots. Nothing is written and the mnemonic is not needed, so the keys stay in the card.",
            actionTitle: viewModel.repairedKeys.isEmpty ? "Read pairing manifest" : "Continue",
            isBusy: viewModel.busy,
            action: {
                if viewModel.repairedKeys.isEmpty {
                    Task { await viewModel.readPairingManifest() }
                } else {
                    viewModel.advance()
                }
            }
        ) {
            if !viewModel.repairedKeys.isEmpty {
                Label("The stored manifest matches the keys in this YubiKey.", systemImage: "checkmark.seal.fill")
                    .font(.callout)
                    .foregroundStyle(.green)
                ForEach(KeyAlgorithm.allCases, id: \.self) { algorithm in
                    if let key = viewModel.repairedKeys[algorithm] {
                        KeySection(
                            title: algorithm.displayName,
                            subtitle: KeySlot(rawValue: key.slot)?.displayName ?? key.slot,
                            rows: [
                                ("Source fingerprint", key.masterFingerprintHex ?? "—"),
                                ("Pairing path", key.pairingPath ?? "—"),
                                ("Key in the card", key.publicKeyHex ?? "—"),
                                ("Identity from that key", key.identity),
                            ]
                        )
                    }
                }
                if let note = viewModel.repairedFromSerial {
                    Text("Read from YubiKey \(note). The card has not been modified; the next screen produces the pairing codes.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Text("This read needs no PIN. If the card has no stored manifest — it was reset, or provisioned before the manifest existed — there is nothing to re-pair from, and the ceremony with the mnemonic is the only way back.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 7b: pairing manifest

/// Stores the public material a wallet needs in the card itself, so the pairing
/// codes can be produced again later without resetting the applet — the chain
/// code is not readable out of a YubiKey, and re-running the ceremony destroys
/// the keys.
struct ManifestStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Stores the public keys and chain codes a desktop wallet needs inside the YubiKey's private-use data object, and reads them straight back. This is what makes the pairing codes reproducible later without resetting the applet: a chain code cannot be read out of the card, only out of the mnemonic. Nothing secret is written — it is the same material the wallet is given — and the card's own key is checked against it before anything is advertised.",
            actionTitle: viewModel.pairingManifestStored == nil ? "Store pairing manifest" : "Continue",
            isBusy: viewModel.busy,
            action: {
                if viewModel.pairingManifestStored == nil {
                    Task { await viewModel.writePairingManifest() }
                } else {
                    viewModel.advance()
                }
            }
        ) {
            if let stored = viewModel.pairingManifestStored {
                if stored {
                    Label("Stored on the YubiKey and read back byte-for-byte.", systemImage: "checkmark.seal.fill")
                        .font(.callout)
                        .foregroundStyle(.green)
                    Text("A later re-pair can read this off the card, so it will not need the mnemonic and will not reset the applet. A reset erases it.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Label("Not stored on this card — the pairing codes are only available now.", systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                    if let note = viewModel.pairingManifestNote {
                        Text(note).font(.caption).foregroundStyle(.secondary)
                    }
                    Text("This does not affect the keys or the mnemonic. Re-pairing later will mean running the ceremony again with the mnemonic.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Text("This write needs the Admin PIN, which is re-verified in this session. The object is readable afterwards with no PIN — that is what makes a re-pair possible without one.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 11: pairing

struct PairingStepView: View {
    @Bindable var viewModel: CeremonyViewModel
    @State private var showAdvanced = false

    private var prepared: Bool { viewModel.pairingPrepared }

    var body: some View {
        StepScaffold(
            why: "Scan both codes with your desktop wallet's QR hardware-wallet import. Each carries one public key, its derivation path and the master fingerprint — never a private key.",
            actionTitle: prepared ? "Continue" : "Prepare pairing codes",
            isEnabled: prepared
                ? viewModel.pairingAddressConfirmed
                : viewModel.acknowledgeChainCodeWarning,
            secondaryTitle: prepared ? "Regenerate with current settings" : nil,
            secondaryAction: prepared ? { viewModel.buildPairingURs() } : nil,
            action: {
                if prepared {
                    viewModel.advance()
                } else {
                    viewModel.buildPairingURs()
                }
            }
        ) {
            chainCodeWarning

            if prepared {
                ForEach(KeyAlgorithm.allCases, id: \.self) { algorithm in
                    if let key = viewModel.keyRecord(for: algorithm) {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(algorithm.displayName).font(.subheadline.weight(.semibold))
                                Spacer(minLength: 8)
                                if viewModel.pairingAccountLevel(for: algorithm) {
                                    Text("account-level export")
                                        .font(.caption2)
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(Color.orange.opacity(0.2))
                                        .clipShape(Capsule())
                                }
                            }
                            if let urString = viewModel.pairingURStrings[algorithm],
                               let ur = try? UR(urString: urString) {
                                AnimatedURView(ur: ur)
                                Text("Type: \(ur.type)")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            if let evm = key.evmAddress {
                                AddressDisplay(label: "Address your wallet must show (EVM)", value: evm)
                            }
                            if let btc = key.bitcoinAddress {
                                AddressDisplay(label: "Address your wallet must show (Bitcoin)", value: btc)
                            }
                            if key.evmAddress == nil {
                                AddressDisplay(label: "Public key your wallet must show", value: key.identity)
                            }
                            if algorithm == .secp256k1 {
                                Text("""
                                The secp256k1 code exports the account-level key so a Keystone/MetaMask \
                                wallet can derive from it. Its derivation is pinned to the single key on \
                                this YubiKey: every account the wallet offers is the same address shown \
                                above. Do not fund any address that differs from it.
                                """)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            }
                        }
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.secondary.opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                }
            }

            Toggle("I confirmed my desktop wallet shows these exact values", isOn: Binding(
                get: { viewModel.pairingAddressConfirmed },
                set: { viewModel.setPairingAddressConfirmed($0) }
            ))
            .font(.footnote)
            .disabled(!prepared)

            DisclosureGroup("Advanced: wire format", isExpanded: $showAdvanced) {
                Picker("UR type", selection: $viewModel.pairingStyle) {
                    ForEach(URTypeStyle.allCases, id: \.self) { style in
                        Text(style.displayName).tag(style)
                    }
                }
                .pickerStyle(.inline)
                .labelsHidden()
            }
        }
    }

    /// Always visible, not hidden behind "Advanced": the payload always carries a
    /// chain code, and the operator must acknowledge that before the codes are
    /// built. This is the forced warning that pairs with the account-level export.
    private var chainCodeWarning: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Chain code required by Keystone/MetaMask", systemImage: "exclamationmark.triangle.fill")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.orange)
            Text(PairingPolicy.chainCodeWarning)
                .font(.caption)
                .foregroundStyle(.secondary)
            Toggle(
                "I understand that only the address shown here can be signed for",
                isOn: $viewModel.acknowledgeChainCodeWarning
            )
            .font(.footnote)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

// MARK: - Step 12: counter baseline

struct CounterStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Reads the YubiKey's hardware signature counter, which must be zero after an import. This number is the baseline your desktop wallet compares against later: any increase means the card signed something you did not ask for.",
            actionTitle: viewModel.counterBaseline == nil ? "Read counter" : "Continue",
            isBusy: viewModel.busy,
            action: {
                if viewModel.counterBaseline == nil {
                    Task { await viewModel.readCounterBaseline() }
                } else {
                    viewModel.advance()
                }
            }
        ) {
            if let counter = viewModel.counterBaseline {
                KeyValueRows(rows: [
                    ("Signature counter (secp256k1 / signature slot)", "\(counter)"),
                    ("Ed25519 / authentication slot", "no hardware counter"),
                ])
                Label("Baseline recorded.", systemImage: "checkmark.seal.fill")
                    .font(.footnote).foregroundStyle(.green)
                Text("""
                Only the signature slot increments a hardware counter. The Ed25519 key lives in \
                the authentication slot, so the counter audit covers your secp256k1 chains only. \
                Ed25519 signatures are still gated by the PIN and a physical touch.
                """)
                .font(.caption)
                .foregroundStyle(.secondary)
            } else {
                Text("No PIN is needed to read the counter, and it exposes no secrets.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 13: teardown

struct TeardownStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Clears the mnemonic, seed and private keys from memory and produces the provisioning record you keep with the steel plate. The app requires a restart before another ceremony.",
            actionTitle: "Wipe secrets and finish",
            action: { viewModel.finish() }
        ) {
            Text("Nothing secret is written to disk at any point in this app. The record below contains only public data.")
                .font(.callout)
        }
    }
}
