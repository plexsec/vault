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
                : (viewModel.cardIndex > 0
                    ? "Hold the next YubiKey against the phone, and check the serial it reports is one you have not already written in this ceremony — a card that already holds these keys is refused rather than reset, because resetting it would erase them. This records the applet version, the serial number, and which key slots are occupied."
                    : "Read the card before changing anything. This records the applet version, the serial number, and which key slots are already occupied."),
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
                     : (viewModel.cardCount > 1
                        ? "This is YubiKey \(viewModel.cardIndex + 1) of \(viewModel.cardCount). Check the serial against the card in your hand."
                        : "Check the serial number against the key you intend to provision, then continue."))
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
            why: "Terminates and re-activates the OpenPGP applet, which clears the keys in every slot and resets the PINs to their factory defaults. No PIN is needed: the app blocks both PINs and then terminates the applet, exactly as `ykman openpgp reset` does.",
            caution: "This erases everything already on the OpenPGP applet, in both the signature and authentication slots — and it does so without the Admin PIN, so a card whose Admin PIN is unknown or blocked can be reset too.",
            actionTitle: "Reset applet",
            isBusy: viewModel.busy,
            action: { confirmReset = true }
        ) {
            if viewModel.cardHoldsAnyKey {
                Toggle(
                    "I understand this erases the existing key on this YubiKey",
                    isOn: $viewModel.acknowledgeDestructiveReset
                )
                .font(.footnote)
            }

            Text("The app sends wrong PINs until the card blocks PW1 and PW3, then terminates the applet — the applet only accepts TERMINATE DF without a verified Admin PIN while that PIN is blocked, so this is the half of the reset that a wrong attempt cannot spoil. If the tap is interrupted between the two, the card is left with blocked PINs and its keys still in place; tapping reset again finishes the job, and that needs no PIN either.")
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
            Text("All keys on the applet are deleted and the PINs return to their factory defaults. No PIN is needed for this.")
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
            why: "The User PIN is required for every signature; the Admin PIN protects configuration and is needed to provision, re-pair or set the retry limits.",
            caution: "Three wrong Admin PIN entries block this card for provisioning and re-pairing — the reset step can clear it again without a PIN, but only by erasing both keys. Record both PINs in your password manager before continuing.",
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

// MARK: - Step 4b: PIN retry limits

struct RetryLimitStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    private var userLimit: Int { viewModel.userPINRetryLimit }
    private var adminLimit: Int { viewModel.adminPINRetryLimit }

    var body: some View {
        StepScaffold(
            why: "How many wrong PIN entries each password tolerates before the YubiKey blocks it. The YubiKey keeps one counter per password and refills it to this number on every correct entry; three is its factory value. The two are set separately because the passwords are not used alike — the User PIN is typed on every signature, the Admin PIN almost never — and the card stores them separately anyway.",
            caution: "Each number is that password's brute-force budget, and also how many typos stand between you and a blocked card. The User PIN is 6 digits and typed often; the Admin PIN is 8 and rarely typed at all. Keep both low.",
            actionTitle: "Set PIN retry limits",
            isBusy: viewModel.busy,
            action: { Task { await viewModel.setPINRetryLimits() } }
        ) {
            Stepper(value: Binding(
                get: { viewModel.userPINRetryLimit },
                set: { viewModel.userPINRetryLimit = $0 }
            ), in: CardPolicy.retryLimits) {
                Text("User PIN attempts allowed: **\(userLimit)**")
            }
            .accessibilityIdentifier("pin-retry-limit-user")

            Stepper(value: Binding(
                get: { viewModel.adminPINRetryLimit },
                set: { viewModel.adminPINRetryLimit = $0 }
            ), in: CardPolicy.retryLimits) {
                Text("Admin PIN attempts allowed: **\(adminLimit)**")
            }
            .accessibilityIdentifier("pin-retry-limit-admin")

            KeyValueRows(rows: [
                ("User PIN (PW1)", "\(userLimit) wrong entries, then blocked"),
                ("Admin PIN (PW3)", "\(adminLimit) wrong entries, then blocked"),
            ])

            VStack(alignment: .leading, spacing: 6) {
                Text("If every attempt is used up").font(.footnote.weight(.semibold))
                Text("""
                **User PIN blocked** — nothing can be signed until it is unblocked, and unblocking needs the Admin PIN.

                **Admin PIN blocked** — the card can no longer be provisioned or re-paired. The reset step clears it again and needs no PIN, but it also erases all keys.

                The funds are not lost while the 24 words mnemonic is safe, but the YubiKey has to be set up again from them.
                """)
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 4b: how many YubiKeys

/// The count comes after the keys exist and before any card is touched: it is what tells the
/// mnemonic step how much the paper backup matters, and it is what the per-card block below
/// is repeated for.
struct CardCountStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Every YubiKey written here gets the same two private keys and the same pairing material, so any of them can sign for this wallet. Each one is provisioned in its own pass — reset, PINs, retry limits, write and read back — so the number is what the next steps will repeat.",
            caution: viewModel.cardCount == 1
                ? "With one YubiKey there is no second copy of these keys. Write the 24 words down: if this card is lost, reset or destroyed, they are the only way back to the wallet."
                : nil,
            actionTitle: "Continue",
            isBusy: viewModel.busy,
            action: { Task { await viewModel.setCardCount() } }
        ) {
            Stepper(value: Binding(
                get: { viewModel.cardCount },
                set: { viewModel.cardCount = $0 }
            ), in: CardPolicy.cardCountRange) {
                Text("YubiKeys to provision: **\(viewModel.cardCount)**")
            }
            .accessibilityIdentifier("card-count")

            Text("Each YubiKey gets its own User PIN and Admin PIN; the retry limits are one decision for the whole ceremony and are written to every card. Have every card to hand before starting — the next card cannot be skipped once this run has begun.")
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
            why: "The 24 words mnemonic is generated from 256 bits entropy produced by the YubiKey's hardware random-number generator, together with iOS system CSPRNG. The commitment below lets you verify later that the mnemonic you wrote down is the one this device generated.",
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

            } else {
                Text("256 bits of entropy will be generated on this device and never leave it, or be stored.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 7: mnemonic

struct MnemonicStepView: View {
    @Bindable var viewModel: CeremonyViewModel
    @State private var confirmSkip = false

    /// The backup is optional, and the model is where that is decided: a restore ceremony's
    /// words came from an existing backup, so there is nothing new to write down there.
    private var canSkipBackup: Bool { viewModel.mode == .freshGeneration }

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
            why: "Transcribe these 24 words onto your steel plate now. They are the only backup of the wallet; a YubiKey can be replaced from them, and nothing else can.",
            caution: viewModel.screenIsCaptured
                ? "Screen recording or mirroring is active. The words cannot be shown."
                : (viewModel.cardCount == 1
                    ? "This is the only copy. With one YubiKey, the words are the whole backup: no second card holds these keys. No cameras, no screenshots."
                    : "No cameras, no screenshots. The words hide themselves again after \(CeremonyViewModel.revealWindowSeconds) seconds."),
            actionTitle: "Confirm transcription",
            isEnabled: backfillComplete,
            secondaryTitle: viewModel.mnemonicRevealed
                ? "Hide the words now"
                : (canSkipBackup ? "Continue without writing them down" : nil),
            secondaryAction: viewModel.mnemonicRevealed
                ? { viewModel.hideMnemonic() }
                : (canSkipBackup ? { confirmSkip = true } : nil),
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
        .confirmationDialog(
            "Provision without a paper backup?",
            isPresented: $confirmSkip,
            titleVisibility: .visible
        ) {
            Button("Continue without a backup", role: .destructive) {
                viewModel.declineMnemonicBackup()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                viewModel.cardCount == 1
                    ? "No second copy of these keys will exist: this YubiKey is then the wallet. If it is lost, reset or destroyed, the funds are unreachable — nothing can recreate the keys."
                    : "The 24 words will not be written down. \(viewModel.cardCount) YubiKeys will hold these keys, and there will be no way to recreate them if all of them are lost."
            )
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
            why: "Derives keys from the mnemonic: secp256k1 at \(DerivationPath.secp256k1Default.description) via BIP32, and Ed25519 at \(DerivationPath.ed25519Default.description) via SLIP-0010. The private keys stay in memory until they are imported into the YubiKey.",
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

// MARK: - Step 9: write the card and read it back

/// One step, one action: both keys, the policy and the pairing manifest are written,
/// and then all of it is read back off the card and checked against what was written.
/// There is no screen between a write and its proof, and nothing can be skipped — the
/// step only advances once the card has reported every value back (amendment 37).
struct ImportStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    /// True once the step has run. The read-back is the step's own proof, so its
    /// presence is what says the card holds the keys.
    private var written: Bool { !viewModel.readBack.isEmpty }

    var body: some View {
        StepScaffold(
            why: "Writes both private keys into the YubiKey — secp256k1 into the signature slot, Ed25519 into the authentication slot — then the policy that makes them safe to hold (a physical touch for every use on both slots, and the User PIN re-entered for every signature), then the public keys and chain codes your desktop wallet needs. It then reads all of it straight back out of the card.\(viewModel.cardCount > 1 ? " This is YubiKey \(viewModel.cardIndex + 1) of \(viewModel.cardCount); each card is written and verified in its own pass." : "")",
            caution: written
                ? nil
                : "Do not remove the YubiKey during this step. Nothing here is optional: a card that does not report back exactly what was written stops the ceremony rather than being used.",
            actionTitle: written ? "Continue" : "Write and verify the YubiKey",
            isBusy: viewModel.busy,
            action: {
                if written {
                    viewModel.advance()
                } else {
                    Task { await viewModel.importAndVerify() }
                }
            }
        ) {
            if let keys = viewModel.derivedKeys {
                ForEach(keys.all, id: \.algorithm) { key in
                    KeySection(
                        title: key.algorithm.displayName,
                        subtitle: key.slot == .signature
                            ? "\(key.slot.displayName) (CRT B6)"
                            : "\(key.slot.displayName) (CRT A4)",
                        rows: [
                            ("Algorithm", key.algorithm == .secp256k1
                                ? "ECDSA secp256k1 (1.3.132.0.10)"
                                : "EdDSA Ed25519 (1.3.6.1.4.1.11591.15.1)"),
                            ("Key", key.publicKeyHex),
                            ("Fingerprint", key.fingerprintHex),
                        ]
                    )
                }
            }

            if written {
                Label("The card reported back everything that was written.", systemImage: "checkmark.seal.fill")
                    .font(.callout)
                    .foregroundStyle(.green)

                // The keys as the card gave them, next to the keys derived here: a
                // mismatch voids the procedure rather than reaching this screen.
                ForEach(KeyAlgorithm.allCases, id: \.self) { algorithm in
                    if let result = viewModel.readBack[algorithm] {
                        KeySection(
                            title: "\(algorithm.displayName) — as the card reports it",
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

                // The policy half of the same read. Shown as the card reports it, not
                // as the app asked for it: this is the check that the touch policy
                // survived the key import (amendment 26).
                KeySection(
                    title: "Policy read back from the YubiKey",
                    subtitle: "The card's own answer, after the last write to those slots",
                    rows: viewModel.policyConfirmationRows
                )

                // And the chain codes, which live in the card's private-use object. The
                // step does not complete without them, so reaching this screen means the
                // manifest was written and read back off the card (amendment 38).
                if viewModel.pairingManifestStored == true {
                    Label("The pairing manifest is stored on the YubiKey and read back byte-for-byte.", systemImage: "checkmark.seal.fill")
                        .font(.callout)
                        .foregroundStyle(.green)
                    Text("A later re-pair can read this off the card, so it will not need the mnemonic and will not reset the applet. A reset erases it.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Text("The Admin PIN is re-entered for each write, in its own card session, and again for each read that needs it. The card is left holding the keys only if it reports them back exactly.")
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

// MARK: - The wipe that ends the provisioning process (design.md §4.2, the paragraph before step 8)

/// The end of the first of a run's two processes: the secrets go, and the record of what was written
/// is produced. Pairing the wallet is a second process, which rebuilds the codes from the card's
/// manifest and is reached by quitting and reopening the app from the record screen (amendment 43).
///
/// The action is the wipe alone. It used to be "Wipe secrets & Exit", which was wrong on its face:
/// this screen closes nothing — the record it produces is the next screen, and that screen carries
/// the one action that ends the process, behind its own confirmation (amendment 45).
struct WipeSecretsStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    private var cards: String { viewModel.cardCount > 1 ? "The YubiKeys you just wrote hold" : "The YubiKey you just wrote holds" }

    var body: some View {
        StepScaffold(
            why: "Clears the mnemonic, the seed and both private keys out of this app's memory, and produces the provisioning record. Everything that needs a secret is finished: what is left is the public material the wallet is given, and that is rebuilt from the YubiKey when you pair it.",
            caution: "One-way: the words and the keys cannot be shown again. \(cards) the only copy of both keys unless you wrote the mnemonic down.",
            actionTitle: "Wipe secrets",
            isBusy: viewModel.busy,
            action: { viewModel.wipeSecretsAndShowRecord() }
        ) {
            VStack(alignment: .leading, spacing: 8) {
                Label("The record is produced next; pairing is a separate process.", systemImage: "link")
                    .font(.callout)
                Text("Pairing produces its own record: it reads the pairing keys back out of the YubiKey's stored manifest — no mnemonic, nothing secret — and shows the codes for the wallet to scan. Quit the app from the record screen and reopen it to reach it. Nothing is written to or erased from the card here.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 12: teardown

/// The pairing process's last step, and its record. There is no separate pairing-record screen:
/// the record is shown here, and Finish returns to the home screen. The provisioning process's
/// record is the screen that follows its wipe (`ReportView`), which carries the one confirmed exit
/// (amendments 43, 45, 46).
struct TeardownStepView: View {
    @Bindable var viewModel: CeremonyViewModel
    let onFinish: () -> Void

    var body: some View {
        StepScaffold(
            why: "This is the pairing record: the public keys, paths and chain codes this YubiKey's stored manifest describes, checked against the keys the card reports for itself. The app holds no secrets at this point — the provisioning process wiped them before this one started.",
            actionTitle: "Finish",
            action: {
                viewModel.finishPairing()
                onFinish()
            }
        ) {
            CeremonyRecordContent(report: viewModel.report)
        }
    }
}
