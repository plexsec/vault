import SwiftUI
import VaultKit
import YubikeyKit

// MARK: - Step 2: card inventory

struct InventoryStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    private var hasInventory: Bool { viewModel.inventory != nil }

    var body: some View {
        StepScaffold(
            why: "Read the card before changing anything. This records the applet version, the serial number and the signature-counter baseline in your provisioning record.",
            caution: viewModel.inventory?.hasSignatureKey == true
                ? "This YubiKey already holds a signature key. Continuing will erase it."
                : nil,
            actionTitle: hasInventory ? "Continue" : "Read YubiKey",
            isBusy: viewModel.busy,
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

                if !inventory.likelySupportsSecp256k1 {
                    Label(
                        "This applet version may not support secp256k1. YubiKey firmware 5.2.3 or newer is required.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .font(.footnote)
                    .foregroundStyle(.orange)
                }

                Text("Check the serial number against the key you intend to provision, then continue.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text(viewModel.transportChoice == .usbC
                     ? "Plug the YubiKey into the USB-C port."
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
            why: "Terminates and re-activates the OpenPGP applet, which clears all keys, resets the PINs to their factory defaults and sets the signature counter back to zero.",
            caution: "This erases everything already on the OpenPGP applet. Three wrong Admin PIN entries also make this card unusable for provisioning, so check the PIN before confirming.",
            actionTitle: "Reset applet",
            isBusy: viewModel.busy,
            isEnabled: viewModel.resetAdminPIN.count >= 8,
            action: { confirmReset = true }
        ) {
            if viewModel.inventory?.hasSignatureKey == true {
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
            why: "Writes two permanent policies: the signature key requires a physical touch for every use and cannot be relaxed later, and the User PIN must be re-entered for every signature.",
            caution: "These policies are the basis of the whole scheme's security. If the read-back check after this step reports a discrepancy, stop.",
            actionTitle: "Apply policy",
            isBusy: viewModel.busy,
            action: { Task { await viewModel.applyPolicy() } }
        ) {
            KeyValueRows(rows: [
                ("Touch policy (UIF 0xD6)", "Fixed — 02"),
                ("PW1 status (0xC4[0])", "0x00 — PIN required per signature"),
                ("Expected APDU", "00 DA 00 D6 02 02 20"),
            ])
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
            why: "The 24 words are generated from 256 bits produced by the iOS system CSPRNG (SecRandomCopyBytes). The commitment below lets you verify later that the mnemonic you wrote down is the one this device generated.",
            actionTitle: hasCommitment ? "Reveal the mnemonic" : "Generate entropy",
            isEnabled: !hasCommitment || commitmentRecorded,
            action: {
                if hasCommitment {
                    // Advancing here is also what derives the words, so the
                    // mnemonic step can never be reached empty.
                    viewModel.advance()
                } else {
                    viewModel.generateEntropy()
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
            why: "Enter the existing 24-word mnemonic. It is checked against the BIP39 checksum before any key is derived, and it stays in memory only for this ceremony.",
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
            why: "Transcribe these 24 words onto your steel plate now. They are the only backup of the wallet; the YubiKey can be replaced, the words cannot.",
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
            why: "Derives the signing key for \(viewModel.chain.displayName) at \(viewModel.chain.defaultPath.description). The key itself stays in memory until it is imported into the YubiKey.",
            actionTitle: viewModel.derivedKey == nil ? "Derive key" : "Continue",
            action: {
                if viewModel.derivedKey == nil {
                    viewModel.deriveKey()
                } else {
                    viewModel.advance()
                }
            }
        ) {
            if let key = viewModel.derivedKey {
                AddressDisplay(label: "Address", value: key.address)
                KeyValueRows(rows: [
                    ("Path", key.path.description),
                    ("Public key (compressed)", key.publicKeyHex),
                    ("Key fingerprint", key.fingerprintHex),
                    ("Parent fingerprint", key.parentFingerprintHex),
                    ("Master fingerprint", key.masterFingerprintHex),
                ])
                Text("This address is what you will verify against an independent tool in two steps' time.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Deriving takes a moment: PBKDF2 with 2048 iterations, then four hardened derivation steps.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 9: import

struct ImportStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Writes the private key into the YubiKey's signature slot, along with the secp256k1 algorithm attributes, the key fingerprint and the creation time. This is the only step that puts key material on the card.",
            caution: "Do not remove the YubiKey during this step.",
            actionTitle: "Import key into YubiKey",
            isBusy: viewModel.busy,
            action: { Task { await viewModel.importKey() } }
        ) {
            if let key = viewModel.derivedKey {
                KeyValueRows(rows: [
                    ("Slot", "Signature (CRT B6)"),
                    ("Algorithm", "ECDSA secp256k1 (1.3.132.0.10)"),
                    ("Key", key.publicKeyHex),
                    ("Fingerprint", key.fingerprintHex),
                    ("Import APDU", "00 DB 3F FF 2C 4D …"),
                ])
            }
        }
    }
}

// MARK: - Step 10: read-back

struct ReadBackStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Reads the public key back out of the YubiKey and compares it byte-for-byte against the key derived on this device. This is the mandatory check that the card holds the key you think it does.",
            actionTitle: viewModel.readBack == nil ? "Verify read-back" : "Continue",
            isBusy: viewModel.busy,
            action: {
                if viewModel.readBack == nil {
                    Task { await viewModel.verifyReadBack() }
                } else {
                    viewModel.advance()
                }
            }
        ) {
            if let result = viewModel.readBack {
                KeyValueRows(rows: [
                    ("Matches derived key", result.matches ? "yes" : "NO"),
                    ("Key from YubiKey", result.cardPublicKeyHex),
                    ("Derived key", result.derivedPublicKeyHex),
                    ("Address from YubiKey key", result.addressFromCardKey),
                ])
                if result.matches {
                    Label("The YubiKey holds exactly the derived key.", systemImage: "checkmark.seal.fill")
                        .font(.footnote)
                        .foregroundStyle(.green)
                }
            } else {
                Text("No PIN is required for this read. The card returns its public key, which is public data.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 11: independent cross-check

struct IndependentCheckStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Enter the same address as derived by a different tool on a different device — tools/derive from this repository, an offline BIP39 site, a Coldcard or a SeedSigner. This is the check that catches a tampered iPhone or a wrong wordlist.",
            actionTitle: viewModel.independentCheck?.matched == true ? "Continue" : "Compare addresses",
            isEnabled: viewModel.independentCheck?.matched == true
                || !viewModel.independentAddress.trimmingCharacters(in: .whitespaces).isEmpty,
            action: {
                if viewModel.independentCheck?.matched == true {
                    viewModel.advance()
                } else {
                    viewModel.submitIndependentCheck()
                }
            }
        ) {
            if let key = viewModel.derivedKey {
                AddressDisplay(label: "Address from this device", value: key.address)
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Address from the independent tool").font(.subheadline.weight(.medium))
                TextField("0x… or bc1…", text: $viewModel.independentAddress)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .font(.system(.body, design: .monospaced))
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Which tool?").font(.subheadline.weight(.medium))
                TextField("tool and device", text: $viewModel.independentSource)
                    .textFieldStyle(.roundedBorder)
            }

            if let check = viewModel.independentCheck, !check.matched {
                Text("Mismatch. Do not proceed: restart the ceremony on a different device.")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
    }
}

// MARK: - Step 12: pairing

struct PairingStepView: View {
    @Bindable var viewModel: CeremonyViewModel
    @State private var showAdvanced = false

    var body: some View {
        StepScaffold(
            why: "Scan this code with your desktop wallet's QR hardware-wallet import. It carries the public key, the derivation path and the master fingerprint — never the private key.",
            actionTitle: viewModel.pairingURString == nil ? "Prepare pairing code" : "Continue",
            isEnabled: viewModel.pairingURString == nil
                ? (!viewModel.pairingIncludesChainCode || viewModel.acknowledgeChainCodeWarning)
                : viewModel.pairingAddressConfirmed,
            secondaryTitle: viewModel.pairingURString == nil ? nil : "Regenerate with current settings",
            secondaryAction: viewModel.pairingURString == nil ? nil : { viewModel.buildPairingUR() },
            action: {
                if viewModel.pairingURString == nil {
                    viewModel.buildPairingUR()
                } else {
                    viewModel.advance()
                }
            }
        ) {
            if let urString = viewModel.pairingURString, let ur = try? UR(urString: urString) {
                AnimatedURView(ur: ur)
                Text("Type: \(ur.type)")
                    .font(.caption).foregroundStyle(.secondary)
            }

            if let key = viewModel.derivedKey {
                AddressDisplay(label: "Address your wallet must show", value: key.address)
            }

            Toggle("I confirmed my desktop wallet shows this exact address", isOn: Binding(
                get: { viewModel.pairingAddressConfirmed },
                set: { viewModel.setPairingAddressConfirmed($0) }
            ))
            .font(.footnote)
            .disabled(viewModel.pairingURString == nil)

            DisclosureGroup("Advanced: wire format and chain code", isExpanded: $showAdvanced) {
                Picker("UR type", selection: $viewModel.pairingStyle) {
                    ForEach(URTypeStyle.allCases, id: \.self) { style in
                        Text(style.displayName).tag(style)
                    }
                }
                .pickerStyle(.inline)
                .labelsHidden()

                Toggle("Export a chain code as well", isOn: $viewModel.pairingIncludesChainCode)

                if viewModel.pairingIncludesChainCode {
                    Text("""
                    A chain code lets a wallet derive further addresses. This YubiKey holds \
                    one key and can only sign for the address above, so derived addresses \
                    would receive funds you could not spend from this device.
                    """)
                    .font(.caption)
                    .foregroundStyle(.orange)

                    Toggle("I understand that derived addresses cannot be signed for", isOn: $viewModel.acknowledgeChainCodeWarning)
                        .font(.footnote)
                }
            }
        }
    }
}

// MARK: - Step 13: counter baseline

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
                KeyValueRows(rows: [("Signature counter", "\(counter)")])
                Label("Baseline recorded.", systemImage: "checkmark.seal.fill")
                    .font(.footnote).foregroundStyle(.green)
            } else {
                Text("No PIN is needed to read the counter, and it exposes no secrets.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Step 14: teardown

struct TeardownStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Clears the mnemonic, seed and private key from memory and produces the provisioning record you keep with the steel plate. The app requires a restart before another ceremony.",
            actionTitle: "Wipe secrets and finish",
            action: { viewModel.finish() }
        ) {
            Text("Nothing secret is written to disk at any point in this app. The record below contains only public data.")
                .font(.callout)
        }
    }
}
