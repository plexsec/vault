import SwiftUI
import VaultKit
import YubikeyKit

// MARK: - Step 2: card inventory

struct InventoryStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Read the card before changing anything. This records the applet version, the serial number and the signature counter baseline in your provisioning record.",
            caution: viewModel.inventory?.hasSignatureKey == true
                ? "This YubiKey already holds a signature key. Continuing will erase it."
                : nil,
            actionTitle: viewModel.inventory == nil ? "Read YubiKey" : "Continue",
            isBusy: viewModel.busy,
            action: {
                if viewModel.inventory == nil {
                    Task { await viewModel.inspectCard() }
                } else {
                    // The ceremony advances on its own; this button only re-reads.
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

                Text("Hold the YubiKey against the top of the iPhone" )
                    .font(.caption).foregroundStyle(.secondary)
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

    var body: some View {
        StepScaffold(
            why: "The 24 words are generated from 256 bits produced by the iOS system CSPRNG (SecRandomCopyBytes). The commitment below lets you verify later that the mnemonic you wrote down is the one this device generated.",
            actionTitle: "Generate entropy",
            isEnabled: viewModel.entropyCommitment == nil,
            action: { viewModel.generateEntropy() }
        ) {
            if let commitment = viewModel.entropyCommitment {
                AddressDisplay(label: "Entropy commitment (first 8 hex of SHA-256)", value: commitment)
                Text("Write this down. It goes on your provisioning record.")
                    .font(.caption).foregroundStyle(.secondary)

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

                Button {
                    viewModel.generateMnemonic()
                } label: {
                    Text("Continue to the mnemonic").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(.top, 8)
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
                ? "Screen recording or mirroring is active. The words are hidden."
                : "No cameras, no screenshots. The words are hidden unless you hold your finger down.",
            actionTitle: "Confirm transcription",
            isEnabled: backfillComplete,
            action: { viewModel.confirmTranscription() }
        ) {
            HoldToReveal(isCaptured: viewModel.screenIsCaptured) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 96), spacing: 8)], spacing: 8) {
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
            }

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
}

// MARK: - Step 8: derivation

struct DerivationStepView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        StepScaffold(
            why: "Derives the signing key for \(viewModel.chain.displayName) at \(viewModel.chain.defaultPath.description). The key itself stays in memory until it is imported into the YubiKey.",
            actionTitle: "Derive key",
            isEnabled: viewModel.derivedKey == nil,
            action: { viewModel.deriveKey() }
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
            actionTitle: "Verify read-back",
            isBusy: viewModel.busy,
            action: { Task { await viewModel.verifyReadBack() } }
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
            actionTitle: "Compare addresses",
            isEnabled: !viewModel.independentAddress.trimmingCharacters(in: .whitespaces).isEmpty,
            action: { viewModel.submitIndependentCheck() }
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
            actionTitle: viewModel.pairingURString == nil ? "Prepare pairing code" : "Re-generate pairing code",
            isEnabled: viewModel.pairingURString == nil
                || (!viewModel.pairingIncludesChainCode || viewModel.acknowledgeChainCodeWarning),
            secondaryTitle: viewModel.pairingURString == nil ? nil : "Regenerate with current settings",
            secondaryAction: viewModel.pairingURString == nil ? nil : { viewModel.buildPairingUR() },
            action: { viewModel.buildPairingUR() }
        ) {
            if let urString = viewModel.pairingURString, let ur = try? UR(urString: urString) {
                AnimatedURView(ur: ur)
                Text("Type: \(ur.type)")
                    .font(.caption).foregroundStyle(.secondary)
            }

            if let key = viewModel.derivedKey {
                AddressDisplay(label: "Address your wallet must show", value: key.address)
            }

            Toggle("I confirmed my desktop wallet shows this exact address", isOn: $viewModel.pairingAddressConfirmed)
                .font(.footnote)

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
            actionTitle: "Read counter",
            isBusy: viewModel.busy,
            action: { Task { await viewModel.readCounterBaseline() } }
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
