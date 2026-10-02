import AVFoundation
import Foundation
import VaultKit

/// Receives an animated UR over the camera.
///
/// The scanner is deliberately dumb: it decodes QR frames, feeds every `ur:` string
/// to a fountain decoder, and publishes progress. It does not decide whether a
/// request is good — that is `SigningCeremony`'s job, and the split matters,
/// because a scanner that "helpfully" filtered frames would be making a policy
/// decision in the view layer (design.md §5.2 rule 1).
///
/// Frames that are not `ur:` at all are ignored rather than reported: an operator
/// pointing the camera at the wrong screen should not get an error, and a QR code
/// that is not a signing request is not an error until it claims to be one.
@MainActor
@Observable
final class QRScanModel: NSObject {
    enum State: Equatable {
        case idle
        /// The camera is on and no complete UR has arrived yet.
        case scanning
        case received(UR)
        case failed(String)
    }

    private(set) var state: State = .idle
    /// 0...1, the fountain decoder's own estimate.
    private(set) var progress: Double = 0
    private(set) var framesSeen = 0
    private(set) var partsSeen = 0
    /// The type the incoming stream announced (`eth-sign-request`, or something
    /// else the operator pointed the camera at).
    private(set) var announcedType: String?

    let session = AVCaptureSession()

    override init() { super.init() }
    /// Recreated rather than reset: `URDecoder` carries a fountain decoder whose
    /// fragment state must not survive between requests, because the next request
    /// is a different message with its own sequence numbers.
    private var decoder = URDecoder()
    private var isConfigured = false
    private var lastReportedProgress = Date.distantPast

    /// Starts the camera, requesting permission the first time.
    func start() async {
        // A completed UR stays on screen, and a failure stays until the operator
        // asks again: restarting the stream over either would hide the result.
        switch state {
        case .received, .failed, .scanning:
            return
        case .idle:
            break
        }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            break
        case .notDetermined:
            let granted = await AVCaptureDevice.requestAccess(for: .video)
            guard granted else {
                state = .failed("Camera access was refused. PlexVault needs the camera to read the wallet's QR code; enable it in Settings.")
                return
            }
        default:
            state = .failed("Camera access is off. Enable it in Settings to scan the wallet's QR code.")
            return
        }

        decoder = URDecoder()
        progress = 0
        framesSeen = 0
        partsSeen = 0
        announcedType = nil
        state = .scanning
        configureIfNeeded()
        guard !session.isRunning else { return }
        // `startRunning` blocks; moving it off the main actor keeps the UI live.
        let session = self.session
        await Task.detached(priority: .userInitiated) { session.startRunning() }.value
    }

    func stop() {
        guard session.isRunning else { return }
        let session = self.session
        Task.detached(priority: .utility) { session.stopRunning() }
    }

    /// Feeds one QR payload. Public so the DEBUG sample-request path and the tests
    /// go through the same decoder as the camera does.
    func receive(_ payload: String) {
        guard case .received = state else {
            let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.lowercased().hasPrefix("ur:") else { return }
            framesSeen += 1
            guard decoder.receivePart(trimmed) else { return }
            partsSeen = decoder.processedPartsCount
            announcedType = decoder.expectedType
            progress = decoder.estimatedPercentComplete
            if let result = decoder.result {
                switch result {
                case .success(let ur):
                    progress = 1
                    state = .received(ur)
                case .failure(let error):
                    state = .failed("That QR code could not be read as a complete request (\(error)).")
                }
            }
            return
        }
    }

    /// Resets so a second request can be scanned in the same session.
    func reset() {
        decoder = URDecoder()
        progress = 0
        framesSeen = 0
        partsSeen = 0
        announcedType = nil
        state = .idle
    }

    private func configureIfNeeded() {
        guard !isConfigured else { return }
        isConfigured = true
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
              let input = try? AVCaptureDeviceInput(device: device)
        else {
            state = .failed("No camera is available on this device.")
            return
        }
        session.beginConfiguration()
        if session.canAddInput(input) { session.addInput(input) }
        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
        }
        session.commitConfiguration()
    }
}

extension QRScanModel: AVCaptureMetadataOutputObjectsDelegate {
    nonisolated func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let payload = object.stringValue
        else { return }
        Task { @MainActor in self.receive(payload) }
    }
}
