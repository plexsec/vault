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
    /// The lifecycle rules live in `VaultKit.QRScanSession`, where they are unit-tested;
    /// this type owns the capture session, the fountain decoder and the counters, and asks
    /// that type what each event means. The split is the same one as `NFCSessionPolicy`:
    /// a camera is needed to see a mistake, but not to notice one.
    typealias State = QRScanSession.State

    private var scanSession = QRScanSession()

    var state: State { scanSession.state }
    /// 0...1, the fountain decoder's own estimate.
    private(set) var progress: Double = 0
    private(set) var framesSeen = 0
    private(set) var partsSeen = 0
    /// The type the incoming stream announced (`eth-sign-request`, or something
    /// else the operator pointed the camera at).
    private(set) var announcedType: String?

    let session = AVCaptureSession()

    /// Called on the main actor when a complete request has been read.
    ///
    /// The flow that owns the scanner sets this, so the handoff to the ceremony happens
    /// *where the decode happens* rather than in a view's `onChange`. That is not a style
    /// choice: this handoff was missing from the app entirely — the camera decoded a
    /// request, the screen said "Read a eth-sign-request", and nothing followed, because
    /// nothing was subscribed to the state the view was rendering (amendment 24). A
    /// callback fires with the value in hand, and cannot be forgotten by a view.
    var onRequest: ((UR) -> Void)?

    override init() { super.init() }
    /// Recreated rather than reset: `URDecoder` carries a fountain decoder whose
    /// fragment state must not survive between requests, because the next request
    /// is a different message with its own sequence numbers.
    private var decoder = URDecoder()
    private var isConfigured = false
    /// The camera's transitions, serialised. `startRunning`/`stopRunning` block, so they
    /// happen off the main actor; chaining them means a cancel followed immediately by
    /// re-entry cannot interleave — the second `startRunning` would be skipped as
    /// "already running" while the stop was still in flight, which is a dark preview with
    /// nothing in the log to explain it.
    private var sessionWork: Task<Void, Never>?

    /// Starts the camera, requesting permission the first time.
    ///
    /// Whether a start is even meaningful is `QRScanSession.begin()`'s decision, and it is
    /// asked *first*: it is the type that knows whether the camera is supposed to be on.
    func start() async {
        guard scanSession.begin() else { return }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            break
        case .notDetermined:
            let granted = await AVCaptureDevice.requestAccess(for: .video)
            guard granted else {
                scanSession.failed("Camera access was refused. PlexVault needs the camera to read the wallet's QR code; enable it in Settings.")
                return
            }
        default:
            scanSession.failed("Camera access is off. Enable it in Settings to scan the wallet's QR code.")
            return
        }

        decoder = URDecoder()
        progress = 0
        framesSeen = 0
        partsSeen = 0
        announcedType = nil
        guard configureIfNeeded() else { return }
        await performSessionWork { session in
            guard !session.isRunning else { return }
            session.startRunning()
        }
    }

    /// Stops the camera. Used by a cancel and by the app leaving the foreground: the camera
    /// goes off, but a result or a failure stays on screen for the operator to read.
    func stop() {
        scanSession.suspend()
        Task {
            await performSessionWork { session in
                guard session.isRunning else { return }
                session.stopRunning()
            }
        }
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
                    scanSession.received(ur)
                    // Guarded above (the body only runs when the state is not yet
                    // `.received`), so this fires once per request.
                    onRequest?(ur)
                case .failure(let error):
                    scanSession.failed("That QR code could not be read as a complete request (\(error)).")
                }
            }
            return
        }
    }

    /// Leaving the flow: the camera stops and nothing decoded so far carries over. A request
    /// left from the previous visit would otherwise both hide the camera and be offered to
    /// the ceremony as if it were this one.
    func reset() {
        stop()
        decoder = URDecoder()
        progress = 0
        framesSeen = 0
        partsSeen = 0
        announcedType = nil
        scanSession.reset()
    }

    /// Returns whether the capture session is usable, reporting the reason when it is not.
    ///
    /// A failure is *not* remembered as "configured": caching it would leave the next
    /// attempt claiming `scanning` with no input attached, which is a dark preview and no
    /// explanation. Re-detecting it makes the reason appear again on the retry.
    private func configureIfNeeded() -> Bool {
        if isConfigured { return true }
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
              let input = try? AVCaptureDeviceInput(device: device)
        else {
            scanSession.failed("No camera is available on this device.")
            return false
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
        isConfigured = true
        return true
    }

    /// Runs one camera transition, after every transition already queued.
    private func performSessionWork(
        _ body: @escaping @Sendable (AVCaptureSession) -> Void
    ) async {
        let previous = sessionWork
        let session = self.session
        let task = Task.detached(priority: .userInitiated) {
            await previous?.value
            body(session)
        }
        sessionWork = task
        await task.value
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
