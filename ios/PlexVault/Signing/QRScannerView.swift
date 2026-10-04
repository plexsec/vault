import Foundation
import SwiftUI
import AVFoundation

/// The scanner's rounded corners. The frost over the preview has to match the preview's own
/// radius, so the number lives in one place.
private let previewCornerRadius: CGFloat = 12

/// What does the blurring: the frost's one control, and it sits at full strength.
///
/// The five system materials differ in thickness — how much of the background shows through — and
/// not in blur radius, so this is not a dial between "blurry" and "clear": `.ultraThinMaterial`
/// is already the most translucent of them, and every other choice only makes the picture greyer
/// while hiding no more detail. A numerically tunable radius would mean blurring the *frames*
/// (a Core Image pipeline in place of the preview layer) rather than the display, which is a
/// different piece of work with a real cost (amendment 36).
///
/// Diluting the frost with `.opacity` was tried and reverted. Apple's `UIVisualEffectView`
/// documentation — the machinery under a SwiftUI material — says to avoid alpha values below 1 on
/// a visual effect view *or any of its superviews*, because "many effects look incorrect or not
/// show up at all". The device bore the suspicion out: with an opacity over it, changing this
/// material appeared to change nothing. Full strength, then, and the aiming trade-off is paid
/// where it belongs instead of by weakening the frost.
private let previewFrost: Material = .ultraThinMaterial

/// The camera preview behind the scanner, plus the reading of it.
///
/// A `UIViewRepresentable` rather than SwiftUI's own preview because the session
/// has to be shared with the model that feeds the fountain decoder — two capture
/// sessions competing for the camera is a bug that only shows up on a device.
struct QRScannerView: UIViewRepresentable {
    let session: AVCaptureSession
    /// Called when the preview layer is on screen with a real size, and when it leaves again.
    ///
    /// This is where the camera is started from, and it is not decoration: a session started
    /// before the layer can display it shows **one frame** and then sits still, until the
    /// session is stopped and started again — which is what a trip to the background and back
    /// does by hand. Measured on the device: entering the flow (taps, app already active) left
    /// a frozen first frame, while the same app started after the layer was up showed live
    /// video, and the way to get from the first state to the second was to background and
    /// foreground it (amendment 35).
    var onPreviewReady: () -> Void = {}
    var onPreviewGone: () -> Void = {}

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.onReady = onPreviewReady
        view.onGone = onPreviewGone
        view.videoPreviewLayer.session = session
        view.videoPreviewLayer.videoGravity = .resizeAspectFill
        return view
    }

    func updateUIView(_ uiView: PreviewView, context: Context) {
        uiView.onReady = onPreviewReady
        uiView.onGone = onPreviewGone
        if uiView.videoPreviewLayer.session !== session {
            uiView.videoPreviewLayer.session = session
        }
    }

    final class PreviewView: UIView {
        var onReady: (() -> Void)?
        var onGone: (() -> Void)?
        private var isReady = false

        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var videoPreviewLayer: AVCaptureVideoPreviewLayer {
            // Safe: `layerClass` above makes this the only possible layer type.
            layer as! AVCaptureVideoPreviewLayer
        }

        override func didMoveToWindow() {
            super.didMoveToWindow()
            reportIfChanged()
        }

        override func layoutSubviews() {
            super.layoutSubviews()
            reportIfChanged()
        }

        /// Reports only on a change, so a layout pass cannot restart the camera.
        private func reportIfChanged() {
            let ready = window != nil && bounds.width > 1 && bounds.height > 1
            guard ready != isReady else { return }
            isReady = ready
            if ready { onReady?() } else { onGone?() }
        }
    }
}

/// Frosted glass over the camera image: the scanner's display is for aiming, not for reading.
///
/// Nothing about scanning needs to be *seen*: the request is decoded from the session's sample
/// buffers, not from the screen, so the display can be obscured without costing anything. That
/// is worth doing, because the preview is a live picture of whatever is in front of the phone —
/// and on a phone that picture sits on a screen someone else can look at, photograph, or record
/// (amendment 36). Through this the camera shows shapes and light, which is enough to centre a
/// QR code in the frame, and no detail at all.
///
/// A sibling *on top of* `QRScannerView`, deliberately, rather than a `blur` on the preview's own
/// view: how that view renders has already gone wrong once, in a way a simulator cannot show
/// (amendment 35), so it stays untouched. The reverse is not true — the frost's own appearance is
/// only checkable by eye, which is exactly why it is a plain view over a plain view.
struct ScannerFrost: View {
    var body: some View {
        Rectangle()
            .foregroundStyle(previewFrost)
            .clipShape(RoundedRectangle(cornerRadius: previewCornerRadius))
            // The redaction applies to the snapshot iOS takes for the app switcher, which would
            // otherwise be the last camera frame — the one place the preview is shown while
            // nobody is looking at the scanner. It does not apply to a screen recording; no
            // public API spans that, and the blur is what covers it.
            .privacySensitive()
            .allowsHitTesting(false)
            .accessibilityIdentifier("scanner-frost")
    }
}

/// The scanning screen: preview, progress, and what the stream says it is.
struct ScanningView: View {
    @Bindable var model: QRScanModel
    /// Shown above the preview, e.g. which address the request will be checked
    /// against.
    let headline: String
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(headline).font(.headline)
            Text(detail).font(.footnote).foregroundStyle(.secondary)

            ZStack {
                QRScannerView(
                    session: model.session,
                    onPreviewReady: { model.previewDidAppear() },
                    onPreviewGone: { model.previewDidDisappear() }
                )
                    .clipShape(RoundedRectangle(cornerRadius: previewCornerRadius))
                    .accessibilityIdentifier("scanner-preview")
                // Above the preview, below everything that is there to be read.
                ScannerFrost()
                if case .failed(let message) = model.state {
                    VStack(spacing: 8) {
                        Image(systemName: "video.slash")
                        Text(message).font(.footnote).multilineTextAlignment(.center)
                    }
                    .padding()
                    .background(.regularMaterial)
                }
            }
            .frame(height: 320)

            switch model.state {
            case .scanning:
                ProgressView(value: model.progress)
                    .accessibilityIdentifier("scan-progress")
                Text(progressText)
                    .font(.footnote.monospacedDigit())
                    .foregroundStyle(.secondary)
            case .received(let ur):
                Label("Read a \(ur.type)", systemImage: "checkmark.circle")
                    .foregroundStyle(.green)
            case .idle:
                // `.idle` means "not running", which for one moment is also the state of a
                // camera that is about to start. Saying "Starting…" here was a claim the
                // state does not make; the scanner says what is true instead.
                Text("Camera is off").font(.footnote).foregroundStyle(.secondary)
            case .failed:
                EmptyView()
            }
        }
    }

    private var progressText: String {
        if let type = model.announcedType {
            return "\(type): \(Int(model.progress * 100))% complete, \(model.partsSeen) frame(s) read"
        }
        return "Waiting for the wallet's QR code (\(model.framesSeen) frame(s) seen)"
    }
}
