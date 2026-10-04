import Foundation
import SwiftUI
import AVFoundation

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
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .accessibilityIdentifier("scanner-preview")
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
