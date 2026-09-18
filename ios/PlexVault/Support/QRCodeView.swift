import CoreImage.CIFilterBuiltins
import VaultKit
import SwiftUI

/// Renders a UR string as a QR code, animating through the parts of a multi-part
/// UR so a wallet can scan a payload that does not fit in one frame.
struct QRCodeView: View {
    let text: String
    let correctionLevel: String

    init(text: String, correctionLevel: String = "L") {
        self.text = text
        self.correctionLevel = correctionLevel
    }

    var body: some View {
        if let image = Self.makeImage(text: text, correctionLevel: correctionLevel) {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .accessibilityLabel("QR code")
        } else {
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.secondary.opacity(0.2))
                .overlay(Text("QR unavailable").foregroundStyle(.secondary))
        }
    }

    static func makeImage(text: String, correctionLevel: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = correctionLevel
        guard let output = filter.outputImage else { return nil }
        // Scale up so the modules stay crisp on a Retina display.
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        let context = CIContext()
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

/// Animated multi-part UR presenter.
///
/// The parts are generated once by `UREncoder` and cycled; that is the fountain
/// codec's intended behaviour (the receiver needs any sufficiently large subset
/// of parts, in any order). The displayed frame rate is deliberately slow enough
/// to scan and fast enough to transfer 24-word-scale payloads quickly.
struct AnimatedURView: View {
    let ur: UR
    let maxFragmentLength: Int
    let framesPerSecond: Double

    @State private var parts: [String] = []
    @State private var index = 0
    @State private var timer: Timer?

    init(ur: UR, maxFragmentLength: Int = 120, framesPerSecond: Double = 4) {
        self.ur = ur
        self.maxFragmentLength = maxFragmentLength
        self.framesPerSecond = framesPerSecond
    }

    var body: some View {
        VStack(spacing: 12) {
            QRCodeView(text: parts.isEmpty ? ur.string : parts[index % max(parts.count, 1)])
                .frame(maxWidth: 320, maxHeight: 320)
                .padding(12)
                .background(Color.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))

            if parts.count > 1 {
                Text("Part \((index % parts.count) + 1) of \(parts.count)")
                    .font(.footnote.monospacedDigit())
                    .foregroundStyle(.secondary)
            } else {
                Text("Single frame")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .onAppear(perform: start)
        .onDisappear(perform: stop)
    }

    private func start() {
        let encoder = UREncoder(ur, maxFragmentLen: maxFragmentLength, minFragmentLen: 20)
        if encoder.isSinglePart {
            parts = [encoder.nextPart()]
        } else {
            // Generate one full pass plus a few fountain frames.
            var generated: [String] = []
            for _ in 0..<(encoder.seqLen + 2) { generated.append(encoder.nextPart()) }
            parts = generated
        }
        index = 0
        guard parts.count > 1 else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 1 / framesPerSecond, repeats: true) { _ in
            index = (index + 1) % parts.count
        }
    }

    private func stop() {
        timer?.invalidate()
        timer = nil
    }
}
