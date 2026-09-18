import Foundation
import VaultKit

/// Build identity, surfaced in the UI so the operator can compare it against the
/// published reproducible-build hash (design.md Appendix B).
public enum BuildInfo {
    public static var version: String {
        let short = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
        return "\(short) (\(build))"
    }

    public static var summary: String {
        "\(version) \(binarySHA256 ?? "hash-unavailable")"
    }

    /// SHA-256 of the running executable, computed on demand. This is what the
    /// operator writes on the Appendix B checklist.
    public static var binarySHA256: String? {
        guard let url = Bundle.main.executableURL else { return nil }
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }

        var hasher = SHA256Hasher()
        while true {
            guard let chunk = try? handle.read(upToCount: 1 << 20), !chunk.isEmpty else { break }
            hasher.update(chunk)
        }
        return Hex.encode(hasher.finalize())
    }

    /// Short form for a compact UI row.
    public static var shortHash: String {
        guard let hash = binarySHA256 else { return "unavailable" }
        return String(hash.prefix(16))
    }
}
