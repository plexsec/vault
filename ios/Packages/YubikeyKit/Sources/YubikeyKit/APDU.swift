import Foundation
import VaultKit

/// An ISO 7816-4 command APDU.
///
/// Short form only: the largest command this app sends is the secp256k1 key
/// import at ~41 bytes of data, so extended-length APDUs are never needed. That
/// keeps the encoder, and the two transports, simple enough to review.
public struct CommandAPDU: Equatable {
    public let cla: UInt8
    public let ins: UInt8
    public let p1: UInt8
    public let p2: UInt8
    public let data: [UInt8]
    /// Expected response length. `nil` means "no Le byte" (case 1/3),
    /// 0 means `Le = 0x00` for case 2/4.
    public let expectedLength: Int?

    public init(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: [UInt8] = [], expectedLength: Int? = nil) {
        precondition(data.count <= 255, "short APDU only: data must fit in one byte of Lc")
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.expectedLength = expectedLength
    }

    /// Encoded APDU bytes.
    public var bytes: [UInt8] {
        var out: [UInt8] = [cla, ins, p1, p2]
        if !data.isEmpty {
            out.append(UInt8(data.count))
            out.append(contentsOf: data)
            // Case 4: data + Le
            out.append(UInt8(expectedLength ?? 0))
        } else if let expectedLength {
            // Case 2: Le only.
            out.append(UInt8(expectedLength))
        }
        // Case 1: header only.
        return out
    }

    /// Hex rendering for logs and golden-APDU tests.
    public var hex: String { Hex.encode(bytes) }
}

/// Status word returned by the card.
public struct StatusWord: Equatable {
    public let sw1: UInt8
    public let sw2: UInt8

    public init(sw1: UInt8, sw2: UInt8) {
        self.sw1 = sw1
        self.sw2 = sw2
    }

    public static let success = StatusWord(sw1: 0x90, sw2: 0x00)

    public var isSuccess: Bool { sw1 == 0x90 && sw2 == 0x00 }

    /// `61xx`: `xx` more response bytes are available; issue GET RESPONSE.
    public var remainingResponseBytes: Int? {
        sw1 == 0x61 ? Int(sw2) : nil
    }

    /// `6Cxx`: wrong Le; re-issue with `Le = xx`.
    public var correctLe: Int? {
        sw1 == 0x6C ? Int(sw2) : nil
    }

    /// `63Cx`: verification failed, `x` attempts remain.
    public var pinRetriesRemaining: Int? {
        guard sw1 == 0x63, (sw2 & 0xF0) == 0xC0 else { return nil }
        return Int(sw2 & 0x0F)
    }

    public var hex: String { String(format: "%02X%02X", sw1, sw2) }
}

/// A response APDU: data plus status word.
public struct ResponseAPDU: Equatable {
    public let data: [UInt8]
    public let status: StatusWord

    public init(data: [UInt8], status: StatusWord) {
        self.data = data
        self.status = status
    }

    public init(bytes: [UInt8]) throws {
        guard bytes.count >= 2 else { throw APDUError.truncatedResponse }
        self.data = Array(bytes.dropLast(2))
        self.status = StatusWord(sw1: bytes[bytes.count - 2], sw2: bytes[bytes.count - 1])
    }

    public var hex: String { Hex.encode(data) + " " + status.hex }
}

public enum APDUError: Swift.Error, Equatable {
    case truncatedResponse
    case malformedTLV(String)
    case responseTooLong(Int)
}
