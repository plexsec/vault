import Foundation
import XCTest

@testable import VaultKit

/// The scanner's lifecycle rules.
///
/// The reported bug, verbatim: tap "Read the YubiKey", the camera opens, tap Cancel, come
/// back, and there is no picture — for good, until the app is restarted. The cause was that
/// cancelling stopped the capture session but left the state claiming `scanning`, and
/// `start()` treats `scanning` as "the camera is already on". None of that needs a camera to
/// test, which is the point of keeping it here.
final class QRScanSessionTests: XCTestCase {

    private func ur() throws -> UR {
        try UR(type: "eth-sign-request", cbor: CBOR.unsigned(1))
    }

    // MARK: - The reported sequence

    /// The bug as an operator performed it: start, cancel, start again. Repeatedly, because
    /// the failure was "the second visit", not "the second visit specifically".
    func testCancellingAndComingBackAlwaysStartsTheCameraAgain() {
        var session = QRScanSession()
        for visit in 1...5 {
            XCTAssertTrue(session.begin(), "visit \(visit) must start the camera")
            XCTAssertEqual(session.state, .scanning, "visit \(visit) must claim the camera is on")
            session.suspend()
            XCTAssertEqual(session.state, .idle, "a cancel must withdraw the claim after visit \(visit)")
        }
    }

    /// The exact shape of the defect: `begin()` returning `false` while nothing is running
    /// would leave the operator looking at a camera that never starts.
    func testASuspendedSessionDoesNotClaimTheCameraIsRunning() {
        var session = QRScanSession()
        XCTAssertTrue(session.begin())
        session.suspend()
        XCTAssertFalse(
            session.state == .scanning,
            "after a cancel the state must not still claim the camera is on"
        )
        XCTAssertTrue(session.begin(), "and the camera must be startable again")
    }

    /// The app going to the background is the same event as a cancel (both stop the camera),
    /// so returning to the foreground must be able to start it again.
    func testBackgroundingAndReturningStartsTheCameraAgain() {
        var session = QRScanSession()
        XCTAssertTrue(session.begin())
        session.suspend()  // applicationDidBackground()
        XCTAssertTrue(session.begin(), "coming back with the scanner on screen must start the camera")
    }

    // MARK: - What must not be restarted over

    func testBeginningWhileAlreadyScanningIsRefused() {
        var session = QRScanSession()
        XCTAssertTrue(session.begin())
        XCTAssertFalse(session.begin(), "a second start must not restart a running camera")
        XCTAssertEqual(session.state, .scanning)
    }

    func testAResultIsNotRestartedOverButSurvivesACancel() throws {
        let ur = try ur()
        var session = QRScanSession()
        XCTAssertTrue(session.begin())
        session.received(ur)
        XCTAssertFalse(session.begin(), "a start must not hide a request that is in hand")

        // Cancelling stops the camera but the operator still has to read the result.
        session.suspend()
        XCTAssertEqual(session.state, .received(ur))
        XCTAssertFalse(session.begin(), "still not a startable state")
    }

    func testAFailureIsNotRestartedOverButSurvivesACancel() {
        var session = QRScanSession()
        XCTAssertTrue(session.begin())
        session.failed("Camera access is off.")
        session.suspend()
        XCTAssertEqual(session.state, .failed("Camera access is off."))
        XCTAssertFalse(
            session.begin(),
            "a refused permission must stay on screen rather than be retried into silence"
        )
    }

    /// Which is why leaving the flow clears it: that is how the operator gets a second
    /// attempt at the camera, and it is the only way.
    func testResetIsWhatMakesAFailureStartableAgain() {
        var session = QRScanSession()
        XCTAssertTrue(session.begin())
        session.failed("No camera is available on this device.")
        XCTAssertFalse(session.begin())

        session.reset()
        XCTAssertEqual(session.state, .idle)
        XCTAssertTrue(session.begin(), "leaving the flow and coming back must start the camera")
    }

    /// The ceremony is handed whatever arrived; a request from the previous visit is not it.
    func testResetForgetsARequestFromThePreviousVisit() throws {
        var session = QRScanSession()
        XCTAssertTrue(session.begin())
        session.received(try ur())
        session.reset()
        XCTAssertEqual(session.state, .idle)
        XCTAssertFalse(session.begin() == false, "and the scanner is usable again")
    }
}
