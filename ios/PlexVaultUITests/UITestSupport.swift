import XCTest

/// Shared helpers for driving the real app in a simulator.
///
/// Scrolling was the flakiest thing in this suite, and the reason is worth
/// recording: the original helper used `swipeUp()`/`swipeDown()`, which flick with
/// momentum. A flick overshoots the target, the correction flicks back past it,
/// and the loop oscillates — so whether the row ended up inside the tappable band
/// came down to luck. A slow press-and-drag has no momentum and settles.
///
/// The band exists because `isHittable` is not sufficient: an element underneath
/// the pinned bottom bar still reports `isHittable` while the tap is intercepted by
/// the bar. That is not hypothetical — it is how the posture toggles came to be
/// silently left unticked, with the primary action then disabled.
extension XCTestCase {

    /// The area in which a tap is reliable: below the navigation bar and above the
    /// pinned primary action.
    ///
    /// Measured from the real chrome rather than a fixed inset, because both edges
    /// move with the device and with Dynamic Type.
    func visibleBand(in app: XCUIApplication) -> CGRect {
        let window = app.windows.firstMatch.frame
        // `.frame` on a query with no matches records a failure, so existence is
        // checked first: the ceremony's running phase has a navigation bar but no
        // pinned `begin-ceremony`.
        let navBar = app.navigationBars.firstMatch
        let top = (navBar.exists ? navBar.frame.maxY : window.minY) + 8
        let primaryAction = app.buttons["begin-ceremony"]
        // With no pinned action on screen (the running phase puts each step's
        // action inside the scroll view) fall back to clearing the toolbar and the
        // privacy footer.
        let bottom = (primaryAction.exists ? primaryAction.frame.minY : window.maxY - 140) - 12
        return CGRect(x: window.minX, y: top, width: window.width,
                      height: max(1, bottom - top))
    }

    /// Scrolls by a bounded amount; positive `delta` reveals content further down.
    func scroll(_ app: XCUIApplication, by delta: CGFloat) {
        let clamped = max(-200, min(200, delta))
        guard abs(clamped) >= 1 else { return }
        // x=0.02 keeps the touch in the scroll view's side padding, clear of the
        // rows, so press-and-drag cannot be picked up by a button or a toggle.
        let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.02, dy: 0.5))
        start.press(forDuration: 0.25, thenDragTo: start.withOffset(CGVector(dx: 0, dy: -clamped)))
    }

    /// Brings `element` into the tappable band, then taps it.
    func tapWhenVisible(_ element: XCUIElement, in app: XCUIApplication,
                        file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(element.waitForExistence(timeout: 10), "\(element) never appeared",
                      file: file, line: line)

        var midY = element.frame.midY
        var landed = false
        for _ in 0..<12 {
            let band = visibleBand(in: app)
            let frame = element.frame
            midY = frame.midY
            if band.contains(CGPoint(x: frame.midX, y: midY)) { landed = true; break }
            scroll(app, by: midY - band.midY)
        }
        // Asserted on the value measured inside the loop: re-reading the frame
        // afterwards races with a scroll that is still settling.
        XCTAssertTrue(
            landed,
            "\(element) could not be brought into the visible area (midY=\(midY))",
            file: file, line: line
        )
        element.tap()
    }

    /// Taps the pinned primary action, which must be reachable without scrolling.
    func tapPinnedPrimaryAction(_ app: XCUIApplication,
                                file: StaticString = #filePath, line: UInt = #line) {
        let begin = app.buttons["begin-ceremony"]
        XCTAssertTrue(begin.waitForExistence(timeout: 15),
                      "the primary action never appeared", file: file, line: line)
        XCTAssertTrue(begin.isHittable,
                      "the primary action must be hittable without scrolling",
                      file: file, line: line)
        begin.tap()
    }

    /// Ticks both posture acknowledgements, scrolling each into view first.
    ///
    /// Addressed by label rather than by index: `app.switches` also matches the
    /// decorative knob inside each SwiftUI `Toggle`, so an index-based loop visits
    /// four elements instead of two.
    func acknowledgePosture(in app: XCUIApplication,
                            file: StaticString = #filePath, line: UInt = #line) {
        for label in ["This iPhone is factory-reset, has no SIM, and is in airplane mode",
                      "No cameras or other people can see this screen"] {
            let toggle = app.switches[label]
            XCTAssertTrue(toggle.waitForExistence(timeout: 5),
                          "posture toggle missing: \(label)", file: file, line: line)
            if (toggle.value as? String) == "0" {
                tapWhenVisible(toggle, in: app, file: file, line: line)
            }
        }
    }
}
