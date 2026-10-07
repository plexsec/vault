import XCTest

/// The guide: one home-screen entry, a table with two rows, a page per row, and a back button at
/// each level.
///
/// The screen is copy, so the assertions are about the wiring that breaks when screens are
/// rearranged — that both rows reach their own page, that the manual's entries are listed, and that
/// each level's back button comes back — rather than about the wording, which is checked by review
/// against design.md and the checklists.
final class GuideUITests: XCTestCase {
    func testTheGuideIsATableOfTwoRowsAndEveryWayBackWorks() {
        let app = launchApp(deviceChoice: "simulated")

        XCTAssertTrue(
            app.buttons["route-signing"].waitForExistence(timeout: 15),
            "the home screen never appeared:\n\(app.debugDescription)"
        )

        // The entry is at the foot of the screen, under a divider and away from the flows, so it is
        // reached the way a pinned action is: without scrolling.
        let entry = app.buttons["route-how-it-works"]
        XCTAssertTrue(
            entry.waitForExistence(timeout: 10),
            "the guide entry never appeared:\n\(app.debugDescription)"
        )
        XCTAssertTrue(
            entry.isHittable,
            "the guide entry is at the bottom of the home screen and must be tappable without "
                + "scrolling:\n\(app.debugDescription)"
        )
        entry.tap()

        // The table: the explanation, and the manual with its entries behind its row. The manual is
        // closed to start with, which is asserted on hittability rather than on existence: whether a
        // collapsed disclosure group keeps its children in the hierarchy at all is SwiftUI's
        // business, and either way they are not on screen.
        XCTAssertTrue(
            row("guide-row-explanation", in: app).waitForExistence(timeout: 10),
            "the guide must open on its table:\n\(app.debugDescription)"
        )
        let manualRow = row("guide-row-manual", in: app)
        XCTAssertTrue(
            manualRow.exists,
            "the manual must be the table's second row:\n\(app.debugDescription)"
        )
        let createEntry = row("guide-row-createWallet", in: app)
        XCTAssertFalse(
            createEntry.isHittable,
            "the manual must start closed:\n\(app.debugDescription)"
        )

        // Tapping the row opens it, and the entries are then listed.
        tap(app.staticTexts["Manual"], in: app)
        XCTAssertTrue(
            createEntry.waitForExistence(timeout: 10),
            "tapping Manual must list its entries:\n\(app.debugDescription)"
        )
        for topic in ["restoreWallet", "pairWithMetaMask", "signWithMetaMask", "whenSomethingGoesWrong"] {
            XCTAssertTrue(
                row("guide-row-\(topic)", in: app).exists,
                "the manual's '\(topic)' entry must be listed:\n\(app.debugDescription)"
            )
        }

        // The first row pushes the explanation, as one page of cards.
        tap(row("guide-row-explanation", in: app), in: app)
        XCTAssertTrue(
            app.staticTexts["The YubiKey holds the key"].waitForExistence(timeout: 10),
            "'How it works' must push the explanation:\n\(app.debugDescription)"
        )
        tapNavigationBack(in: app)
        XCTAssertTrue(
            row("guide-row-explanation", in: app).waitForExistence(timeout: 10),
            "the explanation's back button must return to the table:\n\(app.debugDescription)"
        )

        // A manual entry pushes its own procedure.
        tap(createEntry, in: app)
        XCTAssertTrue(
            app.staticTexts["Choose how the YubiKey is read"].waitForExistence(timeout: 10),
            "a manual entry must push its own procedure:\n\(app.debugDescription)"
        )
        tapNavigationBack(in: app)

        // And the way out of the table is its own back button.
        let back = app.buttons["guide-back"]
        XCTAssertTrue(
            back.waitForExistence(timeout: 10),
            "the guide's table needs a back button:\n\(app.debugDescription)"
        )
        back.tap()
        XCTAssertTrue(
            app.buttons["route-signing"].waitForExistence(timeout: 15),
            "back must return to the home screen:\n\(app.debugDescription)"
        )
    }

    /// A row of the guide's table, by the identifier the row carries.
    ///
    /// Addressed by identifier and matched as any descendant rather than as a button or a cell: which
    /// of those a `NavigationLink` row in a `List` becomes is SwiftUI's business, and the identifier
    /// is on the row either way.
    private func row(_ identifier: String, in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any)[identifier].firstMatch
    }

    private func tap(
        _ element: XCUIElement,
        in app: XCUIApplication,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertTrue(
            element.waitForExistence(timeout: 10),
            "\(element) never appeared:\n\(app.debugDescription)",
            file: file, line: line
        )
        tapWhenVisible(element, in: app, file: file, line: line)
    }

    /// The navigation bar's first button on a pushed screen is the system back button.
    private func tapNavigationBack(
        in app: XCUIApplication,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let back = app.navigationBars.buttons.element(boundBy: 0)
        XCTAssertTrue(
            back.waitForExistence(timeout: 10),
            "a pushed screen must have a back button:\n\(app.debugDescription)",
            file: file, line: line
        )
        back.tap()
    }
}
