import SwiftUI

/// The guide's table: **How it works**, and **Manual** with its procedures under it.
///
/// Two rows, as deep as this screen goes. The explanation is one page — it is meant to be read
/// through, not navigated — while the manual is five procedures that are looked up one at a time, so
/// its row opens into the entries instead of leading somewhere itself. Everything past this screen is
/// a pushed page with the navigation bar's back button at its head.
struct GuideView: View {
    /// Leaves the guide. Named for what the button says: this screen is the root of its own stack, so
    /// its way out is a back button in the navigation bar rather than a bar of its own at the foot.
    let onBack: () -> Void

    /// The manual's entries are closed until they are asked for: the table is a menu of two things,
    /// and the one row that leads straight to a page should not have to compete with six rows that
    /// each lead somewhere else.
    @State private var manualIsExpanded = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink(value: GuideDestination.explanation) {
                        GuideRow(
                            title: "How it works",
                            subtitle: "Where the key lives, what this app keeps, and what the wallet does."
                        )
                    }
                    .accessibilityIdentifier("guide-row-explanation")

                    DisclosureGroup(isExpanded: $manualIsExpanded) {
                        ForEach(ManualTopic.allCases) { topic in
                            NavigationLink(value: GuideDestination.manual(topic)) {
                                GuideRow(title: topic.title, subtitle: topic.subtitle)
                            }
                            .accessibilityIdentifier("guide-row-\(topic.rawValue)")
                        }
                    } label: {
                        GuideRow(
                            title: "Manual",
                            subtitle: "Creating, restoring, pairing and signing, step by step."
                        )
                    }
                    .accessibilityIdentifier("guide-row-manual")
                }
            }
            .navigationTitle("How it works")
            .navigationDestination(for: GuideDestination.self) { destination in
                switch destination {
                case .explanation:
                    ExplanationPage()
                case .manual(let topic):
                    ManualTopicPage(topic: topic)
                }
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        onBack()
                    } label: {
                        Label("Back", systemImage: "chevron.left")
                    }
                    .accessibilityIdentifier("guide-back")
                }
            }
        }
    }
}

/// Where a row of the table leads.
enum GuideDestination: Hashable {
    /// The explanation, as one page.
    case explanation
    /// One procedure of the manual.
    case manual(ManualTopic)
}

/// The explanation: nine cards that run in the order the questions come in.
private struct ExplanationPage: View {
    var body: some View {
        ScrollView {
            HowItWorksView()
                .padding()
        }
        .navigationTitle("How it works")
        .navigationBarTitleDisplayMode(.inline)
    }
}
