import SwiftUI

/// The pieces the guide page is built from.
///
/// The guide is copy, not logic: nothing in this directory decides anything about a ceremony, and
/// every claim on the page is a restatement of design.md or of the two operator checklists in
/// `docs/`. These are shared so the two halves of the page read as one document rather than as two
/// that drifted apart.

/// A titled block: the shape most of the guide is made of.
struct GuideCard<Content: View>: View {
    let title: String
    let systemImage: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: systemImage)
                .font(.headline)
            content()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

/// A paragraph inside a card.
struct GuideText: View {
    let text: String

    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text)
            .font(.callout)
            .foregroundStyle(.primary)
    }
}

/// One bulleted item.
struct GuideBullet: View {
    let text: String

    init(_ text: String) { self.text = text }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("•")
                .font(.callout)
                .foregroundStyle(.secondary)
            Text(text).font(.callout)
        }
    }
}

/// A warning or a rule the operator has to keep in mind. Deliberately loud: the things in these
/// notes are the ones whose cost is measured in lost funds or a card that has to be re-provisioned.
struct GuideNote: View {
    let title: String
    let text: String
    let systemImage: String
    var tint: Color = .orange

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: systemImage)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(tint)
            Text(text)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

/// One numbered step in a procedure.
///
/// `side` names which screen the step happens on when the procedure spans two devices — the pairing
/// and signing sections alternate, and "open the account selector" is ambiguous without it.
struct GuideStep {
    let title: String
    let detail: String
    let side: String?

    init(_ title: String, _ detail: String = "", side: String? = nil) {
        self.title = title
        self.detail = detail
        self.side = side
    }
}

/// A numbered procedure.
struct GuideSteps: View {
    let steps: [GuideStep]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text("\(index + 1)")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.white)
                        .frame(width: 20, height: 20)
                        .background(Color.accentColor, in: Circle())
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            if let side = step.side {
                                Text(side)
                                    .font(.caption2.weight(.semibold))
                                    .foregroundStyle(side == "MetaMask" ? Color.orange : Color.accentColor)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(
                                        (side == "MetaMask" ? Color.orange : Color.accentColor)
                                            .opacity(0.15),
                                        in: Capsule()
                                    )
                            }
                            Text(step.title)
                                .font(.callout.weight(.semibold))
                        }
                        if !step.detail.isEmpty {
                            Text(step.detail)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }
}

/// A heading between the parts of the page, and between the procedures inside the manual.
struct GuideHeading: View {
    let text: String

    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text)
            .font(.title3.weight(.semibold))
            .padding(.top, 4)
    }
}
