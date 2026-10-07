import SwiftUI

/// One row of the guide's table: the row's own text.
///
/// The table is two rows deep — *How it works*, and *Manual* with its procedures under it — so a row
/// carries a title and one line saying what it opens.
struct GuideRow: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
            Text(subtitle)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}
