import SwiftUI

struct SuppressionView: View {
  let suppressions: [FindingSuppression]
  let onRemove: (FindingSuppression) -> Void

  var body: some View {
    if suppressions.isEmpty {
      Text("No active suppressions.")
        .font(.subheadline)
        .foregroundStyle(.secondary)
    } else {
      ForEach(suppressions) { suppression in
        HStack(alignment: .top, spacing: 12) {
          VStack(alignment: .leading, spacing: 3) {
            Text("Rule: \(suppression.ruleID)")
              .font(.subheadline)
              .fontWeight(.semibold)
            if let filePath = suppression.filePath {
              Text(filePath)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
            }
            Text(suppression.reason)
              .font(.footnote)
              .foregroundStyle(.secondary)
            if let expiresAt = suppression.expiresAt {
              Text("Expires \(expiresAt.formatted(date: .abbreviated, time: .omitted))")
                .font(.footnote)
                .foregroundStyle(.tertiary)
            }
          }
          Spacer()
          Button("Remove") {
            onRemove(suppression)
          }
          .buttonStyle(.bordered)
          .controlSize(.small)
        }
        .padding(10)
        .background(Color(nsColor: .quaternaryLabelColor).opacity(0.09), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
      }
    }
  }
}
