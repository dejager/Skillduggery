import SwiftUI

struct FindingsListView: View {
  let runs: [ScanRun]
  @Binding var expandedRunIDs: Set<UUID>
  let onSuppress: (ScanFinding) -> Void

  var body: some View {
    if runs.isEmpty {
      Text("No findings yet.")
        .font(.subheadline)
        .foregroundStyle(.secondary)
    } else {
      ForEach(Array(runs.prefix(10)), id: \.id) { run in
        DisclosureGroup(
          isExpanded: isExpandedBinding(for: run.id),
          content: {
            if run.findings.isEmpty {
              Text("No findings")
                .font(.footnote)
                .foregroundStyle(.secondary)
            } else {
              ForEach(run.findings.prefix(8), id: \.id) { finding in
                HStack(alignment: .top, spacing: 12) {
                  Text(finding.severity.rawValue)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(severityColor(finding.severity), in: Capsule())

                  VStack(alignment: .leading, spacing: 4) {
                    Text(finding.title)
                      .font(.subheadline.weight(.medium))
                    Text(finding.description)
                      .font(.footnote)
                      .foregroundStyle(.secondary)
                    if let path = finding.filePath {
                      Text(path)
                        .font(.footnote)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                    }
                  }
                  Spacer()
                  Button("Suppress 7d") {
                    onSuppress(finding)
                  }
                  .buttonStyle(.bordered)
                  .controlSize(.small)
                }
                .padding(10)
                .background(Color(nsColor: .quaternaryLabelColor).opacity(0.09), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
              }
            }
          },
          label: {
            Text("\(run.finishedAt.formatted(date: .abbreviated, time: .shortened)) • \(run.maxSeverity.rawValue)")
          }
        )
        .id(run.id)
        .padding(.vertical, 2)
      }
    }
  }

  private func isExpandedBinding(for runID: UUID) -> Binding<Bool> {
    Binding(
      get: { expandedRunIDs.contains(runID) },
      set: { isExpanded in
        if isExpanded {
          expandedRunIDs.insert(runID)
        } else {
          expandedRunIDs.remove(runID)
        }
      }
    )
  }

  private func severityColor(_ severity: Severity) -> Color {
    switch severity {
      case .critical:
        return .red
      case .high:
        return .orange
      case .medium:
        return .yellow
      case .low:
        return .blue
      case .info, .safe:
        return .gray
    }
  }
}
