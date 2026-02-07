import SwiftUI
import AppKit

struct MenuBarSceneView: View {
  @ObservedObject var model: AppModel

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      Text("Skillduggery")
        .font(.headline)

      Text(model.menuStatusLabel)
        .font(.caption)
        .foregroundStyle(.secondary)

      if model.isScanRunning {
        HStack(spacing: 8) {
          ProgressView()
            .controlSize(.small)
          Text("Scanning…")
            .font(.caption)
        }
      }

      if let pending = model.pendingTrigger {
        Text("Pending: \(pending.rawValue)")
          .font(.caption2)
          .foregroundStyle(.orange)
      }

      Divider()

      Button {
        model.runManualScan()
      } label: {
        Label("Scan Agent Skills", systemImage: "eye.fill")
          .labelStyle(MenuActionLabelStyle(iconWidth: 18))
      }
      .buttonStyle(.plain)
      .keyboardShortcut("s", modifiers: [.command])

      SettingsLink {
        Label("Settings…", systemImage: "gearshape.fill")
          .labelStyle(MenuActionLabelStyle(iconWidth: 18))
      }
      .simultaneousGesture(TapGesture().onEnded {
        model.requestSettingsFocus()
      })
      .buttonStyle(.plain)
      .keyboardShortcut(",", modifiers: [.command])

      Divider()

      if model.menuThreats.isEmpty {
        Text("No HIGH/CRITICAL threats found")
          .font(.caption2)
          .foregroundStyle(.secondary)
      } else {
        Text("Threats")
          .font(.caption)
          .fontWeight(.semibold)

        ForEach(model.menuThreats, id: \.id) { threat in
          VStack(alignment: .leading, spacing: 2) {
            Text("[\(threat.severity.rawValue)] \(threat.title)")
              .font(.caption2)
              .foregroundStyle(threat.severity == .critical ? .red : .orange)

            if let path = threat.filePath {
              Text(path)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            }
          }
        }
      }

      Divider()

      let latest = model.recentRuns.prefix(5)
      if latest.isEmpty {
        Text("No scan history")
          .font(.caption)
          .foregroundStyle(.secondary)
      } else {
        Text("Recent Findings")
          .font(.caption)
          .fontWeight(.semibold)

        ForEach(Array(latest), id: \.id) { run in
          let alertCount = run.highOrCriticalCount
          let warningCount = run.findings.filter { finding in
            finding.severity == .medium || finding.severity == .low
          }.count

          SettingsLink {
            HStack {
              Text(run.maxSeverity.rawValue)
                .font(.caption2)
                .foregroundStyle(severityColor(run.maxSeverity))
              if alertCount > 0 {
                Text("^[\(alertCount) alert](inflect: true)")
                  .font(.caption2)
              } else if warningCount > 0 {
                Text("^[\(warningCount) warning](inflect: true)")
                  .font(.caption2)
              }
              Spacer(minLength: 8)
              Text(run.finishedAt.formatted(date: .omitted, time: .shortened))
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
          }
          .buttonStyle(.plain)
          .simultaneousGesture(TapGesture().onEnded {
            model.openSettingsForRecentRun(run.id)
          })
        }
      }

      Divider()

      Button("Quit") {
        NSApplication.shared.terminate(nil)
      }
      .buttonStyle(.plain)
      .keyboardShortcut("q", modifiers: [.command])
    }
    .padding(12)
    .frame(width: 320)
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
        return .green
      case .safe:
        return .blue
      case .info:
        return .secondary
    }
  }

}

private struct MenuActionLabelStyle: LabelStyle {
  let iconWidth: CGFloat

  func makeBody(configuration: Configuration) -> some View {
    HStack(spacing: 8) {
      configuration.icon
        .frame(width: iconWidth, alignment: .center)

      configuration.title
        .frame(maxWidth: .infinity, alignment: .leading)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}
