import SwiftUI
import AppKit

struct SettingsView: View {
  @ObservedObject var model: AppModel
  @State private var expandedRunIDs: Set<UUID> = []
  @State private var settingsWindow: NSWindow?
  private let findingsSectionScrollID = "settings-recent-findings-section"

  var body: some View {
    ScrollViewReader { proxy in
      ScrollView {
        VStack(alignment: .leading, spacing: 18) {
          header
          rootsSection
          scheduleSection
          policySection
          findingsSection
          suppressionsSection
          manualSection
        }
        .padding(24)
        .frame(maxWidth: 860, alignment: .leading)
      }
      .frame(minWidth: 760, idealWidth: 840, minHeight: 640)
      .onAppear {
        bringSettingsWindowToFront()
        applyNavigationRequest(with: proxy)
      }
      .onChange(of: model.settingsNavigationRequest?.id) {
        bringSettingsWindowToFront()
        applyNavigationRequest(with: proxy)
      }
      .onChange(of: model.settingsFocusRequestID) {
        bringSettingsWindowToFront()
      }
      .background(
        WindowAccessor { window in
          settingsWindow = window
        }
      )
    }
  }

  private var header: some View {
    HStack(alignment: .center, spacing: 12) {
      Image(systemName: model.menuBarSymbol)
        .font(.title2)
        .foregroundStyle(.tint)
        .frame(width: 32, height: 32)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))

      VStack(alignment: .leading, spacing: 2) {
        Text("Skillduggery Settings")
          .font(.title3.weight(.semibold))
        Text(model.latestSummaryText)
          .font(.subheadline)
          .foregroundStyle(.secondary)
      }
    }
  }

  private var rootsSection: some View {
    settingsSection(
      title: "Scan Roots",
      subtitle: "Choose folders that contain OpenAI/Claude skill packages.",
      systemImage: "folder.badge.gearshape"
    ) {
      if model.roots.isEmpty {
        Text("No folders selected yet.")
          .font(.subheadline)
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(12)
          .background(Color(nsColor: .quaternaryLabelColor).opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
      } else {
        LazyVStack(spacing: 8) {
          ForEach(model.roots) { root in
            HStack(alignment: .top, spacing: 12) {
              VStack(alignment: .leading, spacing: 4) {
                Text(root.displayName)
                  .font(.subheadline.weight(.medium))
                Text(root.path)
                  .font(.footnote)
                  .foregroundStyle(.secondary)
                  .textSelection(.enabled)
              }
              Spacer(minLength: 16)
              Button("Remove") {
                model.removeRoot(root)
              }
              .buttonStyle(.bordered)
              .controlSize(.small)
            }
            .padding(10)
            .background(Color(nsColor: .quaternaryLabelColor).opacity(0.09), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
          }
        }
      }

      Button("Add Folder…") {
        model.openRootPicker()
      }
      .buttonStyle(.borderedProminent)
    }
  }

  private var scheduleSection: some View {
    settingsSection(
      title: "Scheduling",
      subtitle: "Configure automatic scans and startup behavior.",
      systemImage: "clock.arrow.circlepath"
    ) {
      settingToggle(
        title: "Enable daily scans",
        description: "Runs one scheduled scan per day and catches up if missed.",
        binding: Binding(
          get: { model.settings.dailySchedulingEnabled },
          set: { newValue in
            model.settings.dailySchedulingEnabled = newValue
            model.saveSettings()
          }
        )
      )

      settingToggle(
        title: "Auto-launch at login",
        description: "Starts the scanner in the menu bar when you sign in.",
        binding: Binding(
          get: { model.settings.loginAtLaunchEnabled },
          set: { newValue in
            model.settings.loginAtLaunchEnabled = newValue
            model.saveSettings()
          }
        )
      )
    }
  }

  private var policySection: some View {
    settingsSection(
      title: "Detection Policy",
      subtitle: "Tune signal level and analyzer behavior.",
      systemImage: "eyeglasses"
    ) {
      settingToggle(
        title: "High-signal only notifications",
        description: "Notify only when HIGH or CRITICAL findings are detected.",
        binding: Binding(
          get: { model.settings.highSignalOnlyNotifications },
          set: { newValue in
            model.settings.highSignalOnlyNotifications = newValue
            model.saveSettings()
          }
        )
      )

      settingToggle(
        title: "Behavioral analyzer",
        description: "Inspect script flows for suspicious source/sink behavior.",
        binding: Binding(
          get: { model.settings.analyzerBehavioralEnabled },
          set: { newValue in
            model.settings.analyzerBehavioralEnabled = newValue
            model.saveSettings()
          }
        )
      )

      settingToggle(
        title: "Meta false-positive filter",
        description: "Deduplicate and suppress low-confidence findings.",
        binding: Binding(
          get: { model.settings.analyzerMetaEnabled },
          set: { newValue in
            model.settings.analyzerMetaEnabled = newValue
            model.saveSettings()
          }
        )
      )
    }
  }

  private var findingsSection: some View {
    settingsSection(
      title: "Recent Findings",
      subtitle: "Review recent alerts and suppress noisy rules for 7 days.",
      systemImage: "exclamationmark.triangle"
    ) {
      FindingsListView(runs: model.recentRuns, expandedRunIDs: $expandedRunIDs) { finding in
        model.suppress(finding, forDays: 7, reason: "Suppressed from settings")
      }
    }
    .id(findingsSectionScrollID)
  }

  private var suppressionsSection: some View {
    settingsSection(
      title: "Suppressions",
      subtitle: "Manage active suppression rules.",
      systemImage: "line.3.horizontal.decrease.circle"
    ) {
      SuppressionView(suppressions: model.suppressions) { suppression in
        model.removeSuppression(suppression)
      }
    }
  }

  private var manualSection: some View {
    settingsSection(
      title: "Manual Control",
      subtitle: "Run scans on demand.",
      systemImage: "bolt.circle"
    ) {
      HStack(spacing: 12) {
        Button(model.isScanRunning ? "Scanning…" : "Run Manual Scan") {
          model.runManualScan()
        }
        .buttonStyle(.borderedProminent)
        .disabled(model.isScanRunning)

        if model.isScanRunning {
          ProgressView()
            .controlSize(.small)
        }
      }

      if let error = model.lastErrorMessage {
        Text(error)
          .font(.footnote)
          .foregroundStyle(.red)
          .padding(.top, 2)
      }
    }
  }

  @ViewBuilder
  private func settingToggle(title: String, description: String, binding: Binding<Bool>) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      Toggle(title, isOn: binding)
      Text(description)
        .font(.footnote)
        .foregroundStyle(.secondary)
        .padding(.leading, 2)
    }
  }

  @ViewBuilder
  private func settingsSection<Content: View>(
    title: String,
    subtitle: String,
    systemImage: String,
    @ViewBuilder content: () -> Content
  ) -> some View {
    GroupBox {
      VStack(alignment: .leading, spacing: 12) {
        content()
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.top, 4)
    } label: {
      VStack(alignment: .leading, spacing: 2) {
        Label(title, systemImage: systemImage)
          .font(.headline)
        Text(subtitle)
          .font(.footnote)
          .foregroundStyle(.secondary)
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }

  private func applyNavigationRequest(with proxy: ScrollViewProxy) {
    guard let request = model.settingsNavigationRequest else {
      return
    }

    expandedRunIDs.insert(request.runID)

    DispatchQueue.main.async {
      withAnimation(.easeInOut(duration: 0.2)) {
        proxy.scrollTo(findingsSectionScrollID, anchor: .top)
      }

      DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
        withAnimation(.easeInOut(duration: 0.2)) {
          proxy.scrollTo(request.runID, anchor: .top)
        }
        model.clearSettingsNavigationRequest(request.id)
      }
    }
  }

  private func bringSettingsWindowToFront() {
    DispatchQueue.main.async {
      if #available(macOS 14, *) {
        NSApp.activate(ignoringOtherApps: false)
      } else {
        NSApp.activate(ignoringOtherApps: true)
      }

      if let window = settingsWindow {
        window.orderFrontRegardless()
        window.makeKeyAndOrderFront(nil)
      }
    }
  }
}

private struct WindowAccessor: NSViewRepresentable {
  let onWindowResolved: (NSWindow?) -> Void

  func makeNSView(context: Context) -> NSView {
    let view = NSView(frame: .zero)
    DispatchQueue.main.async {
      onWindowResolved(view.window)
    }
    return view
  }

  func updateNSView(_ nsView: NSView, context: Context) {
    DispatchQueue.main.async {
      onWindowResolved(nsView.window)
    }
  }
}
