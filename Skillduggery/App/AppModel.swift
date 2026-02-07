import Foundation
import AppKit
import Combine

struct SettingsNavigationRequest: Equatable {
  let id: UUID
  let runID: UUID
}

@MainActor final class AppModel: ObservableObject {
  @Published private(set) var roots: [ScanRoot] = []
  @Published private(set) var recentRuns: [ScanRun] = []
  @Published private(set) var suppressions: [FindingSuppression] = []
  @Published var settings: AppSettings = .default
  @Published var isScanRunning = false
  @Published var pendingTrigger: ScanTrigger?
  @Published var lastErrorMessage: String?
  @Published private(set) var settingsNavigationRequest: SettingsNavigationRequest?
  @Published private(set) var settingsFocusRequestID: UUID?

  private let store: Store
  private let engine: ScanEngine
  private let notifications: NotificationService
  private let scheduler: ScheduleService

  private var lifecycleObserver: AppLifecycleObserver?

  init(
    store: Store? = nil,
    engine: ScanEngine? = nil,
    notifications: NotificationService? = nil,
    scheduler: ScheduleService? = nil,
    requestNotificationPermissionOnInit: Bool = true
  ) {
    self.store = store ?? Store()
    self.engine = engine ?? ScanEngine()
    self.notifications = notifications ?? NotificationService()
    self.scheduler = scheduler ?? ScheduleService()

    self.scheduler.delegate = self
    if requestNotificationPermissionOnInit {
      self.notifications.requestPermission()
    }

    lifecycleObserver = AppLifecycleObserver { [weak self] in
      Task { @MainActor in
        self?.handleWake()
      }
    }

    Task {
      await bootstrap()
    }
  }

  var menuBarSymbol: String {
    if isScanRunning { return "eye.half.closed.fill" }
    if let run = recentRuns.first, run.maxSeverity.priority >= Severity.high.priority {
      return "eye.trianglebadge.exclamationmark.fill"
    }
    return "eye.fill"
  }

  var menuStatusLabel: String {
    if isScanRunning {
      return "Scanning..."
    }

    guard let run = recentRuns.first else {
      return "No scans yet"
    }

    let timestamp = run.finishedAt.formatted(date: .numeric, time: .shortened)
    return "Last scan: \(timestamp)"
  }

  var menuThreats: [ScanFinding] {
    var seen: Set<String> = []
    var threats: [ScanFinding] = []

    for run in recentRuns {
      for finding in run.findings where finding.severity == .high || finding.severity == .critical {
        let key = "\(finding.ruleID)|\(finding.filePath ?? "")|\(finding.lineNumber ?? 0)"
        if seen.contains(key) { continue }
        seen.insert(key)
        threats.append(finding)

        if threats.count >= 8 {
          return threats
        }
      }
    }

    return threats
  }

  var latestSummaryText: String {
    guard let run = recentRuns.first else {
      return "No scans yet"
    }

    let formatter = RelativeDateTimeFormatter()
    formatter.unitsStyle = .short
    let when = formatter.localizedString(for: run.finishedAt, relativeTo: Date())
    return "\(run.maxSeverity.rawValue) • \(run.highOrCriticalCount) high/critical • \(when)"
  }

  func bootstrap() async {
    let loadedSettings = await store.loadSettings()
    let loadedRoots = await store.loadRoots()
    let loadedRuns = await store.recentRuns(limit: 25)
    let loadedSuppressions = await store.activeSuppressions(at: Date())

    settings = loadedSettings
    roots = loadedRoots
    recentRuns = loadedRuns
    suppressions = loadedSuppressions

    scheduler.start(enabled: settings.dailySchedulingEnabled) { [weak self] in
      self?.settings.lastScanAttemptAt ?? self?.settings.lastSuccessfulRunAt
    }
    scheduler.handleLaunchOrWake()

    if settings.loginAtLaunchEnabled {
      _ = LoginLaunchService.setEnabled(true)
    }
  }

  func openRootPicker() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.allowsMultipleSelection = true
    panel.prompt = "Add Roots"

    if panel.runModal() == .OK {
      addRoots(panel.urls)
    }
  }

  func addRoots(_ urls: [URL]) {
    for url in urls {
      do {
        let bookmark = try url.bookmarkData(options: [.withSecurityScope], includingResourceValuesForKeys: nil, relativeTo: nil)
        Task {
          await store.addRoot(path: url.path, bookmarkData: bookmark)
          let latestRoots = await store.loadRoots()
          await MainActor.run {
            roots = latestRoots
          }
        }
      } catch {
        lastErrorMessage = "Failed to add root: \(url.path)"
      }
    }
  }

  func removeRoot(_ root: ScanRoot) {
    Task {
      await store.removeRoot(id: root.id)
      let latest = await store.loadRoots()
      await MainActor.run {
        roots = latest
      }
    }
  }

  func saveSettings() {
    Task {
      await store.saveSettings(settings)
    }

    scheduler.start(enabled: settings.dailySchedulingEnabled) { [weak self] in
      self?.settings.lastScanAttemptAt ?? self?.settings.lastSuccessfulRunAt
    }

    _ = LoginLaunchService.setEnabled(settings.loginAtLaunchEnabled)
  }

  func runManualScan() {
    requestScan(.manual)
  }

  func openSettingsForRecentRun(_ runID: UUID) {
    requestSettingsFocus()
    settingsNavigationRequest = SettingsNavigationRequest(id: UUID(), runID: runID)
  }

  func requestSettingsFocus() {
    settingsFocusRequestID = UUID()
  }

  func clearSettingsNavigationRequest(_ requestID: UUID) {
    guard settingsNavigationRequest?.id == requestID else { return }
    settingsNavigationRequest = nil
  }

  func requestScan(_ trigger: ScanTrigger) {
    if isScanRunning {
      enqueuePending(trigger)
      return
    }

    isScanRunning = true
    Task {
      await performScan(trigger)
    }
  }

  func handleWake() {
    scheduler.handleLaunchOrWake()
  }

  func suppress(_ finding: ScanFinding, forDays days: Int = 7, reason: String = "User suppression") {
    let suppression = FindingSuppression(
      id: UUID(),
      ruleID: finding.ruleID,
      filePath: finding.filePath,
      reason: reason,
      createdAt: Date(),
      expiresAt: Calendar.current.date(byAdding: .day, value: days, to: Date())
    )

    Task {
      await store.upsertSuppression(suppression)
      let latest = await store.activeSuppressions(at: Date())
      await MainActor.run {
        suppressions = latest
      }
    }
  }

  func removeSuppression(_ suppression: FindingSuppression) {
    Task {
      await store.deleteSuppression(id: suppression.id)
      let latest = await store.activeSuppressions(at: Date())
      await MainActor.run {
        suppressions = latest
      }
    }
  }

  private func enqueuePending(_ trigger: ScanTrigger) {
    if let existing = pendingTrigger {
      if trigger.priority >= existing.priority {
        pendingTrigger = trigger
      }
    } else {
      pendingTrigger = trigger
    }
  }

  private func performScan(_ trigger: ScanTrigger) async {
    let (urls, cleanup) = resolveRootURLs()
    defer { cleanup() }

    let activeSuppressions = await store.activeSuppressions(at: Date())
    await MainActor.run {
      suppressions = activeSuppressions
    }

    let config = ScanEngineConfiguration(
      useBehavioralAnalyzer: settings.analyzerBehavioralEnabled,
      useMetaAnalyzer: settings.analyzerMetaEnabled,
      suppressions: activeSuppressions
    )

    let run: ScanRun
    if urls.isEmpty {
      run = await engine.failedRun(trigger: trigger, reason: "No readable roots selected.")
    } else {
      run = await engine.scan(roots: urls, trigger: trigger, config: config)
    }

    await store.saveScanRun(run)
    settings.lastScanAttemptAt = run.finishedAt
    if urls.isEmpty == false {
      settings.lastSuccessfulRunAt = run.finishedAt
    }
    await store.saveSettings(settings)
    let latestRuns = await store.recentRuns(limit: 25)

    await MainActor.run {
      recentRuns = latestRuns
      notifications.notifyIfNeeded(run: run, highSignalOnly: settings.highSignalOnlyNotifications)
      isScanRunning = false
      lastErrorMessage = urls.isEmpty ? "No readable roots selected" : nil
      scheduler.start(enabled: settings.dailySchedulingEnabled) { [weak self] in
        self?.settings.lastScanAttemptAt ?? self?.settings.lastSuccessfulRunAt
      }

      if let pending = pendingTrigger {
        pendingTrigger = nil
        requestScan(pending)
      }
    }
  }

  private func resolveRootURLs() -> ([URL], () -> Void) {
    var resolved: [URL] = []
    var startedURLs: [URL] = []

    for root in roots {
      var stale = false
      guard let url = try? URL(
        resolvingBookmarkData: root.bookmarkData,
        options: [.withSecurityScope],
        relativeTo: nil,
        bookmarkDataIsStale: &stale
      ) else {
        continue
      }

      if url.startAccessingSecurityScopedResource() {
        startedURLs.append(url)
        resolved.append(url)
      }
    }

    let cleanup = {
      for url in startedURLs {
        url.stopAccessingSecurityScopedResource()
      }
    }

    return (resolved, cleanup)
  }
}

extension AppModel: ScheduleServiceDelegate {
  func scheduleServiceDidRequestScheduledScan() {
    requestScan(.scheduled)
  }

  func scheduleServiceDidRequestCatchUpScan() {
    requestScan(.catchUp)
  }
}
