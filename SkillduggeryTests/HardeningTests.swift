import Foundation
import Testing
@testable import Skillduggery

struct Release2HardeningTests {
  @MainActor
  @Test
  func menuRemainsInteractiveDuringActiveScanState() async throws {
    let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-menu-interactive-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }

    let model = AppModel(
      store: Store(databaseURL: tempDir.appendingPathComponent("state.sqlite")),
      engine: ScanEngine(),
      notifications: NotificationService(),
      scheduler: ScheduleService(interval: 24 * 60 * 60),
      requestNotificationPermissionOnInit: false
    )

    model.isScanRunning = true
    #expect(model.menuStatusLabel == "Scanning...")

    let focusBefore = model.settingsFocusRequestID
    model.requestSettingsFocus()
    #expect(model.settingsFocusRequestID != focusBefore)

    let targetRunID = UUID()
    model.openSettingsForRecentRun(targetRunID)
    #expect(model.settingsNavigationRequest?.runID == targetRunID)
  }

  @Test
  func benignFixtureProducesNoHighSignalFindings() async throws {
    let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-benign-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempRoot) }

    let skillDir = tempRoot.appendingPathComponent("safe-helper", isDirectory: true)
    try FileManager.default.createDirectory(at: skillDir, withIntermediateDirectories: true)

    let skillMarkdown = """
        ---
        name: safe-helper
        description: Benign helper skill for baseline validation.
        ---

        Summarize notes and format bullet lists for readability.
        """
    try skillMarkdown.write(to: skillDir.appendingPathComponent("SKILL.md"), atomically: true, encoding: .utf8)

    let pythonScript = """
        def summarize_notes(lines):
            return "\\n".join(f"- {line.strip()}" for line in lines if line.strip())
        """
    try pythonScript.write(to: skillDir.appendingPathComponent("summarize.py"), atomically: true, encoding: .utf8)

    let engine = ScanEngine()
    let config = ScanEngineConfiguration(
      useBehavioralAnalyzer: true,
      useMetaAnalyzer: true,
      suppressions: []
    )

    let run = await engine.scan(roots: [tempRoot], trigger: .manual, config: config)
    let highSignal = run.findings.filter { $0.severity == .high || $0.severity == .critical }

    #expect(run.skillCount == 1)
    #expect(highSignal.isEmpty)
  }

  @Test
  func staticScanOfHundredSmallSkillsStaysWithinBudget() async throws {
    let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-scale-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempRoot) }

    for index in 0..<100 {
      let skillDir = tempRoot.appendingPathComponent("skill-\(index)", isDirectory: true)
      try FileManager.default.createDirectory(at: skillDir, withIntermediateDirectories: true)
      try """
          ---
          name: skill-\(index)
          description: Fixture skill \(index)
          ---

          Perform a safe deterministic transformation.
          """.write(to: skillDir.appendingPathComponent("SKILL.md"), atomically: true, encoding: .utf8)
      try "print('safe \(index)')\n".write(to: skillDir.appendingPathComponent("task.py"), atomically: true, encoding: .utf8)
    }

    let engine = ScanEngine()
    let config = ScanEngineConfiguration(
      useBehavioralAnalyzer: false,
      useMetaAnalyzer: true,
      suppressions: []
    )

    let startedAt = Date()
    let run = await engine.scan(roots: [tempRoot], trigger: .manual, config: config)
    let elapsed = Date().timeIntervalSince(startedAt)

    #expect(run.skillCount == 100)
    #expect(elapsed < 10.0)
  }

  @MainActor
  @Test
  func settingsDeepLinkRequestOpensSpecificRunContext() async throws {
    let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-nav-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }

    let model = AppModel(
      store: Store(databaseURL: tempDir.appendingPathComponent("state.sqlite")),
      engine: ScanEngine(),
      notifications: NotificationService(),
      scheduler: ScheduleService(interval: 24 * 60 * 60),
      requestNotificationPermissionOnInit: false
    )

    let runID = UUID()
    model.openSettingsForRecentRun(runID)

    #expect(model.settingsFocusRequestID != nil)
    #expect(model.settingsNavigationRequest?.runID == runID)

    let requestID = try #require(model.settingsNavigationRequest?.id)
    model.clearSettingsNavigationRequest(requestID)
    #expect(model.settingsNavigationRequest == nil)
  }
}
