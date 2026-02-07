import Foundation
import Testing
@testable import Skillduggery

struct NotificationThresholdTests {
  @Test
  func highSignalOnlySkipsMediumFindings() {
    let run = ScanRun(
      id: UUID(),
      trigger: .manual,
      startedAt: Date(),
      finishedAt: Date(),
      durationSeconds: 0.5,
      skillCount: 1,
      findingCount: 1,
      maxSeverity: .medium,
      findings: [
        ScanFinding(
          id: "1",
          ruleID: "RULE",
          category: .policyViolation,
          severity: .medium,
          title: "Medium finding",
          description: "Informational issue",
          analyzer: "static"
        )
      ]
    )

    let summary = NotificationService.makeSummary(for: run, highSignalOnly: true)
    #expect(summary == nil)
  }

  @Test
  func highSignalOnlyNotifiesForHighAndCritical() {
    let run = ScanRun(
      id: UUID(),
      trigger: .manual,
      startedAt: Date(),
      finishedAt: Date(),
      durationSeconds: 0.5,
      skillCount: 2,
      findingCount: 2,
      maxSeverity: .critical,
      findings: [
        ScanFinding(
          id: "1",
          ruleID: "RULE1",
          category: .dataExfiltration,
          severity: .critical,
          title: "Critical finding",
          description: "Critical",
          analyzer: "static"
        ),
        ScanFinding(
          id: "2",
          ruleID: "RULE2",
          category: .promptInjection,
          severity: .high,
          title: "High finding",
          description: "High",
          analyzer: "behavioral"
        )
      ]
    )

    let summary = NotificationService.makeSummary(for: run, highSignalOnly: true)
    #expect(summary != nil)
    #expect(summary?.body.contains("1 critical") == true)
    #expect(summary?.body.contains("1 high") == true)
  }
}
