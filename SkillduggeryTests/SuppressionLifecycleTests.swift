import Foundation
import Testing
@testable import Skillduggery

struct SuppressionLifecycleTests {
  @Test
  func suppressionPersistsAndExpires() async throws {
    let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-suppress-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }
    
    let dbURL = tempDir.appendingPathComponent("state.sqlite")
    let store = Store(databaseURL: dbURL)
    
    let active = FindingSuppression(
      id: UUID(),
      ruleID: "RULE_ACTIVE",
      filePath: "script.py",
      reason: "known-safe fixture",
      createdAt: Date(),
      expiresAt: Date().addingTimeInterval(3600)
    )
    let expired = FindingSuppression(
      id: UUID(),
      ruleID: "RULE_EXPIRED",
      filePath: nil,
      reason: "old",
      createdAt: Date().addingTimeInterval(-7200),
      expiresAt: Date().addingTimeInterval(-3600)
    )
    
    await store.upsertSuppression(active)
    await store.upsertSuppression(expired)
    
    let loaded = await store.activeSuppressions(at: Date())
    #expect(loaded.count == 1)
    #expect(loaded.first?.ruleID == "RULE_ACTIVE")
  }
  
  @Test
  func metaAnalyzerFiltersSuppressedFindings() {
    let analyzer = MetaAnalyzer()
    let finding = ScanFinding(
      id: "f1",
      ruleID: "RULE",
      category: .promptInjection,
      severity: .high,
      title: "Prompt override",
      description: "Detected",
      filePath: "SKILL.md",
      analyzer: "static"
    )
    
    let suppression = FindingSuppression(
      id: UUID(),
      ruleID: "RULE",
      filePath: "SKILL.md",
      reason: "reviewed",
      createdAt: Date(),
      expiresAt: Date().addingTimeInterval(3600)
    )
    
    let refined = analyzer.refine(findings: [finding], suppressions: [suppression], now: Date())
    #expect(refined.isEmpty)
  }
}
