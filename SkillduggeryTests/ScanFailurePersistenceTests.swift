import Foundation
import Testing
@testable import Skillduggery

struct ScanFailurePersistenceTests {
  @Test
  func persistsFailureRunForUnreadableRoots() async throws {
    let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-failure-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }
    
    let store = Store(databaseURL: tempDir.appendingPathComponent("state.sqlite"))
    let engine = ScanEngine()
    let run = await engine.failedRun(trigger: .scheduled, reason: "No readable roots selected.")
    await store.saveScanRun(run)
    
    let recent = await store.recentRuns(limit: 1)
    #expect(recent.count == 1)
    #expect(recent[0].trigger == .scheduled)
    #expect(recent[0].findings.contains(where: { $0.ruleID == "SCAN_FAILURE" }))
  }
}
