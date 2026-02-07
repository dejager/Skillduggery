import Foundation
import SQLite3
import Testing
@testable import Skillduggery

struct MigrationBackupTests {
  @Test
  func createsBackupBeforeVersionUpgrade() throws {
    let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-migrate-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }

    let dbURL = tempDir.appendingPathComponent("state.sqlite")
    try seedVersion1Database(at: dbURL)

    _ = Store(databaseURL: dbURL)

    let backupFiles = try FileManager.default.contentsOfDirectory(at: tempDir, includingPropertiesForKeys: nil)
      .filter { $0.lastPathComponent.contains(".backup.") && $0.pathExtension == "sqlite" }
    #expect(backupFiles.isEmpty == false)
  }

  @Test
  func priorVersionSettingsAreReadableAfterMigration() async throws {
    let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-prior-version-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }

    let dbURL = tempDir.appendingPathComponent("state.sqlite")
    var v1Settings = AppSettings.default
    v1Settings.dailySchedulingEnabled = false
    v1Settings.highSignalOnlyNotifications = false
    try seedVersion1Database(at: dbURL, settings: v1Settings)

    let migratedStore = Store(databaseURL: dbURL)
    let loaded = await migratedStore.loadSettings()

    #expect(loaded.dailySchedulingEnabled == false)
    #expect(loaded.highSignalOnlyNotifications == false)
  }

  @Test
  func rollbackRestoreKeepsStateReadableAndManualScanSmokePasses() async throws {
    let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-rollback-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }

    let dbURL = tempDir.appendingPathComponent("state.sqlite")
    let backupURL = tempDir.appendingPathComponent("state.backup.sqlite")

    var baseline = AppSettings.default
    baseline.dailySchedulingEnabled = false
    baseline.highSignalOnlyNotifications = true

    do {
      let store = Store(databaseURL: dbURL)
      await store.saveSettings(baseline)
      try FileManager.default.copyItem(at: dbURL, to: backupURL)

      var mutated = baseline
      mutated.dailySchedulingEnabled = true
      await store.saveSettings(mutated)
    }

    try FileManager.default.removeItem(at: dbURL)
    try FileManager.default.copyItem(at: backupURL, to: dbURL)

    let restoredStore = Store(databaseURL: dbURL)
    let restoredSettings = await restoredStore.loadSettings()
    #expect(restoredSettings.dailySchedulingEnabled == false)
    #expect(restoredSettings.highSignalOnlyNotifications == true)

    let scanRoot = tempDir.appendingPathComponent("rollback-safe-skill", isDirectory: true)
    try FileManager.default.createDirectory(at: scanRoot, withIntermediateDirectories: true)
    try """
        ---
        name: rollback-safe-skill
        description: Benign skill for post-rollback manual scan smoke test.
        ---

        Summarize plaintext content into bullet points.
        """.write(to: scanRoot.appendingPathComponent("SKILL.md"), atomically: true, encoding: .utf8)
    try "print('safe rollback smoke')\n".write(to: scanRoot.appendingPathComponent("script.py"), atomically: true, encoding: .utf8)

    let engine = ScanEngine()
    let run = await engine.scan(
      roots: [tempDir],
      trigger: .manual,
      config: ScanEngineConfiguration(useBehavioralAnalyzer: true, useMetaAnalyzer: true, suppressions: [])
    )
    await restoredStore.saveScanRun(run)
    let latest = await restoredStore.recentRuns(limit: 1)

    #expect(run.skillCount >= 1)
    #expect(latest.isEmpty == false)
    #expect(latest[0].trigger == .manual)
  }

  private func seedVersion1Database(at url: URL, settings: AppSettings? = nil) throws {
    var db: OpaquePointer?
    guard sqlite3_open(url.path, &db) == SQLITE_OK else {
      throw NSError(domain: "MigrationBackupTests", code: 1)
    }
    defer { sqlite3_close(db) }

    sqlite3_exec(db, "PRAGMA user_version = 1;", nil, nil, nil)
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value BLOB NOT NULL);", nil, nil, nil)
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS scan_roots (id TEXT PRIMARY KEY, path TEXT NOT NULL, bookmark BLOB NOT NULL, created_at REAL NOT NULL);", nil, nil, nil)
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS scan_runs (id TEXT PRIMARY KEY, trigger TEXT NOT NULL, started_at REAL NOT NULL, finished_at REAL NOT NULL, duration_seconds REAL NOT NULL, skill_count INTEGER NOT NULL, finding_count INTEGER NOT NULL, max_severity TEXT NOT NULL, high_critical_count INTEGER NOT NULL);", nil, nil, nil)
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, rule_id TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, file_path TEXT NULL, line_number INTEGER NULL, snippet TEXT NULL, remediation TEXT NULL, analyzer TEXT NOT NULL, metadata_json TEXT NOT NULL);", nil, nil, nil)

    if let settings {
      let data = try JSONEncoder().encode(settings)
      let sql = "INSERT INTO app_settings (key, value) VALUES (?, ?);"
      var statement: OpaquePointer?
      guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
        throw NSError(domain: "MigrationBackupTests", code: 2)
      }
      defer { sqlite3_finalize(statement) }

      _ = "app_settings".withCString { ptr in
        sqlite3_bind_text(statement, 1, ptr, -1, SQLITE_TRANSIENT)
      }
      _ = data.withUnsafeBytes { ptr in
        sqlite3_bind_blob(statement, 2, ptr.baseAddress, Int32(data.count), SQLITE_TRANSIENT)
      }
      _ = sqlite3_step(statement)
    }
  }
}

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
