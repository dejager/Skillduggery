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

  private func seedVersion1Database(at url: URL) throws {
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
  }
}
