import Foundation
import SQLite3

actor Store {
  private var db: OpaquePointer?
  private let databaseURL: URL

  init(databaseURL: URL? = nil) {
    if let databaseURL {
      self.databaseURL = databaseURL
    } else {
      let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
      let folder = appSupport.appendingPathComponent("Skillduggery", isDirectory: true)
      try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
      self.databaseURL = folder.appendingPathComponent("skillduggery.sqlite")
    }

    self.db = Self.openDatabase(at: self.databaseURL)
    Self.migrate(databaseURL: self.databaseURL, db: self.db)
  }

  deinit {
    sqlite3_close(db)
  }

  func loadSettings() -> AppSettings {
    guard let data = loadSettingBlob(key: "app_settings") else {
      return .default
    }

    return (try? JSONDecoder().decode(AppSettings.self, from: data)) ?? .default
  }

  func saveSettings(_ settings: AppSettings) {
    guard let data = try? JSONEncoder().encode(settings) else { return }
    saveSettingBlob(key: "app_settings", value: data)
  }

  func loadRoots() -> [ScanRoot] {
    let sql = "SELECT id, path, bookmark, created_at FROM scan_roots ORDER BY created_at ASC;"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return []
    }
    defer { sqlite3_finalize(statement) }

    var roots: [ScanRoot] = []
    while sqlite3_step(statement) == SQLITE_ROW {
      guard
        let idCString = sqlite3_column_text(statement, 0),
        let id = UUID(uuidString: String(cString: idCString)),
        let pathCString = sqlite3_column_text(statement, 1),
        let bookmarkBlob = sqlite3_column_blob(statement, 2)
      else {
        continue
      }

      let path = String(cString: pathCString)
      let bookmarkSize = Int(sqlite3_column_bytes(statement, 2))
      let bookmark = Data(bytes: bookmarkBlob, count: bookmarkSize)
      let createdAt = Date(timeIntervalSince1970: sqlite3_column_double(statement, 3))

      roots.append(ScanRoot(id: id, path: path, bookmarkData: bookmark, createdAt: createdAt))
    }

    return roots
  }

  func addRoot(path: String, bookmarkData: Data) {
    let root = ScanRoot(id: UUID(), path: path, bookmarkData: bookmarkData, createdAt: Date())
    let sql = "INSERT INTO scan_roots (id, path, bookmark, created_at) VALUES (?, ?, ?, ?);"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return
    }
    defer { sqlite3_finalize(statement) }

    bindText(statement, index: 1, value: root.id.uuidString)
    bindText(statement, index: 2, value: root.path)
    bindBlob(statement, index: 3, value: root.bookmarkData)
    sqlite3_bind_double(statement, 4, root.createdAt.timeIntervalSince1970)

    _ = sqlite3_step(statement)
  }

  func removeRoot(id: UUID) {
    let sql = "DELETE FROM scan_roots WHERE id = ?;"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return
    }
    defer { sqlite3_finalize(statement) }

    bindText(statement, index: 1, value: id.uuidString)
    _ = sqlite3_step(statement)
  }

  func saveScanRun(_ run: ScanRun) {
    let runSQL = "INSERT INTO scan_runs (id, trigger, started_at, finished_at, duration_seconds, skill_count, finding_count, max_severity, high_critical_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"
    var runStatement: OpaquePointer?
    guard sqlite3_prepare_v2(db, runSQL, -1, &runStatement, nil) == SQLITE_OK else {
      return
    }

    bindText(runStatement, index: 1, value: run.id.uuidString)
    bindText(runStatement, index: 2, value: run.trigger.rawValue)
    sqlite3_bind_double(runStatement, 3, run.startedAt.timeIntervalSince1970)
    sqlite3_bind_double(runStatement, 4, run.finishedAt.timeIntervalSince1970)
    sqlite3_bind_double(runStatement, 5, run.durationSeconds)
    sqlite3_bind_int(runStatement, 6, Int32(run.skillCount))
    sqlite3_bind_int(runStatement, 7, Int32(run.findingCount))
    bindText(runStatement, index: 8, value: run.maxSeverity.rawValue)
    sqlite3_bind_int(runStatement, 9, Int32(run.highOrCriticalCount))

    _ = sqlite3_step(runStatement)
    sqlite3_finalize(runStatement)

    let findingSQL = "INSERT INTO findings (id, run_id, rule_id, category, severity, title, description, file_path, line_number, snippet, remediation, analyzer, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"

    for finding in run.findings {
      var findingStatement: OpaquePointer?
      guard sqlite3_prepare_v2(db, findingSQL, -1, &findingStatement, nil) == SQLITE_OK else { continue }

      bindText(findingStatement, index: 1, value: "\(run.id.uuidString)::\(finding.id)")
      bindText(findingStatement, index: 2, value: run.id.uuidString)
      bindText(findingStatement, index: 3, value: finding.ruleID)
      bindText(findingStatement, index: 4, value: finding.category.rawValue)
      bindText(findingStatement, index: 5, value: finding.severity.rawValue)
      bindText(findingStatement, index: 6, value: finding.title)
      bindText(findingStatement, index: 7, value: finding.description)
      bindText(findingStatement, index: 8, value: finding.filePath)

      if let line = finding.lineNumber {
        sqlite3_bind_int(findingStatement, 9, Int32(line))
      } else {
        sqlite3_bind_null(findingStatement, 9)
      }

      bindText(findingStatement, index: 10, value: finding.snippet)
      bindText(findingStatement, index: 11, value: finding.remediation)
      bindText(findingStatement, index: 12, value: finding.analyzer)

      let metadataJSON = (try? JSONSerialization.data(withJSONObject: finding.metadata)) ?? Data("{}".utf8)
      let metadataText = String(data: metadataJSON, encoding: .utf8) ?? "{}"
      bindText(findingStatement, index: 13, value: metadataText)

      _ = sqlite3_step(findingStatement)
      sqlite3_finalize(findingStatement)
    }
  }

  func recentRuns(limit: Int = 20) -> [ScanRun] {
    let sql = "SELECT id, trigger, started_at, finished_at, duration_seconds, skill_count, finding_count, max_severity FROM scan_runs ORDER BY started_at DESC LIMIT ?;"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return []
    }
    defer { sqlite3_finalize(statement) }

    sqlite3_bind_int(statement, 1, Int32(limit))
    var runs: [ScanRun] = []

    while sqlite3_step(statement) == SQLITE_ROW {
      guard
        let idCString = sqlite3_column_text(statement, 0),
        let id = UUID(uuidString: String(cString: idCString)),
        let triggerCString = sqlite3_column_text(statement, 1),
        let trigger = ScanTrigger(rawValue: String(cString: triggerCString)),
        let severityCString = sqlite3_column_text(statement, 7),
        let severity = Severity(rawValue: String(cString: severityCString))
      else {
        continue
      }

      let run = ScanRun(
        id: id,
        trigger: trigger,
        startedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 2)),
        finishedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 3)),
        durationSeconds: sqlite3_column_double(statement, 4),
        skillCount: Int(sqlite3_column_int(statement, 5)),
        findingCount: Int(sqlite3_column_int(statement, 6)),
        maxSeverity: severity,
        findings: findingsForRun(id: id)
      )
      runs.append(run)
    }

    return runs
  }

  func upsertSuppression(_ suppression: FindingSuppression) {
    let sql = """
        INSERT INTO finding_suppressions
            (id, rule_id, file_path, reason, created_at, expires_at)
        VALUES
            (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            rule_id = excluded.rule_id,
            file_path = excluded.file_path,
            reason = excluded.reason,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at;
        """
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return
    }
    defer { sqlite3_finalize(statement) }

    bindText(statement, index: 1, value: suppression.id.uuidString)
    bindText(statement, index: 2, value: suppression.ruleID)
    bindText(statement, index: 3, value: suppression.filePath)
    bindText(statement, index: 4, value: suppression.reason)
    sqlite3_bind_double(statement, 5, suppression.createdAt.timeIntervalSince1970)
    if let expiresAt = suppression.expiresAt {
      sqlite3_bind_double(statement, 6, expiresAt.timeIntervalSince1970)
    } else {
      sqlite3_bind_null(statement, 6)
    }
    _ = sqlite3_step(statement)
  }

  func deleteSuppression(id: UUID) {
    let sql = "DELETE FROM finding_suppressions WHERE id = ?;"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return
    }
    defer { sqlite3_finalize(statement) }

    bindText(statement, index: 1, value: id.uuidString)
    _ = sqlite3_step(statement)
  }

  func activeSuppressions(at date: Date) -> [FindingSuppression] {
    pruneExpiredSuppressions(before: date)

    let sql = """
        SELECT id, rule_id, file_path, reason, created_at, expires_at
        FROM finding_suppressions
        WHERE expires_at IS NULL OR expires_at > ?
        ORDER BY created_at DESC;
        """
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return []
    }
    defer { sqlite3_finalize(statement) }

    sqlite3_bind_double(statement, 1, date.timeIntervalSince1970)
    var suppressions: [FindingSuppression] = []

    while sqlite3_step(statement) == SQLITE_ROW {
      guard
        let idCString = sqlite3_column_text(statement, 0),
        let id = UUID(uuidString: String(cString: idCString)),
        let ruleIDCString = sqlite3_column_text(statement, 1),
        let reasonCString = sqlite3_column_text(statement, 3)
      else {
        continue
      }

      let filePath = sqlite3_column_text(statement, 2).map { String(cString: $0) }
      let createdAt = Date(timeIntervalSince1970: sqlite3_column_double(statement, 4))
      let expiresAt: Date?
      if sqlite3_column_type(statement, 5) == SQLITE_NULL {
        expiresAt = nil
      } else {
        expiresAt = Date(timeIntervalSince1970: sqlite3_column_double(statement, 5))
      }

      suppressions.append(
        FindingSuppression(
          id: id,
          ruleID: String(cString: ruleIDCString),
          filePath: filePath,
          reason: String(cString: reasonCString),
          createdAt: createdAt,
          expiresAt: expiresAt
        )
      )
    }

    return suppressions
  }

  func latestRunSummary() -> ScanSummary? {
    let sql = "SELECT id, trigger, max_severity, high_critical_count, finding_count, started_at, finished_at FROM scan_runs ORDER BY started_at DESC LIMIT 1;"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return nil
    }
    defer { sqlite3_finalize(statement) }

    guard
      sqlite3_step(statement) == SQLITE_ROW,
      let idCString = sqlite3_column_text(statement, 0),
      let id = UUID(uuidString: String(cString: idCString)),
      let triggerCString = sqlite3_column_text(statement, 1),
      let trigger = ScanTrigger(rawValue: String(cString: triggerCString)),
      let severityCString = sqlite3_column_text(statement, 2),
      let severity = Severity(rawValue: String(cString: severityCString))
    else {
      return nil
    }

    return ScanSummary(
      runID: id,
      trigger: trigger,
      maxSeverity: severity,
      highOrCriticalCount: Int(sqlite3_column_int(statement, 3)),
      findingCount: Int(sqlite3_column_int(statement, 4)),
      startedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 5)),
      finishedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 6))
    )
  }

  func findingsForRun(id: UUID) -> [ScanFinding] {
    let sql = "SELECT id, rule_id, category, severity, title, description, file_path, line_number, snippet, remediation, analyzer, metadata_json FROM findings WHERE run_id = ? ORDER BY severity DESC, id ASC;"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return []
    }
    defer { sqlite3_finalize(statement) }

    bindText(statement, index: 1, value: id.uuidString)
    var findings: [ScanFinding] = []

    while sqlite3_step(statement) == SQLITE_ROW {
      guard
        let idC = sqlite3_column_text(statement, 0),
        let ruleIDC = sqlite3_column_text(statement, 1),
        let categoryC = sqlite3_column_text(statement, 2),
        let severityC = sqlite3_column_text(statement, 3),
        let titleC = sqlite3_column_text(statement, 4),
        let descC = sqlite3_column_text(statement, 5),
        let category = ThreatCategory(rawValue: String(cString: categoryC)),
        let severity = Severity(rawValue: String(cString: severityC))
      else {
        continue
      }

      let metadataText = sqlite3_column_text(statement, 11).map { String(cString: $0) } ?? "{}"
      let metadata: [String: String]
      if let data = metadataText.data(using: .utf8),
         let decoded = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
        metadata = decoded
      } else {
        metadata = [:]
      }

      findings.append(
        ScanFinding(
          id: String(cString: idC),
          ruleID: String(cString: ruleIDC),
          category: category,
          severity: severity,
          title: String(cString: titleC),
          description: String(cString: descC),
          filePath: sqlite3_column_text(statement, 6).map { String(cString: $0) },
          lineNumber: sqlite3_column_type(statement, 7) == SQLITE_NULL ? nil : Int(sqlite3_column_int(statement, 7)),
          snippet: sqlite3_column_text(statement, 8).map { String(cString: $0) },
          remediation: sqlite3_column_text(statement, 9).map { String(cString: $0) },
          analyzer: sqlite3_column_text(statement, 10).map { String(cString: $0) } ?? "unknown",
          metadata: metadata
        )
      )
    }

    return findings
  }

  private static func openDatabase(at databaseURL: URL) -> OpaquePointer? {
    var db: OpaquePointer?
    if sqlite3_open(databaseURL.path, &db) != SQLITE_OK {
      sqlite3_close(db)
      return nil
    }
    return db
  }

  private static func migrate(databaseURL: URL, db: OpaquePointer?) {
    guard db != nil else { return }

    var userVersion = queryUserVersion(db: db)
    if userVersion < 1 {
      backupIfNeeded(databaseURL: databaseURL)
      execute(db: db, sql: "PRAGMA foreign_keys = ON;")
      execute(db: db, sql: "CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value BLOB NOT NULL);")
      execute(db: db, sql: "CREATE TABLE IF NOT EXISTS scan_roots (id TEXT PRIMARY KEY, path TEXT NOT NULL, bookmark BLOB NOT NULL, created_at REAL NOT NULL);")
      execute(db: db, sql: "CREATE TABLE IF NOT EXISTS scan_runs (id TEXT PRIMARY KEY, trigger TEXT NOT NULL, started_at REAL NOT NULL, finished_at REAL NOT NULL, duration_seconds REAL NOT NULL, skill_count INTEGER NOT NULL, finding_count INTEGER NOT NULL, max_severity TEXT NOT NULL, high_critical_count INTEGER NOT NULL);")
      execute(db: db, sql: "CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, rule_id TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, file_path TEXT NULL, line_number INTEGER NULL, snippet TEXT NULL, remediation TEXT NULL, analyzer TEXT NOT NULL, metadata_json TEXT NOT NULL, FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE);")
      execute(db: db, sql: "PRAGMA user_version = 1;")
      userVersion = 1
    }

    if userVersion < 2 {
      backupIfNeeded(databaseURL: databaseURL)
      execute(db: db, sql: "CREATE TABLE IF NOT EXISTS finding_suppressions (id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, file_path TEXT NULL, reason TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NULL);")
      execute(db: db, sql: "CREATE INDEX IF NOT EXISTS idx_finding_suppressions_rule_path ON finding_suppressions (rule_id, file_path);")
      execute(db: db, sql: "PRAGMA user_version = 2;")
    }
  }

  private func pruneExpiredSuppressions(before date: Date) {
    let sql = "DELETE FROM finding_suppressions WHERE expires_at IS NOT NULL AND expires_at <= ?;"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return
    }
    defer { sqlite3_finalize(statement) }

    sqlite3_bind_double(statement, 1, date.timeIntervalSince1970)
    _ = sqlite3_step(statement)
  }

  private static func queryUserVersion(db: OpaquePointer?) -> Int {
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &statement, nil) == SQLITE_OK else {
      return 0
    }
    defer { sqlite3_finalize(statement) }

    guard sqlite3_step(statement) == SQLITE_ROW else {
      return 0
    }

    return Int(sqlite3_column_int(statement, 0))
  }

  private static func backupIfNeeded(databaseURL: URL) {
    guard FileManager.default.fileExists(atPath: databaseURL.path) else { return }
    let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
    let backupURL = databaseURL.deletingPathExtension().appendingPathExtension("backup.\(stamp).sqlite")
    try? FileManager.default.copyItem(at: databaseURL, to: backupURL)
  }

  private static func execute(db: OpaquePointer?, sql: String) {
    sqlite3_exec(db, sql, nil, nil, nil)
  }

  private func saveSettingBlob(key: String, value: Data) {
    let sql = "INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return
    }
    defer { sqlite3_finalize(statement) }

    bindText(statement, index: 1, value: key)
    bindBlob(statement, index: 2, value: value)
    _ = sqlite3_step(statement)
  }

  private func loadSettingBlob(key: String) -> Data? {
    let sql = "SELECT value FROM app_settings WHERE key = ? LIMIT 1;"
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
      return nil
    }
    defer { sqlite3_finalize(statement) }

    bindText(statement, index: 1, value: key)
    guard sqlite3_step(statement) == SQLITE_ROW,
          let blob = sqlite3_column_blob(statement, 0)
    else {
      return nil
    }

    let size = Int(sqlite3_column_bytes(statement, 0))
    return Data(bytes: blob, count: size)
  }

  private func bindText(_ statement: OpaquePointer?, index: Int32, value: String?) {
    guard let value else {
      sqlite3_bind_null(statement, index)
      return
    }
    _ = value.withCString { ptr in
      sqlite3_bind_text(statement, index, ptr, -1, SQLITE_TRANSIENT)
    }
  }

  private func bindBlob(_ statement: OpaquePointer?, index: Int32, value: Data) {
    _ = value.withUnsafeBytes { ptr in
      sqlite3_bind_blob(statement, index, ptr.baseAddress, Int32(value.count), SQLITE_TRANSIENT)
    }
  }
}

nonisolated(unsafe) private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
