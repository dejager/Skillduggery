import Foundation

nonisolated enum Severity: String, Codable, CaseIterable, Sendable {
  case critical = "CRITICAL"
  case high = "HIGH"
  case medium = "MEDIUM"
  case low = "LOW"
  case info = "INFO"
  case safe = "SAFE"

  var priority: Int {
    switch self {
      case .critical: return 5
      case .high: return 4
      case .medium: return 3
      case .low: return 2
      case .info: return 1
      case .safe: return 0
    }
  }

  static func max(_ lhs: Severity, _ rhs: Severity) -> Severity {
    lhs.priority >= rhs.priority ? lhs : rhs
  }
}

nonisolated enum ThreatCategory: String, Codable, CaseIterable, Sendable {
  case promptInjection = "prompt_injection"
  case commandInjection = "command_injection"
  case dataExfiltration = "data_exfiltration"
  case unauthorizedToolUse = "unauthorized_tool_use"
  case obfuscation = "obfuscation"
  case hardcodedSecrets = "hardcoded_secrets"
  case socialEngineering = "social_engineering"
  case resourceAbuse = "resource_abuse"
  case policyViolation = "policy_violation"
  case malware = "malware"
  case harmfulContent = "harmful_content"
  case skillDiscoveryAbuse = "skill_discovery_abuse"
  case transitiveTrustAbuse = "transitive_trust_abuse"
  case autonomyAbuse = "autonomy_abuse"
  case toolChainingAbuse = "tool_chaining_abuse"
  case unicodeSteganography = "unicode_steganography"
}

nonisolated struct ScanFinding: Codable, Identifiable, Hashable, Sendable {
  let id: String
  let ruleID: String
  let category: ThreatCategory
  let severity: Severity
  let title: String
  let description: String
  let filePath: String?
  let lineNumber: Int?
  let snippet: String?
  let remediation: String?
  let analyzer: String
  var metadata: [String: String]

  init(
    id: String,
    ruleID: String,
    category: ThreatCategory,
    severity: Severity,
    title: String,
    description: String,
    filePath: String? = nil,
    lineNumber: Int? = nil,
    snippet: String? = nil,
    remediation: String? = nil,
    analyzer: String,
    metadata: [String: String] = [:]
  ) {
    self.id = id
    self.ruleID = ruleID
    self.category = category
    self.severity = severity
    self.title = title
    self.description = description
    self.filePath = filePath
    self.lineNumber = lineNumber
    self.snippet = snippet
    self.remediation = remediation
    self.analyzer = analyzer
    self.metadata = metadata
  }
}

nonisolated enum SkillFileType: String, Codable, Sendable {
  case markdown
  case python
  case bash
  case binary
  case other
}

nonisolated struct SkillFile: Sendable {
  let path: URL
  let relativePath: String
  let fileType: SkillFileType
  let sizeBytes: Int
  let content: String?
}

nonisolated struct SkillManifest: Codable, Sendable {
  let name: String
  let description: String
  let license: String?
  let compatibility: String?
  let allowedTools: [String]
  let metadata: [String: String]
  let disableModelInvocation: Bool
}

nonisolated struct SkillPackage: Sendable {
  let directory: URL
  let manifest: SkillManifest
  let skillMarkdownPath: URL
  let instructionBody: String
  let files: [SkillFile]
  let referencedFiles: [String]

  var name: String { manifest.name }
  var description: String { manifest.description }

  var scripts: [SkillFile] {
    files.filter { $0.fileType == .python || $0.fileType == .bash }
  }
}

nonisolated enum ScanTrigger: String, Codable, Sendable {
  case manual
  case catchUp = "catch_up"
  case scheduled

  var priority: Int {
    switch self {
      case .manual: return 3
      case .catchUp: return 2
      case .scheduled: return 1
    }
  }
}

nonisolated struct ScanRun: Codable, Identifiable, Sendable {
  let id: UUID
  let trigger: ScanTrigger
  let startedAt: Date
  let finishedAt: Date
  let durationSeconds: Double
  let skillCount: Int
  let findingCount: Int
  let maxSeverity: Severity
  let findings: [ScanFinding]

  var highOrCriticalCount: Int {
    findings.filter { $0.severity == .high || $0.severity == .critical }.count
  }
}

nonisolated struct FindingSuppression: Codable, Identifiable, Hashable, Sendable {
  let id: UUID
  let ruleID: String
  let filePath: String?
  let reason: String
  let createdAt: Date
  let expiresAt: Date?

  func isActive(at date: Date) -> Bool {
    guard let expiresAt else { return true }
    return expiresAt > date
  }

  func matches(_ finding: ScanFinding, at date: Date) -> Bool {
    guard isActive(at: date) else { return false }
    guard ruleID == finding.ruleID else { return false }
    guard let filePath else { return true }
    return filePath == finding.filePath
  }
}

nonisolated struct ScanRoot: Codable, Identifiable, Hashable, Sendable {
  let id: UUID
  let path: String
  let bookmarkData: Data
  let createdAt: Date

  var displayName: String {
    URL(fileURLWithPath: path).lastPathComponent
  }
}

nonisolated struct AppSettings: Codable, Sendable {
  var highSignalOnlyNotifications: Bool
  var dailySchedulingEnabled: Bool
  var lastSuccessfulRunAt: Date?
  var lastScanAttemptAt: Date?
  var loginAtLaunchEnabled: Bool
  var analyzerBehavioralEnabled: Bool
  var analyzerMetaEnabled: Bool

  static let `default` = AppSettings(
    highSignalOnlyNotifications: true,
    dailySchedulingEnabled: true,
    lastSuccessfulRunAt: nil,
    lastScanAttemptAt: nil,
    loginAtLaunchEnabled: true,
    analyzerBehavioralEnabled: true,
    analyzerMetaEnabled: true
  )
}

nonisolated struct ScanSummary: Sendable {
  let runID: UUID
  let trigger: ScanTrigger
  let maxSeverity: Severity
  let highOrCriticalCount: Int
  let findingCount: Int
  let startedAt: Date
  let finishedAt: Date
}

extension Collection where Element == ScanFinding {
  nonisolated func maxSeverity() -> Severity {
    reduce(.safe) { Severity.max($0, $1.severity) }
  }
}

extension Array where Element == ScanFinding {
  nonisolated func onlyHighSignal() -> [ScanFinding] {
    filter { $0.severity == .high || $0.severity == .critical }
  }
}

extension Array where Element == FindingSuppression {
  nonisolated func active(at date: Date) -> [FindingSuppression] {
    filter { $0.isActive(at: date) }
  }
}
