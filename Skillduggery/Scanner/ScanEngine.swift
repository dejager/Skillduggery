import Foundation
import CryptoKit

nonisolated struct ScanEngineConfiguration: Sendable {
  var useBehavioralAnalyzer: Bool
  var useMetaAnalyzer: Bool
  var suppressions: [FindingSuppression] = []
}

actor ScanEngine {
  private let loader: SkillLoader
  private let staticAnalyzer: StaticAnalyzer
  private let behavioralAnalyzer: BehavioralAnalyzer
  private let metaAnalyzer: MetaAnalyzer

  init(
    loader: SkillLoader? = nil,
    staticAnalyzer: StaticAnalyzer? = nil,
    behavioralAnalyzer: BehavioralAnalyzer? = nil,
    metaAnalyzer: MetaAnalyzer? = nil
  ) {
    self.loader = loader ?? SkillLoader()
    self.staticAnalyzer = staticAnalyzer ?? StaticAnalyzer()
    self.behavioralAnalyzer = behavioralAnalyzer ?? BehavioralAnalyzer()
    self.metaAnalyzer = metaAnalyzer ?? MetaAnalyzer()
  }

  func scan(roots: [URL], trigger: ScanTrigger, config: ScanEngineConfiguration) async -> ScanRun {
    let start = Date()

    let directories = loader.discoverSkillDirectories(in: roots)
    var findings: [ScanFinding] = []
    var scannedSkillCount = 0

    for directory in directories {
      do {
        let skill = try loader.loadSkill(at: directory)
        scannedSkillCount += 1

        var skillFindings = staticAnalyzer.analyze(skill: skill)

        if config.useBehavioralAnalyzer {
          skillFindings.append(contentsOf: behavioralAnalyzer.analyze(skill: skill))
        }

        findings.append(contentsOf: skillFindings)
      } catch {
        findings.append(
          ScanFinding(
            id: id(prefix: "LOAD_ERROR", context: directory.path),
            ruleID: "SKILL_LOAD_ERROR",
            category: .policyViolation,
            severity: .low,
            title: "Failed to load skill",
            description: error.localizedDescription,
            filePath: directory.path,
            analyzer: "engine"
          )
        )
      }
    }

    let finalFindings = metaAnalyzer.refine(
      findings: findings,
      suppressions: config.suppressions,
      enableFalsePositiveFiltering: config.useMetaAnalyzer
    )
    let finish = Date()

    return ScanRun(
      id: UUID(),
      trigger: trigger,
      startedAt: start,
      finishedAt: finish,
      durationSeconds: finish.timeIntervalSince(start),
      skillCount: scannedSkillCount,
      findingCount: finalFindings.count,
      maxSeverity: finalFindings.maxSeverity(),
      findings: finalFindings
    )
  }

  func failedRun(trigger: ScanTrigger, reason: String) -> ScanRun {
    let now = Date()
    let finding = ScanFinding(
      id: id(prefix: "SCAN_FAILURE", context: "\(trigger.rawValue):\(reason)"),
      ruleID: "SCAN_FAILURE",
      category: .policyViolation,
      severity: .low,
      title: "Scan could not execute",
      description: reason,
      filePath: nil,
      lineNumber: nil,
      snippet: nil,
      remediation: "Review settings and selected roots.",
      analyzer: "engine",
      metadata: ["trigger": trigger.rawValue]
    )
    return ScanRun(
      id: UUID(),
      trigger: trigger,
      startedAt: now,
      finishedAt: now,
      durationSeconds: 0,
      skillCount: 0,
      findingCount: 1,
      maxSeverity: .low,
      findings: [finding]
    )
  }

  private func id(prefix: String, context: String) -> String {
    let digest = SHA256.hash(data: Data("\(prefix):\(context)".utf8))
      .compactMap { String(format: "%02x", $0) }
      .joined()
    return "\(prefix)_\(digest.prefix(12))"
  }
}
