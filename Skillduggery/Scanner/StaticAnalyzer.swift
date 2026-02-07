import Foundation
import CryptoKit

nonisolated struct StaticAnalyzer {
  private let yamlRules: [PatternRule]
  private let yaraRules: [YaraRule]
  private let rulePackWarnings: [String]

  init(rulePackLoader: RulePackLoader = RulePackLoader()) {
    let loaded = rulePackLoader.load()
    self.yamlRules = loaded.yamlRules
    self.yaraRules = loaded.yaraRules
    self.rulePackWarnings = loaded.warnings
  }

  func analyze(skill: SkillPackage) -> [ScanFinding] {
    var findings: [ScanFinding] = []

    for file in skill.files {
      guard let content = file.content else { continue }

      findings.append(contentsOf: runYAMLRules(on: file, content: content))
      findings.append(contentsOf: runYaraRules(on: file, content: content))
    }

    findings.append(contentsOf: checkManifest(manifest: skill.manifest))
    findings.append(contentsOf: rulePackIntegrityFindings())
    return dedupe(findings)
  }

  private func runYAMLRules(on file: SkillFile, content: String) -> [ScanFinding] {
    var findings: [ScanFinding] = []
    for rule in yamlRules {
      if !rule.fileTypes.isEmpty && !rule.fileTypes.contains(file.fileType) {
        continue
      }

      if RegexRuntime.matchesAny(patterns: rule.excludePatterns, in: content) {
        continue
      }

      for pattern in rule.patterns {
        guard let hit = RegexRuntime.firstMatch(pattern: pattern, in: content) else {
          continue
        }

        findings.append(
          ScanFinding(
            id: findingID(prefix: rule.id, context: "\(file.relativePath):\(hit.line):\(pattern)"),
            ruleID: rule.id,
            category: rule.category,
            severity: rule.severity,
            title: rule.id.replacingOccurrences(of: "_", with: " "),
            description: rule.description,
            filePath: file.relativePath,
            lineNumber: hit.line,
            snippet: hit.snippet,
            remediation: rule.remediation,
            analyzer: "static",
            metadata: ["source": "yaml"]
          )
        )
      }
    }
    return findings
  }

  private func runYaraRules(on file: SkillFile, content: String) -> [ScanFinding] {
    var findings: [ScanFinding] = []

    for rule in yaraRules {
      if RegexRuntime.matchesAny(patterns: rule.excludePatterns, in: content) {
        continue
      }

      var firstHit: (line: Int, snippet: String)?
      for pattern in rule.includePatterns {
        if let hit = RegexRuntime.firstMatch(pattern: pattern, in: content) {
          firstHit = hit
          break
        }
      }

      guard let hit = firstHit else { continue }

      let mapped = mapThreatType(rule.threatType)
      findings.append(
        ScanFinding(
          id: findingID(prefix: "YARA_\(rule.name)", context: "\(file.relativePath):\(hit.line)"),
          ruleID: "YARA_\(rule.name)",
          category: mapped.category,
          severity: mapped.severity,
          title: "YARA: \(rule.name)",
          description: rule.description.isEmpty ? "YARA pattern matched for \(rule.name)" : rule.description,
          filePath: file.relativePath,
          lineNumber: hit.line,
          snippet: hit.snippet,
          remediation: "Review and remove malicious pattern",
          analyzer: "static",
          metadata: ["source": "yara", "threat_type": rule.threatType]
        )
      )
    }

    return findings
  }

  private func checkManifest(manifest: SkillManifest) -> [ScanFinding] {
    var findings: [ScanFinding] = []
    if manifest.name.count > 64 || !isSkillNameValid(manifest.name) {
      findings.append(
        ScanFinding(
          id: findingID(prefix: "MANIFEST_INVALID_NAME", context: manifest.name),
          ruleID: "MANIFEST_INVALID_NAME",
          category: .policyViolation,
          severity: .info,
          title: "Skill name does not match expected format",
          description: "Skill names should use lowercase letters, numbers, and hyphens only (max 64 chars).",
          filePath: "SKILL.md",
          analyzer: "static"
        )
      )
    }

    if manifest.description.count > 1024 {
      findings.append(
        ScanFinding(
          id: findingID(prefix: "MANIFEST_DESCRIPTION_TOO_LONG", context: manifest.name),
          ruleID: "MANIFEST_DESCRIPTION_TOO_LONG",
          category: .policyViolation,
          severity: .low,
          title: "Skill description too long",
          description: "Description exceeds 1024 characters and should be reduced.",
          filePath: "SKILL.md",
          analyzer: "static"
        )
      )
    }

    return findings
  }

  private func mapThreatType(_ threatType: String) -> (category: ThreatCategory, severity: Severity) {
    let value = threatType.uppercased()
    if value.contains("PROMPT") {
      return (.promptInjection, .high)
    }
    if value.contains("CREDENTIAL") {
      return (.dataExfiltration, .critical)
    }
    if value.contains("CODE") {
      return (.commandInjection, .critical)
    }
    return (.policyViolation, .medium)
  }

  private func findingID(prefix: String, context: String) -> String {
    let digest = SHA256.hash(data: Data("\(prefix):\(context)".utf8))
      .compactMap { String(format: "%02x", $0) }
      .joined()
    return "\(prefix)_\(digest.prefix(12))"
  }

  private func dedupe(_ findings: [ScanFinding]) -> [ScanFinding] {
    var map: [String: ScanFinding] = [:]
    for finding in findings {
      let key = "\(finding.ruleID)|\(finding.filePath ?? "")|\(finding.lineNumber ?? 0)"
      if let existing = map[key] {
        if finding.severity.priority > existing.severity.priority {
          map[key] = finding
        }
      } else {
        map[key] = finding
      }
    }
    return Array(map.values).sorted { lhs, rhs in
      if lhs.severity.priority == rhs.severity.priority {
        return lhs.ruleID < rhs.ruleID
      }
      return lhs.severity.priority > rhs.severity.priority
    }
  }

  private func isSkillNameValid(_ value: String) -> Bool {
    guard let regex = try? NSRegularExpression(pattern: "^[a-z0-9-]+$") else {
      return false
    }
    let range = NSRange(value.startIndex..<value.endIndex, in: value)
    return regex.firstMatch(in: value, options: [], range: range) != nil
  }

  private func rulePackIntegrityFindings() -> [ScanFinding] {
    rulePackWarnings.map { warning in
      ScanFinding(
        id: findingID(prefix: "RULE_PACK_INTEGRITY", context: warning),
        ruleID: "RULE_PACK_INTEGRITY",
        category: .policyViolation,
        severity: .high,
        title: "Rule pack integrity check failed",
        description: warning,
        filePath: "rules/current",
        lineNumber: nil,
        snippet: nil,
        remediation: "Restore a signed rule pack with matching checksums.",
        analyzer: "static",
        metadata: ["source": "rule-pack"]
      )
    }
  }
}
