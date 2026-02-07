import Foundation

nonisolated struct MetaAnalyzer {
  func refine(
    findings: [ScanFinding],
    suppressions: [FindingSuppression] = [],
    now: Date = Date(),
    enableFalsePositiveFiltering: Bool = true
  ) -> [ScanFinding] {
    let deduped = dedupeKeepingHighestSeverity(findings)
    return deduped.compactMap { finding in
      if let matched = suppressions.first(where: { $0.matches(finding, at: now) }) {
        var suppressed = finding
        suppressed.metadata["suppressed"] = "true"
        suppressed.metadata["suppression_id"] = matched.id.uuidString
        return nil
      }

      guard enableFalsePositiveFiltering else {
        return finding
      }

      if shouldMarkAsFalsePositive(finding) {
        if finding.severity.priority >= Severity.high.priority {
          var kept = finding
          kept.metadata["meta_false_positive"] = "true"
          kept.metadata["meta_reason"] = "Possible test/example context"
          return kept
        }
        return nil
      }
      var enriched = finding
      enriched.metadata["meta_false_positive"] = "false"
      return enriched
    }
  }

  private func shouldMarkAsFalsePositive(_ finding: ScanFinding) -> Bool {
    let text = [finding.title, finding.description, finding.snippet ?? "", finding.filePath ?? ""]
      .joined(separator: " ")
      .lowercased()

    if finding.severity.priority >= Severity.high.priority {
      return false
    }

    if text.contains("example") || text.contains("demo") || text.contains("tutorial") || text.contains("test") {
      return true
    }

    if finding.ruleID.contains("MANIFEST") {
      return true
    }

    return false
  }

  private func dedupeKeepingHighestSeverity(_ findings: [ScanFinding]) -> [ScanFinding] {
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
    return Array(map.values)
  }
}
