import Foundation

nonisolated enum YAMLRuleParser {
  static func parse(_ source: String) -> [PatternRule] {
    let lines = source.components(separatedBy: .newlines)
    var parsedRules: [[String: Any]] = []
    var current: [String: Any] = [:]
    var currentListKey: String?
    
    func commitCurrent() {
      guard !current.isEmpty else { return }
      parsedRules.append(current)
      current = [:]
      currentListKey = nil
    }
    
    for rawLine in lines {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      if line.isEmpty || line.hasPrefix("#") {
        continue
      }
      
      if line.hasPrefix("- id:") {
        commitCurrent()
        let idValue = valueAfterColon(line)
        current["id"] = unquote(idValue)
        continue
      }
      
      if line.hasPrefix("-") {
        if let listKey = currentListKey {
          let value = line.dropFirst().trimmingCharacters(in: .whitespaces)
          var list = current[listKey] as? [String] ?? []
          list.append(unquote(String(value)))
          current[listKey] = list
        }
        continue
      }
      
      guard line.contains(":") else {
        continue
      }
      
      let key = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: true)[0]
      let value = valueAfterColon(line)
      let normalizedKey = String(key).trimmingCharacters(in: .whitespaces)
      
      switch normalizedKey {
        case "patterns", "exclude_patterns":
          currentListKey = normalizedKey
          if value.hasPrefix("[") {
            current[normalizedKey] = parseInlineArray(value)
            currentListKey = nil
          } else {
            current[normalizedKey] = [String]()
          }
        case "file_types":
          current[normalizedKey] = parseInlineArray(value)
          currentListKey = nil
        default:
          current[normalizedKey] = unquote(value)
          currentListKey = nil
      }
    }
    
    commitCurrent()
    
    return parsedRules.compactMap { item in
      guard
        let id = item["id"] as? String,
        let categoryRaw = item["category"] as? String,
        let category = ThreatCategory(rawValue: categoryRaw),
        let severityRaw = item["severity"] as? String,
        let severity = Severity(rawValue: severityRaw),
        let description = item["description"] as? String
      else {
        return nil
      }
      
      let patterns = item["patterns"] as? [String] ?? []
      let excludePatterns = item["exclude_patterns"] as? [String] ?? []
      let fileTypeStrings = item["file_types"] as? [String] ?? []
      let fileTypes = fileTypeStrings.compactMap(SkillFileType.fromRule)
      let remediation = item["remediation"] as? String ?? ""
      
      return PatternRule(
        id: id,
        category: category,
        severity: severity,
        patterns: patterns,
        excludePatterns: excludePatterns,
        fileTypes: fileTypes,
        description: description,
        remediation: remediation
      )
    }
  }
  
  private static func parseInlineArray(_ value: String) -> [String] {
    let trimmed = value.trimmingCharacters(in: .whitespaces)
    guard trimmed.hasPrefix("["), trimmed.hasSuffix("]") else { return [] }
    let content = String(trimmed.dropFirst().dropLast())
    return content
      .split(separator: ",")
      .map { unquote(String($0).trimmingCharacters(in: .whitespaces)) }
      .filter { !$0.isEmpty }
  }
  
  private static func unquote(_ value: String) -> String {
    var v = value.trimmingCharacters(in: .whitespaces)
    if (v.hasPrefix("\"") && v.hasSuffix("\"")) || (v.hasPrefix("'") && v.hasSuffix("'")) {
      v = String(v.dropFirst().dropLast())
    }
    return v
  }
  
  private static func valueAfterColon(_ line: String) -> String {
    let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
    guard parts.count == 2 else { return "" }
    return String(parts[1]).trimmingCharacters(in: .whitespaces)
  }
}

private extension SkillFileType {
  nonisolated static func fromRule(_ value: String) -> SkillFileType? {
    switch value.lowercased() {
      case "markdown": return .markdown
      case "python": return .python
      case "bash": return .bash
      case "binary": return .binary
      case "other": return .other
      default: return nil
    }
  }
}
