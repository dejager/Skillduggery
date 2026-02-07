import Foundation

nonisolated enum YaraRuleParser {
  static func parseMany(_ source: String) -> [YaraRule] {
    let chunks = source
      .components(separatedBy: "\nrule ")
      .enumerated()
      .map { index, chunk in
        index == 0 ? chunk : "rule " + chunk
      }
      .filter { $0.contains("rule ") && $0.contains("{") && $0.contains("}") }

    return chunks.compactMap(parse)
  }

  static func parse(ruleText: String) -> YaraRule? {
    let lines = ruleText.components(separatedBy: .newlines)
    var name: String?
    var threatType = "UNKNOWN"
    var description = ""
    var includePatterns: [String] = []
    var excludePatterns: [String] = []

    for line in lines {
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      guard !trimmed.isEmpty else { continue }

      if trimmed.hasPrefix("rule ") {
        let raw = String(trimmed.dropFirst("rule ".count))
        let head = raw.split(separator: " ").first ?? ""
        name = String(head).replacingOccurrences(of: "{", with: "")
      }

      if trimmed.contains("threat_type") {
        threatType = extractQuotedValue(trimmed) ?? threatType
      }
      if trimmed.contains("description") {
        description = extractQuotedValue(trimmed) ?? description
      }

      guard trimmed.hasPrefix("$") else { continue }
      guard let pattern = extractRegex(trimmed) else { continue }

      let identifier = trimmed.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: true).first ?? ""
      let idLower = identifier.lowercased()
      if idLower.contains("legitimate") || idLower.contains("documentation") || idLower.contains("ignore") {
        excludePatterns.append(pattern)
      } else {
        includePatterns.append(pattern)
      }
    }

    guard let resolvedName = name, !includePatterns.isEmpty else {
      return nil
    }

    return YaraRule(
      name: resolvedName,
      threatType: threatType,
      description: description,
      includePatterns: includePatterns,
      excludePatterns: excludePatterns
    )
  }

  private static func extractQuotedValue(_ line: String) -> String? {
    guard let first = line.firstIndex(of: "\""), let last = line.lastIndex(of: "\""), first < last else {
      return nil
    }
    let start = line.index(after: first)
    return String(line[start..<last])
  }

  private static func extractRegex(_ line: String) -> String? {
    guard let firstSlash = line.firstIndex(of: "/"), let lastSlash = line.lastIndex(of: "/"), firstSlash < lastSlash else {
      return nil
    }
    let start = line.index(after: firstSlash)
    return String(line[start..<lastSlash])
  }
}
