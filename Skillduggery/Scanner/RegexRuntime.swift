import Foundation

nonisolated enum RegexRuntime {
  static func firstMatch(pattern: String, in content: String) -> (line: Int, snippet: String)? {
    guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
      return nil
    }

    let nsRange = NSRange(content.startIndex..<content.endIndex, in: content)
    guard let match = regex.firstMatch(in: content, options: [], range: nsRange),
          let range = Range(match.range, in: content)
    else {
      return nil
    }

    let prefix = content[..<range.lowerBound]
    let line = prefix.reduce(into: 1) { partialResult, character in
      if character == "\n" {
        partialResult += 1
      }
    }

    let lineStart = content[..<range.lowerBound].lastIndex(of: "\n") ?? content.startIndex
    let lineStartIndex = lineStart == content.startIndex ? content.startIndex : content.index(after: lineStart)
    let lineEndIndex = content[range.upperBound...].firstIndex(of: "\n") ?? content.endIndex
    let snippet = content[lineStartIndex..<lineEndIndex].trimmingCharacters(in: .whitespaces)

    return (line: line, snippet: snippet)
  }

  static func matchesAny(patterns: [String], in content: String) -> Bool {
    for pattern in patterns {
      guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { continue }
      let nsRange = NSRange(content.startIndex..<content.endIndex, in: content)
      if regex.firstMatch(in: content, options: [], range: nsRange) != nil {
        return true
      }
    }
    return false
  }
}
