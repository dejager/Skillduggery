import Foundation
import CryptoKit

nonisolated struct BehavioralAnalyzer {
  func analyze(skill: SkillPackage) -> [ScanFinding] {
    var findings: [ScanFinding] = []

    for file in skill.files where file.fileType == .python {
      guard let content = file.content, !content.isEmpty else { continue }

      let analysis = analyzePython(content: content)
      findings.append(contentsOf: analysis.findings(filePath: file.relativePath))

      for url in suspiciousURLs(in: content) {
        findings.append(
          ScanFinding(
            id: id(prefix: "BEHAVIOR_SUSPICIOUS_URL", context: "\(file.relativePath):\(url)"),
            ruleID: "BEHAVIOR_SUSPICIOUS_URL",
            category: .dataExfiltration,
            severity: .high,
            title: "Suspicious URL detected",
            description: "Script references suspicious endpoint: \(url)",
            filePath: file.relativePath,
            remediation: "Verify endpoint legitimacy and intended usage.",
            analyzer: "behavioral",
            metadata: ["url": url]
          )
        )
      }
    }

    return dedupe(findings)
  }

  private func analyzePython(content: String) -> PythonFlowAnalysis {
    var taintedVars: Set<String> = []
    var sourceLines: [String: Int] = [:]
    var sinkEvents: [PythonSinkEvent] = []

    let lines = content.components(separatedBy: .newlines)
    for (index, rawLine) in lines.enumerated() {
      let lineNumber = index + 1
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      guard line.isEmpty == false else { continue }

      if let assigned = assignedVariable(in: line) {
        if isSourceLine(line) {
          taintedVars.insert(assigned)
          sourceLines[assigned] = lineNumber
        } else if isVariablePropagation(line: line, variable: assigned, taintedVars: taintedVars) {
          taintedVars.insert(assigned)
          sourceLines[assigned] = sourceLines[extractSourceVariable(line: line) ?? ""] ?? lineNumber
        }
      }

      if isNetworkSink(line), containsTaintedValue(line: line, taintedVars: taintedVars) {
        sinkEvents.append(
          PythonSinkEvent(
            kind: .network,
            lineNumber: lineNumber,
            snippet: rawLine.trimmingCharacters(in: .whitespaces)
          )
        )
      }

      if isExecSink(line), containsTaintedValue(line: line, taintedVars: taintedVars) {
        sinkEvents.append(
          PythonSinkEvent(
            kind: .exec,
            lineNumber: lineNumber,
            snippet: rawLine.trimmingCharacters(in: .whitespaces)
          )
        )
      }

      if isDynamicExecution(line) {
        let tainted = containsTaintedValue(line: line, taintedVars: taintedVars)
        if tainted || line.contains("input(") || line.contains("request") {
          sinkEvents.append(
            PythonSinkEvent(
              kind: .dynamicExecution,
              lineNumber: lineNumber,
              snippet: rawLine.trimmingCharacters(in: .whitespaces)
            )
          )
        }
      }
    }

    return PythonFlowAnalysis(taintedVars: taintedVars, sourceLines: sourceLines, sinks: sinkEvents)
  }

  private func isSourceLine(_ line: String) -> Bool {
    hasAny(content: line, patterns: [
      #"\bos\.environ\b"#,
      #"\bos\.getenv\s*\("#,
      #"\bgetenv\s*\("#,
      #"\bopen\s*\([^)]*(\.aws/credentials|\.ssh/id_rsa|\.ssh/id_dsa|/etc/passwd|/etc/shadow)"#
    ])
  }

  private func isNetworkSink(_ line: String) -> Bool {
    hasAny(content: line, patterns: [
      #"\brequests\.(post|put|get|delete)\s*\("#,
      #"\bhttpx\.(post|put|get|delete)\s*\("#,
      #"\burllib\.request\.urlopen\s*\("#,
      #"\bsocket\.(create_connection|socket)\s*\("#
    ])
  }

  private func isExecSink(_ line: String) -> Bool {
    hasAny(content: line, patterns: [
      #"\bos\.system\s*\("#,
      #"\bsubprocess\.(run|call|Popen)\s*\("#
    ])
  }

  private func isDynamicExecution(_ line: String) -> Bool {
    hasAny(content: line, patterns: [#"\b(eval|exec)\s*\("#])
  }

  private func assignedVariable(in line: String) -> String? {
    guard
      let regex = try? NSRegularExpression(pattern: #"^([A-Za-z_][A-Za-z0-9_]*)\s*="#),
      let match = regex.firstMatch(in: line, range: NSRange(line.startIndex..<line.endIndex, in: line)),
      let range = Range(match.range(at: 1), in: line)
    else {
      return nil
    }
    return String(line[range])
  }

  private func isVariablePropagation(line: String, variable: String, taintedVars: Set<String>) -> Bool {
    guard let source = extractSourceVariable(line: line), source != variable else { return false }
    return taintedVars.contains(source)
  }

  private func extractSourceVariable(line: String) -> String? {
    guard let equals = line.firstIndex(of: "=") else { return nil }
    let rhs = String(line[line.index(after: equals)...]).trimmingCharacters(in: .whitespaces)
    guard
      let regex = try? NSRegularExpression(pattern: #"^([A-Za-z_][A-Za-z0-9_]*)$"#),
      let match = regex.firstMatch(in: rhs, range: NSRange(rhs.startIndex..<rhs.endIndex, in: rhs)),
      let range = Range(match.range(at: 1), in: rhs)
    else {
      return nil
    }
    return String(rhs[range])
  }

  private func containsTaintedValue(line: String, taintedVars: Set<String>) -> Bool {
    for variable in taintedVars {
      if line.contains(variable) {
        return true
      }
    }
    return false
  }

  private func hasAny(content: String, patterns: [String]) -> Bool {
    RegexRuntime.matchesAny(patterns: patterns, in: content)
  }

  private func suspiciousURLs(in content: String) -> [String] {
    let urlPattern = #"https?://[A-Za-z0-9._\-/]+"#
    guard let regex = try? NSRegularExpression(pattern: urlPattern) else { return [] }
    let nsRange = NSRange(content.startIndex..<content.endIndex, in: content)
    let matches = regex.matches(in: content, range: nsRange)

    let suspiciousDomains = [
      "pastebin.com", "transfer.sh", "webhook.site", "attacker.example.com", "evil.example.com",
      "ngrok.io", "pipedream.net", "requestbin"
    ]

    var hits: Set<String> = []
    for match in matches {
      guard let range = Range(match.range, in: content) else { continue }
      let url = String(content[range])
      if suspiciousDomains.contains(where: { url.localizedCaseInsensitiveContains($0) }) {
        hits.insert(url)
      }
    }
    return Array(hits).sorted()
  }

  private func id(prefix: String, context: String) -> String {
    let digest = SHA256.hash(data: Data("\(prefix):\(context)".utf8))
      .compactMap { String(format: "%02x", $0) }
      .joined()
    return "\(prefix)_\(digest.prefix(12))"
  }

  private func dedupe(_ findings: [ScanFinding]) -> [ScanFinding] {
    var unique: [String: ScanFinding] = [:]
    for finding in findings {
      let key = "\(finding.ruleID)|\(finding.filePath ?? "")|\(finding.lineNumber ?? 0)"
      if let existing = unique[key] {
        if finding.severity.priority > existing.severity.priority {
          unique[key] = finding
        }
      } else {
        unique[key] = finding
      }
    }
    return Array(unique.values)
  }
}

nonisolated private enum PythonSinkKind {
  case network
  case exec
  case dynamicExecution
}

nonisolated private struct PythonSinkEvent {
  let kind: PythonSinkKind
  let lineNumber: Int
  let snippet: String
}

nonisolated private struct PythonFlowAnalysis {
  let taintedVars: Set<String>
  let sourceLines: [String: Int]
  let sinks: [PythonSinkEvent]

  func findings(filePath: String) -> [ScanFinding] {
    var output: [ScanFinding] = []

    if taintedVars.isEmpty == false {
      output.append(
        ScanFinding(
          id: "BEHAVIOR_TAINT_SOURCES_\(filePath)",
          ruleID: "BEHAVIOR_TAINT_SOURCES",
          category: .dataExfiltration,
          severity: .medium,
          title: "Sensitive source values detected",
          description: "Found potential credential/environment data sources that may flow to sinks.",
          filePath: filePath,
          analyzer: "behavioral",
          metadata: ["tainted_var_count": "\(taintedVars.count)"]
        )
      )
    }

    for sink in sinks {
      switch sink.kind {
        case .network:
          output.append(
            ScanFinding(
              id: "BEHAVIOR_DATAFLOW_NETWORK_\(filePath)_\(sink.lineNumber)",
              ruleID: "BEHAVIOR_DATAFLOW_NETWORK",
              category: .dataExfiltration,
              severity: .critical,
              title: "Tainted data reaches network sink",
              description: "Potential exfiltration path: sensitive source value flows into outbound network call.",
              filePath: filePath,
              lineNumber: sink.lineNumber,
              snippet: sink.snippet,
              remediation: "Sanitize data and restrict outbound requests.",
              analyzer: "behavioral"
            )
          )
        case .exec:
          output.append(
            ScanFinding(
              id: "BEHAVIOR_DATAFLOW_EXEC_\(filePath)_\(sink.lineNumber)",
              ruleID: "BEHAVIOR_DATAFLOW_EXEC",
              category: .commandInjection,
              severity: .high,
              title: "Tainted data reaches process execution sink",
              description: "Potential command injection path via subprocess or shell execution.",
              filePath: filePath,
              lineNumber: sink.lineNumber,
              snippet: sink.snippet,
              remediation: "Use strict argument arrays and validate/escape untrusted input.",
              analyzer: "behavioral"
            )
          )
        case .dynamicExecution:
          output.append(
            ScanFinding(
              id: "BEHAVIOR_DYNAMIC_EXEC_\(filePath)_\(sink.lineNumber)",
              ruleID: "BEHAVIOR_DYNAMIC_EXEC",
              category: .commandInjection,
              severity: .critical,
              title: "Dynamic execution on untrusted input",
              description: "eval/exec appears to execute tainted or user-controlled input.",
              filePath: filePath,
              lineNumber: sink.lineNumber,
              snippet: sink.snippet,
              remediation: "Remove dynamic execution and replace with explicit safe logic.",
              analyzer: "behavioral"
            )
          )
      }
    }

    return output
  }
}
