import Foundation

nonisolated enum SkillLoadError: Error, LocalizedError {
  case directoryMissing(URL)
  case missingSkillMarkdown(URL)
  case invalidFrontMatter(URL)
  case missingManifestField(String)

  var errorDescription: String? {
    switch self {
      case .directoryMissing(let url):
        return "Skill directory does not exist: \(url.path)"
      case .missingSkillMarkdown(let url):
        return "SKILL.md not found in \(url.path)"
      case .invalidFrontMatter(let url):
        return "Invalid YAML frontmatter in \(url.path)"
      case .missingManifestField(let field):
        return "SKILL.md missing required field: \(field)"
    }
  }
}

nonisolated struct SkillLoader {
  private let maxFileSizeBytes: Int

  init(maxFileSizeMB: Int = 10) {
    self.maxFileSizeBytes = maxFileSizeMB * 1_024 * 1_024
  }

  func discoverSkillDirectories(in roots: [URL]) -> [URL] {
    var discovered: Set<URL> = []
    for root in roots {
      guard let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
        options: [.skipsPackageDescendants, .skipsHiddenFiles]
      ) else {
        continue
      }

      for case let fileURL as URL in enumerator {
        if fileURL.lastPathComponent == "SKILL.md" {
          discovered.insert(fileURL.deletingLastPathComponent())
        }
      }
    }

    return discovered.sorted { $0.path < $1.path }
  }

  func loadSkill(at directory: URL) throws -> SkillPackage {
    var isDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDir), isDir.boolValue else {
      throw SkillLoadError.directoryMissing(directory)
    }

    let skillMarkdownPath = directory.appendingPathComponent("SKILL.md")
    guard FileManager.default.fileExists(atPath: skillMarkdownPath.path) else {
      throw SkillLoadError.missingSkillMarkdown(directory)
    }

    let content = try String(contentsOf: skillMarkdownPath, encoding: .utf8)
    let (frontMatter, instructionBody) = try parseFrontMatter(content: content, path: skillMarkdownPath)
    let manifest = try parseManifest(frontMatter)
    let files = discoverFiles(in: directory)
    let referencedFiles = extractReferencedFiles(in: instructionBody)

    return SkillPackage(
      directory: directory,
      manifest: manifest,
      skillMarkdownPath: skillMarkdownPath,
      instructionBody: instructionBody,
      files: files,
      referencedFiles: referencedFiles
    )
  }

  private func parseFrontMatter(content: String, path: URL) throws -> (frontMatter: String, body: String) {
    guard content.hasPrefix("---\n") || content.hasPrefix("---\r\n") else {
      throw SkillLoadError.invalidFrontMatter(path)
    }

    let marker = "\n---"
    guard let endRange = content.range(of: marker, options: [], range: content.index(content.startIndex, offsetBy: 3)..<content.endIndex) else {
      throw SkillLoadError.invalidFrontMatter(path)
    }

    let frontMatterStart = content.index(content.startIndex, offsetBy: 4)
    let frontMatter = String(content[frontMatterStart..<endRange.lowerBound])
    let bodyStart = content.index(endRange.lowerBound, offsetBy: marker.count)
    let body = String(content[bodyStart...]).trimmingCharacters(in: .whitespacesAndNewlines)
    return (frontMatter, body)
  }

  private func parseManifest(_ frontMatter: String) throws -> SkillManifest {
    let lines = frontMatter.components(separatedBy: .newlines)

    var values: [String: String] = [:]
    var allowedTools: [String] = []
    var metadata: [String: String] = [:]
    var inMetadata = false

    for rawLine in lines {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      if line.isEmpty || line.hasPrefix("#") {
        continue
      }

      if line.hasPrefix("metadata:") {
        inMetadata = true
        continue
      }

      if inMetadata, line.hasPrefix("-") {
        continue
      }

      if inMetadata, rawLine.hasPrefix("  "), line.contains(":") {
        let key = String(line.split(separator: ":", maxSplits: 1)[0]).trimmingCharacters(in: .whitespaces)
        let value = unquote(String(line.split(separator: ":", maxSplits: 1)[1]).trimmingCharacters(in: .whitespaces))
        metadata[key] = value
        continue
      }

      if !rawLine.hasPrefix("  ") {
        inMetadata = false
      }

      guard line.contains(":") else { continue }
      let parts = line.split(separator: ":", maxSplits: 1)
      guard parts.count == 2 else { continue }
      let key = String(parts[0]).trimmingCharacters(in: .whitespaces)
      let value = unquote(String(parts[1]).trimmingCharacters(in: .whitespaces))
      values[key] = value

      if key == "allowed-tools" || key == "allowed_tools" {
        if value.hasPrefix("[") && value.hasSuffix("]") {
          let list = String(value.dropFirst().dropLast())
          allowedTools = list.split(separator: ",").map { unquote(String($0).trimmingCharacters(in: .whitespaces)) }
        } else {
          allowedTools = value.split(separator: ",").map { unquote(String($0).trimmingCharacters(in: .whitespaces)) }
        }
      }
    }

    guard let name = values["name"], !name.isEmpty else {
      throw SkillLoadError.missingManifestField("name")
    }
    guard let description = values["description"], !description.isEmpty else {
      throw SkillLoadError.missingManifestField("description")
    }

    let disableInvocation = (values["disable-model-invocation"] ?? values["disable_model_invocation"] ?? "false").lowercased() == "true"

    return SkillManifest(
      name: name,
      description: description,
      license: values["license"],
      compatibility: values["compatibility"],
      allowedTools: allowedTools,
      metadata: metadata,
      disableModelInvocation: disableInvocation
    )
  }

  private func discoverFiles(in directory: URL) -> [SkillFile] {
    guard let enumerator = FileManager.default.enumerator(
      at: directory,
      includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
      options: [.skipsHiddenFiles]
    ) else {
      return []
    }

    var files: [SkillFile] = []
    for case let fileURL as URL in enumerator {
      guard let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
            values.isRegularFile == true
      else {
        continue
      }

      let relativePath = fileURL.path.replacingOccurrences(of: directory.path + "/", with: "")
      let size = values.fileSize ?? 0
      var fileType = determineFileType(fileURL)
      var content: String?
      if size <= maxFileSizeBytes, fileType != .binary {
        content = try? String(contentsOf: fileURL, encoding: .utf8)
        if content == nil {
          fileType = .binary
        }
      }

      files.append(
        SkillFile(
          path: fileURL,
          relativePath: relativePath,
          fileType: fileType,
          sizeBytes: size,
          content: content
        )
      )
    }

    return files
  }

  private func determineFileType(_ url: URL) -> SkillFileType {
    switch url.pathExtension.lowercased() {
      case "py":
        return .python
      case "sh", "bash", "zsh":
        return .bash
      case "md", "markdown":
        return .markdown
      case "exe", "dylib", "dll", "so", "bin":
        return .binary
      default:
        return .other
    }
  }

  private func extractReferencedFiles(in body: String) -> [String] {
    var refs: Set<String> = []

    if let markdownRegex = try? NSRegularExpression(pattern: #"\[[^\]]+\]\(([^\)]+)\)"#) {
      let nsRange = NSRange(body.startIndex..<body.endIndex, in: body)
      for match in markdownRegex.matches(in: body, range: nsRange) {
        guard match.numberOfRanges > 1,
              let range = Range(match.range(at: 1), in: body)
        else {
          continue
        }
        let link = String(body[range])
        if !link.hasPrefix("http://") && !link.hasPrefix("https://") && !link.hasPrefix("#") {
          refs.insert(link)
        }
      }
    }

    if let runRegex = try? NSRegularExpression(pattern: #"(?:run|execute|invoke)\s+([A-Za-z0-9_\-./]+\.(?:py|sh))"#, options: [.caseInsensitive]) {
      let nsRange = NSRange(body.startIndex..<body.endIndex, in: body)
      for match in runRegex.matches(in: body, range: nsRange) {
        guard match.numberOfRanges > 1,
              let range = Range(match.range(at: 1), in: body)
        else {
          continue
        }
        refs.insert(String(body[range]))
      }
    }

    return refs.sorted()
  }

  private func unquote(_ text: String) -> String {
    var value = text
    if (value.hasPrefix("\"") && value.hasSuffix("\"")) || (value.hasPrefix("'") && value.hasSuffix("'")) {
      value = String(value.dropFirst().dropLast())
    }
    return value
  }
}
