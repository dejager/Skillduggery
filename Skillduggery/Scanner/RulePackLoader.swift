import Foundation
import CryptoKit

nonisolated struct LoadedRulePack {
  let yamlRules: [PatternRule]
  let yaraRules: [YaraRule]
  let warnings: [String]
}

nonisolated private struct RulePackManifest: Decodable {
  struct RuleFile: Decodable {
    let path: String
    let sha256: String
  }

  let packID: String?
  let version: String?
  let files: [RuleFile]

  enum CodingKeys: String, CodingKey {
    case packID = "pack_id"
    case version
    case files
  }
}

nonisolated struct RulePackLoader {
  private let activePackURL: URL?
  private let publicKeyData: Data

  init(
    activePackURL: URL? = RulePackLoader.defaultActivePackURL(),
    publicKeyData: Data = RulePackLoader.defaultPublicKeyData
  ) {
    self.activePackURL = activePackURL
    self.publicKeyData = publicKeyData
  }

  func load() -> LoadedRulePack {
    guard let activePackURL else {
      return Self.defaultPack()
    }

    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: activePackURL.path, isDirectory: &isDirectory), isDirectory.boolValue else {
      return Self.defaultPack()
    }

    let manifestURL = activePackURL.appendingPathComponent("manifest.json")
    let signatureURL = activePackURL.appendingPathComponent("manifest.sig")

    guard let manifestData = try? Data(contentsOf: manifestURL) else {
      return Self.defaultPack(with: "Rule pack missing manifest.json. Falling back to bundled rules.")
    }

    guard let signatureData = loadSignature(from: signatureURL) else {
      return Self.defaultPack(with: "Rule pack missing or invalid manifest.sig. Falling back to bundled rules.")
    }

    guard verifySignature(manifestData: manifestData, signatureData: signatureData) else {
      return Self.defaultPack(with: "Rule pack signature verification failed. Falling back to bundled rules.")
    }

    guard let manifest = try? JSONDecoder().decode(RulePackManifest.self, from: manifestData) else {
      return Self.defaultPack(with: "Rule pack manifest format is invalid. Falling back to bundled rules.")
    }

    for file in manifest.files {
      let fileURL = activePackURL.appendingPathComponent(file.path)
      guard let data = try? Data(contentsOf: fileURL) else {
        return Self.defaultPack(with: "Rule pack file missing: \(file.path). Falling back to bundled rules.")
      }

      let expected = file.sha256.lowercased()
      let actual = sha256Hex(data)
      if expected != actual {
        return Self.defaultPack(with: "Rule pack checksum mismatch for \(file.path). Falling back to bundled rules.")
      }
    }

    var yamlSource = ""
    var yaraSource = ""
    for file in manifest.files {
      let lower = file.path.lowercased()
      let fileURL = activePackURL.appendingPathComponent(file.path)
      guard let content = try? String(contentsOf: fileURL, encoding: .utf8) else { continue }

      if lower.hasSuffix(".yaml") || lower.hasSuffix(".yml") {
        yamlSource += "\n" + content
      } else if lower.hasSuffix(".yar") || lower.hasSuffix(".yara") {
        yaraSource += "\n" + content
      }
    }

    let parsedYAML = YAMLRuleParser.parse(yamlSource)
    let parsedYARA = YaraRuleParser.parseMany(yaraSource)
    if parsedYAML.isEmpty && parsedYARA.isEmpty {
      return Self.defaultPack(with: "Rule pack parsed zero rules. Falling back to bundled rules.")
    }

    return LoadedRulePack(
      yamlRules: parsedYAML.isEmpty ? YAMLRuleParser.parse(DefaultRulePack.yamlSignatures) : parsedYAML,
      yaraRules: parsedYARA.isEmpty ? DefaultRulePack.yaraRules.compactMap(YaraRuleParser.parse) : parsedYARA,
      warnings: []
    )
  }

  private func verifySignature(manifestData: Data, signatureData: Data) -> Bool {
    guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData) else {
      return false
    }
    return publicKey.isValidSignature(signatureData, for: manifestData)
  }

  private func loadSignature(from url: URL) -> Data? {
    guard let data = try? Data(contentsOf: url), !data.isEmpty else {
      return nil
    }
    if data.count == 64 {
      return data
    }

    guard
      let text = String(data: data, encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines),
      let decoded = Data(base64Encoded: text)
    else {
      return nil
    }
    return decoded
  }

  static func defaultPack(with warning: String? = nil) -> LoadedRulePack {
    LoadedRulePack(
      yamlRules: YAMLRuleParser.parse(DefaultRulePack.yamlSignatures),
      yaraRules: DefaultRulePack.yaraRules.compactMap(YaraRuleParser.parse),
      warnings: warning.map { [$0] } ?? []
    )
  }

  static func defaultActivePackURL() -> URL? {
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
    return appSupport?
      .appendingPathComponent("Skillduggery", isDirectory: true)
      .appendingPathComponent("rules", isDirectory: true)
      .appendingPathComponent("current", isDirectory: true)
  }

  static let defaultPublicKeyData: Data = Data(base64Encoded: "XvzVn84LJbVpTMEvUK/MPNJXL0Y74B+bXZnnhWbRf60=") ?? Data()
}

nonisolated private func sha256Hex(_ data: Data) -> String {
  SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
}
