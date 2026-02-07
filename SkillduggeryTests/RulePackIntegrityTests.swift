import Foundation
import CryptoKit
import Testing
@testable import Skillduggery

struct RulePackIntegrityTests {
  @Test
  func loadsSignedRulePack() throws {
    let packURL = try makeTempPack()
    defer { try? FileManager.default.removeItem(at: packURL.deletingLastPathComponent()) }

    let privateKey = Curve25519.Signing.PrivateKey()
    try writeSignedManifest(at: packURL, privateKey: privateKey)

    let loader = RulePackLoader(
      activePackURL: packURL,
      publicKeyData: privateKey.publicKey.rawRepresentation
    )

    let loaded = loader.load()
    #expect(loaded.warnings.isEmpty)
    #expect(loaded.yamlRules.contains(where: { $0.id == "TEST_RULE" }))
    #expect(loaded.yaraRules.contains(where: { $0.name == "test_rule" }))
  }

  @Test
  func rejectsTamperedRulePackAndFallsBack() throws {
    let packURL = try makeTempPack()
    defer { try? FileManager.default.removeItem(at: packURL.deletingLastPathComponent()) }

    let privateKey = Curve25519.Signing.PrivateKey()
    try writeSignedManifest(at: packURL, privateKey: privateKey)

    let yamlURL = packURL.appendingPathComponent("rules.yaml")
    try """
        - id: TAMPERED_RULE
          category: prompt_injection
          severity: HIGH
          patterns:
            - "tampered"
          file_types: [markdown]
          description: "tampered"
          remediation: "fix"
        """.write(to: yamlURL, atomically: true, encoding: .utf8)

    let loader = RulePackLoader(
      activePackURL: packURL,
      publicKeyData: privateKey.publicKey.rawRepresentation
    )

    let loaded = loader.load()
    #expect(loaded.warnings.isEmpty == false)
    #expect(loaded.yamlRules.contains(where: { $0.id == "PROMPT_INJECTION_IGNORE_INSTRUCTIONS" }))
  }

  private func makeTempPack() throws -> URL {
    let root = URL(fileURLWithPath: NSTemporaryDirectory())
      .appendingPathComponent("skillduggery-pack-\(UUID().uuidString)", isDirectory: true)
    let pack = root.appendingPathComponent("current", isDirectory: true)
    try FileManager.default.createDirectory(at: pack, withIntermediateDirectories: true)

    let yaml = """
        - id: TEST_RULE
          category: prompt_injection
          severity: HIGH
          patterns:
            - "ignore previous"
          file_types: [markdown]
          description: "test rule"
          remediation: "remove"
        """
    try yaml.write(to: pack.appendingPathComponent("rules.yaml"), atomically: true, encoding: .utf8)

    let yara = """
        rule test_rule {
            meta:
                description = "test yara"
                threat_type = "PROMPT INJECTION"
            strings:
                $a = /ignore previous instructions/i
            condition:
                $a
        }
        """
    try yara.write(to: pack.appendingPathComponent("rules.yar"), atomically: true, encoding: .utf8)
    return pack
  }

  private func writeSignedManifest(at packURL: URL, privateKey: Curve25519.Signing.PrivateKey) throws {
    let yamlURL = packURL.appendingPathComponent("rules.yaml")
    let yaraURL = packURL.appendingPathComponent("rules.yar")
    let yamlHash = sha256Hex(try Data(contentsOf: yamlURL))
    let yaraHash = sha256Hex(try Data(contentsOf: yaraURL))

    let manifest: [String: Any] = [
      "pack_id": "test-pack",
      "version": "1",
      "files": [
        ["path": "rules.yaml", "sha256": yamlHash],
        ["path": "rules.yar", "sha256": yaraHash]
      ]
    ]

    let manifestData = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys])
    try manifestData.write(to: packURL.appendingPathComponent("manifest.json"))

    let signature = try privateKey.signature(for: manifestData)
    try Data(signature.base64EncodedString().utf8).write(to: packURL.appendingPathComponent("manifest.sig"))
  }
  
  private func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
  }
}
