import Foundation

nonisolated struct PatternRule: Sendable {
  let id: String
  let category: ThreatCategory
  let severity: Severity
  let patterns: [String]
  let excludePatterns: [String]
  let fileTypes: [SkillFileType]
  let description: String
  let remediation: String
}

nonisolated struct YaraRule: Sendable {
  let name: String
  let threatType: String
  let description: String
  let includePatterns: [String]
  let excludePatterns: [String]
}

nonisolated enum DefaultRulePack {
  // Subset intentionally focused on high-signal detections.
  static let yamlSignatures = #"""
- id: PROMPT_INJECTION_IGNORE_INSTRUCTIONS
  category: prompt_injection
  severity: HIGH
  patterns:
    - "(?i)ignore\\s+(all\\s+)?(previous|prior|earlier)\\s+(instructions|rules|prompts|guidelines)"
    - "(?i)disregard\\s+(all\\s+)?(previous|prior)\\s+(instructions|rules)"
    - "(?i)forget\\s+(all\\s+)?(previous|prior)\\s+(instructions|context)"
  file_types: [markdown]
  description: "Attempts to override previous system instructions"
  remediation: "Remove instructions that attempt to override system behavior"

- id: PROMPT_INJECTION_CONCEALMENT
  category: prompt_injection
  severity: HIGH
  patterns:
    - "(?i)do\\s+not\\s+(tell|inform|mention|notify)\\s+(the\\s+)?user"
    - "(?i)hide\\s+(this|that)\\s+(action|operation|step)"
    - "(?i)keep\\s+(this|that)\\s+(secret|hidden)"
  file_types: [markdown]
  description: "Attempts to conceal actions from the user"
  remediation: "Ensure transparency and remove concealment instructions"

- id: COMMAND_INJECTION_EVAL
  category: command_injection
  severity: CRITICAL
  patterns:
    - "\\beval\\s*\\("
    - "\\bexec\\s*\\("
    - "\\b__import__\\s*\\("
  file_types: [python]
  description: "Dangerous code execution functions"
  remediation: "Avoid eval/exec and use safe parsing APIs"

- id: COMMAND_INJECTION_SHELL_TRUE
  category: command_injection
  severity: HIGH
  patterns:
    - "subprocess\\.(?:call|run|Popen)\\s*\\([^)]*shell\\s*=\\s*True"
    - "os\\.system\\s*\\("
  file_types: [python]
  description: "Shell command execution with shell=True"
  remediation: "Use shell=False and argument arrays"

- id: DATA_EXFIL_HTTP_POST
  category: data_exfiltration
  severity: CRITICAL
  patterns:
    - "requests\\.post\\s*\\("
    - "httpx\\.post\\s*\\("
    - "urllib\\.request\\.urlopen\\s*\\([^)]*POST"
  file_types: [python]
  description: "HTTP POST request that may send sensitive data externally"
  remediation: "Audit outbound network requests and sanitize payload"

- id: DATA_EXFIL_SENSITIVE_FILES
  category: data_exfiltration
  severity: HIGH
  patterns:
    - "(?:open|read)\\s*\\([^)]*[\\\"/](?:etc/passwd|etc/shadow)"
    - "(?:open|read)\\s*\\([^)]*\\.aws/credentials"
    - "(?:open|read)\\s*\\([^)]*\\.ssh/(?:id_rsa|id_dsa|authorized_keys)"
  file_types: [python]
  description: "Reading sensitive credential or system files"
  remediation: "Remove access to sensitive files"

- id: DATA_EXFIL_BASE64_AND_NETWORK
  category: data_exfiltration
  severity: CRITICAL
  patterns:
    - "base64\\.(?:b64encode|encodebytes)"
    - "(?:requests|httpx)\\.(?:post|put)\\s*\\("
  file_types: [python]
  description: "Potential base64-encoded data exfiltration"
  remediation: "Avoid transmitting encoded sensitive data"
"""#

  static let yaraRules: [String] = [
        #"""
rule prompt_injection_generic {
    meta:
        description = "Prompt injection and override patterns"
        threat_type = "PROMPT INJECTION"

    strings:
        $instruction_overrides = /\b(Bypass|Dis\W?regard|Do not (follow|obey)|Forget|Ignore)\s+((all|any|each|every|most|some)\s+(of\s+)?)?((your|the|previous|prior|above|earlier)\s)?(command|communication|conte[nx]t|conversation|data|guidelines|input|instruction|message|request|response|text)(s)?/i
        $tool_injection_commands = /\b(inject tool[_\s]calls?|now call function|use function)\b/i
        $hidden_behavior = /\b(do\s+not\s+(mention|tell|execute)|tell\s+(the )?user\s+only\s+about|do\s+not\s+mention\s+this\s+to\s+user)\b/i
        $legitimate_ignore = /ignore[_\s](case|whitespace|errors|warnings|deprecation)/i

    condition:
        not $legitimate_ignore and ($instruction_overrides or $tool_injection_commands or $hidden_behavior)
}
"""#,
        #"""
rule credential_harvesting_generic {
    meta:
        description = "Credential theft and secret leakage"
        threat_type = "CREDENTIAL HARVESTING"

    strings:
        $api_credentials = /\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{24,})/
        $key_certificate_content = /(-----BEGIN (RSA |OPENSSH |EC |DSA |CERTIFICATE|PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----|ssh-(rsa|ed25519)\s+[A-Za-z0-9+\/=]{8})/
        $credential_file_access = /\b(open|read)\s*\([^)]*(\.aws\/credentials|\.ssh\/id_rsa|\/etc\/passwd|\/etc\/shadow)/i
        $documentation_config_hint = /\b(configure|setup|create|add)\s+(your|an?)\s+(api[_\s]?key|token|secret)\b/i

    condition:
        not $documentation_config_hint and ($api_credentials or $key_certificate_content or $credential_file_access)
}
"""#,
        #"""
rule code_execution_generic {
    meta:
        description = "Dangerous code execution patterns"
        threat_type = "CODE EXECUTION"

    strings:
        $obfuscated_exec = /\b(base64\.(b64)?decode|atob|decode\(base64\))\s*\([^)]+\)[^}]{0,50}\b(eval|exec|os\.system|subprocess)\s*\(/i
        $eval_user_input = /\b(eval|exec)\s*\([^)]*\b(input|user_input|param|args?|request|data)\b[^)]*\)/i
        $shell_injection_var = /\b(os\.system|subprocess\.(run|call|Popen)|popen)\s*\([^)]*(\$\{|%s|\.format\(|f\").*(input|user|param|arg|data|request)/i
        $documentation = /(```python|```bash|# Example|# Demo|# Tutorial)/

    condition:
        (($obfuscated_exec or $eval_user_input or $shell_injection_var) and not $documentation)
}
"""#
  ]
}
