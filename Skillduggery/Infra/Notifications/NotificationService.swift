import Foundation
import UserNotifications

struct NotificationSummary: Sendable, Equatable {
  let title: String
  let body: String
}

final class NotificationService {
  private let center: UNUserNotificationCenter

  init(center: UNUserNotificationCenter = .current()) {
    self.center = center
  }

  func requestPermission() {
    center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
  }

  func notifyIfNeeded(run: ScanRun, highSignalOnly: Bool) {
    guard let summary = Self.makeSummary(for: run, highSignalOnly: highSignalOnly) else {
      return
    }

    let content = UNMutableNotificationContent()
    content.title = summary.title
    content.body = summary.body
    content.sound = .default

    let request = UNNotificationRequest(
      identifier: "skillduggery.scan.\(run.id.uuidString)",
      content: content,
      trigger: nil
    )

    center.add(request)
  }

  static func makeSummary(for run: ScanRun, highSignalOnly: Bool) -> NotificationSummary? {
    let source = highSignalOnly ? run.findings.onlyHighSignal() : run.findings
    guard !source.isEmpty else { return nil }

    let critical = source.filter { $0.severity == .critical }.count
    let high = source.filter { $0.severity == .high }.count

    if highSignalOnly, critical + high == 0 {
      return nil
    }

    let title = "Skillduggery threat scan"
    let body = "Detected \(critical) critical and \(high) high findings across \(run.skillCount) skills."
    return NotificationSummary(title: title, body: body)
  }
}
