import Foundation
import AppKit

final class AppLifecycleObserver {
  private let onWake: () -> Void

  init(onWake: @escaping () -> Void) {
    self.onWake = onWake
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(handleWake),
      name: NSWorkspace.didWakeNotification,
      object: nil
    )
  }

  deinit {
    NotificationCenter.default.removeObserver(self)
  }

  @objc private func handleWake() {
    onWake()
  }
}
