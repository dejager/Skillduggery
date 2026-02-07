import Foundation
import ServiceManagement

enum LoginLaunchService {
  static func setEnabled(_ enabled: Bool) -> Bool {
    guard #available(macOS 13.0, *) else {
      return false
    }

    do {
      if enabled {
        try SMAppService.mainApp.register()
      } else {
        try SMAppService.mainApp.unregister()
      }
      return true
    } catch {
      return false
    }
  }

  static func status() -> Bool {
    guard #available(macOS 13.0, *) else {
      return false
    }
    return SMAppService.mainApp.status == .enabled
  }
}
