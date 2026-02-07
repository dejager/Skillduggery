import Foundation

@MainActor
protocol ScheduleServiceDelegate: AnyObject {
  func scheduleServiceDidRequestScheduledScan()
  func scheduleServiceDidRequestCatchUpScan()
}

final class ScheduleService {
  weak var delegate: ScheduleServiceDelegate?

  private var timer: Timer?
  private let interval: TimeInterval
  private var isEnabled = true
  private var lastRunProvider: (() -> Date?)?

  init(interval: TimeInterval = 24 * 60 * 60) {
    self.interval = interval
  }

  func start(enabled: Bool, lastRunProvider: @escaping () -> Date?) {
    stop()
    self.isEnabled = enabled
    self.lastRunProvider = lastRunProvider
    guard enabled else { return }

    timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
      self?.tick()
    }
  }

  func stop() {
    timer?.invalidate()
    timer = nil
  }

  func handleLaunchOrWake() {
    guard isEnabled else { return }
    let lastRunAt = lastRunProvider?()
    guard let lastRunAt else {
      delegate?.scheduleServiceDidRequestCatchUpScan()
      return
    }

    if Date().timeIntervalSince(lastRunAt) >= interval {
      delegate?.scheduleServiceDidRequestCatchUpScan()
    }
  }

  private func tick() {
    guard isEnabled else { return }
    let lastRunAt = lastRunProvider?()
    guard let lastRunAt else {
      delegate?.scheduleServiceDidRequestScheduledScan()
      return
    }

    if Date().timeIntervalSince(lastRunAt) >= interval {
      delegate?.scheduleServiceDidRequestScheduledScan()
    }
  }
}
