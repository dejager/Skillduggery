import Foundation
import Testing
@testable import Skillduggery

@MainActor
struct ScheduleServiceTests {
  @Test
  func launchCatchUpTriggersWhenNoPreviousRun() {
    let service = ScheduleService(interval: 24 * 60 * 60)
    let delegate = ScheduleDelegateSpy()
    service.delegate = delegate
    service.start(enabled: true) { nil }
    
    service.handleLaunchOrWake()
    
    #expect(delegate.catchUpCount == 1)
    #expect(delegate.scheduledCount == 0)
    service.stop()
  }
  
  @Test
  func launchCatchUpDoesNotTriggerWhenRecentRunExists() {
    let service = ScheduleService(interval: 24 * 60 * 60)
    let delegate = ScheduleDelegateSpy()
    service.delegate = delegate
    service.start(enabled: true) { Date().addingTimeInterval(-60) }
    
    service.handleLaunchOrWake()
    
    #expect(delegate.catchUpCount == 0)
    #expect(delegate.scheduledCount == 0)
    service.stop()
  }
  
  @Test
  func launchCatchUpTriggersWhenRunIsStale() {
    let service = ScheduleService(interval: 24 * 60 * 60)
    let delegate = ScheduleDelegateSpy()
    service.delegate = delegate
    service.start(enabled: true) { Date().addingTimeInterval(-(25 * 60 * 60)) }
    
    service.handleLaunchOrWake()
    
    #expect(delegate.catchUpCount == 1)
    #expect(delegate.scheduledCount == 0)
    service.stop()
  }

  @Test
  func disablingScheduleStopsImmediateCatchUpRequests() {
    let service = ScheduleService(interval: 24 * 60 * 60)
    let delegate = ScheduleDelegateSpy()
    service.delegate = delegate

    service.start(enabled: true) { nil }
    service.start(enabled: false) { nil }
    service.handleLaunchOrWake()

    #expect(delegate.catchUpCount == 0)
    #expect(delegate.scheduledCount == 0)
    service.stop()
  }
}

@MainActor
private final class ScheduleDelegateSpy: ScheduleServiceDelegate {
  private(set) var scheduledCount = 0
  private(set) var catchUpCount = 0
  
  func scheduleServiceDidRequestScheduledScan() {
    scheduledCount += 1
  }
  
  func scheduleServiceDidRequestCatchUpScan() {
    catchUpCount += 1
  }
}
