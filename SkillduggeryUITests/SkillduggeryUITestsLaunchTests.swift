//
//  SkillduggeryUITestsLaunchTests.swift
//  SkillduggeryUITests
//
//  Created by Nate de Jager on 2026-02-06.
//

import XCTest

final class SkillduggeryUITestsLaunchTests: XCTestCase {
  
  override class var runsForEachTargetApplicationUIConfiguration: Bool {
    true
  }
  
  override func setUpWithError() throws {
    continueAfterFailure = false
  }
  
  @MainActor
  func testLaunch() throws {
    throw XCTSkip("UI automation is disabled by default for this project run profile.")
  }
}
