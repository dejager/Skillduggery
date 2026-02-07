import Foundation
import Testing
@testable import Skillduggery

struct SettingsPersistenceTests {
  @Test
  func savesAndLoadsSettingsAndRoots() async throws {
    let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("skillduggery-db-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }
    
    let dbURL = tempDir.appendingPathComponent("state.sqlite")
    let store = Store(databaseURL: dbURL)
    
    var settings = AppSettings.default
    settings.dailySchedulingEnabled = false
    settings.highSignalOnlyNotifications = false
    settings.loginAtLaunchEnabled = false
    settings.analyzerBehavioralEnabled = true
    settings.analyzerMetaEnabled = true
    
    await store.saveSettings(settings)
    
    let loadedSettings = await store.loadSettings()
    #expect(loadedSettings.dailySchedulingEnabled == false)
    #expect(loadedSettings.highSignalOnlyNotifications == false)
    #expect(loadedSettings.loginAtLaunchEnabled == false)
    #expect(loadedSettings.analyzerBehavioralEnabled == true)
    #expect(loadedSettings.analyzerMetaEnabled == true)
    
    let folder = tempDir.appendingPathComponent("root", isDirectory: true)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    let bookmark = try folder.bookmarkData()
    
    await store.addRoot(path: folder.path, bookmarkData: bookmark)
    let roots = await store.loadRoots()
    
    #expect(roots.count == 1)
    #expect(roots.first?.path == folder.path)
  }
}
