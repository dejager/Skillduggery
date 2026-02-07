import SwiftUI

@main
struct SkillduggeryApp: App {
  @StateObject private var model = AppModel()
  
  var body: some Scene {
    MenuBarExtra("Skillduggery", systemImage: model.menuBarSymbol) {
      MenuBarSceneView(model: model)
    }
    .menuBarExtraStyle(.window)
    
    Settings {
      SettingsView(model: model)
    }
  }
}
