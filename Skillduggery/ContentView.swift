//
//  ContentView.swift
//  Skillduggery
//
//  Created by Nate de Jager on 2026-02-06.
//

import SwiftUI

struct ContentView: View {
  var body: some View {
    VStack {
      Image(systemName: "eye")
        .imageScale(.large)
        .foregroundStyle(.tint)
      Text("Skillduggery")
    }
    .padding()
  }
}

#Preview {
  ContentView()
}
