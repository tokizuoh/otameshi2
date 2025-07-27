import SwiftUI
import Shared

struct ContentView: View {
    @State private var showContent = false
    var body: some View {
        VStack {
            Button("Click me!") {
                let manager = CryptoManager()
                manager.aesEncryptAndDecrypt()
                manager.rsaOaepEncryptAndDecrypt()
                manager.pbkdf2DeriveKey()
                manager.hkdfDeriveKey()
                manager.hmacSignAndVerify()
            }
        }
    }
}
