import SwiftUI

// Цвета и градиенты из дизайна (design/MacCleaner.dc.html).
enum Theme {
    static let bg          = Color(hex: 0x06080c)
    static let panel       = Color(hex: 0x0a0d13)
    static let card        = Color(hex: 0x10141d)
    static let sidebarTop   = Color(hex: 0x0b0e14)
    static let sidebarBot   = Color(hex: 0x090b10)
    static let titleTop     = Color(hex: 0x11151d)
    static let titleBot     = Color(hex: 0x0d1117)
    static let stroke      = Color.white.opacity(0.07)
    static let strokeSoft  = Color.white.opacity(0.045)

    static let text        = Color(hex: 0xe9eef7)
    static let textDim     = Color(hex: 0x8893a4)
    static let textMute    = Color(hex: 0x6b7585)
    static let textFaint   = Color(hex: 0x566073)

    // Акцент (сине-бирюзовый)
    static let accentA     = Color(hex: 0x2a91ff)
    static let accentB     = Color(hex: 0x2fd9c4)
    static var accentGrad: LinearGradient {
        LinearGradient(colors: [accentA, accentB], startPoint: .topLeading, endPoint: .bottomTrailing)
    }

    // Риск (совпадает с классификацией: safe / discretion / never)
    static let safe        = Color(hex: 0x2fd98a)
    static let caution     = Color(hex: 0xffb340)
    static let danger      = Color(hex: 0xff5c5c)
    static let purple      = Color(hex: 0xbf7bff)

    static func risk(_ v: Verdict) -> Color {
        switch v { case .safe: return safe; case .discretion: return caution; case .never: return danger }
    }
    static func riskLabel(_ v: Verdict) -> String {
        switch v { case .safe: return "Safe"; case .discretion: return "Caution"; case .never: return "Don't touch" }
    }
    static func tier(_ s: SafetyLevel) -> Color {
        switch s { case .safe: return safe; case .moderate: return caution; case .risky: return danger; case .manual: return textDim }
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xff) / 255,
                  green: Double((hex >> 8) & 0xff) / 255,
                  blue: Double(hex & 0xff) / 255,
                  opacity: 1)
    }
}
