import Foundation

// Умная классификация файлов: путь → вердикт (safe/discretion/never) + причина.
// Правила собраны и проверены роем (classification.json), матчатся по подстроке пути,
// в порядке убывания priority — первое совпадение выигрывает.

enum Verdict: String, Codable {
    case safe, discretion, never
}

struct ClassRule: Codable {
    let pattern: String
    let verdict: Verdict
    let label: String
    let reason: String
    let priority: Int
}

struct Classification {
    let verdict: Verdict
    let label: String
    let reason: String

    static let unknown = Classification(
        verdict: .discretion,
        label: "Unrecognized",
        reason: "Not recognized — your call. Delete only if you know what it is.")
}

enum Classifier {
    private struct File: Codable { let rules: [ClassRule] }

    static let rules: [ClassRule] = {
        guard let url = Bundle.main.url(forResource: "classification", withExtension: "json") else { return [] }
        return loadRules(from: url)
    }()

    /// Первое правило (по убыванию priority), чей pattern — подстрока пути.
    static func classify(_ path: String, rules: [ClassRule]? = nil) -> Classification {
        // B1-fix: /System/Volumes/Data/… — это firmlink на том ДАННЫХ, а не системный раздел.
        // Без выреза правило "/System/" глушило бы пользовательские файлы (DerivedData и т.п.).
        // I10: APFS регистронезависим — сверяем firmlink-префикс без учёта регистра (как norm() везде).
        var p = path
        if let r = p.range(of: "/System/Volumes/Data", options: .caseInsensitive), r.lowerBound == p.startIndex {
            p = String(p[r.upperBound...])
        }
        for r in (rules ?? self.rules) where p.contains(r.pattern) {
            return Classification(verdict: r.verdict, label: r.label, reason: r.reason)
        }
        return .unknown
    }

    static func loadRules(from url: URL) -> [ClassRule] {
        guard let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode(File.self, from: data)
        else { return [] }
        return decoded.rules.sorted { $0.priority > $1.priority }
    }
}
