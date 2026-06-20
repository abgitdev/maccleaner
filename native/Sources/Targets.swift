import Foundation

// Каталог целей чистки. Загружается из targets.json (порт default_targets.yaml).

enum SafetyLevel: String, Codable {
    case safe, moderate, risky, manual
}

enum CleanMethod: String, Codable {
    case trash, report, builtin
}

struct Target: Codable, Identifiable {
    let id: String
    let name: String
    let group: String
    let safety: SafetyLevel
    let method: CleanMethod
    var note: String?
    var paths: [String]?
    var blockedByProcesses: [String]?
    var keepNewest: Bool?           // версионные папки: оставить новейшую, предлагать только старые

    enum CodingKeys: String, CodingKey {
        case id, name, group, safety, method, note, paths
        case blockedByProcesses = "blocked_by_processes"
        case keepNewest = "keep_newest"
    }
}

enum TargetCatalog {
    private struct File: Codable { let targets: [Target] }

    /// Загрузить из конкретного файла (используется в тестах).
    static func load(from url: URL) throws -> [Target] {
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(File.self, from: data).targets
    }

    /// Загрузить из ресурсов собранного приложения.
    static func loadBundled() throws -> [Target] {
        guard let url = Bundle.main.url(forResource: "targets", withExtension: "json") else {
            throw SafetyError(reason: "targets.json not found in bundle")
        }
        return try load(from: url)
    }
}
