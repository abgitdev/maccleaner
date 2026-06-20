import Foundation

// «Кэши проектов»: локальные build-папки внутри проектов (.build, node_modules, target, Pods, .gradle).
// Регенерируются сборкой → безопасно в Корзину (но rebuild будет дольше → safety=moderate, ноль предвыбора).
//
// Точность: папку считаем build-кэшем ТОЛЬКО если рядом есть манифест проекта (Package.swift и т.п.) —
// иначе папка с именем «target»/«build» может быть не сборкой. Внутрь найденной папки не углубляемся.

enum ProjectCaches {
    // (имя папки, манифесты-соседи — любой подходит, человекочитаемый ярлык)
    static let kinds: [(name: String, manifests: [String], label: String)] = [
        (".build",       ["Package.swift"],                               "SwiftPM"),
        ("node_modules", ["package.json"],                               "npm"),
        ("target",       ["Cargo.toml", "pom.xml"],                      "Rust/Maven"),
        ("Pods",         ["Podfile"],                                     "CocoaPods"),
        (".gradle",      ["build.gradle", "settings.gradle", "build.gradle.kts"], "Gradle"),
    ]

    /// Обходит home (минуя Library/личные/скрытые), ищет build-папки с манифестом-соседом.
    static func scan(home: String, maxDepth: Int = 6, limit: Int = 200) -> [ScanItem] {
        guard !home.isEmpty else { return [] }
        var out: [ScanItem] = []
        let skip = skipSet(home)
        let homeDev = Scanner.homeVolumeDevice()   // L4: чужой том (NAS/внешний) под ~ — не обходим
        walk(home, depth: 0, maxDepth: maxDepth, skip: skip, homeDev: homeDev, out: &out)
        out.sort { $0.size > $1.size }
        return Array(out.prefix(limit))
    }

    /// Верхнеуровневые папки, в которые НЕ углубляемся (кэши/личное обрабатываются отдельно или защищены).
    static func skipSet(_ home: String) -> Set<String> {
        ["Library", ".Trash", "Documents", "Desktop", "Downloads", "Pictures", "Movies", "Music", "Public"]
            .reduce(into: Set<String>()) { $0.insert(home + "/" + $1) }
    }

    private static func walk(_ dir: String, depth: Int, maxDepth: Int, skip: Set<String>,
                             homeDev: dev_t?, out: inout [ScanItem]) {
        if depth > maxDepth { return }   // L5: кап по числу убран — детерминированный top-N задаёт sort+prefix в scan()
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
        let hasManifest: (String) -> Bool = { FileManager.default.fileExists(atPath: dir + "/" + $0) }
        for e in entries {
            let full = dir + "/" + e
            var st = stat()
            guard lstat(full, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { continue }   // только папки, не симлинки
            if let hd = homeDev, st.st_dev != hd { continue }   // L4: чужой том под ~ — не обходим/не считаем
            if kinds.contains(where: { $0.name == e }) {
                if let kind = kinds.first(where: { $0.name == e && $0.manifests.contains(where: hasManifest) }) {
                    let size = Trasher.directorySize(full)
                    if size > 0 {
                        out.append(ScanItem(path: full,
                                            displayName: "\((dir as NSString).lastPathComponent) · \(kind.label)",
                                            size: size))
                    }
                }
                continue                       // внутрь build-папки не обходим (даже без манифеста)
            }
            if e.hasPrefix(".") { continue }   // прочие скрытые (.git/.cache/.cargo/…) пропускаем
            if skip.contains(full) { continue }
            walk(full, depth: depth + 1, maxDepth: maxDepth, skip: skip, homeDev: homeDev, out: &out)
        }
    }
}
