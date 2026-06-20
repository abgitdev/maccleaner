import Foundation

// Адаптивная карта хранилища: куда уходит место на диске.
//
// Принцип (приложение публичное — машины у всех РАЗНЫЕ):
//  • категории описаны данными (storage.json), не зашиты в код;
//  • размеры считаются ВЖИВУЮ по реальным папкам (Trasher.directorySize — честные блоки, дедуп хардлинков);
//  • показываем только непустые/заметные категории → на чистой машине их мало, на забитой много;
//  • всё, что не разложено по категориям, попадает в «System & other» (остаток = used − измеренное),
//    поэтому сумма сегментов = реально занятому месту, без выдуманных чисел;
//  • это ТОЛЬКО показ (read-only) — удаление живёт в Cleanup со всеми проверками безопасности.

/// Правило категории из storage.json.
struct StorageRule: Codable {
    let id: String
    let name: String
    let color: String        // hex без '#'
    let icon: String         // SF Symbol
    let paths: [String]      // glob-шаблоны (поддерживают ~)
}

/// Посчитанная категория (готова к показу).
struct StorageCategory: Identifiable {
    let id: String
    let name: String
    let colorHex: UInt32
    let icon: String
    var bytes: Int64
}

/// Результат разбивки.
struct StorageReport {
    var categories: [StorageCategory]   // непустые/заметные, по убыванию
    var systemOther: Int64              // macOS + всё неразложенное + свёрнутая мелочь
    var free: Int64
    var total: Int64
    var used: Int64 { max(0, total - free) }
}

enum StorageRuleset {
    private struct FileDoc: Codable { let categories: [StorageRule] }

    static func load(from url: URL) throws -> [StorageRule] {
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(FileDoc.self, from: data).categories
    }

    /// Из ресурсов собранного приложения. Пусто → разбивки просто не будет (не падаем).
    static func loadBundled() -> [StorageRule] {
        guard let url = Bundle.main.url(forResource: "storage", withExtension: "json"),
              let rules = try? load(from: url) else { return [] }
        return rules
    }
}

enum StorageScanner {
    /// Считает реальные размеры категорий.
    /// - progress(fraction, имя текущей категории) — для прогресс-бара (вызывается в фоне).
    /// - minShow: категории меньше этого порога сворачиваются в «System & other» (адаптивность UI).
    static func scan(rules: [StorageRule],
                     total: Int64,
                     free: Int64,
                     minShow: Int64 = 64 * 1024 * 1024,
                     progress: ((Double, String) -> Void)? = nil) -> StorageReport {
        var seen = Set<String>()            // дедуп путей между категориями (защита от двойного счёта)
        var measured: [StorageCategory] = []
        let n = max(1, rules.count)

        for (i, rule) in rules.enumerated() {
            progress?(Double(i) / Double(n), rule.name)
            var bytes: Int64 = 0
            for pattern in rule.paths {
                for path in Scanner.expandGlob(pattern) where seen.insert(path).inserted {
                    bytes += Trasher.directorySize(path)
                }
            }
            if bytes > 0 {
                measured.append(StorageCategory(id: rule.id, name: rule.name,
                                                colorHex: parseHex(rule.color), icon: rule.icon, bytes: bytes))
            }
        }
        progress?(1.0, "")

        // Крупные — отдельными сегментами; мелочь сворачиваем (попадёт в systemOther автоматически).
        let shown = measured.filter { $0.bytes >= minShow }.sorted { $0.bytes > $1.bytes }
        let shownSum = shown.reduce(0) { $0 + $1.bytes }
        let used = max(0, total - free)
        // Остаток: macOS + всё неучтённое + свёрнутая мелочь. Не уходит в минус.
        let systemOther = max(0, used - shownSum)
        return StorageReport(categories: shown, systemOther: systemOther, free: free, total: total)
    }

    private static func parseHex(_ s: String) -> UInt32 {
        UInt32(s.replacingOccurrences(of: "#", with: ""), radix: 16) ?? 0x5b6573
    }
}
