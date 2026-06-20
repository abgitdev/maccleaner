import Foundation
import AppKit

// Поиск крупных файлов — «куда ушло место». Только показ + «Показать в Finder», без удаления.
// «Large & Old»: к размеру добавлена дата изменения (st_mtime) → сортировка по возрасту и бейдж «old».

struct LargeFile: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let displayName: String
    let size: Int64
    let modified: Date        // время последнего изменения (st_mtime)
}

enum LargeFiles {
    /// Обходит домашнюю папку и возвращает файлы >= minBytes, отсортированные по размеру.
    static func scan(root: String,
                     minBytes: Int64 = 100 * 1024 * 1024,
                     limit: Int = 200) -> [LargeFile] {
        let url = URL(fileURLWithPath: root)
        guard let en = FileManager.default.enumerator(
            at: url,
            includingPropertiesForKeys: nil,
            options: [],                       // включая скрытые (~/Library тоже скрыт)
            errorHandler: { _, _ in true }
        ) else { return [] }

        var found: [LargeFile] = []
        var seenHardlinks = Set<String>()   // B5-fix: хардлинк-копии не дублируем
        let homeDev = Scanner.homeVolumeDevice()   // L4: чужой том (NAS/внешний) под ~ — не показываем
        for case let f as URL in en {
            if f.path.contains("/.Trash/") { continue }   // уже удалённое не показываем
            var st = stat()
            if lstat(f.path, &st) != 0 { continue }
            if let hd = homeDev, st.st_dev != hd {            // L4: чужой том под ~ — пропускаем (и поддерево)
                if (st.st_mode & S_IFMT) == S_IFDIR { en.skipDescendants() }
                continue
            }
            guard (st.st_mode & S_IFMT) == S_IFREG else { continue }   // только обычные файлы
            let size = Int64(st.st_blocks) * 512                       // честный allocated-размер
            if size >= minBytes {
                if st.st_nlink > 1 {
                    let key = "\(st.st_dev):\(st.st_ino)"
                    if !seenHardlinks.insert(key).inserted { continue }
                }
                found.append(LargeFile(
                    path: f.path,
                    displayName: (f.path as NSString).lastPathComponent,
                    size: size,
                    modified: Date(timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec))))
            }
        }
        found.sort { $0.size > $1.size }
        return Array(found.prefix(limit))
    }

    static func revealInFinder(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    /// «N дней/месяцев/лет назад» — по-английски (UI только English, без локали системы).
    static func ago(_ date: Date, now: Date = Date()) -> String {
        let s = now.timeIntervalSince(date)
        if s < 0 { return "just now" }
        let day = 86_400.0
        if s < day { return "today" }
        let days = Int(s / day)
        if days == 1 { return "yesterday" }
        if days < 30 { return "\(days) days ago" }
        let months = days / 30
        if months < 12 { return months == 1 ? "1 month ago" : "\(months) months ago" }
        let years = days / 365
        return years <= 1 ? "1 year ago" : "\(years) years ago"
    }

    /// Давно не трогали (по умолчанию > 1 года) → кандидат на «old».
    static func isOld(_ date: Date, now: Date = Date(), days: Int = 365) -> Bool {
        now.timeIntervalSince(date) > Double(days) * 86_400
    }
}
