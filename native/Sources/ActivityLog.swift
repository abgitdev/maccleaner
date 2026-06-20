import Foundation

// Журнал активности: что приложение РЕАЛЬНО делало (scan/trash/quarantine/restore/empty/kill/uninstall).
// Назначение — прозрачность и экспорт «что софт трогает» (для теста на другой машине). Пишется в наш
// стандартный каталог ~/Library/Application Support/MacCleaner/activity.log — его же убирает аптинсталл.
// Потокобезопасен (серийная очередь). Никуда наружу не уходит — только локальный файл + ручной экспорт.

final class ActivityLog {
    static let shared = ActivityLog()

    private let queue = DispatchQueue(label: "maccleaner.activitylog")
    let dirURL: URL
    let fileURL: URL

    private init() {
        let base = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/MacCleaner", isDirectory: true)
        dirURL = base
        fileURL = base.appendingPathComponent("activity.log")
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
    }

    /// Записать одну строку (категория + сообщение). Best-effort, не бросает.
    func log(_ category: String, _ message: String) {
        let line = Self.stamp() + " [\(category)] " + message + "\n"
        queue.async {
            guard let data = line.data(using: .utf8) else { return }
            if let fh = try? FileHandle(forWritingTo: self.fileURL) {
                defer { try? fh.close() }
                _ = try? fh.seekToEnd()
                try? fh.write(contentsOf: data)
            } else {
                try? data.write(to: self.fileURL)   // первая запись — создаём файл
            }
        }
    }

    /// Удобный батч для переносов в Корзину: сводка + КАЖДЫЙ путь (что именно тронули — это и есть форензика).
    func trashed(_ category: String, _ summary: String, _ outcomes: [TrashOutcome]) {
        log(category, summary)
        for o in outcomes where o.moved  { log(category, "  moved \(o.path) (\(ByteFmt.string(o.movedBytes)))") }
        for o in outcomes where !o.moved { log(category, "  FAILED \(o.path): \(o.error ?? "")") }
    }

    /// Батч для операций карантина/восстановления/очистки (root) — по каждому результату.
    func quarantineResults(_ category: String, _ summary: String, _ results: [QResult]) {
        log(category, summary)
        for r in results { log(category, "  \(r.ok ? "ok" : "FAILED") \(r.path) (\(ByteFmt.string(r.bytes)))\(r.error.map { " — \($0)" } ?? "")") }
    }

    /// Снимок всего журнала (для экспорта).
    func snapshot() -> String {
        queue.sync { (try? String(contentsOf: fileURL, encoding: .utf8)) ?? "" }
    }

    /// Экспорт на Рабочий стол: MacCleaner-activity-<ts>.txt (+ опц. root audit-log хелпера). Возвращает URL.
    func exportToDesktop(helperAudit: String? = nil) -> URL? {
        let out = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Desktop/MacCleaner-activity-\(Self.fileStamp()).txt")
        var text = "MacCleaner — activity log\nexported \(Self.stamp())\n"
        text += String(repeating: "=", count: 64) + "\n\n"
        text += snapshot()
        if let helperAudit, !helperAudit.isEmpty {
            text += "\n" + String(repeating: "=", count: 64) + "\n"
            text += "Privileged helper audit log (root system cleaning):\n\n" + helperAudit
        }
        do { try text.write(to: out, atomically: true, encoding: .utf8); return out }
        catch { return nil }
    }

    private static func stamp() -> String {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.string(from: Date())
    }
    private static func fileStamp() -> String {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd-HHmmss"
        return f.string(from: Date())
    }
}
