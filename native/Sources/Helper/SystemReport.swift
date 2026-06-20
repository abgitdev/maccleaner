import Foundation

// Сканер системного мусора (хелпер — root, читает всё). НИКАКИХ мутаций — только размеры/перечисление.
// ⭐ После рой-вердикта 2026-06-19 (43 агента, веб-проверка) скан СУЖЕН и сделан умнее: на запечатанном Mac (SSV)
// безопасных НОВЫХ корней почти нет, а «целые» подпапки часто опасны. Поэтому:
//  • /Library/Caches — top-level записи, но ПРОПУСК SIP-data-vault'ов (com.apple.aned/aneuserd/amsengagementd…,
//    EPERM даже на stat) и человеко-владельческих папок (uid≥501 — Desktop Pictures/<UUID> и т.п.);
//  • /Library/Logs — как раньше, но DiagnosticReports → itemize СТАРЫХ не-panic репортов (keep-newest);
//  • /private/var/log — ТОЛЬКО ротированные архивы (живые system.log/install.log и демон-подкаталоги НЕ пересоздаются).

enum SystemReport {
    static let firstHumanUID: uid_t = 501   // macOS: люди с 501; системные демоны (_xxx) ниже → их кэши трогать можно
    static let reportKeepDays = 30          // crash-репорты свежее N дней не предлагаем (консервативно)

    // SIP data-vaults и прочее непереносимое под /Library/Caches (явный denylist + динамический EPERM-skip ниже).
    static let vaultDenylist: Set<String> = [
        "com.apple.aned", "com.apple.aneuserd", "com.apple.amsengagementd.classicdatavault",
    ]
    static func isDataVault(_ name: String) -> Bool {
        if vaultDenylist.contains(name) { return true }
        return name.hasPrefix("com.apple.") && name.lowercased().hasSuffix("datavault")
    }
    /// Ротированный архив лога (безопасно удаляемо): *.gz / *.bz2 / хвост «.<цифры>» (system.log.0, wifi.log.3).
    static func isRotatedArchive(_ name: String) -> Bool {
        if name.hasSuffix(".gz") || name.hasSuffix(".bz2") { return true }
        let comps = name.split(separator: ".")
        if comps.count >= 2, let last = comps.last, !last.isEmpty, last.allSatisfy({ $0.isNumber }) { return true }
        return false
    }
    /// Защищённый crash-репорт (НИКОГДА не предлагаем): kernel panic в любой форме.
    static func isProtectedReport(_ name: String) -> Bool {
        name.lowercased().contains("panic")
    }
    static func isOldReport(mtime: time_t, now: time_t, keepDays: Int = reportKeepDays) -> Bool {
        now - mtime > time_t(keepDays) * 86_400
    }
    /// I8 (аудит 2): можно ли предлагать файл из /private/var/log.
    /// Сжатые архивы (.gz/.bz2) закрыты при ротации → безопасны в любом возрасте. Голый «.<digits>»
    /// (напр. keybagd.log.0 — keybagd пишет ПРЯМО в .0, отдельного live-лога нет) может писаться живьём →
    /// предлагаем только если он действительно старый (вне keep-окна), чтобы не трогать активный лог.
    static func isOfferableRotatedLog(_ name: String, mtime: time_t, now: time_t) -> Bool {
        guard isRotatedArchive(name) else { return false }
        if name.hasSuffix(".gz") || name.hasSuffix(".bz2") { return true }
        return isOldReport(mtime: mtime, now: now)
    }

    static func scan() -> [SystemCleanupItem] {
        var out: [SystemCleanupItem] = []
        scanCaches("/Library/Caches", category: "System Caches", into: &out)
        scanLibraryLogs("/Library/Logs", category: "System Logs", into: &out)
        scanVarLog("/private/var/log", into: &out)
        out.sort { $0.bytes > $1.bytes }
        return out
    }

    // /Library/Caches: top-level записи (dir/файл), пропуск vault'ов/симлинков/EPERM/чужих/пустых.
    private static func scanCaches(_ root: String, category: String, into out: inout [SystemCleanupItem]) {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: root) else { return }
        for e in entries {
            if e == SystemCleanGate.quarantineDirName || isDataVault(e) { continue }
            let p = root + "/" + e
            var st = stat()
            guard lstat(p, &st) == 0 else { continue }              // EPERM (data-vault) → молча пропускаем
            if (st.st_mode & S_IFMT) == S_IFLNK { continue }
            if st.st_uid >= firstHumanUID { continue }              // человеко-владельческое — не системный мусор
            let bytes = (st.st_mode & S_IFMT) == S_IFDIR ? dirSize(p) : Int64(st.st_blocks) * 512
            if bytes <= 0 { continue }
            out.append(SystemCleanupItem(path: p, bytes: bytes, category: category))
        }
    }

    // /Library/Logs: top-level как раньше, но DiagnosticReports — keep-newest по файлам (саму папку/Retired/DiagnosticLogs не трогаем).
    private static func scanLibraryLogs(_ root: String, category: String, into out: inout [SystemCleanupItem]) {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: root) else { return }
        let now = time_t(Date().timeIntervalSince1970)
        for e in entries {
            if e == SystemCleanGate.quarantineDirName { continue }
            let p = root + "/" + e
            var st = stat()
            guard lstat(p, &st) == 0 else { continue }
            if (st.st_mode & S_IFMT) == S_IFLNK { continue }
            if st.st_uid >= firstHumanUID { continue }
            if e == "DiagnosticReports" && (st.st_mode & S_IFMT) == S_IFDIR {
                itemizeDiagnosticReports(p, now: now, into: &out)   // вместо папки целиком — старые файлы
                continue
            }
            let bytes = (st.st_mode & S_IFMT) == S_IFDIR ? dirSize(p) : Int64(st.st_blocks) * 512
            if bytes <= 0 { continue }
            out.append(SystemCleanupItem(path: p, bytes: bytes, category: category))
        }
    }

    // Только СТАРЫЕ (>keep-окна) НЕ-panic репорты, каждый отдельным файлом (depth 4). Свежие/panic и подпапки — мимо.
    private static func itemizeDiagnosticReports(_ dir: String, now: time_t, into out: inout [SystemCleanupItem]) {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
        for f in files {
            let p = dir + "/" + f
            var st = stat()
            guard lstat(p, &st) == 0 else { continue }
            if (st.st_mode & S_IFMT) != S_IFREG { continue }        // только файлы (не Retired/, DiagnosticLogs/)
            if isProtectedReport(f) { continue }                    // kernel panic — никогда
            if !isOldReport(mtime: st.st_mtimespec.tv_sec, now: now) { continue }   // свежие — keep
            let bytes = Int64(st.st_blocks) * 512
            if bytes <= 0 { continue }
            out.append(SystemCleanupItem(path: p, bytes: bytes, category: "Old Crash Reports"))
        }
    }

    // /private/var/log: ТОЛЬКО ротированные архивы-файлы (живые логи + демон-подкаталоги не пересоздаются → не предлагаем).
    private static func scanVarLog(_ root: String, into out: inout [SystemCleanupItem]) {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: root) else { return }
        let now = time_t(Date().timeIntervalSince1970)
        for e in entries {
            let p = root + "/" + e
            var st = stat()
            guard lstat(p, &st) == 0 else { continue }
            if (st.st_mode & S_IFMT) != S_IFREG { continue }
            if st.st_uid >= firstHumanUID { continue }
            // I8: голый «.<digits>» (keybagd.log.0) может писаться живьём → только если реально старый.
            if !isOfferableRotatedLog(e, mtime: st.st_mtimespec.tv_sec, now: now) { continue }
            let bytes = Int64(st.st_blocks) * 512
            if bytes <= 0 { continue }
            out.append(SystemCleanupItem(path: p, bytes: bytes, category: "Rotated Logs"))
        }
    }

    /// Честный allocated-размер дерева (st_blocks*512), хардлинки считаем один раз.
    static func dirSize(_ root: String) -> Int64 {
        var total: Int64 = 0
        var seen = Set<String>()
        var rootSt = stat()
        guard lstat(root, &rootSt) == 0 else { return 0 }   // M7: нужно устройство корня для границы тома
        guard let en = FileManager.default.enumerator(atPath: root) else { return 0 }
        for case let sub as String in en {
            let p = root + "/" + sub
            var st = stat()
            guard lstat(p, &st) == 0 else { continue }
            if st.st_dev != rootSt.st_dev {                 // M7: submount/NAS под системным корнем — не считаем
                if (st.st_mode & S_IFMT) == S_IFDIR { en.skipDescendants() }
                continue
            }
            if st.st_nlink > 1 {
                if !seen.insert("\(st.st_dev):\(st.st_ino)").inserted { continue }
            }
            total += Int64(st.st_blocks) * 512
        }
        return total
    }
}
