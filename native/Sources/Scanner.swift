import Foundation
import AppKit

// Сканер: раскрывает glob-пути целей из каталога, считает размеры, помечает блок процессами.

struct ScanItem: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let displayName: String
    let size: Int64
}

struct ScanGroup: Identifiable {
    var id: String { targetID }
    let targetID: String
    let name: String
    let safety: SafetyLevel
    let note: String?
    let blockedBy: String?          // имя запущенного процесса, если категория заблокирована
    let items: [ScanItem]
    var totalBytes: Int64 { items.reduce(0) { $0 + $1.size } }
}

enum Scanner {
    /// Сканирует только цели с method == .trash (которые реально можно чистить).
    static func scan(targets: [Target]) -> [ScanGroup] {
        var groups: [ScanGroup] = []
        var seen = Set<String>()            // дедуп путей между целями (защита от двойного счёта)
        let homeDev = homeVolumeDevice()    // H1: гейт по тому home (env-цели на NAS/внешний — отбрасываем)
        for t in targets where t.method == .trash {
            let blocker = runningBlocker(t.blockedByProcesses)
            var items: [ScanItem] = []
            for pattern in t.paths ?? [] {
                for path in expandGlob(pattern) where !seen.contains(path) {
                    seen.insert(path)
                    if let hd = homeDev, !isOnVolume(path, device: hd) { continue }   // H1: чужой том — пропускаем
                    let size = sizeOf(path)
                    if size == 0 { continue }   // пустое — чистить нечего, не показываем
                    items.append(ScanItem(
                        path: path,
                        displayName: (path as NSString).lastPathComponent,
                        size: size))
                }
            }
            if t.keepNewest == true { items = excludingNewestPerParent(items) }
            items.sort { $0.size > $1.size }
            if items.isEmpty { continue }   // пустые категории не показываем
            groups.append(ScanGroup(
                targetID: t.id, name: t.name, safety: t.safety,
                note: t.note, blockedBy: blocker, items: items))
        }
        // крупные категории — выше
        groups.sort { $0.totalBytes > $1.totalBytes }
        return groups
    }

    /// Сканирует report-only цели (method == .report): показываем что нашли, но НИКОГДА не удаляем.
    /// Возвращает только непустые группы (адаптивно). Пустые/беспутёвые цели (заглушки) отсеиваются.
    static func scanReport(targets: [Target]) -> [ScanGroup] {
        var groups: [ScanGroup] = []
        var seen = Set<String>()
        let homeDev = homeVolumeDevice()    // H1: и в report-only гейт по тому home
        for t in targets where t.method == .report {
            var items: [ScanItem] = []
            for pattern in t.paths ?? [] {
                for path in expandGlob(pattern) where !seen.contains(path) {
                    seen.insert(path)
                    if let hd = homeDev, !isOnVolume(path, device: hd) { continue }
                    let size = sizeOf(path)
                    if size == 0 { continue }
                    items.append(ScanItem(path: path,
                                          displayName: (path as NSString).lastPathComponent, size: size))
                }
            }
            items.sort { $0.size > $1.size }
            if items.isEmpty { continue }
            groups.append(ScanGroup(targetID: t.id, name: t.name, safety: t.safety,
                                    note: t.note, blockedBy: nil, items: items))
        }
        groups.sort { $0.totalBytes > $1.totalBytes }
        return groups
    }

    // MARK: H1 — граница тома (env-цели не должны уходить на ДРУГОЙ том: NAS/внешний диск)

    /// Устройство (st_dev) домашнего тома. Резолвим home так же, как SafetyPolicy (getpwuid надёжнее
    /// под sandbox). nil — home недоступен; тогда гейт не применяем (это лишь скан — само удаление всё
    /// равно идёт через Trasher с полной политикой).
    static func homeVolumeDevice() -> dev_t? {
        var home = ""
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir { home = String(cString: dir) }
        if home.isEmpty { home = NSHomeDirectory() }
        var st = stat()
        guard !home.isEmpty, lstat(home, &st) == 0 else { return nil }
        return st.st_dev
    }

    /// Лежит ли путь на томе `device` (его собственный st_dev). H1: env-цель вроде
    /// CARGO_HOME=/Volumes/NAS/cargo раскрывается в путь на ДРУГОМ томе → его не сканируем
    /// (наш принцип: чужие тома — NAS/внешние — автоматически не трогаем). Несуществующий путь → false.
    static func isOnVolume(_ path: String, device: dev_t) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0 else { return false }
        return st.st_dev == device
    }

    /// Раскрытие shell-glob (включая ~ и $VAR) через системный glob(3).
    static func expandGlob(_ pattern: String) -> [String] {
        guard let resolved = resolveEnvVars(pattern) else { return [] }   // $VAR не задана → путь-кандидат пропускаем
        var g = glob_t()
        defer { globfree(&g) }
        guard glob(resolved, GLOB_TILDE | GLOB_NOSORT, nil, &g) == 0 else { return [] }
        var out: [String] = []
        for i in 0..<Int(g.gl_pathc) {
            if let c = g.gl_pathv[i] { out.append(String(cString: c)) }
        }
        return out
    }

    /// Подставляет $VAR и ${VAR} из окружения (для dev-кэшей, перенесённых через CARGO_HOME/GOMODCACHE/HF_HOME и т.п.).
    /// Если переменная не задана/пуста → nil: такой путь-кандидат пропускаем, а не превращаем в литерал "$VAR".
    static func resolveEnvVars(_ pattern: String) -> String? {
        guard pattern.contains("$") else { return pattern }
        let env = ProcessInfo.processInfo.environment
        var out = ""
        var i = pattern.startIndex
        while i < pattern.endIndex {
            guard pattern[i] == "$" else { out.append(pattern[i]); i = pattern.index(after: i); continue }
            var j = pattern.index(after: i)
            let braced = j < pattern.endIndex && pattern[j] == "{"
            if braced { j = pattern.index(after: j) }
            var name = ""
            while j < pattern.endIndex {
                let ch = pattern[j]
                if braced && ch == "}" { j = pattern.index(after: j); break }
                if !braced && !(ch == "_" || ch.isLetter || ch.isNumber) { break }
                name.append(ch); j = pattern.index(after: j)
            }
            guard !name.isEmpty, let val = env[name], !val.isEmpty else { return nil }
            out += val
            i = j
        }
        return out
    }

    /// Честный allocated-размер (st_blocks*512), без разыменования симлинков.
    static func sizeOf(_ path: String) -> Int64 {
        var st = stat()
        guard lstat(path, &st) == 0 else { return 0 }
        if (st.st_mode & S_IFMT) == S_IFDIR { return Trasher.directorySize(path) }
        return Int64(st.st_blocks) * 512
    }

    /// Имя первого запущенного блокера. B6-fix: ТОЧНОЕ совпадение имени (раньше substring ловил лишнее).
    /// Ограничение: видит только GUI-приложения (NSWorkspace), не CLI-демонов.
    static func runningBlocker(_ names: [String]?) -> String? {
        guard let names, !names.isEmpty else { return nil }
        let running = NSWorkspace.shared.runningApplications.compactMap { $0.localizedName }
        for n in names where running.contains(where: { $0.caseInsensitiveCompare(n) == .orderedSame }) {
            return n
        }
        return nil
    }

    // MARK: keep-newest (версионные папки вроде Xcode DeviceSupport «17.5.1 (21F90)»)

    /// Внутри каждой родительской папки оставляет новейшую версию (её НЕ предлагаем чистить),
    /// возвращает только более старые. Если в группе одна версия — её и оставляем (предлагать нечего).
    static func excludingNewestPerParent(_ items: [ScanItem]) -> [ScanItem] {
        var byParent: [String: [ScanItem]] = [:]
        for it in items {
            let parent = (it.path as NSString).deletingLastPathComponent
            byParent[parent, default: []].append(it)
        }
        var keep = Set<String>()
        for (_, group) in byParent {
            if let newest = group.max(by: { versionLess(versionKey($0.displayName), versionKey($1.displayName)) }) {
                keep.insert(newest.path)
            }
        }
        return items.filter { !keep.contains($0.path) }
    }

    /// Ведущая версия из имени: «17.5.1 (21F90)» → [17, 5, 1]. Нет цифр → [] (считается самой старой).
    static func versionKey(_ name: String) -> [Int] {
        let head = name.prefix { $0.isNumber || $0 == "." }
        return head.split(separator: ".").compactMap { Int($0) }
    }

    /// Покомпонентное сравнение версий ([17,5] < [17,5,1] < [18]).
    static func versionLess(_ a: [Int], _ b: [Int]) -> Bool {
        for i in 0..<Swift.max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x < y }
        }
        return false
    }
}

enum ByteFmt {
    static func string(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}
