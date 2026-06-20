import Foundation
import AppKit

// Аптинсталлер: приложение + его «хвосты» (Caches/Preferences/Containers/… по bundle id и имени),
// и ОТДЕЛЬНО — осиротевшие остатки приложений, которых уже нет на диске («стёр софт, папка висит»).
//
// Принцип: всё только в Корзину (восстановимо), ноль предвыбора в UI, размеры честные (st_blocks).
// Apple-приложения (com.apple.*) к удалению НЕ предлагаем; их остатки осиротевшими НЕ считаем.

struct AppLeftover: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let kind: String      // "Caches" / "Preferences" / "Container" / "Application Support" / ...
    let size: Int64
    let strong: Bool      // true = совпало по bundle id (точно); false = по имени (слабее, может пересечься)
    let trashable: Bool   // проходит SafetyPolicy → можно в Корзину

    /// Содержит реальные данные приложения (документы/профили/базы), а не просто кэш. Такие хвосты
    /// НЕ выбираются автоматически чекбоксом приложения — пользователь решает по каждому сам (Codex-7).
    var dataBearing: Bool {
        switch kind {
        case "Container", "Application Support", "App scripts", "WebKit data", "Cookies", "HTTP storage":
            return true
        default:    // Caches / Preferences / Saved state / Logs — регенерируемое
            return false
        }
    }
}

struct InstalledApp: Identifiable {
    var id: String { path }
    let path: String
    let name: String
    let bundleId: String
    let version: String
    let appSize: Int64
    let leftovers: [AppLeftover]
    let trashableBundle: Bool      // можно ли перенести сам .app (перм/защита)
    var leftoverBytes: Int64 { leftovers.reduce(0) { $0 + $1.size } }
    var totalBytes: Int64 { appSize + leftoverBytes }
}

struct OrphanApp: Identifiable {
    var id: String { bundleId }
    let bundleId: String
    let displayName: String
    let items: [AppLeftover]
    var size: Int64 { items.reduce(0) { $0 + $1.size } }
}

struct AppScanResult {
    let apps: [InstalledApp]
    let orphans: [OrphanApp]
}

enum Apps {
    /// Системные каталоги приложений (для списка к удалению — только пользовательские дополнительно).
    static let sharedAppDirs = ["/Applications", "/Applications/Utilities"]

    static func scan(home: String, policy: SafetyPolicy,
                     progress: ((Double, String) -> Void)? = nil) -> AppScanResult {
        progress?(0.02, "Finding apps")
        let userAppDirs = sharedAppDirs + [home + "/Applications"]

        // 1) Все установленные bundle id (включая Apple и системные) — нужны для детекта осиротевших.
        //    M6: для installed-СЕТА смотрим на один уровень глубже (вендорские подпапки вроде
        //    /Applications/Vendor/Foo.app), иначе bundle id такого приложения не попадёт в сет и его
        //    хвосты ошибочно посчитаются осиротевшими. Внутрь самих .app не заходим.
        var installedIds = Set<String>()
        for dir in userAppDirs + ["/System/Applications"] {
            for app in appBundles(in: dir, depth: 1) {
                if let info = bundleInfo(app) { installedIds.insert(info.id.lowercased()) }
            }
        }
        // Список «к удалению» — только ПРЯМЫЕ дети (поведение без изменений: вложенные helper-апы не
        // предлагаем как отдельную установку; их id уже в installedIds выше).
        var thirdParty: [(path: String, id: String, name: String, version: String)] = []
        for dir in userAppDirs {
            for app in appBundles(in: dir, depth: 0) {
                guard let info = bundleInfo(app) else { continue }
                let lid = info.id.lowercased()
                // Apple-апы не предлагаем; и сам MacCleaner себя не предлагает (его удаляют через вкладку System).
                if !lid.hasPrefix("com.apple.") && lid != "com.maccleaner.app" {
                    thirdParty.append((app, info.id, info.name, info.version))
                }
            }
        }

        // 2) По каждому стороннему приложению — размер бандла + хвосты.
        var apps: [InstalledApp] = []
        let total = Swift.max(1, thirdParty.count)
        for (i, a) in thirdParty.enumerated() {
            progress?(0.05 + 0.6 * Double(i) / Double(total), "Scanning \(a.name)")
            let lefts = leftovers(bundleId: a.id, name: a.name, home: home, policy: policy)
            apps.append(InstalledApp(path: a.path, name: a.name, bundleId: a.id, version: a.version,
                                     appSize: Trasher.directorySize(a.path), leftovers: lefts,
                                     trashableBundle: trashable(a.path, policy: policy)))
        }
        apps.sort { $0.totalBytes > $1.totalBytes }

        // 3) Осиротевшие остатки удалённых приложений.
        progress?(0.72, "Finding leftovers of removed apps")
        let orphans = findOrphans(installedIds: installedIds, home: home, policy: policy)
        progress?(1, "Done")
        return AppScanResult(apps: apps, orphans: orphans)
    }

    // MARK: приложения

    /// Прямые `.app` (`depth: 0`) или ещё и на один уровень глубже в НЕ-.app подпапках (`depth: 1`,
    /// для вендорских каталогов вроде /Applications/Vendor/Foo.app). Внутрь самих `.app`-бандлов НЕ
    /// заходим (там вложенные helper-приложения — это не отдельная установка).
    static func appBundles(in dir: String, depth: Int = 0) -> [String] {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return [] }
        var out: [String] = []
        for e in entries.sorted() {
            let full = dir + "/" + e
            if e.hasSuffix(".app") { out.append(full); continue }   // сам .app — добавляем, внутрь не идём
            if depth > 0 {
                var st = stat()
                if lstat(full, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR {
                    out += appBundles(in: full, depth: depth - 1)
                }
            }
        }
        return out
    }

    static func bundleInfo(_ appPath: String) -> (id: String, name: String, version: String)? {
        guard let d = NSDictionary(contentsOfFile: appPath + "/Contents/Info.plist"),
              let id = d["CFBundleIdentifier"] as? String, !id.isEmpty else { return nil }
        let fallback = ((appPath as NSString).lastPathComponent as NSString).deletingPathExtension
        let name = (d["CFBundleDisplayName"] as? String) ?? (d["CFBundleName"] as? String) ?? fallback
        let ver = (d["CFBundleShortVersionString"] as? String) ?? (d["CFBundleVersion"] as? String) ?? "—"
        return (id, name, ver)
    }

    // MARK: хвосты по bundle id (+ имени)

    static func leftovers(bundleId: String, name: String, home: String, policy: SafetyPolicy) -> [AppLeftover] {
        let lib = home + "/Library"
        // (путь, вид, strong=совпало по bundle id)
        let candidates: [(String, String, Bool)] = [
            ("\(lib)/Caches/\(bundleId)", "Caches", true),
            ("\(lib)/Preferences/\(bundleId).plist", "Preferences", true),
            ("\(lib)/Containers/\(bundleId)", "Container", true),
            ("\(lib)/HTTPStorages/\(bundleId)", "HTTP storage", true),
            ("\(lib)/WebKit/\(bundleId)", "WebKit data", true),
            ("\(lib)/Saved Application State/\(bundleId).savedState", "Saved state", true),
            ("\(lib)/Application Scripts/\(bundleId)", "App scripts", true),
            ("\(lib)/Cookies/\(bundleId).binarycookies", "Cookies", true),
            ("\(lib)/Application Support/\(bundleId)", "Application Support", true),
            ("\(lib)/Logs/\(bundleId)", "Logs", true),
            // по имени — слабее (может пересечься с другим ПО), помечаем strong=false
            ("\(lib)/Application Support/\(name)", "Application Support", false),
            ("\(lib)/Caches/\(name)", "Caches", false),
            ("\(lib)/Logs/\(name)", "Logs", false),
        ]
        var out: [AppLeftover] = []
        var seen = Set<String>()
        for (path, kind, strong) in candidates where seen.insert(path).inserted {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            let size = sizeOf(path)
            if size == 0 { continue }
            out.append(AppLeftover(path: path, kind: kind, size: size, strong: strong,
                                   trashable: trashable(path, policy: policy)))
        }
        return out
    }

    // MARK: осиротевшие остатки

    /// `lsKnows` — знает ли LaunchServices приложение с этим bundle id (установлено ГДЕ-УГОДНО, в т.ч.
    /// вне 4 сканируемых папок: ~/Developer, /opt, внешний том). Инъекция для детерминизма тестов;
    /// в проде спрашивает реальную базу LaunchServices. Знает → приложение живо → НЕ сирота (F-2).
    static func findOrphans(installedIds: Set<String>, home: String, policy: SafetyPolicy,
                            lsKnows: (String) -> Bool = { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }) -> [OrphanApp] {
        let lib = home + "/Library"
        // Эти каталоги создают именно ПРИЛОЖЕНИЯ (не CLI-тулзы/фреймворки) → надёжный признак «был апп».
        let appSpecific = ["Containers", "Saved Application State", "Application Scripts"]
        var ids = Set<String>()
        for sub in appSpecific {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: lib + "/" + sub) else { continue }
            for e in entries where !e.hasPrefix(".") {
                var id = e
                if id.hasSuffix(".savedState") { id = String(id.dropLast(".savedState".count)) }
                ids.insert(id)
            }
        }
        // Вендоры установленных приложений (com.vendor) — чтобы не принять XPC-компонент
        // установленного приложения (другой bundle id, но тот же вендор) за осиротевший.
        let installedVendors = Set(installedIds.map { vendor($0) })

        var orphans: [OrphanApp] = []
        for id in ids.sorted() {
            let low = id.lowercased()
            if low.hasPrefix("com.apple.") || low.contains(".apple.") { continue }   // Apple (вкл. group.com.apple.*)
            if low.hasPrefix("group.") { continue }                     // групповой контейнер, не одиночное приложение
            if isInstalledOrChild(low, installedIds) { continue }       // приложение (или его расширение) на месте
            if installedVendors.contains(vendor(low)) { continue }      // компонент установленного вендора (напр. DaVinci IOXPC)
            if lsKnows(id) { continue }                                 // F-2: LaunchServices знает приложение → установлено вне 4 папок → не сирота
            let items = leftovers(bundleId: id, name: id, home: home, policy: policy).filter { $0.strong }
            if items.isEmpty { continue }
            orphans.append(OrphanApp(bundleId: id, displayName: orphanName(id), items: items))
        }
        orphans.sort { $0.size > $1.size }
        return orphans
    }

    /// Установлено ли само приложение или его родитель (расширение com.foo.App.Ext ← com.foo.App).
    static func isInstalledOrChild(_ id: String, _ installed: Set<String>) -> Bool {
        if installed.contains(id) { return true }
        for inst in installed where !inst.isEmpty && id.hasPrefix(inst + ".") { return true }
        return false
    }

    /// Вендор bundle id = первые два компонента (com.vendor). Для group.* / коротких id — сам id.
    static func vendor(_ id: String) -> String {
        let parts = id.split(separator: ".")
        guard parts.count >= 2, parts[0] != "group" else { return id }
        return parts.prefix(2).joined(separator: ".")
    }

    static func orphanName(_ bundleId: String) -> String {
        bundleId.split(separator: ".").last.map(String.init) ?? bundleId
    }

    // MARK: обновление списков после переноса в Корзину (мгновенно, без рескана)

    /// Бандл удалён → приложение уходит из списка; иначе убираем удалённые хвосты.
    static func pruneApps(_ apps: [InstalledApp], removing gone: Set<String>) -> [InstalledApp] {
        var out: [InstalledApp] = []
        for a in apps {
            if gone.contains(a.path) { continue }
            let kept = a.leftovers.filter { !gone.contains($0.path) }
            out.append(InstalledApp(path: a.path, name: a.name, bundleId: a.bundleId, version: a.version,
                                    appSize: a.appSize, leftovers: kept, trashableBundle: a.trashableBundle))
        }
        return out
    }

    /// У осиротевшего убираем удалённые элементы; пустой — исчезает.
    static func pruneOrphans(_ orphans: [OrphanApp], removing gone: Set<String>) -> [OrphanApp] {
        var out: [OrphanApp] = []
        for o in orphans {
            let kept = o.items.filter { !gone.contains($0.path) }
            if kept.isEmpty { continue }
            out.append(OrphanApp(bundleId: o.bundleId, displayName: o.displayName, items: kept))
        }
        return out
    }

    // MARK: мелочи

    static func sizeOf(_ path: String) -> Int64 {
        var st = stat(); guard lstat(path, &st) == 0 else { return 0 }
        if (st.st_mode & S_IFMT) == S_IFDIR { return Trasher.directorySize(path) }
        return Int64(st.st_blocks) * 512
    }
    static func trashable(_ path: String, policy: SafetyPolicy) -> Bool {
        do { try policy.validatePath(path); return true } catch { return false }
    }
}
