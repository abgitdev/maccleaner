import Foundation
import AppKit

// «Недоступные симуляторы»: device-папки CoreSimulator, чей рантайм больше не установлен →
// загрузиться они не могут (мёртвый груз, часто десятки ГБ). Безопасный аналог
// `xcrun simctl delete unavailable`, но БЕЗ зависимости от xcrun и БЕЗ permanent delete —
// вся папка устройства уходит в Корзину (восстановимо).
//
// Детект — чисто по файловой системе (verify-first: все plist'ы world-readable на macOS 26):
//   установленные рантаймы ← /Library/Developer/CoreSimulator/Images/images.plist
//   состояние/рантайм устройства ← Devices/<UDID>/device.plist  (state 1 = Shutdown)
//   защищённые (канонические/пары) ← Devices/device_set.plist  (DefaultDevices/DevicePairs)
//
// ЖЁСТКИЕ ГАРАНТИИ (ни одно «живое» устройство не предлагается):
//  • только Shutdown-устройства; • только если рантайм НЕ в установленных;
//  • fail-closed: не знаем установленные рантаймы / нечитаемый device.plist → НЕ трогаем;
//  • защита DefaultDevices/DevicePairs; • гейт по тому Devices/ (симлинк/чужой том — мимо);
//  • блок всей категории при запущенном Simulator/Xcode; • recheck свежим набором перед Корзиной.

enum Simulators {
    static let defaultDevicesDir = NSHomeDirectory() + "/Library/Developer/CoreSimulator/Devices"
    static let defaultImagesPlist = "/Library/Developer/CoreSimulator/Images/images.plist"
    static let defaultXCTestDir = NSHomeDirectory() + "/Library/Developer/XCTestDevices"

    /// Каталоги, где установленные рантаймы лежат как `.simruntime`-бандлы (legacy/встроенные —
    /// их НЕТ в images.plist, который описывает только новые asset-рантаймы). Это ВТОРОЙ источник
    /// «установленных» рантаймов (F-1): чем больше известно установленных — тем меньше шанс
    /// предложить к удалению живое устройство. Источник только ДОБАВЛЯЕТ в набор → внести ложное
    /// удаление он не может, только убрать ложноположительное.
    static var defaultRuntimesDirs: [String] {
        var dirs = ["/Library/Developer/CoreSimulator/Profiles/Runtimes"]
        let volumes = "/Library/Developer/CoreSimulator/Volumes"
        if let mounts = try? FileManager.default.contentsOfDirectory(atPath: volumes) {
            for m in mounts where !m.hasPrefix(".") {
                dirs.append(volumes + "/" + m + "/Library/Developer/CoreSimulator/Profiles/Runtimes")
            }
        }
        return dirs
    }

    /// Имя запущенного GUI-блокера (Simulator/Xcode) или nil. Переиспользует механизм Scanner (B6: точное имя).
    static func runningBlocker() -> String? {
        Scanner.runningBlocker(["Simulator", "Xcode"])
    }

    /// Регенерируемый мусор ВНУТРИ симуляторов (сами устройства остаются): «мёртвые» установки
    /// `Dead/temp.*` (старые копии установленных аппов, которые containermanagerd не подмёл) +
    /// устаревшие клоны XCTestDevices. Только Shutdown-устройства; fail-closed на нечитаемом device.plist.
    static func leftovers(devicesDir: String = defaultDevicesDir,
                          xctestDir: String = defaultXCTestDir,
                          now: TimeInterval = Date().timeIntervalSince1970) -> [ScanItem] {
        var out: [ScanItem] = []
        // Общий seen-set: один и тот же inode (installd хардлинкает неизменные файлы между temp.*)
        // считается ОДИН раз суммарно → честный итог категории (= `du` всех вместе), без N-кратного перебора.
        var seen = Set<String>()

        // 1) Dead/temp.* — staged-копии superseded-установок внутри Shutdown-устройств.
        //    НИКОГДА не трогаем сам Dead/ и его сосед System/ — только дети с префиксом «temp.».
        if let names = try? FileManager.default.contentsOfDirectory(atPath: devicesDir) {
            let dirDev = deviceOf(devicesDir)
            for name in names.sorted() where isUDID(name) {     // sorted: детерминированное marginal-распределение
                let dir = devicesDir + "/" + name
                var st = stat()
                guard lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { continue }
                if let dd = dirDev, st.st_dev != dd { continue }
                guard let info = deviceInfo(dir + "/device.plist"), info.state == 1 else { continue }  // Shutdown, fail-closed
                let deadDir = dir + "/data/Library/Caches/com.apple.containermanagerd/Dead"
                guard let temps = try? FileManager.default.contentsOfDirectory(atPath: deadDir) else { continue }
                for t in temps.sorted() where t.hasPrefix("temp.") {
                    let tp = deadDir + "/" + t
                    var ts = stat()
                    guard lstat(tp, &ts) == 0, (ts.st_mode & S_IFMT) == S_IFDIR else { continue }  // папка, не симлинк
                    let size = Trasher.directorySize(tp, seen: &seen)   // дедуп хардлинков между temp.*
                    if size <= 0 { continue }
                    out.append(ScanItem(path: tp, displayName: "\(info.name) · superseded install", size: size))
                }
            }
        }

        // 2) Клоны XCTestDevices (throwaway-устройства headless `xcodebuild test`).
        //    Только Shutdown + старше 10 мин (анти-гонка: GUI-блокер не ловит headless-тест).
        if let names = try? FileManager.default.contentsOfDirectory(atPath: xctestDir) {
            let dirDev = deviceOf(xctestDir)
            for name in names where isUDID(name) {
                let dir = xctestDir + "/" + name
                var st = stat()
                guard lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { continue }
                if let dd = dirDev, st.st_dev != dd { continue }
                if now - Double(st.st_mtimespec.tv_sec) < 600 { continue }     // <10 мин → возможно пишется тестом
                guard let info = deviceInfo(dir + "/device.plist"), info.state == 1 else { continue }
                let size = Trasher.directorySize(dir, seen: &seen)
                if size <= 0 { continue }
                out.append(ScanItem(path: dir, displayName: "Test clone · \(name.prefix(8))", size: size))
            }
        }

        out.sort { $0.size > $1.size }
        return out
    }

    /// st_dev пути (или nil). Для гейта «дети на том же томе, что и родитель».
    private static func deviceOf(_ path: String) -> dev_t? {
        var st = stat()
        return stat(path, &st) == 0 ? st.st_dev : nil
    }

    /// Device-папки, чей рантайм НЕ установлен и которые выключены → можно целиком в Корзину.
    /// Пусто, если установленные рантаймы определить не удалось (fail-closed — лучше ничего, чем снести живое).
    static func unavailableDevices(devicesDir: String = defaultDevicesDir,
                                   imagesPlist: String = defaultImagesPlist,
                                   runtimesDirs: [String] = defaultRuntimesDirs) -> [ScanItem] {
        let installed = installedRuntimeIDs(imagesPlist: imagesPlist, runtimesDirs: runtimesDirs)
        guard !installed.isEmpty else { return [] }                 // не знаем рантаймы → не рискуем
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: devicesDir) else { return [] }
        let protectedUDIDs = protectedDeviceUDIDs(setPlist: devicesDir + "/device_set.plist")

        // Том самой папки Devices/ — её дети должны быть на нём же (симлинк/маунт наружу — мимо).
        var dst = stat()
        let dirDev: dev_t? = (stat(devicesDir, &dst) == 0) ? dst.st_dev : nil

        var out: [ScanItem] = []
        for name in entries {
            guard isUDID(name) else { continue }                    // только UDID-папки (device_set.plist и пр. — мимо)
            if protectedUDIDs.contains(name.uppercased()) { continue }
            let dir = devicesDir + "/" + name
            var st = stat()
            guard lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { continue }  // папка, не симлинк
            if let dd = dirDev, st.st_dev != dd { continue }        // чужой том/маунт под Devices/ — мимо
            guard let info = deviceInfo(dir + "/device.plist") else { continue }            // fail-closed
            guard info.udid.uppercased() == name.uppercased() else { continue }            // UDID совпал с именем папки
            guard info.state == 1 else { continue }                 // только Shutdown
            guard !installed.contains(info.runtime) else { continue }  // рантайм установлен → ЖИВОЕ, не трогаем
            let size = Trasher.directorySize(dir)
            if size <= 0 { continue }
            out.append(ScanItem(path: dir,
                                displayName: "\(info.name) · \(runtimeLabel(info.runtime)) (runtime removed)",
                                size: size))
        }
        out.sort { $0.size > $1.size }
        return out
    }

    // MARK: внутренности (часть открыта для headless-тестов)

    struct DevInfo { let state: Int; let runtime: String; let udid: String; let name: String }

    static func deviceInfo(_ plist: String) -> DevInfo? {
        guard let data = FileManager.default.contents(atPath: plist),
              let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let d = obj as? [String: Any],
              let state = d["state"] as? Int,
              let runtime = d["runtime"] as? String,
              let udid = d["UDID"] as? String else { return nil }
        let name = (d["name"] as? String) ?? udid
        return DevInfo(state: state, runtime: runtime, udid: udid, name: name)
    }

    /// Установленные рантаймы из ДВУХ источников (объединение → меньше false-positive, F-1):
    ///  (1) images.plist — новые asset/downloadable рантаймы (bundleIdentifier у signatureState.verified);
    ///  (2) `.simruntime`-бандлы на диске — legacy/встроенные, которых в images.plist НЕТ. У бандла
    ///      CFBundleIdentifier совпадает с device.plist `runtime` (com.apple.CoreSimulator.SimRuntime.iOS-*).
    /// Инклюзивно по images[] + standaloneBundles[]. Больше «установленных» → меньше ложных предложений.
    static func installedRuntimeIDs(imagesPlist: String = defaultImagesPlist,
                                    runtimesDirs: [String] = defaultRuntimesDirs) -> Set<String> {
        var ids = Set<String>()
        // (1) images.plist
        if let data = FileManager.default.contents(atPath: imagesPlist),
           let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
           let root = obj as? [String: Any] {
            for key in ["images", "standaloneBundles"] {
                guard let arr = root[key] as? [[String: Any]] else { continue }
                for img in arr {
                    guard let sig = img["signatureState"] as? [String: Any], sig["verified"] != nil,
                          let ri = img["runtimeInfo"] as? [String: Any],
                          let bid = ri["bundleIdentifier"] as? String else { continue }
                    ids.insert(bid)
                }
            }
        }
        // (2) `.simruntime`-бандлы на диске
        for dir in runtimesDirs {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for e in entries where e.hasSuffix(".simruntime") {
                let infoPlist = dir + "/" + e + "/Contents/Info.plist"
                guard let data = FileManager.default.contents(atPath: infoPlist),
                      let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                      let d = obj as? [String: Any],
                      let bid = d["CFBundleIdentifier"] as? String else { continue }
                ids.insert(bid)
            }
        }
        return ids
    }

    /// Защищённые UDID: канонические устройства (DefaultDevices) + члены пар (DevicePairs).
    /// Собираем UDID рекурсивно ТОЛЬКО из этих двух секций (over-protect безопасен: меньше предложим).
    static func protectedDeviceUDIDs(setPlist: String) -> Set<String> {
        guard let data = FileManager.default.contents(atPath: setPlist),
              let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let root = obj as? [String: Any] else { return [] }
        var ids = Set<String>()
        for key in ["DefaultDevices", "DevicePairs"] {
            if let section = root[key] { collectUDIDs(section, into: &ids) }
        }
        return ids
    }

    private static func collectUDIDs(_ any: Any, into ids: inout Set<String>) {
        switch any {
        case let s as String: if isUDID(s) { ids.insert(s.uppercased()) }
        case let arr as [Any]: for v in arr { collectUDIDs(v, into: &ids) }
        case let dict as [String: Any]:
            for (k, v) in dict { if isUDID(k) { ids.insert(k.uppercased()) }; collectUDIDs(v, into: &ids) }
        default: break
        }
    }

    /// 8-4-4-4-12 hex (формат UDID симулятора).
    static func isUDID(_ s: String) -> Bool {
        let parts = s.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 5 else { return false }
        for (p, n) in zip(parts, [8, 4, 4, 4, 12]) {
            guard p.count == n, p.allSatisfy({ $0.isHexDigit }) else { return false }
        }
        return true
    }

    /// «com.apple.CoreSimulator.SimRuntime.iOS-26-5» → «iOS 26.5» (человекочитаемо).
    static func runtimeLabel(_ id: String) -> String {
        guard let tail = id.split(separator: ".").last.map(String.init) else { return id }
        let comps = tail.split(separator: "-").map(String.init)
        guard comps.count >= 2 else { return tail }
        return "\(comps[0]) \(comps.dropFirst().joined(separator: "."))"
    }
}
