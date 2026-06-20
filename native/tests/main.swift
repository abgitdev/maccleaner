import Foundation
import ImageIO
import CoreGraphics
import Security

// Тесты ядра безопасности (порт internal/safety/policy_test.go) + реальная проверка Trasher.
// Запуск: ./native/test.sh  (компилирует логику без UI и прогоняет ассерты).

setvbuf(stdout, nil, _IONBF, 0)   // небуферизованный вывод: последняя строка лога = ровно падающий тест (важно для CI-диагностики)

var passed = 0
var failures = 0

func check(_ cond: Bool, _ name: String) {
    if cond { passed += 1; print("  ok   \(name)") }
    else { failures += 1; print("FAIL   \(name)") }
}
func checkThrows(_ name: String, _ body: () throws -> Void) {
    do { try body(); failures += 1; print("FAIL   \(name) (ожидался отказ)") }
    catch { passed += 1; print("  ok   \(name)") }
}
func checkNoThrow(_ name: String, _ body: () throws -> Void) {
    do { try body(); passed += 1; print("  ok   \(name)") }
    catch { failures += 1; print("FAIL   \(name): \(error)") }
}
func realResolved(_ p: String) -> String {
    var buf = [Int8](repeating: 0, count: Int(PATH_MAX))
    return realpath(p, &buf) != nil ? String(cString: buf) : p
}

let fixture = "PRIVATE-DENYLIST-FIXTURE"

// 1. Denylist блокирует защищённую подстроку
do {
    let p = SafetyPolicy(home: "/Users/me", denylist: Denylist(pathContains: [fixture]))
    check(p.isDenied("/Users/me/Desktop/\(fixture)/file.bin"), "denylist blocks protected fixture")
}

// 2. Защищённые системные пути
do {
    let blocked = ["/System", "/System/Library", "/bin/sh", "/usr/bin/env",
                   "/private/var/db/foo", "/Applications", "/Library", "/Users"]
    for path in blocked { check(SafetyPolicy.isProtected(path), "protected: \(path)") }
    let allowed = ["/usr/local/bin/tool", "/Users/me/Library/Caches/App"]
    for path in allowed { check(!SafetyPolicy.isProtected(path), "allowed: \(path)") }
}

// 3. ValidatePath блокирует корень дома, но пропускает узкого ребёнка в кэше
do {
    let base = realResolved(NSTemporaryDirectory()) + "/mctest-" + UUID().uuidString
    try? FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
    let p = SafetyPolicy(home: base, denylist: Denylist())
    checkThrows("validatePath blocks home root") { try p.validatePath(base) }
    let sub = base + "/Library/Caches/App"
    try? FileManager.default.createDirectory(atPath: sub, withIntermediateDirectories: true)
    checkNoThrow("validatePath allows narrow cache child") { try p.validatePath(sub) }

    // Личные папки заблокированы НАМЕРТВО — «секретные документы» не сотрутся
    let docs = base + "/Documents"
    try? FileManager.default.createDirectory(atPath: docs, withIntermediateDirectories: true)
    let secret = docs + "/secret.txt"
    FileManager.default.createFile(atPath: secret, contents: Data("top secret".utf8))
    checkThrows("validatePath blocks ~/Documents") { try p.validatePath(docs) }
    checkThrows("validatePath blocks file inside ~/Documents") { try p.validatePath(secret) }
    let desktop = base + "/Desktop"
    try? FileManager.default.createDirectory(atPath: desktop, withIntermediateDirectories: true)
    checkThrows("validatePath blocks ~/Desktop") { try p.validatePath(desktop) }
    // даже если перенос вызвать напрямую — Trasher откажет
    let trashAttempt = Trasher.trashCheckedBatch([secret], policy: p)
    check(trashAttempt.first?.moved == false, "Trasher refuses to trash personal Documents")
    check(FileManager.default.fileExists(atPath: secret), "secret document untouched")

    // C1: обход симлинк-гарда через '..' закрыт — любой '..'-компонент отвергается
    checkThrows("C1: '..' component rejected") {
        try p.validateNoSymlinkComponents(base + "/Library/../Documents/x")
    }
    try? FileManager.default.createDirectory(atPath: base + "/realdir", withIntermediateDirectories: true)
    try? FileManager.default.createSymbolicLink(atPath: base + "/lnk", withDestinationPath: base + "/realdir")
    checkThrows("C1: symlink+'..' bypass blocked") {
        try p.validatePath(base + "/lnk/../realdir/x")
    }

    // C2: сравнения регистронезависимы (APFS case-insensitive)
    check(p.isPersonalData(base + "/DOCUMENTS"), "C2: DOCUMENTS matches personal (case-insensitive)")
    check(p.isPersonalData(base + "/DeSkToP/x"), "C2: DeSkToP matches personal")
    check(p.isHomeRoot(base.uppercased()), "C2: home root case-insensitive")
    check(SafetyPolicy.isProtected("/SYSTEM/Library"), "C2: /SYSTEM protected (case-insensitive)")

    // 6. Реальный перенос в Корзину через Trasher (FileManager.trashItem)
    let file = base + "/trashme-\(UUID().uuidString).txt"
    FileManager.default.createFile(atPath: file, contents: Data("bye".utf8))
    let outcomes = Trasher.trashCheckedBatch([file], policy: p)
    check(outcomes.first?.moved == true, "Trasher moved file to Trash (\(outcomes.first?.error ?? "ok"))")
    check(!FileManager.default.fileExists(atPath: file), "file removed from original location")

    try? FileManager.default.removeItem(atPath: base)
}

// 4. Ручные области (manual) определяются точно
do {
    let manual = [
        "/Users/me/Library/Application Support",
        "/Users/me/Library/Containers",
        "/Users/me/Library/Group Containers",
        "/Users/me/Library/LaunchAgents",
    ]
    for path in manual { check(SafetyPolicy.isManualArea(path), "manual area: \(path)") }
}

// 4b. P0: whole-home сканеры (Dups/Similar) держат данные приложений reveal-only — НЕ ломая аптинсталлер.
do {
    let base = realResolved(NSTemporaryDirectory()) + "/mctest-" + UUID().uuidString
    let p = SafetyPolicy(home: base, denylist: Denylist())
    func mkfile(_ rel: String) -> String {
        let f = base + "/" + rel
        try? FileManager.default.createDirectory(atPath: (f as NSString).deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: f, contents: Data("x".utf8))
        return f
    }
    let cache = mkfile("Library/Caches/App/dup.bin")
    let container = mkfile("Library/Containers/com.foo/Data/dup.bin")
    let appSupport = mkfile("Library/Application Support/com.foo/dup.bin")
    let groupC = mkfile("Library/Group Containers/group.foo/dup.bin")

    // Кэш — нормальный дедуп-кандидат.
    check(p.isScannerTrashable(cache), "scanner trashable: Caches child")
    // Данные приложений — reveal-only для сканеров.
    check(!p.isScannerTrashable(container), "scanner reveal-only: Containers child")
    check(!p.isScannerTrashable(appSupport), "scanner reveal-only: Application Support child")
    check(!p.isScannerTrashable(groupC), "scanner reveal-only: Group Containers child")
    // Dups использует тот же предикат.
    check(!Dups.isTrashable(container, policy: p), "Dups reveal-only: Containers child")
    check(Dups.isTrashable(cache, policy: p), "Dups trashable: Caches child")
    // ВАЖНО: аптинсталлер НЕ сломан — validatePath по-прежнему пропускает Containers/App Support
    // (reveal-only действует ТОЛЬКО на уровне сканеров, это не жёсткий блок Trasher).
    checkNoThrow("uninstaller intact: validatePath passes Containers") { try p.validatePath(container) }
    checkNoThrow("uninstaller intact: validatePath passes Application Support") { try p.validatePath(appSupport) }

    // 4b-2: OS-managed индекс/стейт-области → reveal-only в whole-home сканерах. Баг 3-го живого теста:
    // Dups предлагал два компонента индекса Spotlight (live.4.indexArrays / live.4.shadowIndexArrays)
    // как удаляемый «дубль» (APFS-клоны, 0 freed). Набор выверен состязательным роем (42 агента).
    let spotlightIdx = mkfile("Library/Metadata/CoreSpotlight/NSFileProtectionComplete/index.spotlightV3/live.4.indexArrays")
    let spotlightShadow = mkfile("Library/Metadata/CoreSpotlight/NSFileProtectionComplete/index.spotlightV3/live.4.shadowIndexArrays")
    let biome = mkfile("Library/Biome/streams/public/_DKEvent/local/2.sql")
    let savedState = mkfile("Library/Saved Application State/com.foo.savedState/window.data")
    let webkit = mkfile("Library/WebKit/com.foo/dup.bin")
    let suggestions = mkfile("Library/Suggestions/snippets.db")
    let autosave = mkfile("Library/Autosave Information/doc.scratch")
    for f in [spotlightIdx, spotlightShadow, biome, savedState, webkit, suggestions, autosave] {
        let name = (f as NSString).lastPathComponent
        check(!p.isScannerTrashable(f), "scanner reveal-only (OS index/state): \(name)")
        check(!Dups.isTrashable(f, policy: p), "Dups reveal-only (OS index/state): \(name)")
    }
    // АНТИ-ПЕРЕГИБ: реальные места дублей ОСТАЮТСЯ удаляемыми (иначе фикс убьёт главный сценарий Dups —
    // SwiftPM .build-чекауты, AI-модели в Caches, дубли шрифтов/звуков). Рой явно их сохранил.
    let sound = mkfile("Library/Sounds/custom.aiff")
    let font = mkfile("Library/Fonts/MyFont.ttf")
    let buildCheckout = mkfile("Projects/App/.build/checkouts/Pkg/Sources/file.swift")
    let hfCache = mkfile("Library/Caches/huggingface/models/model.bin")
    for f in [sound, font, buildCheckout, hfCache] {
        let name = (f as NSString).lastPathComponent
        check(p.isScannerTrashable(f), "scanner STILL trashable (real-dup area): \(name)")
        check(Dups.isTrashable(f, policy: p), "Dups STILL trashable (real-dup area): \(name)")
    }

    try? FileManager.default.removeItem(atPath: base)
}

// 4c. P1 (Codex-6): Similar Photos keepPath — всегда сохраняем ЛУЧШУЮ копию (keeper photos[0]).
do {
    func ph(_ p: String, _ trashable: Bool) -> SimilarPhoto {
        SimilarPhoto(path: p, displayName: p, size: 1000, width: 100, height: 100,
                     pHash: 1, dHash: 1, trashable: trashable, isKeeper: false)
    }
    let g1 = SimilarGroup(key: "g1", kind: .nearDuplicate,
                          photos: [ph("/best", true), ph("/worse", true)])
    check(SimilarPhotos.keepPath(g1) == "/best", "keepPath keeps best when best is trashable")
    let g2 = SimilarGroup(key: "g2", kind: .nearDuplicate,
                          photos: [ph("/best-protected", false), ph("/worse", true)])
    check(SimilarPhotos.keepPath(g2) == nil, "keepPath nil when best is protected (it survives anyway)")
}

// 4d. P1 (Codex-7): AppLeftover.dataBearing — данные приложения НЕ авто-выбираются чекбоксом аппа.
do {
    func lo(_ kind: String) -> AppLeftover {
        AppLeftover(path: "/x/" + kind, kind: kind, size: 1, strong: true, trashable: true)
    }
    for k in ["Container", "Application Support", "App scripts", "WebKit data", "Cookies", "HTTP storage"] {
        check(lo(k).dataBearing, "dataBearing: \(k)")
    }
    for k in ["Caches", "Preferences", "Saved state", "Logs"] {
        check(!lo(k).dataBearing, "not dataBearing (regenerable): \(k)")
    }
}

// 4e. P2 (SP-2): секретные корни (.ssh/.gnupg/.aws/Safari/Cookies) защищены намертво.
do {
    let base = realResolved(NSTemporaryDirectory()) + "/mctest-" + UUID().uuidString
    let p = SafetyPolicy(home: base, denylist: Denylist())
    func mkf(_ rel: String) -> String {
        let f = base + "/" + rel
        try? FileManager.default.createDirectory(atPath: (f as NSString).deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: f, contents: Data("secret".utf8))
        return f
    }
    for rel in [".ssh/id_rsa", ".gnupg/secring.gpg", ".aws/credentials",
                "Library/Safari/History.db", "Library/Cookies/Cookies.binarycookies"] {
        let f = mkf(rel)
        checkThrows("secret root protected: \(rel)") { try p.validatePath(f) }
    }
    try? FileManager.default.removeItem(atPath: base)
}

// 4f. PROC-3 + M8 (Codex-3rd): terminate с неверным start-time/uid НЕ шлёт сигнал; собственный процесс
//     не убиваем (self-exclusion); start-time несёт микросекунды.
do {
    let me = getpid()
    // M8: даже с верным стартом собственный процесс исключён (pid == getpid()) → false, без сигнала.
    check(ProcessScanner.terminate(me, expectStartSec: 1, expectStartUsec: 0, force: false) == false,
          "terminate refuses our own process (self-exclusion)")
    check(kill(me, 0) == 0, "process still alive (no signal sent)")
    // Не-собственный процесс с неверным стартом/uid (pid 1 = launchd, root) → guard аборт ДО kill.
    check(ProcessScanner.terminate(1, expectStartSec: 1, expectStartUsec: 0, force: false) == false,
          "terminate aborts on non-self start/uid mismatch (no signal)")
    // snapshot заполняет время старта для нашего же процесса (поле startUsec — наличие проверяет компилятор).
    let mine = ProcessScanner.snapshot(sampleMicros: 30_000).first { $0.pid == me }
    check(mine != nil && mine!.startSec > 0, "snapshot populates start time for our process")
}

// 5. ValidatePath блокирует denylist в неразвёрнутом (~) пути
do {
    let p = SafetyPolicy(home: "/Users/me", denylist: Denylist(pathContains: [fixture]))
    checkThrows("validatePath blocks denied nested component") {
        try p.validatePath("~/Desktop/\(fixture)")
    }
}

// 7. Каталог целей декодируется, H1 исправлен
checkNoThrow("targets.json loads") {
    let targets = try TargetCatalog.load(from: URL(fileURLWithPath: "Resources/targets.json"))
    check(targets.count >= 12, "catalog has targets (got \(targets.count))")
    let dl = targets.first { $0.id == "incomplete-downloads" }
    check(dl?.method == .report, "H1 fixed: incomplete-downloads is report-only")
    check(targets.contains { $0.id == "xcode-device-support" }, "catalog includes Xcode Device Support")
    check(targets.contains { $0.id == "user-caches" }, "catalog includes generic User Caches")
}

// 8. Сканер: glob-раскрытие + размеры + фильтр пустых
do {
    let base = realResolved(NSTemporaryDirectory()) + "/mcscan-" + UUID().uuidString
    let withFile = base + "/cacheA"
    try? FileManager.default.createDirectory(atPath: withFile, withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: withFile + "/data.bin", contents: Data(repeating: 0, count: 8192))
    try? FileManager.default.createDirectory(atPath: base + "/emptyDir", withIntermediateDirectories: true)

    let target = Target(id: "t-scan", name: "Scan Test", group: "dev", safety: .safe,
                        method: .trash, note: nil, paths: [base + "/*"], blockedByProcesses: nil)
    let groups = Scanner.scan(targets: [target])
    check(groups.count == 1, "scanner found the target group")
    let names = Set((groups.first?.items ?? []).map(\.displayName))
    check(names.contains("cacheA"), "scanner found non-empty item")
    check(!names.contains("emptyDir"), "scanner filtered out empty dir (size 0)")
    check((groups.first?.totalBytes ?? 0) > 0, "scanner computed a real size")

    try? FileManager.default.removeItem(atPath: base)
}

// 9. Каталог: AI-кэши добавлены (HuggingFace, PyTorch)
checkNoThrow("catalog has AI caches") {
    let t = try TargetCatalog.load(from: URL(fileURLWithPath: "Resources/targets.json"))
    check(t.contains { $0.id == "huggingface-cache" }, "catalog includes HuggingFace cache")
    check(t.contains { $0.id == "torch-cache" }, "catalog includes PyTorch cache")
    check(t.contains { $0.id == "cargo" }, "catalog includes Rust/Cargo cache")
    check(t.contains { $0.id == "go-cache" }, "catalog includes Go module cache")
    check(t.contains { $0.id == "pnpm-store" }, "catalog includes pnpm store")
    check(t.contains { $0.id == "ios-backups" }, "catalog includes iOS backups")
    check(t.contains { $0.id == "ios-software-updates" }, "catalog includes iOS software updates")
    check(t.contains { $0.id == "swiftpm-clones" }, "catalog includes SwiftPM clones")
    check(t.contains { $0.id == "xcode-previews" }, "catalog includes Xcode SwiftUI Previews")
    check(t.contains { $0.id == "mail-downloads" }, "catalog includes Mail Downloads")
    // Безопасность: бэкапы устройств — личные данные → НИКОГДА не safe (значит не предвыбираются автоматически)
    let backups = t.first { $0.id == "ios-backups" }
    check(backups?.safety != .safe && backups?.method == .trash,
          "iOS backups are never auto-selected (safety != safe) but still removable to Trash")
    // Новые семейства (выборочно)
    for id in ["parallels-caches", "jetbrains-caches", "homebrew-cache", "homebrew-logs",
               "vscode-caches", "docker-logs", "maven-repository", "cocoapods-cache",
               "claude-code-media-cache", "opencode-cache", "npx-cache", "conda-pkgs-index"] {
        check(t.contains { $0.id == id }, "catalog includes \(id)")
    }
    // ИНВАРИАНТ дедупа: любой путь под ~/Library/Caches|Logs (кроме самих catch-all) обязан быть
    // глубины 1 (точная подпапка, без вложенных / и без *) И стоять ДО user-caches/user-logs,
    // иначе seen-set не схлопнет и размеры задвоятся.
    func idx(_ id: String) -> Int { t.firstIndex { $0.id == id } ?? Int.max }
    let ucIdx = idx("user-caches"), ulIdx = idx("user-logs")
    var dedupOK = true, badPath = ""
    for (i, tgt) in t.enumerated() where tgt.id != "user-caches" && tgt.id != "user-logs" {
        for p in tgt.paths ?? [] {
            for (root, catchIdx) in [("~/Library/Caches/", ucIdx), ("~/Library/Logs/", ulIdx)] where p.hasPrefix(root) {
                let rest = String(p.dropFirst(root.count))
                if rest.contains("/") || rest.contains("*") || i > catchIdx { dedupOK = false; badPath = "\(tgt.id): \(p)" }
            }
        }
    }
    check(dedupOK, "itemized cache/log targets are depth-1 and precede the catch-all (no double count) [\(badPath)]")
}

// 9b. Dev-кэши: env-переменные ($CARGO_HOME/$GOMODCACHE/$HF_HOME) честно подставляются
do {
    let dir = NSTemporaryDirectory() + "mcenv-\(getpid())"
    try? FileManager.default.createDirectory(atPath: dir + "/sub", withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: dir + "/sub/f.bin", contents: Data(count: 16))
    setenv("MC_TEST_DEV_CACHE", dir, 1)
    let hit = Scanner.expandGlob("$MC_TEST_DEV_CACHE/*")
    check(hit.contains { $0.hasSuffix("/sub") }, "env-var path expands ($VAR honored)")
    let braced = Scanner.expandGlob("${MC_TEST_DEV_CACHE}/sub/*")
    check(braced.contains { $0.hasSuffix("/f.bin") }, "env-var ${VAR} form expands")
    let miss = Scanner.expandGlob("$MC_DEFINITELY_UNSET_xyz_42/*")
    check(miss.isEmpty, "unset env-var path is skipped, not globbed as literal '$VAR'")
    unsetenv("MC_TEST_DEV_CACHE")
    try? FileManager.default.removeItem(atPath: dir)
}

// 10. Классификатор: путь → вердикт (safe/discretion/never)
do {
    let rules = Classifier.loadRules(from: URL(fileURLWithPath: "Resources/classification.json"))
    check(!rules.isEmpty, "classification rules loaded (\(rules.count))")
    func verdict(_ p: String) -> Verdict { Classifier.classify(p, rules: rules).verdict }
    check(verdict("/Users/me/proj/.build/repositories/x/objects/pack/pack-1.pack") == .safe,
          "build artifacts → safe")
    check(verdict("/Users/me/Library/Developer/Xcode/DerivedData/App-x/Build") == .safe,
          "DerivedData → safe")
    check(verdict("/Users/me/.cache/huggingface/hub/models--x/blobs/y") == .discretion,
          "HuggingFace cache → discretion")
    check(verdict("/opt/homebrew/lib/python3.12/site-packages/mlx/lib/mlx.metallib") == .never,
          "mlx.metallib in package → never")
    check(verdict("/private/var/MobileAsset/AssetsV2/x.asset/data.dmg") == .never,
          "MobileAsset → never")
    check(verdict("/Applications/Foo.app/Contents/MacOS/foo") == .never,
          ".app internals → never")
    check(verdict("/Users/me/SomeFolder/unrecognized_blob_12345.xyz") == .discretion,
          "unknown path → discretion (safe default)")
}

// 11. Процессы: снимок содержит наш процесс
do {
    let procs = ProcessScanner.snapshot(sampleMicros: 50_000)
    check(!procs.isEmpty, "process snapshot non-empty (\(procs.count))")
    check(procs.contains { $0.pid == getpid() }, "snapshot includes own process")
    check(procs.contains { $0.isOwn }, "snapshot detects own-user processes")
}

// M3: пустой home → удаление запрещено (fail-closed, не fail-open)
do {
    let empty = SafetyPolicy(home: "")
    checkThrows("M3: empty home refuses deletion") { try empty.validatePath("/tmp/whatever") }
}

// 12. Карта хранилища: реальные размеры, адаптивность, без падений на отсутствующих путях
do {
    let tmp = NSTemporaryDirectory() + "smtest-\(getpid())"
    try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: tmp + "/blob.bin", contents: Data(count: 3_000_000))
    let rules = [StorageRule(id: "t", name: "Test", color: "ff0000", icon: "x", paths: [tmp])]
    let rep = StorageScanner.scan(rules: rules, total: 100_000_000_000, free: 50_000_000_000, minShow: 0)
    check((rep.categories.first?.bytes ?? 0) >= 3_000_000, "storage: real folder size counted (\(rep.categories.first?.bytes ?? 0))")
    check(rep.free == 50_000_000_000 && rep.total == 100_000_000_000, "storage: disk totals preserved")
    check(rep.systemOther >= 0, "storage: systemOther never negative")
    try? FileManager.default.removeItem(atPath: tmp)
}
do {
    // отсутствующие пути → категория не появляется (адаптивность), без краша
    let rules = [StorageRule(id: "z", name: "Nope", color: "00ff00", icon: "x", paths: ["/no-such-dir-\(getpid())"])]
    let rep = StorageScanner.scan(rules: rules, total: 1_000, free: 500, minShow: 0)
    check(rep.categories.isEmpty, "storage: missing paths yield no category (adaptive)")
}
do {
    // мелкие категории сворачиваются в systemOther при пороге minShow
    let tmp = NSTemporaryDirectory() + "smsmall-\(getpid())"
    try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: tmp + "/tiny.bin", contents: Data(count: 1_000))
    let rules = [StorageRule(id: "s", name: "Small", color: "abcdef", icon: "x", paths: [tmp])]
    let rep = StorageScanner.scan(rules: rules, total: 1_000_000_000, free: 0, minShow: 64 * 1024 * 1024)
    check(rep.categories.isEmpty, "storage: sub-threshold category folded out of the list")
    try? FileManager.default.removeItem(atPath: tmp)
}

// 13. keep-newest: новейшую версию оставляем, старые предлагаем (на платформу)
do {
    let ios = "/U/Library/Developer/Xcode/iOS DeviceSupport"
    let watch = "/U/Library/Developer/Xcode/watchOS DeviceSupport"
    let items = [
        ScanItem(path: ios + "/16.4 (20E247)",  displayName: "16.4 (20E247)",  size: 100),
        ScanItem(path: ios + "/17.5.1 (21F90)", displayName: "17.5.1 (21F90)", size: 200),
        ScanItem(path: ios + "/18.0 (22A300)",  displayName: "18.0 (22A300)",  size: 300),
        ScanItem(path: watch + "/10.2 (21S...)", displayName: "10.2 (21S...)", size: 50),
        ScanItem(path: watch + "/11.0 (22R...)", displayName: "11.0 (22R...)", size: 70),
    ]
    let offered = Scanner.excludingNewestPerParent(items)
    check(offered.count == 3, "keep-newest offers only older versions (\(offered.count))")
    check(!offered.contains { $0.displayName.hasPrefix("18.0") }, "keep-newest keeps newest iOS (18.0 not offered)")
    check(!offered.contains { $0.displayName.hasPrefix("11.0") }, "keep-newest keeps newest watchOS (11.0 not offered)")
    check(offered.contains { $0.displayName.hasPrefix("16.4") } && offered.contains { $0.displayName.hasPrefix("17.5") },
          "older iOS versions still offered")
    check(Scanner.versionKey("17.5.1 (21F90)") == [17, 5, 1], "version parsed from folder name")
    // одна версия на платформе → её оставляем (предлагать нечего)
    let single = Scanner.excludingNewestPerParent([ScanItem(path: ios + "/18.0 (x)", displayName: "18.0 (x)", size: 1)])
    check(single.isEmpty, "single version is kept, not offered")
}

// 14. Дубликаты: контент-идентичность, APFS-клоны, хардлинки, защита личных папок
do {
    let base = realResolved(NSTemporaryDirectory()) + "/mcdup-" + UUID().uuidString
    try? FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
    let policy = SafetyPolicy(home: base)
    let minB: Int64 = 4096
    func write(_ path: String, _ byte: UInt8, _ n: Int) {
        FileManager.default.createFile(atPath: path, contents: Data(repeating: byte, count: n))
    }

    // (a) две НЕЗАВИСИМЫЕ идентичные копии + одиночка того же размера, но другого контента + мелочь
    write(base + "/a1.bin", 0xAA, 40_000)
    write(base + "/a2.bin", 0xAA, 40_000)        // идентична a1, но отдельная копия (свои блоки)
    write(base + "/other.bin", 0xBB, 40_000)     // тот же размер, другой контент → не дубль
    write(base + "/small.bin", 0xCC, 1_000)      // ниже порога → игнор
    let groups = Dups.scan(root: base, minBytes: minB, policy: policy)
    check(groups.count == 1, "dups: exactly one content group (independent copies) [\(groups.count)]")
    if let g = groups.first {
        check(g.count == 2, "dups: group has 2 files")
        check(g.cloneSets == 2, "dups: independent copies counted as 2 physical copies")
        check(!g.allClones, "dups: independent copies are not all-clones")
        check(g.reclaimable >= 40_000, "dups: reclaimable ≈ one copy (\(g.reclaimable))")
        check(g.files.allSatisfy { $0.trashable }, "dups: copies outside personal data are trashable")
        check(g.files.allSatisfy { !$0.shared }, "dups: independent copies don't share blocks")
    }

    // (b) APFS-клон делит блоки → один физический набор, освободится 0
    try? FileManager.default.createDirectory(atPath: base + "/clones", withIntermediateDirectories: true)
    let cloneSrc = base + "/clones/orig.bin"
    write(cloneSrc, 0xDD, 50_000)
    let cloneDst = base + "/clones/clone.bin"
    let cloneRC = clonefile(cloneSrc, cloneDst, 0)
    check(cloneRC == 0, "dups: clonefile created APFS clone (rc \(cloneRC))")
    let cg = Dups.scan(root: base + "/clones", minBytes: minB, policy: policy)
    check(cg.count == 1, "dups: clone pair forms one group")
    if let g = cg.first {
        check(g.count == 2, "dups: clone group has 2 files")
        check(g.cloneSets == 1, "dups: APFS clones are one physical copy")
        check(g.allClones, "dups: clone group flagged all-clones")
        check(g.reclaimable == 0, "dups: deleting a clone frees nothing (reclaimable 0)")
        check(g.files.allSatisfy { $0.shared }, "dups: clone files marked as sharing blocks")
    }

    // (c) хардлинк не задваивается: file + hardlink + независимая копия → группа из 2, не 3
    let hb = base + "/hl"
    try? FileManager.default.createDirectory(atPath: hb, withIntermediateDirectories: true)
    write(hb + "/h1.bin", 0xEE, 60_000)
    _ = link(hb + "/h1.bin", hb + "/h2.bin")     // то же содержимое под вторым именем (один inode)
    write(hb + "/h3.bin", 0xEE, 60_000)          // отдельная идентичная копия
    let hg = Dups.scan(root: hb, minBytes: minB, policy: policy)
    check(hg.count == 1, "dups: hardlink + copy → one group")
    if let g = hg.first {
        check(g.count == 2, "dups: hardlink collapsed (2 files, not 3) [\(g.count)]")
        check(g.cloneSets == 2, "dups: kept hardlink + independent copy = 2 physical copies")
    }

    // (d) дубли внутри ~/Documents находятся, но НЕ trashable (только reveal — личные данные)
    let docs = base + "/Documents"
    try? FileManager.default.createDirectory(atPath: docs, withIntermediateDirectories: true)
    write(docs + "/d1.bin", 0x11, 40_000)
    write(docs + "/d2.bin", 0x11, 40_000)
    let dg = Dups.scan(root: docs, minBytes: minB, policy: policy)
    check(dg.first?.count == 2, "dups: duplicates inside Documents are detected")
    check(dg.first?.files.allSatisfy { !$0.trashable } == true,
          "dups: personal-data dups are not trashable (reveal-only)")

    // (e) хэши и clone-ключи как примитивы
    check(Dups.fullHash(base + "/a1.bin") == Dups.fullHash(base + "/a2.bin"),
          "dups: identical content → same full hash")
    check(Dups.fullHash(base + "/a1.bin") != Dups.fullHash(base + "/other.bin"),
          "dups: different content → different hash")
    check(Dups.cloneKey(cloneSrc, size: 50_000) == Dups.cloneKey(cloneDst, size: 50_000),
          "dups: clone shares extent signature")
    check(Dups.cloneKey(base + "/a1.bin", size: 40_000) != Dups.cloneKey(base + "/a2.bin", size: 40_000),
          "dups: independent copies have different extents")

    try? FileManager.default.removeItem(atPath: base)
}

// 15. Dups.prune: список дублей обновляется ПОСЛЕ переноса (мгновенно, без рескана)
do {
    func mk(_ path: String, set: Int, shared: Bool) -> DupFile {
        DupFile(path: path, displayName: (path as NSString).lastPathComponent,
                size: 1000, cloneSet: set, shared: shared, trashable: true)
    }
    // (a) 3 независимые копии → удаляем одну → 2 копии, число физ.копий 3→2, группа жива
    let g1 = DupGroup(key: "g1", size: 1000, files: [
        mk("/a/x1", set: 0, shared: false), mk("/a/x2", set: 1, shared: false), mk("/a/x3", set: 2, shared: false)],
        cloneSets: 3)
    let p1 = Dups.prune([g1], removing: ["/a/x2"])
    check(p1.count == 1, "prune: group with 2 left stays")
    check(p1.first?.count == 2, "prune: removed file gone from group")
    check(p1.first?.cloneSets == 2, "prune: physical-copy count recomputed (3→2)")
    check(p1.first?.reclaimable == 1000, "prune: reclaimable recomputed")
    check(p1.first?.files.contains { $0.path == "/a/x2" } == false, "prune: trashed path absent from list")

    // (b) группа из 2 → удаляем одну → группа исчезает (одной копии — не дубль)
    let g2 = DupGroup(key: "g2", size: 1000, files: [
        mk("/b/y1", set: 0, shared: false), mk("/b/y2", set: 1, shared: false)], cloneSets: 2)
    check(Dups.prune([g2], removing: ["/b/y1"]).isEmpty, "prune: group below 2 copies removed entirely")

    // (c) набор из 2 общих блоков: удалили один → у оставшегося shared снимается
    let g3 = DupGroup(key: "g3", size: 1000, files: [
        mk("/c/z1", set: 0, shared: true), mk("/c/z2", set: 0, shared: true), mk("/c/z3", set: 1, shared: false)],
        cloneSets: 2)
    let p3 = Dups.prune([g3], removing: ["/c/z2"])
    check(p3.first?.count == 2, "prune: clone group keeps remaining two")
    check(p3.first?.files.first { $0.path == "/c/z1" }?.shared == false, "prune: lone clone no longer marked shared")

    // (d) несколько групп: выжившая остаётся, схлопнувшаяся уходит
    let multi = Dups.prune([g1, g2], removing: ["/a/x1", "/b/y2"])
    check(multi.count == 1 && multi.first?.count == 2, "prune: mixed — survivor kept, collapsed dropped")

    // (e) enforceKeepOne: в группе ВСЕГДА остаётся ≥1 копия
    let allSel: Set<String> = ["/a/x1", "/a/x2", "/a/x3"]
    let safe = Dups.enforceKeepOne(allSel, groups: [g1])
    check(safe.count == 2, "enforceKeepOne: drops one when all copies selected")
    check(g1.files.contains { !safe.contains($0.path) }, "enforceKeepOne: at least one copy survives")
    let partial: Set<String> = ["/a/x1", "/a/x2"]
    check(Dups.enforceKeepOne(partial, groups: [g1]) == partial, "enforceKeepOne: partial selection untouched")
    let mixedSel: Set<String> = ["/a/x1", "/a/x2", "/a/x3", "/b/y1"]
    let mixedSafe = Dups.enforceKeepOne(mixedSel, groups: [g1, g2])
    check(mixedSafe.contains("/b/y1") && g1.files.contains { !mixedSafe.contains($0.path) },
          "enforceKeepOne: per-group — full group keeps one, partial group untouched")
}

// 16. Apps: хвосты (bundle id/имя), осиротевшие + исключения, Info.plist, prune
do {
    let base = realResolved(NSTemporaryDirectory()) + "/mcapps-" + UUID().uuidString
    let lib = base + "/Library"
    func mkdir(_ p: String) { try? FileManager.default.createDirectory(atPath: p, withIntermediateDirectories: true) }
    func mkfile(_ p: String, _ n: Int = 8192) {
        mkdir((p as NSString).deletingLastPathComponent)
        FileManager.default.createFile(atPath: p, contents: Data(count: n))
    }
    let policy = SafetyPolicy(home: base)

    // (a) хвосты приложения com.test.app / TestApp
    mkfile(lib + "/Caches/com.test.app/c.bin")
    mkfile(lib + "/Preferences/com.test.app.plist", 1024)
    mkfile(lib + "/Containers/com.test.app/data.bin")
    mkfile(lib + "/Application Support/TestApp/support.bin")     // по ИМЕНИ → strong=false
    let lefts = Apps.leftovers(bundleId: "com.test.app", name: "TestApp", home: base, policy: policy)
    let kinds = Set(lefts.map { $0.kind })
    check(kinds.contains("Caches") && kinds.contains("Preferences") && kinds.contains("Container"),
          "apps: leftovers matched by bundle id (\(kinds.sorted()))")
    check(lefts.contains { $0.path.hasSuffix("/Application Support/TestApp") && !$0.strong },
          "apps: name-based Application Support is a weak match")
    check(lefts.first { $0.path.contains("/Caches/com.test.app") }?.strong == true, "apps: bundle-id match is strong")
    check(lefts.allSatisfy { $0.trashable }, "apps: leftovers outside personal data are trashable")

    // (b) осиротевшие + все исключения
    mkfile(lib + "/Containers/com.gone.oldapp/d.bin")
    mkfile(lib + "/Caches/com.gone.oldapp/c.bin")
    mkdir(lib + "/Containers/com.apple.systemthing")     // Apple
    mkdir(lib + "/Containers/group.com.apple.mail")      // .apple. внутри
    mkdir(lib + "/Containers/group.com.foo.shared")      // групповой
    mkdir(lib + "/Containers/com.vendor.helper")         // тот же вендор, что установлен
    mkdir(lib + "/Containers/com.installed.app.ext")     // расширение установленного
    let installed: Set<String> = ["com.vendor.app", "com.installed.app", "com.test.app"]
    let orphans = Apps.findOrphans(installedIds: installed, home: base, policy: policy, lsKnows: { _ in false })
    let oid = Set(orphans.map { $0.bundleId.lowercased() })
    check(oid.contains("com.gone.oldapp"), "apps: orphan detected (removed app's container)")
    check(!oid.contains("com.apple.systemthing"), "apps: Apple excluded from orphans")
    check(!oid.contains("group.com.apple.mail"), "apps: group.com.apple.* excluded")
    check(!oid.contains("group.com.foo.shared"), "apps: group container excluded")
    check(!oid.contains("com.vendor.helper"), "apps: installed-vendor component not orphaned (e.g. DaVinci IOXPC)")
    check(!oid.contains("com.installed.app.ext"), "apps: extension of installed app not orphaned")
    if let g = orphans.first(where: { $0.bundleId == "com.gone.oldapp" }) {
        check(g.items.count >= 2, "apps: orphan gathers all its leftovers (\(g.items.count))")
        check(g.size > 0, "apps: orphan has real size")
    }
    // (f) F-2: LaunchServices знает приложение с этим id (установлено вне сканируемых папок) → НЕ сирота
    let orphansLS = Apps.findOrphans(installedIds: installed, home: base, policy: policy,
                                     lsKnows: { $0 == "com.gone.oldapp" })
    check(!orphansLS.contains { $0.bundleId == "com.gone.oldapp" },
          "apps F-2: bundle id known to LaunchServices excluded from orphans (live app outside scanned roots)")

    // (c) vendor / isInstalledOrChild
    check(Apps.vendor("com.blackmagic-design.ioxpc") == "com.blackmagic-design", "apps: vendor = first two components")
    check(Apps.vendor("group.com.apple.mail") == "group.com.apple.mail", "apps: group id vendor = full id")
    check(Apps.isInstalledOrChild("com.foo.app.ext", ["com.foo.app"]), "apps: extension is an installed child")
    check(!Apps.isInstalledOrChild("com.foo.other", ["com.foo.app"]), "apps: sibling is not a child")

    // (d) bundleInfo + appBundles из фейкового .app
    let appsDir = base + "/Applications"
    let appPath = appsDir + "/Demo.app"
    mkdir(appPath + "/Contents")
    let plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>" +
        "<key>CFBundleIdentifier</key><string>com.demo.app</string>" +
        "<key>CFBundleName</key><string>Demo</string>" +
        "<key>CFBundleShortVersionString</key><string>3.2.1</string></dict></plist>"
    try? plist.write(toFile: appPath + "/Contents/Info.plist", atomically: true, encoding: .utf8)
    check(Apps.appBundles(in: appsDir).contains(appPath), "apps: appBundles finds .app bundle")
    let info = Apps.bundleInfo(appPath)
    check(info?.id == "com.demo.app" && info?.name == "Demo" && info?.version == "3.2.1",
          "apps: Info.plist parsed (id/name/version)")

    // (e) prune: бандл удалён → приложение уходит; хвост удалён → остаётся
    let appObj = InstalledApp(path: "/A/Foo.app", name: "Foo", bundleId: "com.f.foo", version: "1",
                              appSize: 1000,
                              leftovers: [AppLeftover(path: "/L/cache", kind: "Caches", size: 500, strong: true, trashable: true)],
                              trashableBundle: true)
    check(Apps.pruneApps([appObj], removing: ["/A/Foo.app"]).isEmpty, "apps: removing bundle drops the app")
    let kept = Apps.pruneApps([appObj], removing: ["/L/cache"])
    check(kept.count == 1 && kept.first?.leftovers.isEmpty == true, "apps: removing a leftover keeps the app without it")
    let orphanObj = OrphanApp(bundleId: "com.g.gone", displayName: "gone",
                              items: [AppLeftover(path: "/O/a", kind: "Container", size: 1, strong: true, trashable: true),
                                      AppLeftover(path: "/O/b", kind: "Caches", size: 1, strong: true, trashable: true)])
    check(Apps.pruneOrphans([orphanObj], removing: ["/O/a"]).first?.items.count == 1, "apps: orphan prune removes one item")
    check(Apps.pruneOrphans([orphanObj], removing: ["/O/a", "/O/b"]).isEmpty, "apps: emptied orphan disappears")

    try? FileManager.default.removeItem(atPath: base)
}

// 17. Large & Old: относительный возраст (англ.) и флаг «old»
do {
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    func daysAgo(_ d: Int) -> Date { now.addingTimeInterval(-Double(d) * 86_400) }
    check(LargeFiles.ago(daysAgo(0), now: now) == "today", "ago: today")
    check(LargeFiles.ago(daysAgo(1), now: now) == "yesterday", "ago: yesterday")
    check(LargeFiles.ago(daysAgo(5), now: now) == "5 days ago", "ago: days")
    check(LargeFiles.ago(daysAgo(60), now: now).contains("month"), "ago: months (\(LargeFiles.ago(daysAgo(60), now: now)))")
    check(LargeFiles.ago(daysAgo(800), now: now).contains("year"), "ago: years (\(LargeFiles.ago(daysAgo(800), now: now)))")
    check(!LargeFiles.isOld(daysAgo(100), now: now), "isOld: 100 days is not old")
    check(LargeFiles.isOld(daysAgo(400), now: now), "isOld: 400 days is old")
    // scan заполняет дату изменения
    let base = realResolved(NSTemporaryDirectory()) + "/mclarge-" + UUID().uuidString
    try? FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
    let big = base + "/big.bin"
    FileManager.default.createFile(atPath: big, contents: Data(count: 120 * 1024 * 1024))
    let files = LargeFiles.scan(root: base, minBytes: 100 * 1024 * 1024)
    check(files.first?.displayName == "big.bin", "large scan finds the big file")
    check((files.first?.modified.timeIntervalSince1970 ?? 0) > 1_600_000_000, "large scan records modified date")
    try? FileManager.default.removeItem(atPath: base)
}

// 18. ProjectCaches: build-папки находим ТОЛЬКО при манифесте-соседе; внутрь не углубляемся; личное/скрытое мимо
do {
    let base = realResolved(NSTemporaryDirectory()) + "/mcproj-" + UUID().uuidString
    func mkdir(_ p: String) { try? FileManager.default.createDirectory(atPath: p, withIntermediateDirectories: true) }
    func mkfile(_ p: String, _ n: Int = 8192) {
        mkdir((p as NSString).deletingLastPathComponent)
        FileManager.default.createFile(atPath: p, contents: Data(count: n))
    }
    // (a) настоящий SwiftPM-проект: .build + Package.swift сосед
    mkfile(base + "/ProjA/Package.swift", 100)
    mkfile(base + "/ProjA/.build/artifact.o")
    // (b) node_modules + package.json
    mkfile(base + "/web/package.json", 100)
    mkfile(base + "/web/node_modules/lib/index.js")
    // (c) папка target БЕЗ Cargo.toml → НЕ build-кэш (ложное имя)
    mkfile(base + "/notrust/target/data.bin")
    // (d) .build БЕЗ Package.swift → не считаем
    mkfile(base + "/bare/.build/x.bin")
    // (e) build-папка внутри личной папки Documents → не обходим
    mkfile(base + "/Documents/Proj/Package.swift", 100)
    mkfile(base + "/Documents/Proj/.build/y.bin")

    let items = ProjectCaches.scan(home: base)
    let paths = Set(items.map { $0.path })
    check(paths.contains(base + "/ProjA/.build"), "projcaches: SwiftPM .build with Package.swift found")
    check(paths.contains(base + "/web/node_modules"), "projcaches: node_modules with package.json found")
    check(!paths.contains(base + "/notrust/target"), "projcaches: target without Cargo.toml ignored")
    check(!paths.contains(base + "/bare/.build"), "projcaches: .build without Package.swift ignored")
    check(!paths.contains(base + "/Documents/Proj/.build"), "projcaches: build folder under Documents skipped (personal)")
    // внутрь .build не углубляемся: artifact.o не появляется отдельной записью
    check(!paths.contains(base + "/ProjA/.build/artifact.o"), "projcaches: does not descend into build folder")
    check(items.first(where: { $0.path == base + "/ProjA/.build" })?.displayName.contains("SwiftPM") == true,
          "projcaches: label includes kind (SwiftPM)")
    check((items.first?.size ?? 0) > 0, "projcaches: real size computed")

    try? FileManager.default.removeItem(atPath: base)
}

// 19. report-only: scanReport показывает, scan(trash) — нет; пустые/беспутёвые цели скрыты
do {
    let base = realResolved(NSTemporaryDirectory()) + "/mcreport-" + UUID().uuidString
    try? FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: base + "/partial.crdownload", contents: Data(count: 5000))
    let rep = Target(id: "t-report", name: "Incomplete", group: "downloads", safety: .moderate,
                     method: .report, note: "review", paths: [base + "/*.crdownload"], blockedByProcesses: nil)
    let empty = Target(id: "t-empty", name: "Placeholder", group: "x", safety: .manual,
                       method: .report, note: nil, paths: nil, blockedByProcesses: nil)
    let groups = Scanner.scanReport(targets: [rep, empty])
    check(groups.count == 1 && groups.first?.targetID == "t-report", "report: scanReport returns only the non-empty report target")
    check((groups.first?.items.count ?? 0) >= 1, "report: lists the incomplete file")
    check(Scanner.scan(targets: [rep]).isEmpty, "report: scan(trash) ignores report-only targets")
    try? FileManager.default.removeItem(atPath: base)
}

// ============================ SimilarPhotos (похожие фото) ============================

// Хелперы для синтетических фото и реальных PNG.
func simPhoto(_ p: String, ph: UInt64, dh: UInt64, w: Int = 1000, h: Int = 1000,
              trashable: Bool = true) -> SimilarPhoto {
    SimilarPhoto(path: p, displayName: (p as NSString).lastPathComponent, size: 4096,
                 width: w, height: h, pHash: ph, dHash: dh, trashable: trashable, isKeeper: false)
}
// Частотно-богатая НИЗКОчастотная картинка (сумма косинусов разных частот) — как реальное фото:
// энергия DCT размазана по нескольким коэффициентам ⇒ pHash СТАБИЛЕН к ресемплу. Чисто гладкий
// ramp/треугольник для теста не годится: почти вся энергия в DC ⇒ остальные коэффициенты дрожат
// у медианы и хэш нестабилен (это особенность pHash, а не баг движка — реальные фото не гладкие).
// Низкая частота ⇒ 64px и 32px версии хэшируются близко (проверка на уменьшенные копии).
func gradPixels(_ w: Int, _ h: Int) -> [UInt8] {
    var p = [UInt8](repeating: 0, count: w * h)
    for y in 0..<h {
        for x in 0..<w {
            let fx = Double(x) / Double(w)
            let fy = Double(y) / Double(h)
            let v = 128.0
                + 60 * cos(2 * Double.pi * fx)
                + 50 * cos(2 * Double.pi * 2 * fy)
                + 40 * cos(2 * Double.pi * (fx + fy))
            p[y * w + x] = UInt8(min(255, max(0, v)))
        }
    }
    return p
}
// Другая плотная текстура (иной набор частот) — для теста «разные фото не похожи».
func gradB(_ w: Int, _ h: Int) -> [UInt8] {
    var p = [UInt8](repeating: 0, count: w * h)
    for y in 0..<h {
        for x in 0..<w {
            let fx = Double(x) / Double(w)
            let fy = Double(y) / Double(h)
            let v = 128.0
                + 55 * cos(2 * Double.pi * 3 * fx)
                + 45 * cos(2 * Double.pi * fy)
                + 35 * cos(2 * Double.pi * (2 * fx - fy))
            p[y * w + x] = UInt8(min(255, max(0, v)))
        }
    }
    return p
}
func writePNG(_ path: String, _ pixels: [UInt8], _ w: Int, _ h: Int) {
    var px = pixels
    let cs = CGColorSpaceCreateDeviceGray()
    let img: CGImage? = px.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress,
              let ctx = CGContext(data: base, width: w, height: h, bitsPerComponent: 8,
                                  bytesPerRow: w, space: cs,
                                  bitmapInfo: CGImageAlphaInfo.none.rawValue) else { return nil }
        return ctx.makeImage()
    }
    guard let image = img,
          let dest = CGImageDestinationCreateWithURL(
              URL(fileURLWithPath: path) as CFURL, "public.png" as CFString, 1, nil) else { return }
    CGImageDestinationAddImage(dest, image, nil)
    CGImageDestinationFinalize(dest)
}

// 20. Hamming
do {
    check(SimilarPhotos.hamming(0, 0) == 0, "hamming: 0,0 → 0")
    check(SimilarPhotos.hamming(UInt64.max, 0) == 64, "hamming: max,0 → 64")
    check(SimilarPhotos.hamming(0b1011, 0b1001) == 1, "hamming: differ by 1 bit")
    check(SimilarPhotos.hamming(123, 456) == SimilarPhotos.hamming(456, 123), "hamming: symmetric")
}

// 21. pHash (синтетика 32×32): solid→0, яркостная инвариантность, анти-ложное-срабатывание
do {
    let solid = [UInt8](repeating: 128, count: 32 * 32)
    check(SimilarPhotos.pHash(gray32: solid) == 0, "pHash: solid gray → 0 (DC excluded)")
    let g0 = gradPixels(32, 32)
    let g5 = g0.map { UInt8(min(255, Int($0) + 5)) }     // +5 яркости всем пикселям, без клиппинга
    check(SimilarPhotos.pHash(gray32: g0) == SimilarPhotos.pHash(gray32: g5),
          "pHash: brightness shift (+5) → identical hash (DC-invariant)")
    check(SimilarPhotos.pHash(gray32: g0) != 0, "pHash: gradient is non-degenerate")
    check(SimilarPhotos.pHash(gray32: g0) == SimilarPhotos.pHash(gray32: g0), "pHash: deterministic")
    // Кардинальный анти-ложняк: две РАЗНЫЕ плотные текстуры (как реальные фото) → далеки по Хэммингу.
    let dA = SimilarPhotos.pHash(gray32: gradPixels(32, 32))
    let dB = SimilarPhotos.pHash(gray32: gradB(32, 32))
    check(dA.nonzeroBitCount >= SimilarPhotos.popcountLo && dB.nonzeroBitCount >= SimilarPhotos.popcountLo,
          "pHash: dense textures have non-sparse hashes (fair comparison)")
    check(SimilarPhotos.hamming(dA, dB) > SimilarPhotos.pHashMax,
          "pHash: two different dense textures are NOT similar (cardinal anti-false-positive)")
}

// 22. dHash (синтетика 9×8)
do {
    var inc = [UInt8](repeating: 0, count: 9 * 8)
    var dec = [UInt8](repeating: 0, count: 9 * 8)
    for r in 0..<8 {
        for c in 0..<9 {
            inc[r * 9 + c] = UInt8(c * 28)         // возрастает слева→направо
            dec[r * 9 + c] = UInt8((8 - c) * 28)   // убывает
        }
    }
    check(SimilarPhotos.dHash(gray9x8: inc) == 0, "dHash: increasing rows → 0")
    check(SimilarPhotos.dHash(gray9x8: dec) == UInt64.max, "dHash: decreasing rows → all ones")
    check(SimilarPhotos.hamming(SimilarPhotos.dHash(gray9x8: inc),
                                SimilarPhotos.dHash(gray9x8: dec)) > SimilarPhotos.dHashMax,
          "dHash: opposite gradients exceed threshold")
    check(SimilarPhotos.dHash(gray9x8: inc) == SimilarPhotos.dHash(gray9x8: inc), "dHash: deterministic")
}

// 23. Предикаты сходства (вето dHash, строгий pHash, вето соотношения сторон, related-полоса)
do {
    let base: UInt64 = 0x0F0F_0F0F_0F0F_0F0F
    let a = simPhoto("/x/a", ph: base, dh: base, w: 1000, h: 1000)
    let near = simPhoto("/x/b", ph: base ^ 0b1111, dh: base ^ 0b1111, w: 1000, h: 1000)   // pHash 4, dHash 4
    check(SimilarPhotos.isSimilar(a, near), "predicate: pHash4 & dHash4 & sameAR → similar")
    let dhVeto = simPhoto("/x/c", ph: base ^ 0b1111, dh: base ^ 0xFFFFF, w: 1000, h: 1000) // dHash 20
    check(!SimilarPhotos.isSimilar(a, dhVeto), "predicate: dHash 20 (>12) vetoes")
    let phVeto = simPhoto("/x/d", ph: base ^ 0xFF, dh: base, w: 1000, h: 1000)             // pHash 8
    check(!SimilarPhotos.isSimilar(a, phVeto), "predicate: pHash 8 (>6) → not similar")
    let arVeto = simPhoto("/x/e", ph: base ^ 0b1111, dh: base ^ 0b1111, w: 1920, h: 1080)  // 16:9 vs 1:1
    check(!SimilarPhotos.isSimilar(a, arVeto), "predicate: aspect 16:9 vs 1:1 vetoes")
    let r1 = simPhoto("/x/r1", ph: base, dh: base, w: 1920, h: 1080)
    let r2 = simPhoto("/x/r2", ph: base, dh: base, w: 1280, h: 720)
    check(SimilarPhotos.aspectCompatible(r1, r2), "aspect: 16:9 vs 16:9 compatible")
    let wide = simPhoto("/x/w", ph: base, dh: base, w: 1000, h: 500)
    check(!SimilarPhotos.aspectCompatible(wide, a), "aspect: 2:1 vs 1:1 incompatible")
    let rel = simPhoto("/x/rel", ph: base ^ 0xFFF, dh: base ^ 0xFFF, w: 1000, h: 1000)     // pHash 12
    check(SimilarPhotos.relatedBand(a, rel), "relatedBand: pHash 12 (∈9..16) → related")
    check(!SimilarPhotos.relatedBand(a, near), "relatedBand: pHash 4 (near-dup) → not related")
}

// 24. Группировка + анти-транзитивность + кардинальный true-negative
do {
    let base: UInt64 = 0x0F0F_0F0F_0F0F_0F0F
    // (a) три попарно похожих (≤6) → одна near-dup группа из 3
    let A = simPhoto("/g/a", ph: base, dh: base)
    let B = simPhoto("/g/b", ph: base ^ 0b1110, dh: base)        // dist 3
    let C = simPhoto("/g/c", ph: base ^ 0b1110000, dh: base)     // dist 3 от A, 6 от B
    let g3 = SimilarPhotos.group([A, B, C])
    check(g3.count == 1 && g3.first?.count == 3 && g3.first?.kind == .nearDuplicate,
          "group: 3 mutually-similar → one near-dup group")
    // (b) анти-транзитивность: A~B, B~C, но A!~C (dist 8) — цепочка собирается, прямой ложной пары НЕТ
    let m1: UInt64 = 0b1111, m2: UInt64 = 0b11110000
    let At = simPhoto("/t/a", ph: base, dh: base)
    let Bt = simPhoto("/t/b", ph: base ^ m1, dh: base)
    let Ct = simPhoto("/t/c", ph: base ^ m1 ^ m2, dh: base)
    check(SimilarPhotos.isSimilar(At, Bt) && SimilarPhotos.isSimilar(Bt, Ct), "anti-trans: adjacent pairs similar")
    check(!SimilarPhotos.isSimilar(At, Ct), "anti-trans: A and C NOT directly similar (dist 8 > 6)")
    let chain = SimilarPhotos.group([At, Bt, Ct])   // лидер-кластеризация: C похож только на не-лидера B → НЕ склеивается
    check(chain.count == 1 && chain.first?.count == 2, "anti-trans: leader clustering does NOT chain — only A,B grouped")
    check(chain.first?.photos.contains(where: { $0.path == "/t/c" }) == false, "anti-trans: C (similar only to non-leader B) excluded")
    // (c) КАРДИНАЛЬНЫЙ true-negative: две очень разные → не группируются
    let x1 = simPhoto("/n/x1", ph: base, dh: base)
    let x2 = simPhoto("/n/x2", ph: ~base, dh: ~base)
    check(SimilarPhotos.group([x1, x2]).isEmpty, "cardinal: two very different photos → no group")
    // (d) одинаковый AR, но pHash 24 → не группируются
    let s1 = simPhoto("/s/s1", ph: base, dh: base, w: 1000, h: 1000)
    let s2 = simPhoto("/s/s2", ph: base ^ 0xFFFFFF, dh: base, w: 1000, h: 1000)   // dist 24
    check(SimilarPhotos.group([s1, s2]).isEmpty, "same-AR but pHash 24 apart → not grouped")
    // (e) keeper = копия с наибольшим числом пикселей, на индексе 0
    let big = simPhoto("/k/big", ph: base, dh: base, w: 2000, h: 1500)
    let small = simPhoto("/k/small", ph: base ^ 0b11, dh: base, w: 1000, h: 750)
    let gk = SimilarPhotos.group([small, big])
    check(gk.first?.photos.first?.path == "/k/big" && gk.first?.photos.first?.isKeeper == true,
          "keeper: largest-pixels copy at index 0, flagged isKeeper")
    // (f) related-series: pHash 12 → kind == .relatedSeries
    let rA = simPhoto("/r/a", ph: base, dh: base)
    let rB = simPhoto("/r/b", ph: base ^ 0xFFF, dh: base)
    let gr = SimilarPhotos.group([rA, rB])
    check(gr.count == 1 && gr.first?.kind == .relatedSeries, "related: pHash 12 → relatedSeries group")
    // (g) синглтон не группируется; имя файла не создаёт ребро
    check(SimilarPhotos.group([A]).isEmpty, "singleton never groups")
    let st1 = simPhoto("/d/step_004.png", ph: base, dh: base)
    let st2 = simPhoto("/d/step_028.png", ph: ~base, dh: ~base)
    check(SimilarPhotos.group([st1, st2]).isEmpty, "filename stem does NOT create a group edge")
}

// 25. enforceKeepOne + prune + trashableGroups
do {
    let m = [simPhoto("/e/a", ph: 1, dh: 1, w: 100, h: 100),
             simPhoto("/e/b", ph: 1, dh: 1, w: 200, h: 200),
             simPhoto("/e/c", ph: 1, dh: 1, w: 50, h: 50)]
    let grp = SimilarPhotos.makeGroup(.nearDuplicate, m)
    check(grp.photos.first?.path == "/e/b", "makeGroup: keeper (200x200) at index 0")
    let allSel = Set(grp.photos.map { $0.path })
    let safe = SimilarPhotos.enforceKeepOne(allSel, groups: [grp])
    check(safe.count == grp.photos.count - 1, "enforceKeepOne: all selected → drops exactly one")
    check(!safe.contains("/e/b"), "enforceKeepOne: the kept one is the keeper (index 0)")
    let partial: Set<String> = ["/e/a"]
    check(SimilarPhotos.enforceKeepOne(partial, groups: [grp]) == partial, "enforceKeepOne: partial unchanged")
    let pruned = SimilarPhotos.prune([grp], removing: ["/e/c"])
    check(pruned.first?.count == 2 && pruned.first?.photos.contains(where: { $0.path == "/e/c" }) == false,
          "prune: group of 3 minus 1 → 2, removed absent")
    let prunedK = SimilarPhotos.prune([grp], removing: ["/e/b"])
    check(prunedK.first?.photos.first?.path == "/e/a", "prune: keeper removed → next-largest becomes keeper")
    let gone2 = SimilarPhotos.prune([SimilarPhotos.makeGroup(.nearDuplicate, [m[0], m[1]])], removing: ["/e/a"])
    check(gone2.isEmpty, "prune: group of 2 minus 1 → disappears")
    let rel = SimilarPhotos.makeGroup(.relatedSeries, m)
    let tg = SimilarPhotos.trashableGroups([grp, rel])
    check(tg.count == 1 && tg.first?.kind == .nearDuplicate, "trashableGroups: only near-duplicate (related not deletable)")
}

// 26. Исключения пути + имя-основа
do {
    check(SimilarPhotos.isOpaquePackagePath("/Users/me/Pictures/My.photoslibrary/originals/0/IMG.heic"),
          "opaque: deep file inside .photoslibrary")
    check(SimilarPhotos.isOpaquePackagePath("/Users/me/Movies/Film.fcpbundle/x.jpg"), "opaque: inside .fcpbundle")
    check(SimilarPhotos.isOpaquePackagePath("/Applications/Foo.app/Contents/img.png"), "opaque: inside .app")
    check(!SimilarPhotos.isOpaquePackagePath("/Users/me/proj/out/step_004.png"), "opaque: normal path is not a package")
    check(SimilarPhotos.isExcludedScanPath("/Users/me/proj/.build/render.png"), "excluded: inside .build cache")
    check(SimilarPhotos.isExcludedScanPath("/Users/me/Library/Caches/app/thumb.png"), "excluded: inside Caches")
    check(SimilarPhotos.isExcludedScanPath("/Users/me/d/.build-xcode/SourcePackages/checkouts/lib/ex.png"), "excluded: inside SourcePackages")
    check(SimilarPhotos.isExcludedScanPath("/Users/me/.claude/plugins/x/logo.png"), "excluded: hidden dot-folder (.claude)")
    check(!SimilarPhotos.isExcludedScanPath("/Users/me/Library/Application Support/App/flux_1.png"), "excluded: ~/Library is NOT hidden by the dot rule")
    check(!SimilarPhotos.isExcludedScanPath("/Users/me/Pictures/photo.png"), "excluded: Pictures is NOT a cache")
    check(!SimilarPhotos.isExcludedScanPath("/Users/me/Developer/proj/out/step_004.png"), "excluded: project output is NOT a cache")
    check(SimilarPhotos.sharedStem("step_004") == "step", "stem: step_004 → step")
    check(SimilarPhotos.sharedStem("step_028") == "step", "stem: step_028 → step")
    check(SimilarPhotos.sharedStem("grid-12") == "grid", "stem: grid-12 → grid")
    check(SimilarPhotos.sharedStem("portrait") == nil, "stem: portrait → nil")
}

// 27. (ОБЯЗАТЕЛЬНЫЙ) реальный декод end-to-end: PNG + его уменьшенная копия группируются;
//     личная папка → reveal-only; файл в .photoslibrary исключён.
do {
    let tmp = realResolved(NSTemporaryDirectory()) + "/mcsim-" + UUID().uuidString
    func mkdir(_ p: String) { try? FileManager.default.createDirectory(atPath: p, withIntermediateDirectories: true) }
    mkdir(tmp)
    writePNG(tmp + "/a64.png", gradPixels(64, 64), 64, 64)
    writePNG(tmp + "/a32.png", gradPixels(32, 32), 32, 32)
    let pol = SafetyPolicy(home: tmp)
    let groups = SimilarPhotos.scan(root: tmp, minBytes: 0, policy: pol)   // синтетика крошечная — обходим порог
    check(groups.count == 1 && groups.first?.kind == .nearDuplicate && groups.first?.count == 2,
          "real-decode: 64px image and its 32px downscale grouped as near-duplicates")
    check(SimilarPhotos.scan(root: tmp, minBytes: 10_000_000, policy: pol).isEmpty,
          "real-decode: byte floor excludes small images (icons/thumbnails)")
    check(groups.first?.photos.allSatisfy { $0.trashable } == true,
          "real-decode: both copies trashable (outside personal roots)")
    let smaller = groups.first?.photos.first(where: { $0.path.hasSuffix("a32.png") })
    check(groups.first?.reclaimable == smaller?.size, "real-decode: reclaimable == smaller copy size")

    // личная папка: те же копии под <home>/Pictures → trashable=false (reveal-only)
    let pics = tmp + "/Pictures"; mkdir(pics)
    writePNG(pics + "/a64.png", gradPixels(64, 64), 64, 64)
    writePNG(pics + "/a32.png", gradPixels(32, 32), 32, 32)
    let picGroups = SimilarPhotos.scan(root: pics, minBytes: 0, policy: pol)
    check(picGroups.first?.photos.allSatisfy { !$0.trashable } == true,
          "real-decode: copies under ~/Pictures are reveal-only (not trashable)")

    // .photoslibrary: файл внутри пакета НЕ должен попасть в результат, даже будучи идентичным
    let lib = tmp + "/Foo.photoslibrary/originals/0"; mkdir(lib)
    writePNG(lib + "/x.png", gradPixels(64, 64), 64, 64)
    let allPaths = SimilarPhotos.scan(root: tmp, minBytes: 0, policy: pol).flatMap { $0.photos.map { $0.path } }
    check(!allPaths.contains { $0.contains("Foo.photoslibrary") },
          "real-decode: file inside .photoslibrary is excluded (opaque package)")

    try? FileManager.default.removeItem(atPath: tmp)
}

// 29. Wave 3 — SystemCleanGate: allowlist системного мусора + danger-prefixes (PURE) + C1 + requirement-строки
do {
    func ok(_ p: String) -> Bool { (try? SystemCleanGate.checkCanonical(p)) != nil }
    // положительные: глубина ≥4, строго под safe-корнем
    check(ok("/Library/Caches/com.foo.app/Cache.db"), "gate: /Library/Caches/<app>/file allowed")
    check(ok("/Library/Logs/DiagnosticReports/x.log"), "gate: /Library/Logs/.../file allowed")
    check(ok("/private/var/log/install.log.0.gz"), "gate: /private/var/log/.../rotated allowed")
    // отрицательные: danger / вне allowlist / мелкая глубина / карантин
    check(!ok("/private/var/db/diagnostics/Persist/x.tracev3"), "gate: var/db/diagnostics (unified log) REJECTED")
    check(!ok("/Library/LaunchDaemons/com.foo.plist"), "gate: LaunchDaemons REJECTED")
    check(!ok("/private/var/folders/ab/cd/T/x"), "gate: var/folders REJECTED")
    check(!ok("/System/Library/Caches/x/y"), "gate: /System/... REJECTED (not under allowlist)")
    check(!ok("/usr/lib/foo/bar"), "gate: /usr/... REJECTED")
    check(!ok("/Library/Caches"), "gate: bare /Library/Caches REJECTED (category root)")
    check(!ok("/Library/Logs"), "gate: bare /Library/Logs REJECTED (category root)")
    check(ok("/Library/Caches/com.apple.iconservices.store"), "gate: /Library/Caches/<top-level> ALLOWED (report granularity)")
    check(ok("/Library/Logs/DiagnosticReports"), "gate: /Library/Logs/<top-level> ALLOWED")
    check(!ok("/Library/Caches/.MacCleanerQuarantine/2026/x"), "gate: our quarantine path REJECTED")
    // C2: регистронезависимо
    check(!ok("/LIBRARY/LAUNCHDAEMONS/x.plist"), "gate: case-insensitive danger (LAUNCHDAEMONS) REJECTED")
    // C1: '..' отвергается ДО ФС (полный validate с дефолтной политикой)
    let pol = SafetyPolicy()
    checkThrows("gate: '..' component rejected") { _ = try SystemCleanGate.validate("/Library/Caches/../../etc/passwd", policy: pol) }
    // requirement-строки пиннинга валидны (SecRequirementCreateWithString не падает) — ловит опечатки
    func reqValid(_ s: String) -> Bool {
        var req: SecRequirement?
        return SecRequirementCreateWithString(s as CFString, [], &req) == errSecSuccess && req != nil
    }
    check(reqValid(kAppRequirement), "gate: kAppRequirement is a valid code requirement string")
    check(reqValid(kHelperRequirement), "gate: kHelperRequirement is a valid code requirement string")
}

// 30. Wave 3 Phase 1b/1c — PrivilegedQuarantine: fd-anchored движок на реальных temp-файлах (headless, обычный юзер).
// Гоняем НАСТОЯЩИЙ путь действия (renameatx_np/unlinkat), а не только скан — по уроку verify-action-paths.
// CI (GitHub Actions, headless VM): движок карантина делает реальные root-операции (renameatx_np/fd-walk),
// которые на раннере не отрабатывают → этот интеграционный блок пропускаем именно в CI (локально он идёт).
if ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] != nil {
    print("  skip  (CI headless): privileged-quarantine real-filesystem engine tests (block 30)")
} else {
do {
    func realpathStr(_ p: String) -> String {
        var b = [Int8](repeating: 0, count: Int(PATH_MAX)); return realpath(p, &b) != nil ? String(cString: b) : p
    }
    // Свежий realpath'нутый temp-корень (без симлинк-компонентов — как канонические системные пути).
    func makeBase() -> String {
        let raw = NSTemporaryDirectory() + "mcq-\(getpid())-\(passed)-\(failures)"
        try? FileManager.default.removeItem(atPath: raw)
        try? FileManager.default.createDirectory(atPath: raw, withIntermediateDirectories: true)
        return realpathStr(raw)
    }
    func writeFile(_ path: String, _ s: String) {
        try? FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: path, contents: Data(s.utf8))
    }
    func exists(_ p: String) -> Bool { FileManager.default.fileExists(atPath: p) }
    func ino(_ p: String) -> ino_t { var st = stat(); return lstat(p, &st) == 0 ? st.st_ino : 0 }

    // Движок c temp-allowlist (caches) и temp-qroot (.q под base). expectedUID=getuid() → harden работает под юзером.
    func engine(base: String, strictSource: Bool = true, eligible: Set<String>? = nil) -> PrivilegedQuarantine {
        let caches = base + "/caches"
        let pol = SafetyPolicy()
        return PrivilegedQuarantine(
            prefix: base,
            managed: [PrivilegedQuarantine.ManagedDir(name: ".q", createMode: 0o700, requireMode: 0o700)],
            expectedUID: getuid(),
            validateSource: { raw in
                if strictSource {
                    try pol.validateNoSymlinkComponents(raw)
                    var b = [Int8](repeating: 0, count: Int(PATH_MAX))
                    guard realpath(raw, &b) != nil else { throw SafetyError(reason: "canon") }
                    let c = String(cString: b)
                    guard c.hasPrefix(caches + "/") else { throw SafetyError(reason: "out of test allowlist") }
                    guard !c.contains("/.q/") else { throw SafetyError(reason: "quarantine source") }
                    return c
                } else {
                    return raw   // «слабый» валидатор: проверяем, что fd-walk движка сам ловит симлинк-промежуток
                }
            },
            validateDest: { parent, basename in
                try pol.validateNoSymlinkComponents(parent)
                var b = [Int8](repeating: 0, count: Int(PATH_MAX))
                guard realpath(parent, &b) != nil else { throw SafetyError(reason: "canon parent") }
                let pc = String(cString: b)
                guard (pc + "/" + basename).hasPrefix(caches + "/") else { throw SafetyError(reason: "dest out of allowlist") }
                return pc
            },
            eligibleSource: eligible.map { set in { set } }
        )
    }

    // 30.1 Round-trip: quarantine → list → restore (тот же inode назад, на то же место).
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let src = base + "/caches/app/cache.db"; writeFile(src, "payload-data")
        let srcIno = ino(src)
        let q = e.quarantine([src])
        check(q.count == 1 && q[0].ok && q[0].entryID != nil, "q.roundtrip: quarantine ok")
        check(!exists(src), "q.roundtrip: source moved out")
        let listed = e.list()
        check(listed.count == 1 && listed[0].originalPath == src && listed[0].valid, "q.roundtrip: list shows entry at original path")
        let r = e.restore([listed[0].entryID])
        check(r.count == 1 && r[0].ok, "q.roundtrip: restore ok")
        check(exists(src) && ino(src) == srcIno, "q.roundtrip: file back at original path, same inode")
        check(e.list().isEmpty, "q.roundtrip: entry gone after restore")
        check((try? String(contentsOfFile: src, encoding: .utf8)) == "payload-data", "q.roundtrip: content intact")
    }

    // 30.2 Symlink-лист источника отвергается (через слабый валидатор → отказ на fstatat S_IFLNK).
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base, strictSource: false)
        writeFile(base + "/caches/real.txt", "x")
        let link = base + "/caches/link.txt"; symlink(base + "/caches/real.txt", link)
        let q = e.quarantine([link])
        check(!q[0].ok && (q[0].error?.contains("symlink") ?? false), "q.symlink-leaf: refused")
        check(exists(link) && exists(base + "/caches/real.txt"), "q.symlink-leaf: nothing moved")
    }

    // 30.3 Симлинк на ПРОМЕЖУТОЧНОМ компоненте: даже при слабом валидаторе fd-walk движка отвергает (ELOOP).
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base, strictSource: false)
        let sentinel = base + "/secret/passwd"; writeFile(sentinel, "root:x:0:0")
        symlink(base + "/secret", base + "/caches/evil")          // caches/evil -> base/secret
        let q = e.quarantine([base + "/caches/evil/passwd"])      // путь через симлинк-промежуток
        check(!q[0].ok, "q.symlink-intermediate: refused by engine fd-walk")
        check(exists(sentinel), "q.symlink-intermediate: target untouched")
    }

    // 30.4 No-clobber на restore: жертву на исходном месте RENAME_EXCL не затирает.
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let src = base + "/caches/c/file.bin"; writeFile(src, "original")
        let id = e.quarantine([src])[0].entryID!
        writeFile(src, "VICTIM")                                  // на исходном месте появился новый файл
        let r = e.restore([id])
        check(!r[0].ok && (r[0].error?.contains("occupied") ?? false), "q.no-clobber: restore refused (occupied)")
        check((try? String(contentsOfFile: src, encoding: .utf8)) == "VICTIM", "q.no-clobber: victim intact")
        check(e.list().count == 1, "q.no-clobber: payload retained in quarantine")
    }

    // 30.5 Отравленный sidecar: originalParentPath вне allowlist → validateDest отвергает restore (sidecar НЕдоверен).
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let src = base + "/caches/d/f.dat"; writeFile(src, "z")
        let id = e.quarantine([src])[0].entryID!
        // перезаписываем origin.json злонамеренным родителем вне caches (мы владеем temp-qroot 0600 → проходит integrity).
        let sidecar = base + "/.q/" + id + "/origin.json"
        let poisoned = base + "/outside"; try? FileManager.default.createDirectory(atPath: poisoned, withIntermediateDirectories: true)
        var entry = try! JSONDecoder().decode(QEntry.self, from: Data(contentsOf: URL(fileURLWithPath: sidecar)))
        entry.originalParentPath = poisoned; entry.originalBasename = "planted"
        try! JSONEncoder().encode(entry).write(to: URL(fileURLWithPath: sidecar))
        let r = e.restore([id])
        check(!r[0].ok && (r[0].error?.contains("allowlist") ?? false), "q.poison: restore refused (dest out of allowlist)")
        check(!exists(poisoned + "/planted"), "q.poison: nothing planted outside allowlist")
    }

    // 30.6 Хардлинк-источник (nlink!=1) отвергается; второй линк цел.
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let a = base + "/caches/h/a.bin"; writeFile(a, "shared")
        let b = base + "/caches/h/b.bin"; link(a, b)
        let q = e.quarantine([a])
        check(!q[0].ok && (q[0].error?.contains("hardlink") ?? false), "q.hardlink: refused")
        check(exists(a) && exists(b), "q.hardlink: both links intact")
    }

    // 30.7 Враждебный qroot: .q с mode 0777 (не 0700) → отказ; симлинк-.q → отказ.
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        try? FileManager.default.createDirectory(atPath: base + "/.q", withIntermediateDirectories: true)
        chmod(base + "/.q", 0o777)
        let e = engine(base: base)
        writeFile(base + "/caches/x.txt", "x")
        check(!e.quarantine([base + "/caches/x.txt"])[0].ok, "q.hostile-root: 0777 qroot refused")
    }
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        symlink("/tmp", base + "/.q")                            // .q как симлинк
        let e = engine(base: base)
        writeFile(base + "/caches/x.txt", "x")
        check(!e.quarantine([base + "/caches/x.txt"])[0].ok, "q.hostile-root: symlink qroot refused (ELOOP)")
    }

    // 30.8 empty() с симлинком ВНУТРИ payload: ссылка снимается, цель снаружи выживает.
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let sentinel = base + "/sentinel.txt"; writeFile(sentinel, "alive")
        let dir = base + "/caches/pkg"; writeFile(dir + "/inner.txt", "in")
        symlink(sentinel, dir + "/escape")                      // payload содержит симлинк наружу
        let id = e.quarantine([dir])[0].entryID!
        let r = e.empty([id], confirm: true)
        check(r[0].ok, "q.empty: ok")
        check(exists(sentinel), "q.empty: outside sentinel survived (symlink unlinked, not followed)")
        check(!exists(base + "/.q/" + id), "q.empty: entry dir gone")
        check((try? String(contentsOfFile: sentinel, encoding: .utf8)) == "alive", "q.empty: sentinel content intact")
    }

    // 30.9 empty без confirm → отказ (необратимая операция).
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let src = base + "/caches/e/f.x"; writeFile(src, "y")
        let id = e.quarantine([src])[0].entryID!
        check(!e.empty([id], confirm: false)[0].ok, "q.empty: refused without confirm")
        check(e.list().count == 1, "q.empty: entry retained when not confirmed")
    }

    // 30.10 Монотонные id из .seq (без Date.now/random): три записи → 0…01, 0…02, 0…03.
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        for i in 0..<3 { writeFile(base + "/caches/m/f\(i).x", "v\(i)") }
        let ids = (0..<3).compactMap { e.quarantine([base + "/caches/m/f\($0).x"])[0].entryID }
        check(ids == ["0000000000000001", "0000000000000002", "0000000000000003"], "q.seq: monotonic hex ids")
        check(Set(ids).count == 3, "q.seq: all distinct")
    }

    // 30.11 list.valid=false когда payload пропал; id-regex и restore несуществующего id.
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let id = e.quarantine([{ let p = base + "/caches/v/f.x"; writeFile(p, "p"); return p }()])[0].entryID!
        try? FileManager.default.removeItem(atPath: base + "/.q/" + id + "/payload")
        check(e.list().first?.valid == false, "q.list: valid=false when payload vanished")
        check(PrivilegedQuarantine.isValidID("0000000000000001"), "q.id: valid 16-hex accepted")
        check(!PrivilegedQuarantine.isValidID("../etc"), "q.id: traversal id rejected")
        check(!PrivilegedQuarantine.isValidID("DEADBEEF"), "q.id: non-lowercase/short rejected")
        check(!e.restore(["../../etc/passwd"])[0].ok, "q.id: restore of bogus id refused")
    }

    // 30.12 allowlist источника: depth/вне-allowlist путь отвергается строгим валидатором (как в prod через SystemCleanGate).
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        writeFile(base + "/notcaches/secret.txt", "s")
        check(!e.quarantine([base + "/notcaches/secret.txt"])[0].ok, "q.allowlist: out-of-allowlist source refused")
    }

    // 30.13 КАТАЛОГ-источник (главная цель — кэш-папки): bytes/reclaimable считаются (раньше nlink≥2 у каталога → 0).
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let dir = base + "/caches/bigcache"
        writeFile(dir + "/a.bin", String(repeating: "x", count: 200_000))
        writeFile(dir + "/sub/b.bin", "y")                     // подкаталог → st_nlink каталога ≥3
        let q = e.quarantine([dir])
        check(q[0].ok && q[0].bytes > 0, "q.diraccount: directory reports bytes>0 (not 0)")
        let id = q[0].entryID!
        check(e.list().first(where: { $0.entryID == id })?.reclaimable == true, "q.diraccount: directory reclaimable=true")
        let r = e.empty([id], confirm: true)
        check(r[0].ok && r[0].bytes > 0, "q.diraccount: empty reports bytes>0 for directory")
    }

    // 30.14 isValidID: точная привязка (хвостовой '\n'/' ', верхний регистр — отвергаются).
    do {
        check(!PrivilegedQuarantine.isValidID("0000000000000001\n"), "q.id: trailing newline REJECTED")
        check(!PrivilegedQuarantine.isValidID("0000000000000001 "), "q.id: trailing space REJECTED")
        check(PrivilegedQuarantine.isValidID("00000000000000ab"), "q.id: lowercase hex accepted")
        check(!PrivilegedQuarantine.isValidID("00000000000000AB"), "q.id: uppercase hex REJECTED")
    }

    // 30.15 reconcile: сорванный коммит (payload есть, origin.json не записан) ДОвосстанавливается, запись видна+восстановима.
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let src = base + "/caches/r/f.dat"; writeFile(src, "recoverme")
        let id = e.quarantine([src])[0].entryID!
        let edir = base + "/.q/" + id
        // симулируем падение между move и commit: origin.json → origin.json.pending (payload остаётся).
        try? FileManager.default.moveItem(atPath: edir + "/origin.json", toPath: edir + "/origin.json.pending")
        let listed = e.list()                                  // list → openQuarantineRoot → reconcile → ДОкоммит
        check(listed.contains { $0.entryID == id }, "q.reconcile: stranded commit recovered (visible)")
        let r = e.restore([id])
        check(r[0].ok && exists(src), "q.reconcile: recovered entry restores to original path")
    }

    // 30.16 reconcile: orphan-каталог (только pending, БЕЗ payload — переноса не было) сносится; валидная запись цела.
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let keep = base + "/caches/o/keep.dat"; writeFile(keep, "k")
        _ = e.quarantine([keep])
        let orphan = base + "/.q/000000000000dead"
        try? FileManager.default.createDirectory(atPath: orphan, withIntermediateDirectories: true)
        chmod(orphan, 0o700)
        FileManager.default.createFile(atPath: orphan + "/origin.json.pending", contents: Data("{}".utf8))
        chmod(orphan + "/origin.json.pending", 0o600)
        check(exists(orphan), "q.orphan: crafted orphan present")
        let listed = e.list()                                  // reconcile сносит orphan
        check(!exists(orphan), "q.orphan: orphan (no payload) removed by reconcile")
        check(listed.count == 1, "q.orphan: valid entry untouched")
    }

    // 30.17 Codex-2: карантин принимает ТОЛЬКО пути из свежего eligible-набора (иначе отказ).
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let src = base + "/caches/app/cache.db"; writeFile(src, "x")
        var b = [Int8](repeating: 0, count: Int(PATH_MAX)); _ = realpath(src, &b)
        let canon = String(cString: b)
        // пустой eligible → отказ даже валидному (allowlist-проходящему) пути
        check(!engine(base: base, eligible: []).quarantine([src])[0].ok,
              "q.eligibility: empty eligible rejects an allowlisted path")
        check(exists(src), "q.eligibility: rejected path not moved")
        // eligible содержит путь → принимается
        check(engine(base: base, eligible: [canon]).quarantine([src])[0].ok,
              "q.eligibility: listed path accepted")
    }

    // 30.18 Аптинсталл: purgeAll опустошает карантин и сносит управляемый каталог (.q). confirm обязателен, идемпотентно.
    do {
        let base = makeBase(); defer { try? FileManager.default.removeItem(atPath: base) }
        let e = engine(base: base)
        let a = base + "/caches/o/a.dat"; writeFile(a, String(repeating: "a", count: 5000))
        let b2 = base + "/caches/o/b.dat"; writeFile(b2, String(repeating: "b", count: 5000))
        _ = e.quarantine([a, b2])
        let q = base + "/.q"
        check(exists(q), "purge: quarantine dir exists before purge")
        check(!exists(a) && !exists(b2), "purge: sources moved into quarantine")
        // confirm обязателен
        let refused = e.purgeAll(confirm: false)
        check(!refused.ok && exists(q), "purge: refused without confirm (nothing removed)")
        // полная очистка
        let r = e.purgeAll(confirm: true)
        check(r.ok, "purge: ok with confirm")
        check(r.itemsRemoved == 2, "purge: reports 2 items removed")
        check(r.bytesFreed > 0, "purge: reports freed bytes")
        check(!exists(q), "purge: managed quarantine dir removed")
        check(exists(base), "purge: prefix (base) itself untouched")
        // идемпотентность: повтор на отсутствующем карантине — ok, 0 объектов
        let again = e.purgeAll(confirm: true)
        check(again.ok && again.itemsRemoved == 0, "purge: idempotent when already clean")
    }
}
}  // конец CI-пропуска блока 30

// 31. Wave 3 — расширение System Cleanup (рой-вердикт 2026-06-19): новые danger-prefix, keychain, SystemReport-предикаты.
do {
    func ok(_ p: String) -> Bool { (try? SystemCleanGate.checkCanonical(p)) != nil }
    // новые danger-prefix отвергаются
    check(!ok("/private/var/vm/swapfile0"), "ext: /private/var/vm REJECTED (new danger)")
    check(!ok("/Library/Updates/index.plist"), "ext: /Library/Updates REJECTED (new danger)")
    check(!ok("/private/var/install/x"), "ext: /private/var/install REJECTED (new danger)")
    check(!ok("/System/Volumes/Update/foo"), "ext: /System/Volumes/Update REJECTED")
    // существующие гарантии целы
    check(!ok("/private/var/db/diagnostics/x.tracev3"), "ext: var/db still REJECTED")
    check(!ok("/private/var/folders/ab/cd/C/x"), "ext: var/folders still REJECTED")
    check(!ok("/System/Library/Caches/com.apple.kext.caches/x"), "ext: /System still REJECTED")
    // безопасные цели по-прежнему проходят
    check(ok("/Library/Caches/com.apple.iconservices.store"), "ext: iconservices.store ALLOWED")
    check(ok("/Library/Logs/DiagnosticReports/Foo-2026.ips"), "ext: diagnostic report file ALLOWED (depth 4)")

    // keychain → личные данные (физически недоступно для чистки)
    let pol = SafetyPolicy(home: "/Users/tester")
    check(pol.isPersonalData("/Users/tester/Library/Keychains/login.keychain-db"), "ext: ~/Library/Keychains is personal-data")
    checkThrows("ext: keychain validatePath refuses") { try pol.validatePath("/Users/tester/Library/Keychains/login.keychain-db") }

    // SystemReport-предикаты (чистые, тестируемы)
    check(SystemReport.isDataVault("com.apple.aned"), "ext: aned is data-vault")
    check(SystemReport.isDataVault("com.apple.amsengagementd.classicdatavault"), "ext: classicdatavault is data-vault")
    check(SystemReport.isDataVault("com.apple.SomeFutureDataVault"), "ext: *datavault suffix caught generically")
    check(!SystemReport.isDataVault("com.apple.iconservices.store"), "ext: iconservices NOT a data-vault")
    check(SystemReport.isRotatedArchive("system.log.0.gz"), "ext: *.gz is rotated archive")
    check(SystemReport.isRotatedArchive("wifi.log.3"), "ext: name.<digits> is rotated archive")
    check(!SystemReport.isRotatedArchive("system.log"), "ext: live system.log NOT an archive")
    check(!SystemReport.isRotatedArchive("install.log"), "ext: live install.log NOT an archive")
    check(SystemReport.isProtectedReport("Kernel-2026.panic"), "ext: panic report protected")
    check(SystemReport.isProtectedReport("panic-full-2026.ips"), "ext: panic- prefix protected")
    check(!SystemReport.isProtectedReport("MyApp-2026.ips"), "ext: normal report not protected")
    let nowT = time_t(2_000_000_000)
    check(SystemReport.isOldReport(mtime: nowT - 40 * 86_400, now: nowT), "ext: 40d-old report is old")
    check(!SystemReport.isOldReport(mtime: nowT - 3 * 86_400, now: nowT), "ext: 3d-old report kept (recent)")
}

// 32. Codex third audit (2026-06-20): H1 (том), M6 (вложенные .app), M9 (Dups непрозрачные пакеты).
do {
    func mk(_ p: String) { try? FileManager.default.createDirectory(atPath: p, withIntermediateDirectories: true) }
    let base = NSTemporaryDirectory() + "codex3-\(getpid())"
    mk(base); defer { try? FileManager.default.removeItem(atPath: base) }

    // --- H1: Scanner.isOnVolume / homeVolumeDevice ---
    let f = base + "/x.bin"
    FileManager.default.createFile(atPath: f, contents: Data([1, 2, 3]))
    var st = stat(); _ = lstat(f, &st); let dev = st.st_dev
    check(Scanner.isOnVolume(f, device: dev), "H1: path on its own volume → true")
    check(!Scanner.isOnVolume(f, device: dev &+ 99_999), "H1: path on a DIFFERENT volume → false (NAS/external rejected)")
    check(!Scanner.isOnVolume(base + "/nope.bin", device: dev), "H1: missing path → false")
    if let hd = Scanner.homeVolumeDevice() {
        check(Scanner.isOnVolume(NSHomeDirectory(), device: hd), "H1: home is on the home volume")
    } else { check(true, "H1: home device unresolved (skipped)") }

    // --- M6: appBundles depth (вложенные вендорские .app только при depth 1, внутрь .app не заходим) ---
    mk(base + "/Vendor/Foo.app/Contents")
    mk(base + "/Top.app/Contents")
    let d0 = Apps.appBundles(in: base, depth: 0)
    let d1 = Apps.appBundles(in: base, depth: 1)
    check(d0.contains { $0.hasSuffix("/Top.app") }, "M6: depth0 finds direct Top.app")
    check(!d0.contains { $0.hasSuffix("/Foo.app") }, "M6: depth0 does NOT find nested Vendor/Foo.app")
    check(d1.contains { $0.hasSuffix("/Foo.app") }, "M6: depth1 finds nested Vendor/Foo.app")
    check(!d1.contains { $0.contains("/Foo.app/") }, "M6: never descends INTO a .app bundle")

    // --- M9: Dups пропускает внутренности .photoslibrary, но настоящие копии вне пакета группирует ---
    let lib = base + "/My.photoslibrary/originals"; mk(lib)
    let blob = Data(repeating: 7, count: 200_000)
    FileManager.default.createFile(atPath: base + "/a.bin", contents: blob)
    FileManager.default.createFile(atPath: base + "/b.bin", contents: blob)   // дубль a.bin (вне пакета)
    FileManager.default.createFile(atPath: lib + "/c.bin", contents: blob)    // тот же контент, НО в .photoslibrary
    let dgroups = Dups.scan(root: base, minBytes: 100_000, policy: SafetyPolicy(home: base))
    let dpaths = dgroups.flatMap { $0.files.map(\.path) }
    check(!dpaths.contains { $0.contains(".photoslibrary") }, "M9: .photoslibrary internals excluded from Dups")
    check(dgroups.contains { $0.files.count == 2 }, "M9: the two real copies (a.bin,b.bin) still grouped")

    // --- M7: root-side size-walkers считают обычную папку (>0) и не ломаются от mount-guard (однотомный случай) ---
    let szDir = base + "/szdir"; mk(szDir)
    FileManager.default.createFile(atPath: szDir + "/f.bin", contents: Data(repeating: 9, count: 20_000))
    check(SystemReport.dirSize(szDir) > 0, "M7: SystemReport.dirSize counts a normal dir")
    check(PrivilegedQuarantine.allocatedSize(szDir, isDir: true) > 0, "M7: allocatedSize counts a normal dir")
}

// 33. Аудит 2 (холодный рой, 2026-06-20): I1 (расширенный личный блок), L6 (open hardening), I8 (var/log age-gate).
do {
    // --- I1: расширенный жёсткий блок личных папок (Dups больше не предложит дубль изнутри) ---
    let pol = SafetyPolicy(home: "/Users/i1tester")
    for sub in [".config/gh/hosts.yml", ".kube/config", ".netrc", ".zsh_history", ".bash_history",
                "Library/Calendars/x.ics", "Library/Reminders/r.db", "Library/Application Support/AddressBook/db"] {
        check(pol.isPersonalData("/Users/i1tester/" + sub), "I1: \(sub) is personal-data")
        checkThrows("I1: validatePath refuses \(sub)") { try pol.validatePath("/Users/i1tester/" + sub) }
    }
    // dev-кэши НЕ задеты — остаются чистимыми (не над-блокировали)
    check(!pol.isPersonalData("/Users/i1tester/Library/Caches/black"), "I1: ~/Library/Caches/black still cleanable")
    check(!pol.isPersonalData("/Users/i1tester/.cache/huggingface"), "I1: ~/.cache still cleanable")

    // --- L6: open hardening — симлинк/FIFO не уводят хэш и НЕ вешают скан ---
    let base = NSTemporaryDirectory() + "audit2-\(getpid())"
    try? FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: base) }
    let real = base + "/real.bin"
    FileManager.default.createFile(atPath: real, contents: Data(repeating: 5, count: 4096))
    check(Dups.openRegularFD(real) != nil, "L6: openRegularFD opens a regular file")
    check(Dups.partialKey(real, size: 4096) != nil, "L6: regular file still hashed")
    let link = base + "/link.bin"
    try? FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
    check(Dups.openRegularFD(link) == nil, "L6: symlink rejected (O_NOFOLLOW)")
    check(Dups.partialKey(link, size: 4096) == nil, "L6: partialKey on symlink → nil (not followed)")
    let fifo = base + "/pipe"
    check(mkfifo(fifo, 0o644) == 0, "L6: mkfifo created")
    check(Dups.openRegularFD(fifo) == nil, "L6: FIFO rejected (no hang)")
    check(Dups.partialKey(fifo, size: 10) == nil, "L6: partialKey on FIFO → nil (no hang)")
    check(Dups.cloneKey(fifo, size: 10) == nil, "L6: cloneKey on FIFO → nil (no hang)")

    // --- I8: var/log offer — сжатые архивы всегда, голый «.<digits>» только если реально старый ---
    let nowT = time_t(2_000_000_000)
    check(SystemReport.isOfferableRotatedLog("system.log.0.gz", mtime: nowT, now: nowT), "I8: fresh .gz offered (closed archive)")
    check(SystemReport.isOfferableRotatedLog("wifi.log.3.bz2", mtime: nowT, now: nowT), "I8: fresh .bz2 offered")
    check(!SystemReport.isOfferableRotatedLog("keybagd.log.0", mtime: nowT, now: nowT), "I8: today's keybagd.log.0 NOT offered (active)")
    check(SystemReport.isOfferableRotatedLog("keybagd.log.0", mtime: nowT - 40 * 86_400, now: nowT), "I8: 40d-old .0 offered")
    check(!SystemReport.isOfferableRotatedLog("system.log", mtime: nowT, now: nowT), "I8: live system.log not offered")
}

// --- Unavailable simulators (Xcode deep-clean): только Shutdown + рантайм-не-установлен, с защитами ---
do {
    let fm = FileManager.default
    let root = NSTemporaryDirectory() + "mc-simtest-\(getpid())"
    let devDir = root + "/Devices"
    try? fm.createDirectory(atPath: devDir, withIntermediateDirectories: true)
    defer { try? fm.removeItem(atPath: root) }

    let INSTALLED = "com.apple.CoreSimulator.SimRuntime.iOS-99-9"
    let GONE = "com.apple.CoreSimulator.SimRuntime.iOS-1-1"

    func writePlist(_ obj: [String: Any], _ path: String) {
        let data = try! PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0)
        try? data.write(to: URL(fileURLWithPath: path))
    }
    // device-папка с device.plist и ненулевым размером
    func mkDevice(_ udid: String, runtime: String, state: Int, plist: Bool = true) {
        let dd = devDir + "/" + udid
        try? fm.createDirectory(atPath: dd + "/data", withIntermediateDirectories: true)
        fm.createFile(atPath: dd + "/data/blob", contents: Data(count: 4096))
        if plist {
            writePlist(["state": state, "runtime": runtime, "UDID": udid,
                        "name": "Sim-\(udid.prefix(4))", "isDeleted": false], dd + "/device.plist")
        }
    }
    let uAvail     = "AAAAAAAA-0000-4000-8000-000000000001"   // рантайм установлен → живой
    let uUnavail   = "BBBBBBBB-0000-4000-8000-000000000002"   // рантайм удалён + Shutdown → КАНДИДАТ
    let uBooted    = "CCCCCCCC-0000-4000-8000-000000000003"   // рантайм удалён, но Booted(3) → не трогаем
    let uProtected = "DDDDDDDD-0000-4000-8000-000000000004"   // в DefaultDevices → защищён
    let uNoPlist   = "EEEEEEEE-0000-4000-8000-000000000005"   // нет device.plist → fail-closed
    mkDevice(uAvail,     runtime: INSTALLED, state: 1)
    mkDevice(uUnavail,   runtime: GONE,      state: 1)
    mkDevice(uBooted,    runtime: GONE,      state: 3)
    mkDevice(uProtected, runtime: GONE,      state: 1)
    mkDevice(uNoPlist,   runtime: GONE,      state: 1, plist: false)

    let imagesPath = root + "/images.plist"
    writePlist(["images": [["signatureState": ["verified": ["": 1]],
                            "runtimeInfo": ["bundleIdentifier": INSTALLED]]],
                "standaloneBundles": []], imagesPath)
    writePlist(["DefaultDevices": [GONE: ["com.apple.CoreSimulator.SimDeviceType.iPhone-X": uProtected]],
                "DevicePairs": [:], "Version": 0], devDir + "/device_set.plist")

    let cands = Simulators.unavailableDevices(devicesDir: devDir, imagesPlist: imagesPath, runtimesDirs: [])
    let got = Set(cands.map { ($0.path as NSString).lastPathComponent.uppercased() })
    check(got.contains(uUnavail), "sim: unavailable+Shutdown device offered")
    check(!got.contains(uAvail), "sim: device with INSTALLED runtime NOT offered (live)")
    check(!got.contains(uBooted), "sim: unavailable but BOOTED device NOT offered")
    check(!got.contains(uProtected), "sim: DefaultDevices-protected device NOT offered")
    check(!got.contains(uNoPlist), "sim: unreadable device.plist NOT offered (fail-closed)")
    check(cands.count == 1, "sim: exactly one candidate (only the genuine unavailable)")

    // fail-closed: установленные рантаймы неизвестны → не предлагаем НИЧЕГО (иначе снесли бы живые)
    let emptyImg = root + "/empty.plist"
    writePlist(["images": [], "standaloneBundles": []], emptyImg)
    check(Simulators.unavailableDevices(devicesDir: devDir, imagesPlist: emptyImg, runtimesDirs: []).isEmpty,
          "sim: no installed runtimes known → offer nothing (fail-closed)")
    check(Simulators.unavailableDevices(devicesDir: devDir, imagesPlist: root + "/nope.plist", runtimesDirs: []).isEmpty,
          "sim: missing images.plist → offer nothing (fail-closed)")

    // F-1: рантайм отсутствует в images.plist, но установлен как .simruntime на диске →
    // живое устройство НЕ должно предлагаться (второй источник «установленных» рантаймов).
    let rtDir = root + "/RT"
    let rtBundle = rtDir + "/iOS 1.1.simruntime/Contents"
    try? fm.createDirectory(atPath: rtBundle, withIntermediateDirectories: true)
    writePlist(["CFBundleIdentifier": GONE], rtBundle + "/Info.plist")
    check(Simulators.installedRuntimeIDs(imagesPlist: imagesPath, runtimesDirs: [rtDir]).contains(GONE),
          "sim F-1: on-disk .simruntime bundle counts as an installed runtime")
    let candsRT = Simulators.unavailableDevices(devicesDir: devDir, imagesPlist: imagesPath, runtimesDirs: [rtDir])
    check(candsRT.allSatisfy { ($0.path as NSString).lastPathComponent.uppercased() != uUnavail },
          "sim F-1: device whose runtime exists only as on-disk .simruntime is NOT offered")

    // чистые хелперы
    check(Simulators.isUDID("018E5F8D-6280-49A1-9960-B3D679818B5C"), "sim: valid UDID recognized")
    check(!Simulators.isUDID("device_set.plist"), "sim: non-UDID name rejected")
    check(Simulators.runtimeLabel("com.apple.CoreSimulator.SimRuntime.iOS-26-5") == "iOS 26.5", "sim: runtime label humanized")
    check(Simulators.installedRuntimeIDs(imagesPlist: imagesPath, runtimesDirs: []) == [INSTALLED], "sim: installed runtime parsed (signatureState.verified)")
}

// --- Simulator leftovers (Dead/temp.* + XCTestDevices): только Shutdown, только temp.*, анти-гонка ---
do {
    let fm = FileManager.default
    let root = NSTemporaryDirectory() + "mc-simleft-\(getpid())"
    let devDir = root + "/Devices"
    let xcDir = root + "/XCTestDevices"
    try? fm.createDirectory(atPath: devDir, withIntermediateDirectories: true)
    try? fm.createDirectory(atPath: xcDir, withIntermediateDirectories: true)
    defer { try? fm.removeItem(atPath: root) }

    func writePlist(_ obj: [String: Any], _ path: String) {
        let data = try! PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0)
        try? data.write(to: URL(fileURLWithPath: path))
    }
    func devPlist(_ dir: String, udid: String, state: Int) {
        writePlist(["state": state, "runtime": "com.apple.CoreSimulator.SimRuntime.iOS-99-9",
                    "UDID": udid, "name": "Sim-\(udid.prefix(4))", "isDeleted": false], dir + "/device.plist")
    }
    // устройство с Dead/temp.AAA (→ кандидат) + сосед System/ (НЕ трогаем)
    func mkDeadDevice(_ udid: String, state: Int, plist: Bool = true) {
        let cmd = devDir + "/" + udid + "/data/Library/Caches/com.apple.containermanagerd"
        try? fm.createDirectory(atPath: cmd + "/Dead/temp.AAA", withIntermediateDirectories: true)
        fm.createFile(atPath: cmd + "/Dead/temp.AAA/blob", contents: Data(count: 8192))
        try? fm.createDirectory(atPath: cmd + "/System", withIntermediateDirectories: true)
        fm.createFile(atPath: cmd + "/System/blob", contents: Data(count: 8192))
        if plist { devPlist(devDir + "/" + udid, udid: udid, state: state) }
    }
    let dShut = "11111111-0000-4000-8000-000000000001"   // Shutdown → temp.AAA предлагается
    let dBoot = "22222222-0000-4000-8000-000000000002"   // Booted → ничего
    let dNoPl = "33333333-0000-4000-8000-000000000003"   // нет device.plist → fail-closed
    mkDeadDevice(dShut, state: 1)
    mkDeadDevice(dBoot, state: 3)
    mkDeadDevice(dNoPl, state: 1, plist: false)

    // XCTestDevices: старый Shutdown → да; свежий → нет (анти-гонка); Booted → нет
    let nowTS = 2_000_000_000.0
    func mkXC(_ udid: String, state: Int, ageSec: Double) {
        let dir = xcDir + "/" + udid
        try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        fm.createFile(atPath: dir + "/blob", contents: Data(count: 8192))
        devPlist(dir, udid: udid, state: state)
        try? fm.setAttributes([.modificationDate: Date(timeIntervalSince1970: nowTS - ageSec)], ofItemAtPath: dir)
    }
    let xOld = "44444444-0000-4000-8000-000000000004"
    let xNew = "55555555-0000-4000-8000-000000000005"
    let xBoot = "66666666-0000-4000-8000-000000000006"
    mkXC(xOld, state: 1, ageSec: 3600)    // 1ч → старый
    mkXC(xNew, state: 1, ageSec: 60)      // 1мин → слишком свежий
    mkXC(xBoot, state: 3, ageSec: 3600)

    let items = Simulators.leftovers(devicesDir: devDir, xctestDir: xcDir, now: nowTS)
    let paths = items.map(\.path)
    check(paths.contains { $0.hasSuffix("/Dead/temp.AAA") && $0.contains(dShut) }, "left: Dead/temp.* in Shutdown device offered")
    check(!paths.contains { $0.contains(dBoot) }, "left: Dead/temp.* in Booted device NOT offered")
    check(!paths.contains { $0.contains(dNoPl) }, "left: device without device.plist NOT offered (fail-closed)")
    check(!paths.contains { $0.hasSuffix("/System") || $0.hasSuffix("/Dead") }, "left: Dead/ itself and System sibling NOT offered")
    check(paths.contains { $0.hasSuffix("/" + xOld) }, "left: old Shutdown XCTestDevice clone offered")
    check(!paths.contains { $0.hasSuffix("/" + xNew) }, "left: fresh (<10min) XCTestDevice clone NOT offered (anti-race)")
    check(!paths.contains { $0.hasSuffix("/" + xBoot) }, "left: Booted XCTestDevice clone NOT offered")
}

print("\n— \(passed) passed, \(failures) failed —")
exit(failures == 0 ? 0 : 1)
