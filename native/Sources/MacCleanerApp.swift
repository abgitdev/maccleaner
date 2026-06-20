import SwiftUI
import AppKit
import ImageIO
import ServiceManagement

@main
struct MacCleanerApp: App {
    @StateObject private var model = CleanerModel()
    var body: some Scene {
        WindowGroup("MacCleaner") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 1120, idealWidth: 1200, minHeight: 624, idealHeight: 648)
                .preferredColorScheme(.dark)
                .onAppear { ActivityLog.shared.log("session", "MacCleaner launched") }
        }
        .windowResizability(.contentMinSize)
    }
}

enum AppMode: Hashable { case dashboard, cleaning, largeFiles, duplicates, similar, apps, system, processes }
enum ProcSort: Hashable { case cpu, memory }
enum LargeSort: Hashable { case size, age }

struct ClassifiedFile: Identifiable {
    let file: LargeFile
    let cls: Classification
    var id: String { file.path }
}

// MARK: - Модель

@MainActor
final class CleanerModel: ObservableObject {
    @Published var mode: AppMode = .dashboard
    @Published var fda: FDAStatus = .checking

    // чистка
    @Published var groups: [ScanGroup] = []
    @Published var reportGroups: [ScanGroup] = []   // report-only: показываем, но не удаляем
    @Published var selected: Set<String> = []
    @Published var isScanning = false
    @Published var lastResult: String?

    // крупные файлы
    @Published var largeFiles: [LargeFile] = []
    @Published var isFindingLarge = false
    @Published var largeScanned = false
    @Published var largeSelected: Set<String> = []
    @Published var largeSort: LargeSort = .size

    // дубликаты
    @Published var dups: [DupGroup] = []
    @Published var isFindingDups = false
    @Published var isTrashingDups = false
    @Published var dupsScanned = false
    @Published var dupsSelected: Set<String> = []
    @Published var dupsProgress: Double = 0
    @Published var dupsStage = ""
    @Published var dupsResult: String?

    // приложения (аптинсталлер + осиротевшие остатки)
    @Published var apps: [InstalledApp] = []
    @Published var orphans: [OrphanApp] = []
    @Published var isFindingApps = false
    @Published var isUninstalling = false
    @Published var appsScanned = false
    @Published var appSelected: Set<String> = []
    @Published var appsProgress: Double = 0
    @Published var appsStage = ""
    @Published var appsResult: String?

    // похожие фото (перцептивный хэш)
    @Published var sims: [SimilarGroup] = []
    @Published var isFindingSims = false
    @Published var isTrashingSims = false
    @Published var simsScanned = false
    @Published var simSelected: Set<String> = []
    @Published var simsProgress: Double = 0
    @Published var simsStage = ""
    @Published var simsResult: String?

    // процессы
    @Published var procs: [ProcInfo] = []
    @Published var isLoadingProcs = false
    @Published var procsLoaded = false
    @Published var procSort: ProcSort = .cpu
    @Published var procMessage: String?

    // дашборд (реальные метрики)
    @Published var disk = DiskInfo(totalBytes: 0, freeBytes: 0)
    @Published var mem = MemInfo(totalBytes: 0, usedBytes: 0)
    @Published var cpuHistory: [Double] = []
    @Published var memHistory: [Double] = []
    @Published var gpuHistory: [Double] = []
    @Published var tempC: Double?
    @Published var tempHistory: [Double] = []
    @Published var thermalState = "—"

    // карта хранилища (адаптивная разбивка по категориям)
    @Published var storage: StorageReport?
    @Published var isMappingStorage = false
    @Published var storageProgress: Double = 0
    @Published var storageStage = ""

    private let policy = SafetyPolicy()
    private let cpuSampler = CPUSampler()
    private var timer: Timer?

    func start() {
        refreshFDA()
        disk = SystemStats.disk()
        scan()
        mapStorage()
        _ = cpuSampler.sample()                 // первичный замер
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tickMetrics() }
        }
        tickMetrics()
    }

    private func tickMetrics() {
        mem = SystemStats.memory()
        disk = SystemStats.disk()
        let cpu = cpuSampler.sample()
        cpuHistory.append(cpu); if cpuHistory.count > 46 { cpuHistory.removeFirst() }
        let memGB = Double(mem.usedBytes) / 1_073_741_824
        memHistory.append(memGB); if memHistory.count > 46 { memHistory.removeFirst() }
        gpuHistory.append(SystemStats.gpuUsage()); if gpuHistory.count > 46 { gpuHistory.removeFirst() }
        tempC = Thermal.cpuTemperature()
        if let t = tempC { tempHistory.append(t); if tempHistory.count > 46 { tempHistory.removeFirst() } }
        thermalState = SystemStats.thermalStateString()
    }

    func refreshFDA() {
        fda = .checking
        DispatchQueue.global(qos: .userInitiated).async {
            let r = FullDiskAccess.check()
            DispatchQueue.main.async { self.fda = r }
        }
    }

    // MARK: чистка

    func scan() {
        isScanning = true; lastResult = nil
        DispatchQueue.global(qos: .userInitiated).async {
            let targets = (try? TargetCatalog.loadBundled()) ?? []
            var groups = Scanner.scan(targets: targets)
            // Кэши проектов — динамически (не из targets.json): локальные build-папки с манифестом.
            let projItems = ProjectCaches.scan(home: NSHomeDirectory())
            if !projItems.isEmpty {
                groups.append(ScanGroup(targetID: "project-build-caches", name: "Project build caches",
                    safety: .moderate,
                    note: "Build folders (.build, node_modules, …) — regenerate on next build; rebuild is just slower.",
                    blockedBy: nil, items: projItems))
                groups.sort { $0.totalBytes > $1.totalBytes }
            }
            // Недоступные симуляторы — динамически: device-папки, чей рантайм удалён (умная детекция).
            let simItems = Simulators.unavailableDevices()
            if !simItems.isEmpty {
                groups.append(ScanGroup(targetID: "unavailable-simulators", name: "Unavailable simulators",
                    safety: .manual,
                    note: "Simulator devices whose runtime is no longer installed — they can't launch. The whole device goes to Trash (recoverable). Never pre-selected; review before removing.",
                    blockedBy: Simulators.runningBlocker(), items: simItems))
                groups.sort { $0.totalBytes > $1.totalBytes }
            }
            // Мусор внутри симуляторов (superseded-установки Dead/temp.*, клоны XCTestDevices) — устройства остаются.
            let simLeft = Simulators.leftovers()
            if !simLeft.isEmpty {
                groups.append(ScanGroup(targetID: "simulator-leftovers", name: "Simulator leftovers",
                    safety: .moderate,
                    note: "Superseded app installs and stale test clones inside simulators — regenerated; the devices themselves stay.",
                    blockedBy: Simulators.runningBlocker(), items: simLeft))
                groups.sort { $0.totalBytes > $1.totalBytes }
            }
            let reportGroups = Scanner.scanReport(targets: targets)
            let preselect = Set(groups.filter { $0.safety == .safe && $0.blockedBy == nil }
                .flatMap { $0.items.map(\.path) })
            DispatchQueue.main.async {
                self.groups = groups; self.reportGroups = reportGroups
                self.selected = preselect; self.isScanning = false
            }
        }
    }

    /// Адаптивная разбивка диска по категориям (реальные размеры папок, в фоне, с прогрессом).
    func mapStorage() {
        guard !isMappingStorage else { return }
        isMappingStorage = true; storageProgress = 0; storageStage = ""
        DispatchQueue.global(qos: .utility).async {
            let rules = StorageRuleset.loadBundled()
            let d = SystemStats.disk()
            let report = StorageScanner.scan(rules: rules, total: d.totalBytes, free: d.freeBytes) { frac, stage in
                DispatchQueue.main.async { self.storageProgress = frac; self.storageStage = stage }
            }
            DispatchQueue.main.async {
                self.storage = report; self.isMappingStorage = false; self.storageProgress = 1
            }
        }
    }

    func trashSelected() {
        let chosen = orderedItems.map(\.path).filter { selected.contains($0) }
        guard !chosen.isEmpty else { return }
        isScanning = true
        let policy = self.policy
        DispatchQueue.global(qos: .userInitiated).async {
            // M1: снимок мог устареть между сканом и нажатием — пересобираем АКТУАЛЬНЫЙ набор чистимого
            // (свежие блокеры/keepNewest/границу тома H1) и оставляем только пересечение с выбором.
            let targets = (try? TargetCatalog.loadBundled()) ?? []
            var eligible = Set(Scanner.scan(targets: targets)
                .filter { $0.blockedBy == nil }                 // группа, заблокированная ПОСЛЕ скана, выпадает
                .flatMap { $0.items.map(\.path) })
            eligible.formUnion(ProjectCaches.scan(home: NSHomeDirectory()).map(\.path))  // динамическая категория
            if Simulators.runningBlocker() == nil {                                       // recheck: Simulator/Xcode не запущены
                eligible.formUnion(Simulators.unavailableDevices().map(\.path))            // свежий набор недоступных
                eligible.formUnion(Simulators.leftovers().map(\.path))                     // свежий набор внутри-симуляторного мусора
            }
            let paths = chosen.filter { eligible.contains($0) }
            let skipped = chosen.count - paths.count
            let outcomes = Trasher.trashCheckedBatch(paths, policy: policy)
            let moved = outcomes.filter { $0.moved }
            let freed = moved.reduce(0) { $0 + $1.movedBytes }
            let failed = outcomes.filter { !$0.moved }
            DispatchQueue.main.async {
                var msg = "Moved to Trash: \(moved.count) · \(ByteFmt.string(freed)) (freed after emptying Trash)"
                if skipped > 0 { msg += " · skipped \(skipped) (no longer eligible)" }
                if let f = failed.first { msg += " · errors: \(failed.count) (\(f.error ?? ""))" }
                ActivityLog.shared.trashed("cleanup", msg, outcomes)
                self.lastResult = msg; self.scan()
            }
        }
    }

    var orderedItems: [ScanItem] { groups.flatMap(\.items) }
    var totalFound: Int64 { groups.reduce(0) { $0 + $1.totalBytes } }
    var reclaimableSafe: Int64 { groups.filter { $0.safety == .safe }.reduce(0) { $0 + $1.totalBytes } }
    var selectedCount: Int { selected.count }
    var selectedBytes: Int64 { orderedItems.filter { selected.contains($0.path) }.reduce(0) { $0 + $1.size } }
    func binding(for path: String) -> Binding<Bool> {
        Binding(get: { self.selected.contains(path) },
                set: { if $0 { self.selected.insert(path) } else { self.selected.remove(path) } })
    }
    func setGroup(_ g: ScanGroup, selected on: Bool) {
        for it in g.items { if on { selected.insert(it.path) } else { selected.remove(it.path) } }
    }
    func isGroupFullySelected(_ g: ScanGroup) -> Bool {
        !g.items.isEmpty && g.items.allSatisfy { selected.contains($0.path) }
    }

    // MARK: крупные файлы

    func findLargeFiles() {
        guard !isFindingLarge else { return }   // L13: re-entrancy guard, как у findDuplicates/findApps/findSimilarPhotos
        isFindingLarge = true
        DispatchQueue.global(qos: .userInitiated).async {
            let files = LargeFiles.scan(root: NSHomeDirectory())
            DispatchQueue.main.async {
                self.largeFiles = files; self.largeSelected = []
                self.isFindingLarge = false; self.largeScanned = true
            }
        }
    }
    var classifiedLarge: [ClassifiedFile] {
        largeFiles.map { ClassifiedFile(file: $0, cls: Classifier.classify($0.path)) }
    }
    func largeGroup(_ v: Verdict) -> [ClassifiedFile] {
        let items = classifiedLarge.filter { $0.cls.verdict == v }
        switch largeSort {
        case .size: return items.sorted { $0.file.size > $1.file.size }
        case .age:  return items.sorted { $0.file.modified < $1.file.modified }   // старое — выше
        }
    }
    var largeOldCount: Int { largeFiles.filter { LargeFiles.isOld($0.modified) }.count }

    // MARK: дубликаты

    func findDuplicates() {
        guard !isFindingDups else { return }
        isFindingDups = true; dupsProgress = 0; dupsStage = ""; dupsResult = nil
        let policy = self.policy
        DispatchQueue.global(qos: .userInitiated).async {
            let groups = Dups.scan(root: NSHomeDirectory(), policy: policy) { frac, stage in
                DispatchQueue.main.async { self.dupsProgress = frac; self.dupsStage = stage }
            }
            DispatchQueue.main.async {
                self.dups = groups; self.dupsSelected = []
                self.isFindingDups = false; self.dupsScanned = true
            }
        }
    }

    var dupFiles: [DupFile] { dups.flatMap(\.files) }
    /// Суммарно «как будто» занято всеми дублями сверх одной копии каждой группы.
    var dupsRedundant: Int64 { dups.reduce(0) { $0 + $1.reclaimable } }

    func dupBinding(_ path: String) -> Binding<Bool> {
        Binding(get: { self.dupsSelected.contains(path) },
                set: { if $0 { self.dupsSelected.insert(path) } else { self.dupsSelected.remove(path) } })
    }
    /// Снять галочку — всегда можно; поставить — только если в группе останется ≥1 копия
    /// (последнюю незащищённую копию удалить не даём; защищённая копия тоже считается «оставшейся»).
    func dupCanSelect(_ f: DupFile, in g: DupGroup) -> Bool {
        if dupsSelected.contains(f.path) { return true }
        return g.files.contains { $0.path != f.path && !dupsSelected.contains($0.path) }
    }
    /// «Оставить одну»: выбрать все удаляемые копии, кроме одной оставляемой. Защищённые копии
    /// (личные папки) не выбираем никогда; если такая есть — оставляем её, удаляем все trashable.
    func dupsKeepOne(_ g: DupGroup) {
        let trashable = g.files.filter { $0.trashable }
        let hasProtected = g.files.count > trashable.count
        let keep = hasProtected ? nil : trashable.first?.path
        for f in trashable where f.path != keep { dupsSelected.insert(f.path) }
    }
    func dupsClearGroup(_ g: DupGroup) { for f in g.files { dupsSelected.remove(f.path) } }

    /// Честно освобождаемое выбранным набором: физический набор блоков освобождается, только если
    /// удаляются ВСЕ его файлы (иначе оставшийся родственник держит блоки). Клоны места не дают.
    var dupsFreedBySelection: Int64 {
        var total: Int64 = 0
        for g in dups {
            var sets: [Int: (sel: Int, total: Int)] = [:]
            for f in g.files {
                var e = sets[f.cloneSet] ?? (0, 0)
                e.total += 1; if dupsSelected.contains(f.path) { e.sel += 1 }
                sets[f.cloneSet] = e
            }
            for (_, e) in sets where e.total > 0 && e.sel == e.total { total += g.size }
        }
        return total
    }

    func trashDupsSelected() {
        // Жёсткая гарантия: в каждой группе остаётся ≥1 копия (даже если выбраны все).
        let safe = Dups.enforceKeepOne(dupsSelected, groups: dups)
        if safe != dupsSelected { dupsSelected = safe }   // отразить в UI снятую «последнюю» галочку
        let paths = dupFiles.map(\.path).filter { safe.contains($0) }
        guard !paths.isEmpty, !isTrashingDups else { return }
        isTrashingDups = true
        let policy = self.policy
        DispatchQueue.global(qos: .userInitiated).async {
            let outcomes = Trasher.trashCheckedBatch(paths, policy: policy)
            let moved = outcomes.filter { $0.moved }
            let movedPaths = Set(moved.map(\.path))
            let failed = outcomes.filter { !$0.moved }
            DispatchQueue.main.async {
                var msg = "Moved to Trash: \(moved.count) duplicate\(moved.count == 1 ? "" : "s")"
                if let f = failed.first { msg += " · errors: \(failed.count) (\(f.error ?? ""))" }
                ActivityLog.shared.trashed("duplicates", msg, outcomes)
                self.dupsResult = msg
                // Убираем перенесённое из списка В ПАМЯТИ — мгновенно, без полного рескана.
                // Группа, где осталась <2 копий, перестаёт быть дублем и исчезает.
                self.dups = Dups.prune(self.dups, removing: movedPaths)
                self.dupsSelected.subtract(movedPaths)
                self.isTrashingDups = false
            }
        }
    }

    // MARK: приложения (аптинсталлер)

    func findApps() {
        guard !isFindingApps else { return }
        isFindingApps = true; appsProgress = 0; appsStage = ""; appsResult = nil
        let home = NSHomeDirectory()
        let policy = self.policy
        DispatchQueue.global(qos: .userInitiated).async {
            let r = Apps.scan(home: home, policy: policy) { frac, stage in
                DispatchQueue.main.async { self.appsProgress = frac; self.appsStage = stage }
            }
            DispatchQueue.main.async {
                self.apps = r.apps; self.orphans = r.orphans; self.appSelected = []
                self.isFindingApps = false; self.appsScanned = true
            }
        }
    }

    func appBinding(_ path: String) -> Binding<Bool> {
        Binding(get: { self.appSelected.contains(path) },
                set: { if $0 { self.appSelected.insert(path) } else { self.appSelected.remove(path) } })
    }
    /// Выбрать приложение + его ТОЧНЫЕ (по bundle id) КЭШ-хвосты. Слабые (по имени) и хвосты с реальными
    /// данными приложения (Container/Application Support/…) НЕ трогаем — их пользователь отмечает сам (Codex-7).
    func selectAppWithData(_ a: InstalledApp) {
        if a.trashableBundle { appSelected.insert(a.path) }
        for l in a.leftovers where l.strong && l.trashable && !l.dataBearing { appSelected.insert(l.path) }
    }
    func deselectApp(_ a: InstalledApp) {
        appSelected.remove(a.path); for l in a.leftovers { appSelected.remove(l.path) }
    }
    func isAppSelected(_ a: InstalledApp) -> Bool { appSelected.contains(a.path) }
    func selectOrphan(_ o: OrphanApp) { for l in o.items where l.trashable { appSelected.insert(l.path) } }
    func deselectOrphan(_ o: OrphanApp) { for l in o.items { appSelected.remove(l.path) } }
    func isOrphanSelected(_ o: OrphanApp) -> Bool { o.items.contains { appSelected.contains($0.path) } }

    private var appsAllItems: [(path: String, size: Int64)] {
        var out: [(String, Int64)] = []
        for a in apps { out.append((a.path, a.appSize)); out += a.leftovers.map { ($0.path, $0.size) } }
        for o in orphans { out += o.items.map { ($0.path, $0.size) } }
        return out
    }
    var appSelectedBytes: Int64 {
        let sel = appSelected
        return appsAllItems.filter { sel.contains($0.path) }.reduce(0) { $0 + $1.size }
    }
    var appsReclaimable: Int64 {
        apps.reduce(0) { $0 + $1.totalBytes } + orphans.reduce(0) { $0 + $1.size }
    }

    func trashAppsSelected() {
        let sel = appSelected
        let paths = appsAllItems.map(\.path).filter { sel.contains($0) }
        guard !paths.isEmpty, !isUninstalling else { return }
        isUninstalling = true
        let policy = self.policy
        DispatchQueue.global(qos: .userInitiated).async {
            let outcomes = Trasher.trashCheckedBatch(paths, policy: policy)
            let moved = outcomes.filter { $0.moved }
            let movedPaths = Set(moved.map(\.path))
            let freed = moved.reduce(0) { $0 + $1.movedBytes }
            let failed = outcomes.filter { !$0.moved }
            DispatchQueue.main.async {
                var msg = "Moved to Trash: \(moved.count) items · \(ByteFmt.string(freed))"
                if let f = failed.first { msg += " · errors: \(failed.count) (\(f.error ?? ""))" }
                ActivityLog.shared.trashed("apps", msg, outcomes)
                self.appsResult = msg
                self.apps = Apps.pruneApps(self.apps, removing: movedPaths)
                self.orphans = Apps.pruneOrphans(self.orphans, removing: movedPaths)
                self.appSelected.subtract(movedPaths)
                self.isUninstalling = false
            }
        }
    }

    // MARK: похожие фото

    func findSimilarPhotos() {
        guard !isFindingSims else { return }
        isFindingSims = true; simsProgress = 0; simsStage = ""; simsResult = nil
        let policy = self.policy
        DispatchQueue.global(qos: .userInitiated).async {
            let groups = SimilarPhotos.scan(root: NSHomeDirectory(), policy: policy) { frac, stage in
                DispatchQueue.main.async { self.simsProgress = frac; self.simsStage = stage }
            }
            DispatchQueue.main.async {
                self.sims = groups; self.simSelected = []
                self.isFindingSims = false; self.simsScanned = true
            }
        }
    }

    var simPhotosAll: [SimilarPhoto] { sims.flatMap(\.photos) }
    var simsNear: [SimilarGroup] { sims.filter { $0.kind == .nearDuplicate } }
    var simsRelated: [SimilarGroup] { sims.filter { $0.kind == .relatedSeries } }
    /// Сколько освободится, если оставить keeper в каждой near-dup группе.
    var simsReclaimable: Int64 { simsNear.reduce(0) { $0 + $1.reclaimable } }

    func simBinding(_ path: String) -> Binding<Bool> {
        Binding(get: { self.simSelected.contains(path) },
                set: { if $0 { self.simSelected.insert(path) } else { self.simSelected.remove(path) } })
    }
    /// Можно ли отметить копию: только near-dup, только trashable, и в группе остаётся ≥1 копия.
    /// related-series и защищённые (личные папки) — никогда (reveal-only).
    func simCanSelect(_ p: SimilarPhoto, in g: SimilarGroup) -> Bool {
        guard g.kind == .nearDuplicate, p.trashable else { return false }
        if p.isKeeper { return false }   // M4: лучшую копию вручную тоже не удалить (как в bulk) — всегда остаётся
        if simSelected.contains(p.path) { return true }
        return g.photos.contains { $0.path != p.path && !simSelected.contains($0.path) }
    }
    /// «Оставить одну»: выбрать все удаляемые копии группы, кроме keeper (или, если есть защищённая, все trashable).
    func simsKeepOne(_ g: SimilarGroup) {
        guard g.kind == .nearDuplicate else { return }
        // P1 (Codex-6): всегда сохраняем ЛУЧШУЮ копию (keeper), даже если в группе есть защищённая,
        // иначе удалили бы лучшую и оставили худшую защищённую.
        let keep = SimilarPhotos.keepPath(g)
        for p in g.photos where p.trashable && p.path != keep { simSelected.insert(p.path) }
    }
    func simsClearGroup(_ g: SimilarGroup) { for p in g.photos { simSelected.remove(p.path) } }
    var simsFreedBySelection: Int64 {
        var total: Int64 = 0
        for g in simsNear {
            for p in g.photos where p.trashable && simSelected.contains(p.path) { total += p.size }
        }
        return total
    }

    func trashSimsSelected() {
        let trashableG = SimilarPhotos.trashableGroups(sims)        // только near-dup
        let safe = SimilarPhotos.enforceKeepOne(simSelected, groups: trashableG)
        if safe != simSelected { simSelected = safe }
        let allowed = Set(trashableG.flatMap { $0.photos }.filter { $0.trashable }.map(\.path))
        let paths = simPhotosAll.map(\.path).filter { safe.contains($0) && allowed.contains($0) }
        guard !paths.isEmpty, !isTrashingSims else { return }
        isTrashingSims = true
        let policy = self.policy
        DispatchQueue.global(qos: .userInitiated).async {
            let outcomes = Trasher.trashCheckedBatch(paths, policy: policy)
            let moved = outcomes.filter { $0.moved }
            let movedPaths = Set(moved.map(\.path))
            let freed = moved.reduce(0) { $0 + $1.movedBytes }
            let failed = outcomes.filter { !$0.moved }
            DispatchQueue.main.async {
                var msg = "Moved to Trash: \(moved.count) photo\(moved.count == 1 ? "" : "s") · \(ByteFmt.string(freed))"
                if let f = failed.first { msg += " · errors: \(failed.count) (\(f.error ?? ""))" }
                ActivityLog.shared.trashed("similar-photos", msg, outcomes)
                self.simsResult = msg
                self.sims = SimilarPhotos.prune(self.sims, removing: movedPaths)
                self.simSelected.subtract(movedPaths)
                self.isTrashingSims = false
            }
        }
    }

    // MARK: «Выделить всё» / «Снять всё» (по запросу владельца — в Cleanup, Duplicates, Apps, Similar)

    // Cleanup: report-only сюда не входит (там вообще нет галочек).
    // M2 (Codex-3rd, выбор владельца): «Select all» берёт ТОЛЬКО safe; moderate (JetBrains Local
    // History, Office Document Cache, project build caches и т.п.) и .manual (iOS-бэкапы), а также
    // заблокированные процессом группы — НЕ захватываются, их отмечают вручную по группе.
    var cleanFullSelection: Set<String> {
        Set(groups.filter { $0.safety == .safe && $0.blockedBy == nil }
            .flatMap { $0.items.map(\.path) })
    }
    var cleanAllSelected: Bool { !cleanFullSelection.isEmpty && cleanFullSelection.isSubset(of: selected) }
    func cleanToggleAll() { selected = cleanAllSelected ? [] : cleanFullSelection }

    // Duplicates: все удаляемые копии, КРОМЕ одной на группу (≥1 всегда остаётся).
    var dupsFullSelection: Set<String> {
        var s = Set<String>()
        for g in dups {
            let trashable = g.files.filter { $0.trashable }
            let hasProtected = g.files.count > trashable.count
            guard trashable.count >= 2 || (trashable.count >= 1 && hasProtected) else { continue }
            let keep = hasProtected ? nil : trashable.first?.path
            for f in trashable where f.path != keep { s.insert(f.path) }
        }
        return s
    }
    var dupsAllSelected: Bool { !dupsFullSelection.isEmpty && dupsFullSelection.isSubset(of: dupsSelected) }
    func dupsToggleAll() { dupsSelected = dupsAllSelected ? [] : dupsFullSelection }

    // Similar: все удаляемые near-dup копии, кроме keeper (related не трогаем).
    var simsFullSelection: Set<String> {
        var s = Set<String>()
        for g in simsNear {
            let trashable = g.photos.filter { $0.trashable }
            let hasProtected = g.photos.count > trashable.count
            guard trashable.count >= 2 || (trashable.count >= 1 && hasProtected) else { continue }
            let keep = SimilarPhotos.keepPath(g)   // P1 (Codex-6): всегда сохраняем лучшую копию
            for p in trashable where p.path != keep { s.insert(p.path) }
        }
        return s
    }
    var simsAllSelected: Bool { !simsFullSelection.isEmpty && simsFullSelection.isSubset(of: simSelected) }
    func simsToggleAll() { simSelected = simsAllSelected ? [] : simsFullSelection }

    // Apps: все приложения + их точные хвосты + все осиротевшие остатки.
    var appsFullSelection: Set<String> {
        var s = Set<String>()
        for a in apps {
            if a.trashableBundle { s.insert(a.path) }
            for l in a.leftovers where l.strong && l.trashable && !l.dataBearing { s.insert(l.path) }
        }
        for o in orphans { for l in o.items where l.trashable { s.insert(l.path) } }
        return s
    }
    var appsAllSelected: Bool { !appsFullSelection.isEmpty && appsFullSelection.isSubset(of: appSelected) }
    func appsToggleAll() { appSelected = appsAllSelected ? [] : appsFullSelection }

    // MARK: процессы

    func loadProcesses() {
        isLoadingProcs = true
        DispatchQueue.global(qos: .userInitiated).async {
            let p = ProcessScanner.snapshot()
            DispatchQueue.main.async { self.procs = p; self.isLoadingProcs = false; self.procsLoaded = true }
        }
    }
    var sortedProcs: [ProcInfo] {
        let live = procs.filter { !$0.isZombie }
        switch procSort {
        case .cpu: return live.sorted { $0.cpuPercent > $1.cpuPercent }
        case .memory: return live.sorted { $0.residentBytes > $1.residentBytes }
        }
    }
    var zombies: [ProcInfo] { procs.filter { $0.isZombie } }
    func terminate(_ p: ProcInfo, force: Bool) {
        procMessage = nil
        DispatchQueue.global(qos: .userInitiated).async {
            let ok = ProcessScanner.terminate(p.pid, expectStartSec: p.startSec,
                                              expectStartUsec: p.startUsec, force: force)
            DispatchQueue.main.async {
                self.procMessage = ok ? "Quit: \(p.name)"
                    : (force ? "Couldn't quit \"\(p.name)\"" : "\"\(p.name)\" didn't quit gracefully — try Force")
                ActivityLog.shared.log("process", "\(force ? "SIGKILL" : "SIGTERM") \(p.name) (pid \(p.pid)) → \(ok ? "quit" : "no")")
                self.loadProcesses()
            }
        }
    }
}

// MARK: - Корневой вид

struct ContentView: View {
    @EnvironmentObject var model: CleanerModel
    @State private var killTarget: ProcInfo?

    var body: some View {
        HStack(spacing: 0) {
            Sidebar()
            MainPane(killTarget: $killTarget)
        }
        .background(Theme.bg)
        .onAppear { model.start(); snugWindow() }
        .confirmationDialog(
            "Quit \"\(killTarget?.name ?? "")\"?",
            isPresented: Binding(get: { killTarget != nil }, set: { if !$0 { killTarget = nil } }),
            presenting: killTarget
        ) { p in
            Button("Quit (graceful)") { model.terminate(p, force: false); killTarget = nil }
            Button("Force quit — data loss", role: .destructive) { model.terminate(p, force: true); killTarget = nil }
            Button("Cancel", role: .cancel) { killTarget = nil }
        } message: { _ in Text("Unsaved data in the process will be lost.") }
    }

    /// При запуске подгоняем окно под контент (убираем сохранённую «лишнюю» высоту → нет пустоты внизу).
    private func snugWindow() {
        DispatchQueue.main.async {
            guard let win = NSApplication.shared.windows.first(where: { $0.isVisible && $0.contentView != nil }) else { return }
            let target = NSSize(width: max(1200, win.frame.width), height: 648)
            guard win.frame.height > target.height + 8 else { return }   // уже компактно — не трогаем
            var f = win.frame
            f.origin.y += f.height - target.height        // верхний край на месте
            f.size = target
            win.setFrame(f, display: true, animate: false)
        }
    }
}

// MARK: - Сайдбар

private struct Sidebar: View {
    @EnvironmentObject var model: CleanerModel

    // App version + build, read from Info.plist (single source of truth; no personal data).
    private var appShortVersion: String { Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.1" }
    private var appBuildNumber: String { Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "9" }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 11) {
                GaugeIcon(size: 34)
                    .shadow(color: Color(hex: 0x1f7ec4).opacity(0.45), radius: 8, y: 4)
                VStack(alignment: .leading, spacing: 1) {
                    Text("MacCleaner").font(.system(size: 14.5, weight: .bold)).foregroundStyle(Theme.text)
                    Text("PRO · \(appShortVersion)").font(.system(size: 10.5, weight: .semibold)).foregroundStyle(Theme.textFaint)
                }
            }
            .padding(.horizontal, 8).padding(.bottom, 18).padding(.top, 4)

            navRow(.dashboard, "Overview", "square.grid.2x2")
            navRow(.cleaning, "Cleanup", "sparkles", badge: model.totalFound > 0 ? ByteFmt.string(model.totalFound) : nil)
            navRow(.largeFiles, "Large Files", "folder", badge: model.largeScanned && !model.largeFiles.isEmpty ? "\(model.largeFiles.count)" : nil)
            navRow(.duplicates, "Duplicates", "doc.on.doc", badge: model.dupsScanned && !model.dups.isEmpty ? "\(model.dups.count)" : nil)
            navRow(.similar, "Similar Photos", "photo.on.rectangle.angled", badge: model.simsScanned && !model.sims.isEmpty ? "\(model.sims.count)" : nil)
            navRow(.apps, "Apps", "trash.square", badge: model.appsScanned && !model.apps.isEmpty ? "\(model.apps.count)" : nil)
            navRow(.system, "System", "lock.shield")
            navRow(.processes, "Processes", "waveform.path.ecg")

            Spacer()

            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 7) {
                    Circle().fill(Theme.safe).frame(width: 7, height: 7).shadow(color: Theme.safe, radius: 4)
                    Text("ALL HEALTHY").font(.system(size: 11, weight: .bold)).foregroundStyle(Color(hex: 0xbfe9dd))
                }
                Text("Disk, memory and load are in the green.")
                    .font(.system(size: 11)).foregroundStyle(Theme.textDim).fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
            .background(LinearGradient(colors: [Theme.accentA.opacity(0.10), Theme.accentB.opacity(0.05)],
                                       startPoint: .topLeading, endPoint: .bottomTrailing),
                        in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color(hex: 0x78c8dc).opacity(0.14)))
            .padding(.bottom, 10)

            Text("VERSION \(appShortVersion) BUILD \(appBuildNumber)")
                .font(.system(size: 11, weight: .semibold)).tracking(0.6)
                .foregroundStyle(Theme.textDim)
        }
        .padding(.horizontal, 14).padding(.vertical, 18)
        .frame(width: 236)
        .background(LinearGradient(colors: [Theme.sidebarTop, Theme.sidebarBot], startPoint: .top, endPoint: .bottom))
        .overlay(Rectangle().fill(Theme.strokeSoft).frame(width: 1), alignment: .trailing)
    }

    @ViewBuilder private func navRow(_ m: AppMode, _ label: String, _ icon: String, badge: String? = nil) -> some View {
        let active = model.mode == m
        Button { model.mode = m; lazyLoad(m) } label: {
            HStack(spacing: 12) {
                Image(systemName: icon).font(.system(size: 14, weight: .medium))
                    .foregroundStyle(active ? Theme.accentB : Theme.textDim).frame(width: 18)
                Text(label).font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(active ? Theme.text : Color(hex: 0x828d9e))
                Spacer(minLength: 0)
                if let badge {
                    Text(badge).font(.system(size: 10, weight: .bold))
                        .padding(.horizontal, 7).padding(.vertical, 1)
                        .foregroundStyle(active ? Theme.bg : Theme.textDim)
                        .background(active ? AnyShapeStyle(Theme.accentB) : AnyShapeStyle(Color.white.opacity(0.06)), in: Capsule())
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 10)
            .background(active ? Color.white.opacity(0.055) : .clear, in: RoundedRectangle(cornerRadius: 10))
            .overlay(alignment: .leading) {
                if active {
                    Capsule().fill(Theme.accentGrad).frame(width: 3, height: 18).offset(x: -14)
                }
            }
        }
        .buttonStyle(.plain)
        .padding(.bottom, 3)
    }

    private func lazyLoad(_ m: AppMode) {
        if m == .largeFiles && !model.largeScanned && !model.isFindingLarge { model.findLargeFiles() }
        if m == .duplicates && !model.dupsScanned && !model.isFindingDups { model.findDuplicates() }
        if m == .similar && !model.simsScanned && !model.isFindingSims { model.findSimilarPhotos() }
        if m == .apps && !model.appsScanned && !model.isFindingApps { model.findApps() }
        if m == .processes && !model.procsLoaded && !model.isLoadingProcs { model.loadProcesses() }
    }
}

// MARK: - Главная панель

private struct MainPane: View {
    @EnvironmentObject var model: CleanerModel
    @Binding var killTarget: ProcInfo?

    private var title: (String, String) {
        switch model.mode {
        case .dashboard: return ("System Overview", "Storage, memory and load in real time")
        case .cleaning: return ("Cleanup", "Only junk folders — caches, logs, temp and dev files")
        case .largeFiles: return ("Large Files", "Map of the biggest files on disk")
        case .duplicates: return ("Duplicates", "Identical files — keep one, send the rest to Trash")
        case .similar: return ("Similar Photos", "Visually similar images — keep the best, send the rest to Trash")
        case .apps: return ("Apps", "Uninstall apps with all their leftovers — and clean up after removed ones")
        case .system: return ("System Cleanup", "Root-owned caches & logs — recoverable: quarantine, then restore or empty")
        case .processes: return ("Processes", "What's using CPU and memory right now")
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // toolbar
            HStack(alignment: .bottom, spacing: 16) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title.0).font(.system(size: 21, weight: .bold)).foregroundStyle(Theme.text)
                    Text(title.1).font(.system(size: 12.5)).foregroundStyle(Theme.textMute)
                }
                Spacer()
                fdaPill
                Button { rescan() } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "arrow.clockwise").font(.system(size: 12, weight: .bold))
                        Text(busy ? "Scanning…" : "Scan").font(.system(size: 13, weight: .bold))
                    }
                    .foregroundStyle(Theme.bg)
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    .background(Theme.accentGrad, in: RoundedRectangle(cornerRadius: 9))
                }
                .buttonStyle(.plain).disabled(busy)
            }
            .padding(.horizontal, 26).padding(.top, 18).padding(.bottom, 14)
            .overlay(Rectangle().fill(Theme.strokeSoft).frame(height: 1), alignment: .bottom)

            // тонкий индикатор скана для ЛЮБОЙ вкладки (Cleanup/Large и др.) — честный indeterminate
            if busy {
                ProgressView().progressViewStyle(.linear).tint(Theme.accentA)
            }

            // content — дашборд тянется на всю высоту (без провала), списки скроллятся
            switch model.mode {
            case .dashboard:
                ScrollView { DashboardView().padding(.horizontal, 26).padding(.vertical, 24) }
            case .cleaning:
                ScrollView { CleanView().padding(.horizontal, 26).padding(.vertical, 24) }
            case .largeFiles:
                ScrollView { LargeView().padding(.horizontal, 26).padding(.vertical, 24) }
            case .duplicates:
                ScrollView { DuplicatesView().padding(.horizontal, 26).padding(.vertical, 24) }
            case .similar:
                ScrollView { SimilarPhotosView().padding(.horizontal, 26).padding(.vertical, 24) }
            case .apps:
                ScrollView { AppsView().padding(.horizontal, 26).padding(.vertical, 24) }
            case .system:
                ScrollView { SystemView().padding(.horizontal, 26).padding(.vertical, 24) }
            case .processes:
                ScrollView { ProcessesView(killTarget: $killTarget).padding(.horizontal, 26).padding(.vertical, 24) }
            }

            if model.mode == .cleaning { cleanBottomBar }
            if model.mode == .duplicates { dupBottomBar }
            if model.mode == .similar { simBottomBar }
            if model.mode == .apps { appsBottomBar }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.panel)
    }

    private var busy: Bool {
        switch model.mode {
        case .cleaning: return model.isScanning
        case .dashboard: return model.isScanning || model.isMappingStorage
        case .largeFiles: return model.isFindingLarge
        case .duplicates: return model.isFindingDups || model.isTrashingDups
        case .similar: return model.isFindingSims || model.isTrashingSims
        case .apps: return model.isFindingApps || model.isUninstalling
        case .system: return false
        case .processes: return model.isLoadingProcs
        }
    }
    private func rescan() {
        switch model.mode {
        case .dashboard: model.refreshFDA(); model.scan(); model.mapStorage()
        case .cleaning: model.refreshFDA(); model.scan()
        case .largeFiles: model.findLargeFiles()
        case .duplicates: model.findDuplicates()
        case .similar: model.findSimilarPhotos()
        case .apps: model.findApps()
        case .system: PrivilegedHelper.shared.refreshStatus()
        case .processes: model.loadProcesses()
        }
    }

    @ViewBuilder private var fdaPill: some View {
        switch model.fda {
        case .granted:
            HStack(spacing: 7) {
                Image(systemName: "checkmark.shield.fill").font(.system(size: 12))
                Text("Full Disk Access").font(.system(size: 11.5, weight: .semibold))
            }
            .foregroundStyle(Color(hex: 0x7fe0b0))
            .padding(.horizontal, 12).padding(.vertical, 7)
            .background(Theme.safe.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(Theme.safe.opacity(0.18)))
        default:
            Button { FullDiskAccess.openSettings() } label: {
                HStack(spacing: 7) {
                    Image(systemName: "exclamationmark.shield").font(.system(size: 12))
                    Text("Enable Full Disk Access").font(.system(size: 11.5, weight: .semibold))
                }
                .foregroundStyle(Theme.caution)
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background(Theme.caution.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
            }.buttonStyle(.plain)
        }
    }

    /// Кнопка «Выделить всё / Снять всё» для нижних панелей (по запросу владельца).
    @ViewBuilder private func selectAllButton(_ isAll: Bool, _ enabled: Bool, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: isAll ? "minus.circle" : "checklist").font(.system(size: 12, weight: .bold))
                Text(isAll ? "Clear all" : "Select all").font(.system(size: 12.5, weight: .semibold))
            }
            .foregroundStyle(enabled ? Theme.accentB : Theme.textFaint)
            .padding(.horizontal, 13).padding(.vertical, 8)
            .background(Theme.accentB.opacity(enabled ? 0.10 : 0.03), in: RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(Theme.accentB.opacity(enabled ? 0.22 : 0.06)))
        }
        .buttonStyle(.plain).disabled(!enabled)
    }

    private var cleanBottomBar: some View {
        HStack(spacing: 16) {
            Image(systemName: "arrow.uturn.backward").foregroundStyle(Theme.textFaint).font(.system(size: 13))
            if let r = model.lastResult {
                Text(r).font(.system(size: 12)).foregroundStyle(Theme.safe).lineLimit(1)
            } else {
                Text("Everything goes to Trash — recoverable").font(.system(size: 12)).foregroundStyle(Theme.textMute)
            }
            Spacer()
            selectAllButton(model.cleanAllSelected, !model.orderedItems.isEmpty) { model.cleanToggleAll() }
            VStack(alignment: .trailing, spacing: 1) {
                Text("Selected \(model.selectedCount)").font(.system(size: 11)).foregroundStyle(Theme.textMute)
                Text(ByteFmt.string(model.selectedBytes)).font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.text)
            }
            Button { model.trashSelected() } label: {
                HStack(spacing: 8) {
                    Image(systemName: "trash").font(.system(size: 13, weight: .bold))
                    Text("Move to Trash").font(.system(size: 14, weight: .bold))
                }
                .foregroundStyle(Theme.bg).padding(.horizontal, 20).padding(.vertical, 11)
                .background(model.selected.isEmpty ? AnyShapeStyle(Color.white.opacity(0.12)) : AnyShapeStyle(Theme.accentGrad),
                            in: RoundedRectangle(cornerRadius: 11))
            }
            .buttonStyle(.plain).disabled(model.selected.isEmpty || model.isScanning)
            .opacity(model.selected.isEmpty ? 0.5 : 1)
        }
        .padding(.horizontal, 26).padding(.vertical, 14)
        .background(Theme.panel)
        .overlay(Rectangle().fill(Theme.stroke).frame(height: 1), alignment: .top)
    }

    private var dupBottomBar: some View {
        HStack(spacing: 16) {
            Image(systemName: "arrow.uturn.backward").foregroundStyle(Theme.textFaint).font(.system(size: 13))
            if let r = model.dupsResult {
                Text(r).font(.system(size: 12)).foregroundStyle(Theme.safe).lineLimit(1)
            } else {
                Text("Nothing is pre-selected — pick copies yourself. Everything goes to Trash.")
                    .font(.system(size: 12)).foregroundStyle(Theme.textMute)
            }
            Spacer()
            selectAllButton(model.dupsAllSelected, !model.dupsFullSelection.isEmpty) { model.dupsToggleAll() }
            VStack(alignment: .trailing, spacing: 1) {
                Text("Selected \(model.dupsSelected.count)").font(.system(size: 11)).foregroundStyle(Theme.textMute)
                Text("≈ \(ByteFmt.string(model.dupsFreedBySelection)) freed").font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.text)
            }
            Button { model.trashDupsSelected() } label: {
                HStack(spacing: 8) {
                    Image(systemName: "trash").font(.system(size: 13, weight: .bold))
                    Text("Move to Trash").font(.system(size: 14, weight: .bold))
                }
                .foregroundStyle(Theme.bg).padding(.horizontal, 20).padding(.vertical, 11)
                .background(model.dupsSelected.isEmpty ? AnyShapeStyle(Color.white.opacity(0.12)) : AnyShapeStyle(Theme.accentGrad),
                            in: RoundedRectangle(cornerRadius: 11))
            }
            .buttonStyle(.plain).disabled(model.dupsSelected.isEmpty || model.isTrashingDups || model.isFindingDups)
            .opacity(model.dupsSelected.isEmpty ? 0.5 : 1)
        }
        .padding(.horizontal, 26).padding(.vertical, 14)
        .background(Theme.panel)
        .overlay(Rectangle().fill(Theme.stroke).frame(height: 1), alignment: .top)
    }

    private var appsBottomBar: some View {
        HStack(spacing: 16) {
            Image(systemName: "arrow.uturn.backward").foregroundStyle(Theme.textFaint).font(.system(size: 13))
            if let r = model.appsResult {
                Text(r).font(.system(size: 12)).foregroundStyle(Theme.safe).lineLimit(1)
            } else {
                Text("Review what's checked — apps and their data go to Trash (recoverable).")
                    .font(.system(size: 12)).foregroundStyle(Theme.textMute)
            }
            Spacer()
            selectAllButton(model.appsAllSelected, !model.appsFullSelection.isEmpty) { model.appsToggleAll() }
            VStack(alignment: .trailing, spacing: 1) {
                Text("Selected \(model.appSelected.count)").font(.system(size: 11)).foregroundStyle(Theme.textMute)
                Text(ByteFmt.string(model.appSelectedBytes)).font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.text)
            }
            Button { model.trashAppsSelected() } label: {
                HStack(spacing: 8) {
                    Image(systemName: "trash").font(.system(size: 13, weight: .bold))
                    Text("Move to Trash").font(.system(size: 14, weight: .bold))
                }
                .foregroundStyle(Theme.bg).padding(.horizontal, 20).padding(.vertical, 11)
                .background(model.appSelected.isEmpty ? AnyShapeStyle(Color.white.opacity(0.12)) : AnyShapeStyle(Theme.accentGrad),
                            in: RoundedRectangle(cornerRadius: 11))
            }
            .buttonStyle(.plain).disabled(model.appSelected.isEmpty || model.isUninstalling || model.isFindingApps)
            .opacity(model.appSelected.isEmpty ? 0.5 : 1)
        }
        .padding(.horizontal, 26).padding(.vertical, 14)
        .background(Theme.panel)
        .overlay(Rectangle().fill(Theme.stroke).frame(height: 1), alignment: .top)
    }

    private var simBottomBar: some View {
        HStack(spacing: 16) {
            Image(systemName: "arrow.uturn.backward").foregroundStyle(Theme.textFaint).font(.system(size: 13))
            if let r = model.simsResult {
                Text(r).font(.system(size: 12)).foregroundStyle(Theme.safe).lineLimit(1)
            } else {
                Text("Nothing is pre-selected. One copy always stays. Related/AI series are review-only.")
                    .font(.system(size: 12)).foregroundStyle(Theme.textMute)
            }
            Spacer()
            selectAllButton(model.simsAllSelected, !model.simsFullSelection.isEmpty) { model.simsToggleAll() }
            VStack(alignment: .trailing, spacing: 1) {
                Text("Selected \(model.simSelected.count)").font(.system(size: 11)).foregroundStyle(Theme.textMute)
                Text("≈ \(ByteFmt.string(model.simsFreedBySelection)) freed").font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.text)
            }
            Button { model.trashSimsSelected() } label: {
                HStack(spacing: 8) {
                    Image(systemName: "trash").font(.system(size: 13, weight: .bold))
                    Text("Move to Trash").font(.system(size: 14, weight: .bold))
                }
                .foregroundStyle(Theme.bg).padding(.horizontal, 20).padding(.vertical, 11)
                .background(model.simSelected.isEmpty ? AnyShapeStyle(Color.white.opacity(0.12)) : AnyShapeStyle(Theme.accentGrad),
                            in: RoundedRectangle(cornerRadius: 11))
            }
            .buttonStyle(.plain).disabled(model.simSelected.isEmpty || model.isTrashingSims || model.isFindingSims)
            .opacity(model.simSelected.isEmpty ? 0.5 : 1)
        }
        .padding(.horizontal, 26).padding(.vertical, 14)
        .background(Theme.panel)
        .overlay(Rectangle().fill(Theme.stroke).frame(height: 1), alignment: .top)
    }
}

// MARK: - Общие компоненты

struct Panel<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content.padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(Theme.stroke))
    }
}

struct RiskBadge: View {
    let color: Color; let label: String
    var body: some View {
        Text(label).font(.system(size: 10.5, weight: .bold))
            .foregroundStyle(color).padding(.horizontal, 9).padding(.vertical, 2)
            .background(color.opacity(0.13), in: Capsule())
            .overlay(Capsule().strokeBorder(color.opacity(0.25)))
    }
}

struct Sparkline: View {
    let data: [Double]; let color: Color
    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width, h = geo.size.height
            if data.count >= 2 {
                let lo = data.min() ?? 0, hi = data.max() ?? 1
                let range = hi - lo < 0.0001 ? 1 : hi - lo
                let pts = data.enumerated().map { i, v in
                    CGPoint(x: w * CGFloat(i) / CGFloat(data.count - 1),
                            y: 5 + (1 - CGFloat((v - lo) / range)) * (h - 10))
                }
                ZStack {
                    Path { p in
                        p.move(to: CGPoint(x: 0, y: h)); p.addLine(to: pts[0])
                        pts.dropFirst().forEach { p.addLine(to: $0) }
                        p.addLine(to: CGPoint(x: w, y: h)); p.closeSubpath()
                    }.fill(LinearGradient(colors: [color.opacity(0.3), color.opacity(0)], startPoint: .top, endPoint: .bottom))
                    Path { p in p.move(to: pts[0]); pts.dropFirst().forEach { p.addLine(to: $0) } }
                        .stroke(color, style: StrokeStyle(lineWidth: 1.7, lineJoin: .round))
                }
            }
        }
    }
}

// MARK: - Ring gauge

struct RingGauge: View {
    let fraction: Double            // 0..1 used
    let usedLabel: String
    let totalLabel: String
    // Число и единицу разносим: целиком "117.31 GB" в 40pt налезало на кольцо.
    private var splitLabel: (String, String) {
        let parts = usedLabel.split(whereSeparator: { $0 == " " || $0 == "\u{00A0}" }).map(String.init)
        if parts.count >= 2 { return (parts[0], parts.dropFirst().joined(separator: " ")) }
        return (usedLabel, "")
    }
    var body: some View {
        ZStack {
            Circle().stroke(Color.white.opacity(0.055), lineWidth: 18)
            Circle().trim(from: 0, to: max(0.001, min(1, fraction)))
                .stroke(Theme.accentGrad, style: StrokeStyle(lineWidth: 18, lineCap: .round))
                .rotationEffect(.degrees(-90))
            VStack(spacing: 2) {
                Text("USED").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textMute)
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text(splitLabel.0).font(.system(size: 38, weight: .bold)).foregroundStyle(Theme.text)
                    Text(splitLabel.1).font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textMute)
                }
                .lineLimit(1).minimumScaleFactor(0.6)
                Text("of \(totalLabel)").font(.system(size: 12)).foregroundStyle(Theme.textFaint)
            }
            .frame(width: 150)
        }
        .frame(width: 200, height: 200)
    }
}

// MARK: - App icon glyph (gauge — повторяет Resources/MacCleaner.icns)

/// 4-лучевая звезда-блеск из артворка иконки (design AppIcon, путь в 512-системе).
struct SparkleShape: Shape {
    func path(in rect: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: 256, y: 116))
        p.addCurve(to: CGPoint(x: 396, y: 256), control1: CGPoint(x: 269, y: 197), control2: CGPoint(x: 315, y: 243))
        p.addCurve(to: CGPoint(x: 256, y: 396), control1: CGPoint(x: 315, y: 269), control2: CGPoint(x: 269, y: 315))
        p.addCurve(to: CGPoint(x: 116, y: 256), control1: CGPoint(x: 243, y: 315), control2: CGPoint(x: 197, y: 269))
        p.addCurve(to: CGPoint(x: 256, y: 116), control1: CGPoint(x: 197, y: 243), control2: CGPoint(x: 243, y: 197))
        p.closeSubpath()
        let s = min(rect.width, rect.height) / 512
        let t = CGAffineTransform(translationX: rect.midX - 256 * s, y: rect.midY - 256 * s).scaledBy(x: s, y: s)
        return p.applying(t)
    }
}

/// Иконка приложения (вариант Gauge) как вектор-плитка — кольцо заполнения + блеск.
struct GaugeIcon: View {
    var size: CGFloat
    private let glyph = Color(hex: 0xf3fbff)
    var body: some View {
        let ring = size * 304 / 512                      // диаметр кольца (r=152)
        let lw   = size * 22 / 512                        // толщина кольца
        RoundedRectangle(cornerRadius: size * 0.23, style: .continuous)
            .fill(LinearGradient(colors: [Color(hex: 0x0f3f74), Color(hex: 0x1f7ec4)],
                                 startPoint: .topLeading, endPoint: .bottomTrailing))
            .overlay(
                ZStack {
                    Circle().stroke(glyph.opacity(0.22), lineWidth: lw).frame(width: ring, height: ring)
                    Circle().trim(from: 0, to: 690 / (2 * CGFloat.pi * 152))
                        .stroke(glyph, style: StrokeStyle(lineWidth: lw, lineCap: .round))
                        .frame(width: ring, height: ring)
                        .rotationEffect(.degrees(-90))
                    SparkleShape().fill(glyph).frame(width: size * 0.46, height: size * 0.46)
                }
                .shadow(color: Color(hex: 0x5fd2ff).opacity(0.6), radius: size * 0.045)
            )
            .frame(width: size, height: size)
            .overlay(RoundedRectangle(cornerRadius: size * 0.23, style: .continuous)
                .strokeBorder(Color.white.opacity(0.18), lineWidth: max(1, size * 2 / 512)))
    }
}

// MARK: - Dashboard

private struct DashboardView: View {
    @EnvironmentObject var model: CleanerModel
    private func gb(_ b: Int64) -> String { ByteFmt.string(b) }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 18) {
                // disk
                Panel {
                    HStack(spacing: 24) {
                        RingGauge(fraction: model.disk.totalBytes > 0 ? Double(model.disk.usedBytes) / Double(model.disk.totalBytes) : 0,
                                  usedLabel: gb(model.disk.usedBytes), totalLabel: gb(model.disk.totalBytes))
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(spacing: 8) {
                                Circle().fill(Theme.safe).frame(width: 9, height: 9).shadow(color: Theme.safe, radius: 5)
                                Text("\(gb(model.disk.freeBytes)) free").font(.system(size: 13, weight: .semibold)).foregroundStyle(Color(hex: 0xcdd6e3))
                            }
                            Text("APFS volume. Snapshot reserves accounted — real free space shown.")
                                .font(.system(size: 12.5)).foregroundStyle(Theme.textMute).fixedSize(horizontal: false, vertical: true)
                            storageBreakdown
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                // reclaim
                Panel {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("CAN BE FREED SAFELY").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textMute)
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(gb(model.reclaimableSafe)).font(.system(size: 40, weight: .bold))
                                .foregroundStyle(LinearGradient(colors: [Color(hex: 0x9fe9d2), Color(hex: 0x7fc8ff)], startPoint: .leading, endPoint: .trailing))
                        }
                        Text("Caches, logs and Trash — they regenerate.").font(.system(size: 12.5)).foregroundStyle(Theme.textMute)
                        Button { model.mode = .cleaning } label: {
                            HStack(spacing: 9) { Image(systemName: "sparkles"); Text("Go to cleanup").font(.system(size: 14, weight: .bold)) }
                                .foregroundStyle(Theme.bg).frame(maxWidth: .infinity).padding(.vertical, 12)
                                .background(Theme.accentGrad, in: RoundedRectangle(cornerRadius: 11))
                        }.buttonStyle(.plain).padding(.top, 4)
                        Divider().overlay(Theme.stroke).padding(.vertical, 6)
                        ForEach(model.groups.prefix(5)) { g in
                            let c = Theme.tier(g.safety)
                            VStack(alignment: .leading, spacing: 5) {
                                HStack {
                                    HStack(spacing: 8) { RoundedRectangle(cornerRadius: 3).fill(c).frame(width: 9, height: 9); Text(g.name).font(.system(size: 12.5)).foregroundStyle(Color(hex: 0xc3ccd9)) }
                                    Spacer()
                                    Text(ByteFmt.string(g.totalBytes)).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textDim)
                                }
                                GeometryReader { geo in
                                    let maxB = max(1, model.groups.map(\.totalBytes).max() ?? 1)
                                    ZStack(alignment: .leading) {
                                        Capsule().fill(Color.white.opacity(0.05))
                                        Capsule().fill(c).frame(width: geo.size.width * CGFloat(Double(g.totalBytes) / Double(maxB)))
                                    }
                                }.frame(height: 5)
                            }
                        }
                    }
                }
                .frame(width: 360)
            }
            liveMonitors
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private struct Seg { let color: Color; let bytes: Int64; let name: String }

    private func segments(_ s: StorageReport) -> [Seg] {
        var out = s.categories.map { Seg(color: Color(hex: $0.colorHex), bytes: $0.bytes, name: $0.name) }
        if s.systemOther > 0 { out.append(Seg(color: Color(hex: 0x5b6573), bytes: s.systemOther, name: "System & other")) }
        out.append(Seg(color: Color.white.opacity(0.12), bytes: s.free, name: "Free"))
        return out
    }

    /// Адаптивная разбивка хранилища: считается вживую, показываются только непустые категории.
    @ViewBuilder private var storageBreakdown: some View {
        if let s = model.storage {
            let segs = segments(s)
            let basis = max(1.0, Double(segs.reduce(0) { $0 + $1.bytes }))
            VStack(alignment: .leading, spacing: 12) {
                GeometryReader { geo in
                    HStack(spacing: 1.5) {
                        ForEach(Array(segs.enumerated()), id: \.offset) { _, seg in
                            Rectangle().fill(seg.color)
                                .frame(width: max(0, geo.size.width * CGFloat(Double(seg.bytes) / basis)))
                        }
                    }
                }.frame(height: 14).clipShape(RoundedRectangle(cornerRadius: 7))
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Array(segs.enumerated()), id: \.offset) { _, seg in
                        legend(seg.color, seg.name, ByteFmt.string(seg.bytes))
                    }
                }
                if model.isMappingStorage {     // повторный скан — тонкий индикатор
                    ProgressView(value: model.storageProgress).tint(Theme.accentA).scaleEffect(y: 0.7)
                }
            }
        } else {
            // первый расчёт — прогресс с названием текущей категории
            VStack(alignment: .leading, spacing: 10) {
                ProgressView(value: model.storageProgress).tint(Theme.accentA)
                Text(model.storageStage.isEmpty ? "Mapping storage…" : "Scanning \(model.storageStage)…")
                    .font(.system(size: 12)).foregroundStyle(Theme.textMute)
            }
            .padding(.top, 4)
        }
    }
    private func legend(_ c: Color, _ name: String, _ size: String) -> some View {
        HStack(spacing: 7) {
            RoundedRectangle(cornerRadius: 3).fill(c).frame(width: 9, height: 9)
            Text(name).font(.system(size: 11.5)).foregroundStyle(Theme.textDim)
            Text(size).font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Color(hex: 0xcdd6e3))
        }
    }

    private var liveMonitors: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 9) {
                Circle().fill(Theme.accentA).frame(width: 7, height: 7).shadow(color: Theme.accentA, radius: 5)
                Text("SYSTEM · LIVE").font(.system(size: 13, weight: .bold)).foregroundStyle(Color(hex: 0xaeb8c6))
            }
            HStack(spacing: 14) {
                monitor("CPU", String(format: "%.0f", model.cpuHistory.last ?? 0), "%", "all cores", Theme.accentA, model.cpuHistory)
                monitor("GPU", String(format: "%.0f", model.gpuHistory.last ?? 0), "%", "integrated", Theme.accentB, model.gpuHistory)
                monitor("Memory", String(format: "%.1f", Double(model.mem.usedBytes) / 1_073_741_824), "GB",
                        "of \(ByteFmt.string(Int64(model.mem.totalBytes)))", Theme.purple, model.memHistory)
                tempMonitor
            }
        }
    }
    private static let monitorHeight: CGFloat = 168

    private func monitor(_ label: String, _ val: String, _ unit: String, _ sub: String, _ color: Color, _ data: [Double]) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack { Text(label).font(.system(size: 12, weight: .semibold)).foregroundStyle(Color(hex: 0x7a8696)); Spacer()
                Circle().fill(color).frame(width: 7, height: 7).shadow(color: color, radius: 4) }
            HStack(alignment: .firstTextBaseline, spacing: 3) {
                Text(val).font(.system(size: 26, weight: .bold)).foregroundStyle(color)
                Text(unit).font(.system(size: 14, weight: .bold)).foregroundStyle(Color(hex: 0x7a8696))
            }.padding(.top, 6)
            Text(sub).font(.system(size: 10.5)).foregroundStyle(Theme.textFaint)
            Spacer(minLength: 8)
            Sparkline(data: data, color: color).frame(height: 50)
        }
        .padding(16).frame(maxWidth: .infinity, minHeight: Self.monitorHeight, maxHeight: Self.monitorHeight, alignment: .leading)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.stroke))
    }

    private var tempMonitor: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack {
                Text("Temperature").font(.system(size: 12, weight: .semibold)).foregroundStyle(Color(hex: 0x7a8696))
                Spacer()
                Circle().fill(Theme.caution).frame(width: 7, height: 7).shadow(color: Theme.caution, radius: 4)
            }
            if let t = model.tempC {
                HStack(alignment: .firstTextBaseline, spacing: 3) {
                    Text(String(format: "%.0f", t)).font(.system(size: 26, weight: .bold)).foregroundStyle(Theme.caution)
                    Text("°").font(.system(size: 14, weight: .bold)).foregroundStyle(Color(hex: 0x7a8696))
                }.padding(.top, 6)
                Text("CPU die").font(.system(size: 10.5)).foregroundStyle(Theme.textFaint)
                Spacer(minLength: 8)
                Sparkline(data: model.tempHistory, color: Theme.caution).frame(height: 50)
            } else {
                Spacer()
                Text(model.thermalState).font(.system(size: 28, weight: .bold)).foregroundStyle(Theme.caution)
                Text("macOS thermal state").font(.system(size: 10.5)).foregroundStyle(Theme.textFaint)
                Spacer()
            }
        }
        .padding(16).frame(maxWidth: .infinity, minHeight: Self.monitorHeight, maxHeight: Self.monitorHeight, alignment: .leading)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.stroke))
    }
}

// MARK: - Clean

private struct CleanView: View {
    @EnvironmentObject var model: CleanerModel
    @State private var expanded: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // summary
            HStack(spacing: 18) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("FOUND TO CLEAN").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.textMute)
                    HStack(alignment: .firstTextBaseline, spacing: 5) {
                        Text(ByteFmt.string(model.totalFound)).font(.system(size: 32, weight: .bold)).foregroundStyle(Theme.text)
                        Text("· \(model.orderedItems.count) items").font(.system(size: 13)).foregroundStyle(Theme.textMute)
                    }
                }
                Rectangle().fill(Theme.stroke).frame(width: 1, height: 42)
                HStack(spacing: 18) {
                    legendDot(Theme.safe, "Safe"); legendDot(Theme.caution, "Caution"); legendDot(Theme.danger, "Don't touch")
                }
                Spacer()
                Text("Personal files, photos, iCloud and Mail are protected in the core and cannot be deleted.")
                    .font(.system(size: 11.5)).foregroundStyle(Theme.textFaint).frame(width: 230).multilineTextAlignment(.trailing)
            }
            .padding(18).background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
            .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.stroke))

            if model.isScanning && model.groups.isEmpty {
                HStack { Spacer(); ProgressView().controlSize(.large); Spacer() }.padding(40)
            } else if model.groups.isEmpty {
                Text("Nothing to clean — caches are empty. 🎉").foregroundStyle(Theme.textMute).padding(40)
            } else {
                ForEach(model.groups) { g in categoryCard(g) }
            }
            if !model.reportGroups.isEmpty { reportSection }
            Color.clear.frame(height: 8)
        }
    }

    private var reportSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 9) {
                Image(systemName: "eye").foregroundStyle(Theme.textDim).font(.system(size: 13))
                Text("REVIEW MANUALLY").font(.system(size: 12.5, weight: .bold)).foregroundStyle(Color(hex: 0x9aa6b8))
                Text("found in risky areas — the app never touches these; check them yourself")
                    .font(.system(size: 11.5)).foregroundStyle(Theme.textMute)
            }.padding(.top, 6)
            ForEach(model.reportGroups) { g in reportCard(g) }
        }
    }

    @ViewBuilder private func reportCard(_ g: ScanGroup) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                RoundedRectangle(cornerRadius: 8).fill(Color.white.opacity(0.05)).frame(width: 30, height: 30)
                    .overlay(Image(systemName: "eye").font(.system(size: 13)).foregroundStyle(Theme.textDim))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 9) {
                        Text(g.name).font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                        RiskBadge(color: Theme.textDim, label: "Review only")
                    }
                    Text(g.note ?? "Shown for review — not deleted by the app.").font(.system(size: 11.5)).foregroundStyle(Theme.textMute).lineLimit(1)
                }
                Spacer()
                Text(ByteFmt.string(g.totalBytes)).font(.system(size: 14, weight: .bold)).foregroundStyle(Color(hex: 0xcdd6e3))
            }.padding(.horizontal, 18).padding(.vertical, 13)
            Divider().overlay(Theme.strokeSoft)
            ForEach(g.items.prefix(8)) { it in
                HStack(spacing: 13) {
                    Image(systemName: "doc").foregroundStyle(Theme.textFaint).font(.system(size: 12)).frame(width: 18)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(it.displayName).font(.system(size: 12.5)).foregroundStyle(Color(hex: 0xdbe2ed)).lineLimit(1)
                        Text(it.path).font(.system(size: 10, design: .monospaced)).foregroundStyle(Color(hex: 0x4f5868)).lineLimit(1).truncationMode(.head)
                    }
                    Spacer()
                    Text(ByteFmt.string(it.size)).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textDim)
                    Button { LargeFiles.revealInFinder(it.path) } label: {
                        Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textDim)
                            .frame(width: 30, height: 30).background(Color.white.opacity(0.03), in: RoundedRectangle(cornerRadius: 8))
                            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.white.opacity(0.08)))
                    }.buttonStyle(.plain).help("Reveal in Finder")
                }.padding(.horizontal, 18).padding(.vertical, 10)
                Divider().overlay(Color.white.opacity(0.03))
            }
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Theme.stroke))
    }

    private func legendDot(_ c: Color, _ t: String) -> some View {
        HStack(spacing: 7) { RoundedRectangle(cornerRadius: 3).fill(c).frame(width: 9, height: 9).shadow(color: c.opacity(0.6), radius: 4)
            Text(t).font(.system(size: 12)).foregroundStyle(Color(hex: 0x9aa6b8)) }
    }

    @ViewBuilder private func categoryCard(_ g: ScanGroup) -> some View {
        let c = Theme.tier(g.safety)
        let isOpen = expanded.contains(g.targetID)
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                if g.blockedBy == nil {
                    Button { model.setGroup(g, selected: !model.isGroupFullySelected(g)) } label: {
                        checkbox(model.isGroupFullySelected(g), c)
                    }.buttonStyle(.plain)
                } else {
                    Image(systemName: "lock.fill").foregroundStyle(Theme.caution).frame(width: 20)
                }
                RoundedRectangle(cornerRadius: 8).fill(c.opacity(0.13)).frame(width: 30, height: 30)
                    .overlay(Image(systemName: "folder").font(.system(size: 14)).foregroundStyle(c))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 9) {
                        Text(g.name).font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                        RiskBadge(color: c, label: tierLabel(g.safety))
                    }
                    Text(g.blockedBy != nil ? "Blocked: \(g.blockedBy!) is running — close it and rescan"
                                            : (g.note ?? "")).font(.system(size: 11.5))
                        .foregroundStyle(g.blockedBy != nil ? Theme.caution : Theme.textMute).lineLimit(1)
                }
                Spacer()
                Text(ByteFmt.string(g.totalBytes)).font(.system(size: 14, weight: .bold)).foregroundStyle(Color(hex: 0xcdd6e3))
                if g.blockedBy == nil {
                    Image(systemName: "chevron.down").font(.system(size: 12, weight: .bold)).foregroundStyle(Theme.textMute)
                        .rotationEffect(.degrees(isOpen ? 0 : -90))
                }
            }
            .padding(.horizontal, 18).padding(.vertical, 15).contentShape(Rectangle())
            .onTapGesture { if g.blockedBy == nil { if isOpen { expanded.remove(g.targetID) } else { expanded.insert(g.targetID) } } }

            if isOpen && g.blockedBy == nil {
                Divider().overlay(Theme.strokeSoft)
                ForEach(g.items) { it in
                    Button { model.binding(for: it.path).wrappedValue.toggle() } label: {
                        HStack(spacing: 13) {
                            checkbox(model.selected.contains(it.path), c, size: 18)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(it.displayName).font(.system(size: 13)).foregroundStyle(Color(hex: 0xdbe2ed)).lineLimit(1)
                                Text(it.path).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Color(hex: 0x4f5868)).lineLimit(1).truncationMode(.head)
                            }
                            Spacer()
                            Text(ByteFmt.string(it.size)).font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.textDim)
                        }
                        .padding(.horizontal, 18).padding(.vertical, 11).contentShape(Rectangle())
                    }.buttonStyle(.plain)
                    Divider().overlay(Color.white.opacity(0.03))
                }
            }
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(model.selected.contains(where: { p in g.items.contains { $0.path == p } }) ? c.opacity(0.33) : Theme.stroke))
    }

    private func checkbox(_ on: Bool, _ color: Color, size: CGFloat = 20) -> some View {
        RoundedRectangle(cornerRadius: 6).fill(on ? color : Color.white.opacity(0.02))
            .frame(width: size, height: size)
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(on ? color : Color.white.opacity(0.18), lineWidth: 1.5))
            .overlay(on ? Image(systemName: "checkmark").font(.system(size: size * 0.5, weight: .heavy)).foregroundStyle(Theme.bg) : nil)
    }
    private func tierLabel(_ s: SafetyLevel) -> String {
        switch s { case .safe: return "Safe"; case .moderate: return "Caution"; case .risky: return "Risky"; case .manual: return "Manual" }
    }
}

// MARK: - Large files

private struct LargeView: View {
    @EnvironmentObject var model: CleanerModel
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 11) {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(Theme.caution)
                Text("Map of large files — where space went. Sort by age to surface big files you haven't touched in ages. Includes important files (AI models, images, projects). The app deletes nothing here — view only; reveal in Finder.")
                    .font(.system(size: 12.5)).foregroundStyle(Color(hex: 0xcaa97a)).fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16).padding(.vertical, 13)
            .background(Theme.caution.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.caution.opacity(0.18)))

            if model.isFindingLarge {
                HStack { Spacer(); ProgressView("Scanning home folder…").controlSize(.large); Spacer() }.padding(40)
            } else if !model.largeScanned {
                HStack { Spacer(); Button("Find large files (≥ 100 MB)") { model.findLargeFiles() }; Spacer() }.padding(40)
            } else {
                HStack(spacing: 12) {
                    Picker("", selection: $model.largeSort) {
                        Text("By size").tag(LargeSort.size); Text("By age").tag(LargeSort.age)
                    }.pickerStyle(.segmented).fixedSize().labelsHidden()
                    if model.largeOldCount > 0 {
                        HStack(spacing: 5) {
                            Circle().fill(Theme.caution).frame(width: 6, height: 6)
                            Text("\(model.largeOldCount) not touched in over a year")
                                .font(.system(size: 11.5)).foregroundStyle(Theme.caution)
                        }
                    }
                    Spacer()
                    Text("\(model.largeFiles.count) files ≥ 100 MB").font(.system(size: 11)).foregroundStyle(Theme.textFaint)
                }.padding(.horizontal, 4).padding(.bottom, 2)
                group(.safe, "Safe to delete", "regenerates or junk")
                group(.discretion, "Your call", "might be needed — you decide")
                group(.never, "Don't touch", "system or part of installed software")
            }
            Color.clear.frame(height: 8)
        }
    }
    @ViewBuilder private func group(_ v: Verdict, _ title: String, _ sub: String) -> some View {
        let items = model.largeGroup(v)
        if !items.isEmpty {
            let c = Theme.risk(v)
            VStack(spacing: 0) {
                HStack(spacing: 11) {
                    RiskBadge(color: c, label: Theme.riskLabel(v))
                    Text(title).font(.system(size: 14, weight: .bold)).foregroundStyle(Theme.text)
                    Text(sub).font(.system(size: 12)).foregroundStyle(Theme.textMute)
                    Spacer()
                    Text("\(items.count) · \(ByteFmt.string(items.reduce(0) { $0 + $1.file.size }))")
                        .font(.system(size: 13, weight: .bold)).foregroundStyle(Color(hex: 0xcdd6e3))
                }.padding(.horizontal, 18).padding(.vertical, 14)
                Divider().overlay(Theme.strokeSoft)
                ForEach(items) { cf in
                    HStack(spacing: 14) {
                        RoundedRectangle(cornerRadius: 4).fill(c).frame(width: 4, height: 34)
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 7) {
                                Text(cf.file.displayName).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color(hex: 0xdbe2ed)).lineLimit(1)
                                if LargeFiles.isOld(cf.file.modified) {
                                    Text("old").font(.system(size: 9.5, weight: .semibold)).foregroundStyle(Theme.caution)
                                        .padding(.horizontal, 6).padding(.vertical, 1).background(Theme.caution.opacity(0.13), in: Capsule())
                                }
                            }
                            Text(cf.cls.reason).font(.system(size: 11)).foregroundStyle(Theme.textMute).lineLimit(1)
                            Text(cf.file.path).font(.system(size: 10, design: .monospaced)).foregroundStyle(Color(hex: 0x4f5868)).lineLimit(1).truncationMode(.head)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 2) {
                            Text(ByteFmt.string(cf.file.size)).font(.system(size: 13.5, weight: .bold)).foregroundStyle(Theme.text)
                            Text("modified \(LargeFiles.ago(cf.file.modified))").font(.system(size: 10)).foregroundStyle(Theme.textFaint)
                        }
                        Button { LargeFiles.revealInFinder(cf.file.path) } label: {
                            Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textDim)
                                .frame(width: 30, height: 30).background(Color.white.opacity(0.03), in: RoundedRectangle(cornerRadius: 8))
                                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.white.opacity(0.08)))
                        }.buttonStyle(.plain).help("Reveal in Finder")
                    }.padding(.horizontal, 18).padding(.vertical, 13)
                    Divider().overlay(Color.white.opacity(0.03))
                }
            }
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
            .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.stroke))
        }
    }
}

// MARK: - Duplicates

private struct DuplicatesView: View {
    @EnvironmentObject var model: CleanerModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            banner
            if model.isFindingDups && model.dups.isEmpty {
                scanning
            } else if !model.dupsScanned {
                HStack { Spacer()
                    Button("Find duplicate files (≥ 1 MB)") { model.findDuplicates() }
                    Spacer() }.padding(40)
            } else if model.dups.isEmpty {
                Text("No duplicate files found. 🎉").foregroundStyle(Theme.textMute).padding(40)
            } else {
                summary
                ForEach(model.dups) { g in card(g) }
            }
            Color.clear.frame(height: 8)
        }
    }

    private var banner: some View {
        HStack(spacing: 11) {
            Image(systemName: "doc.on.doc").foregroundStyle(Theme.accentB)
            Text("Exact, byte-for-byte duplicates. APFS clones share the same blocks on disk — deleting them frees nothing, so they're flagged and counted as 0. Nothing is pre-selected; protected personal files can only be revealed.")
                .font(.system(size: 12.5)).foregroundStyle(Color(hex: 0x8fb9c9)).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16).padding(.vertical, 13)
        .background(Theme.accentA.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.accentA.opacity(0.16)))
    }

    private var scanning: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Spacer(); ProgressView().controlSize(.large); Spacer() }
            ProgressView(value: model.dupsProgress).tint(Theme.accentA)
            Text(model.dupsStage.isEmpty ? "Scanning home folder…" : "\(model.dupsStage)…")
                .font(.system(size: 12)).foregroundStyle(Theme.textMute)
        }.padding(.vertical, 24)
    }

    private var summary: some View {
        HStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 3) {
                Text("RECLAIMABLE").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.textMute)
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text(ByteFmt.string(model.dupsRedundant)).font(.system(size: 32, weight: .bold)).foregroundStyle(Theme.text)
                    Text("· \(model.dups.count) groups").font(.system(size: 13)).foregroundStyle(Theme.textMute)
                }
            }
            Rectangle().fill(Theme.stroke).frame(width: 1, height: 42)
            Text("Real space freed by keeping one copy in each group — APFS clones excluded.")
                .font(.system(size: 11.5)).foregroundStyle(Theme.textMute).frame(width: 260).fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
        .padding(18).background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.stroke))
    }

    @ViewBuilder private func card(_ g: DupGroup) -> some View {
        let accent = g.allClones ? Theme.caution : Theme.safe
        let anySelected = g.files.contains { model.dupsSelected.contains($0.path) }
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                RoundedRectangle(cornerRadius: 8).fill(accent.opacity(0.13)).frame(width: 30, height: 30)
                    .overlay(Image(systemName: g.allClones ? "link" : "doc.on.doc").font(.system(size: 13)).foregroundStyle(accent))
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 9) {
                        Text("\(g.count) copies · \(ByteFmt.string(g.size)) each")
                            .font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                        if g.allClones {
                            RiskBadge(color: Theme.caution, label: "APFS clones · 0 freed")
                        } else {
                            RiskBadge(color: Theme.safe, label: "Frees \(ByteFmt.string(g.reclaimable))")
                        }
                    }
                    Text(g.files.first?.displayName ?? "").font(.system(size: 11.5)).foregroundStyle(Theme.textMute).lineLimit(1)
                }
                Spacer()
                if anySelected {
                    Button { model.dupsClearGroup(g) } label: {
                        Text("Clear").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textDim)
                            .padding(.horizontal, 12).padding(.vertical, 6)
                            .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(.plain)
                }
                Button { model.dupsKeepOne(g) } label: {
                    Text("Keep one").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.accentB)
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .background(Theme.accentB.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
                }.buttonStyle(.plain).help("Select every copy except one")
            }
            .padding(.horizontal, 18).padding(.vertical, 14)
            Divider().overlay(Theme.strokeSoft)
            ForEach(g.files) { f in row(f, in: g, accent: accent) }
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(anySelected ? accent.opacity(0.33) : Theme.stroke))
    }

    @ViewBuilder private func row(_ f: DupFile, in g: DupGroup, accent: Color) -> some View {
        let canSelect = model.dupCanSelect(f, in: g)
        HStack(spacing: 13) {
            if f.trashable && canSelect {
                Button { model.dupBinding(f.path).wrappedValue.toggle() } label: {
                    checkbox(model.dupsSelected.contains(f.path), accent)
                }.buttonStyle(.plain)
            } else if f.trashable {
                // последняя копия группы — её оставляем, отметить нельзя
                Image(systemName: "checkmark.shield.fill").foregroundStyle(Theme.safe).frame(width: 18)
                    .help("Kept — at least one copy always stays")
            } else {
                Image(systemName: "lock.fill").foregroundStyle(Theme.textDim).frame(width: 18)
                    .help("Protected personal file — reveal only")
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 7) {
                    Text(f.displayName).font(.system(size: 13)).foregroundStyle(Color(hex: 0xdbe2ed)).lineLimit(1)
                    if f.shared { tag("shares blocks", Theme.caution) }
                    if !f.trashable { tag("protected", Theme.textDim) }
                    if f.trashable && !canSelect { tag("kept", Theme.safe) }
                }
                Text(f.path).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Color(hex: 0x4f5868))
                    .lineLimit(1).truncationMode(.head)
            }
            Spacer()
            Text(ByteFmt.string(f.size)).font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.textDim)
            Button { LargeFiles.revealInFinder(f.path) } label: {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textDim)
                    .frame(width: 30, height: 30).background(Color.white.opacity(0.03), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.white.opacity(0.08)))
            }.buttonStyle(.plain).help("Reveal in Finder")
        }
        .padding(.horizontal, 18).padding(.vertical, 11)
        Divider().overlay(Color.white.opacity(0.03))
    }

    private func tag(_ t: String, _ c: Color) -> some View {
        Text(t).font(.system(size: 9.5, weight: .semibold)).foregroundStyle(c)
            .padding(.horizontal, 6).padding(.vertical, 1).background(c.opacity(0.13), in: Capsule())
    }
    private func checkbox(_ on: Bool, _ color: Color, size: CGFloat = 18) -> some View {
        RoundedRectangle(cornerRadius: 6).fill(on ? color : Color.white.opacity(0.02))
            .frame(width: size, height: size)
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(on ? color : Color.white.opacity(0.18), lineWidth: 1.5))
            .overlay(on ? Image(systemName: "checkmark").font(.system(size: size * 0.5, weight: .heavy)).foregroundStyle(Theme.bg) : nil)
    }
}

// MARK: - Similar Photos (перцептивный хэш — визуально похожие)

/// Ленивая миниатюра картинки через ImageIO (декод вне главного потока, заполняет ширину ячейки).
private struct PhotoThumb: View {
    let path: String
    var height: CGFloat = 118
    @State private var img: NSImage?
    var body: some View {
        ZStack {
            if let img {
                Image(nsImage: img).resizable().aspectRatio(contentMode: .fill)
            } else {
                Rectangle().fill(Color.white.opacity(0.05))
                    .overlay(Image(systemName: "photo").font(.system(size: 18)).foregroundStyle(Theme.textFaint))
            }
        }
        .frame(maxWidth: .infinity).frame(height: height).clipped()
        .task(id: path) { await load() }
    }
    private func load() async {
        let p = path
        let maxPix = Int(height * 2)
        let loaded: NSImage? = await Task.detached(priority: .utility) {
            guard let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: p) as CFURL, nil) else { return nil }
            let opts: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceThumbnailMaxPixelSize: maxPix,
                kCGImageSourceShouldCacheImmediately: true]
            guard let cg = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else { return nil }
            return NSImage(cgImage: cg, size: NSSize(width: cg.width, height: cg.height))
        }.value
        if !Task.isCancelled { img = loaded }
    }
}

private struct SimilarPhotosView: View {
    @EnvironmentObject var model: CleanerModel
    private let cols = [GridItem(.adaptive(minimum: 132, maximum: 168), spacing: 12)]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            banner
            if model.isFindingSims && model.sims.isEmpty {
                scanning
            } else if !model.simsScanned {
                HStack { Spacer()
                    Button("Find similar photos") { model.findSimilarPhotos() }
                    Spacer() }.padding(40)
            } else if model.sims.isEmpty {
                Text("No similar photos found. 🎉").foregroundStyle(Theme.textMute).padding(40)
            } else {
                summary
                if !model.simsNear.isEmpty {
                    sectionHeader("NEAR-DUPLICATES", "Resized or re-compressed copies — keep the best, send the rest to Trash")
                    ForEach(model.simsNear) { g in card(g) }
                }
                if !model.simsRelated.isEmpty {
                    sectionHeader("RELATED · AI SERIES", "Look alike but not the same (e.g. generation steps) — review only, nothing is deleted")
                    ForEach(model.simsRelated) { g in card(g) }
                }
            }
            Color.clear.frame(height: 8)
        }
    }

    private var banner: some View {
        HStack(spacing: 11) {
            Image(systemName: "photo.on.rectangle.angled").foregroundStyle(Theme.accentB)
            Text("Finds images that LOOK alike — resized, re-compressed, screenshots — not byte-identical ones (those live under Duplicates). Photos in Pictures/Downloads/Desktop and inside Photo Libraries are protected: shown for review only. One copy always stays.")
                .font(.system(size: 12.5)).foregroundStyle(Color(hex: 0x8fb9c9)).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16).padding(.vertical, 13)
        .background(Theme.accentA.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.accentA.opacity(0.16)))
    }

    private var scanning: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Spacer(); ProgressView().controlSize(.large); Spacer() }
            ProgressView(value: model.simsProgress).tint(Theme.accentA)
            Text(model.simsStage.isEmpty ? "Scanning home folder…" : "\(model.simsStage)…")
                .font(.system(size: 12)).foregroundStyle(Theme.textMute)
        }.padding(.vertical, 24)
    }

    private var summary: some View {
        HStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 3) {
                Text("RECLAIMABLE").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.textMute)
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text(ByteFmt.string(model.simsReclaimable)).font(.system(size: 32, weight: .bold)).foregroundStyle(Theme.text)
                    Text("· \(model.simsNear.count) near-dup\(model.simsRelated.isEmpty ? "" : " · \(model.simsRelated.count) related")")
                        .font(.system(size: 13)).foregroundStyle(Theme.textMute)
                }
            }
            Rectangle().fill(Theme.stroke).frame(width: 1, height: 42)
            Text("Space freed by keeping the best copy in each near-duplicate group. Protected photos and related series are review-only.")
                .font(.system(size: 11.5)).foregroundStyle(Theme.textMute).frame(width: 300).fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
        .padding(18).background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.stroke))
    }

    private func sectionHeader(_ title: String, _ subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.system(size: 12, weight: .bold)).foregroundStyle(Theme.textMute).tracking(0.6)
            Text(subtitle).font(.system(size: 11.5)).foregroundStyle(Theme.textFaint)
        }.padding(.top, 6)
    }

    @ViewBuilder private func card(_ g: SimilarGroup) -> some View {
        let isRelated = g.kind == .relatedSeries
        let accent = isRelated ? Theme.caution : Theme.safe
        let anySelected = g.photos.contains { model.simSelected.contains($0.path) }
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                RoundedRectangle(cornerRadius: 8).fill(accent.opacity(0.13)).frame(width: 30, height: 30)
                    .overlay(Image(systemName: isRelated ? "sparkles" : "photo.stack").font(.system(size: 13)).foregroundStyle(accent))
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 9) {
                        Text("\(g.count) similar · \(ByteFmt.string(g.keeper?.size ?? 0)) each")
                            .font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                        if isRelated {
                            RiskBadge(color: Theme.caution, label: "Review only")
                        } else if g.reclaimable > 0 {
                            RiskBadge(color: Theme.safe, label: "Frees \(ByteFmt.string(g.reclaimable))")
                        } else {
                            RiskBadge(color: Theme.caution, label: "Protected · review")
                        }
                    }
                    Text(g.keeper?.displayName ?? "").font(.system(size: 11.5)).foregroundStyle(Theme.textMute).lineLimit(1)
                }
                Spacer()
                if !isRelated {
                    if anySelected {
                        Button { model.simsClearGroup(g) } label: {
                            Text("Clear").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textDim)
                                .padding(.horizontal, 12).padding(.vertical, 6)
                                .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
                        }.buttonStyle(.plain)
                    }
                    Button { model.simsKeepOne(g) } label: {
                        Text("Keep best").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.accentB)
                            .padding(.horizontal, 12).padding(.vertical, 6)
                            .background(Theme.accentB.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(.plain).help("Select every copy except the best one")
                }
            }
            .padding(.horizontal, 18).padding(.vertical, 14)
            Divider().overlay(Theme.strokeSoft)
            LazyVGrid(columns: cols, alignment: .leading, spacing: 12) {
                ForEach(g.photos) { p in cell(p, in: g, accent: accent, isRelated: isRelated) }
            }
            .padding(16)
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(anySelected ? accent.opacity(0.33) : Theme.stroke))
    }

    @ViewBuilder private func cell(_ p: SimilarPhoto, in g: SimilarGroup, accent: Color, isRelated: Bool) -> some View {
        let selectable = model.simCanSelect(p, in: g)
        let selected = model.simSelected.contains(p.path)
        VStack(alignment: .leading, spacing: 5) {
            ZStack(alignment: .topLeading) {
                PhotoThumb(path: p.path)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(selected ? accent : Color.white.opacity(0.08), lineWidth: selected ? 2 : 1))
                // левый-верх: чекбокс / щит keeper / замок / глаз
                Group {
                    if !p.trashable {
                        badgeIcon("lock.fill", Theme.textDim).help("Protected personal file — reveal only")
                    } else if isRelated {
                        badgeIcon("eye", Theme.caution).help("Related — review only, not deleted")
                    } else if selectable {
                        checkbox(selected, accent)
                    } else {
                        badgeIcon("checkmark.shield.fill", Theme.safe).help("Best copy — always kept")
                    }
                }
                .padding(6)
                if p.isKeeper && !isRelated {
                    Text("BEST").font(.system(size: 8.5, weight: .heavy)).foregroundStyle(Theme.bg)
                        .padding(.horizontal, 5).padding(.vertical, 2)
                        .background(Theme.safe, in: Capsule())
                        .padding(6).frame(maxWidth: .infinity, alignment: .topTrailing)
                }
            }
            .contentShape(Rectangle())
            .onTapGesture { if selectable { model.simBinding(p.path).wrappedValue.toggle() } }
            HStack(spacing: 5) {
                Text(p.displayName).font(.system(size: 10.5)).foregroundStyle(Color(hex: 0xdbe2ed)).lineLimit(1)
                Spacer(minLength: 0)
                Button { LargeFiles.revealInFinder(p.path) } label: {
                    Image(systemName: "magnifyingglass").font(.system(size: 10)).foregroundStyle(Theme.textDim)
                }.buttonStyle(.plain).help("Reveal in Finder")
            }
            Text("\(p.width)×\(p.height) · \(ByteFmt.string(p.size))").font(.system(size: 9.5)).foregroundStyle(Theme.textFaint)
        }
    }

    private func badgeIcon(_ name: String, _ color: Color) -> some View {
        Image(systemName: name).font(.system(size: 12, weight: .bold)).foregroundStyle(color)
            .frame(width: 20, height: 20)
            .background(Theme.bg.opacity(0.55), in: RoundedRectangle(cornerRadius: 6))
    }
    private func checkbox(_ on: Bool, _ color: Color, size: CGFloat = 20) -> some View {
        RoundedRectangle(cornerRadius: 6).fill(on ? color : Theme.bg.opacity(0.55))
            .frame(width: size, height: size)
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(on ? color : Color.white.opacity(0.5), lineWidth: 1.5))
            .overlay(on ? Image(systemName: "checkmark").font(.system(size: size * 0.5, weight: .heavy)).foregroundStyle(Theme.bg) : nil)
    }
}

// MARK: - System Cleanup (привилегированный хелпер, Phase 1b/1c — восстановимый карантин)

private struct SystemView: View {
    @ObservedObject private var helper = PrivilegedHelper.shared
    @State private var report: [SystemCleanupItem] = []
    @State private var scanning = false
    @State private var scanError: String?
    @State private var reported = false
    @State private var selected: Set<String> = []
    @State private var entries: [QEntryReport] = []
    @State private var busy = false
    @State private var busyMsg: String?
    @State private var confirmEmpty = false
    @State private var confirmUninstall = false
    @State private var uninstalling = false
    @State private var uninstallMsg: String?
    @State private var exportMsg: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            banner
            switch helper.state {
            case .enabled: enabledBody
            case .requiresApproval: approvalBody
            default: enableBody
            }
            activityLogSection
            uninstallSection
            Color.clear.frame(height: 8)
        }
        .onAppear { helper.refreshStatus(); if helper.state == .enabled { refreshQuarantine() } }
        .confirmationDialog("Permanently empty quarantine?",
                            isPresented: $confirmEmpty, titleVisibility: .visible) {
            Button("Empty \(entries.count) item\(entries.count == 1 ? "" : "s") — permanent", role: .destructive) { emptyAll() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("These were moved out of the system and can still be restored right now. Emptying deletes them for good — this cannot be undone.")
        }
        .confirmationDialog("Uninstall MacCleaner?", isPresented: $confirmUninstall, titleVisibility: .visible) {
            Button("Uninstall & quit", role: .destructive) { uninstall() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(uninstallWarning)
        }
    }

    // MARK: Полное удаление приложения «за собой» (one-click)

    /// Текст предупреждения: учитывает, есть ли что-то невосстановленное в карантине.
    private var uninstallWarning: String {
        let q = entries.isEmpty ? "" :
            " It also permanently deletes \(entries.count) quarantined item\(entries.count == 1 ? "" : "s") you haven't restored."
        return "This removes the background helper, deletes MacCleaner's preferences and its system quarantine, then moves MacCleaner to the Trash and quits.\(q) macOS keeps Full Disk Access until you turn it off in System Settings, and writes a few system logs no app can delete."
    }

    private var activityLogSection: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Activity log").font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.text)
                Text("Everything MacCleaner does — scans, items moved to Trash, quarantine, restores, process quits — is recorded locally (nothing leaves your Mac). Export a copy to your Desktop.")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMute).fixedSize(horizontal: false, vertical: true)
                if let m = exportMsg { Text(m).font(.system(size: 11)).foregroundStyle(Theme.safe) }
            }
            Spacer(minLength: 8)
            HStack(spacing: 8) {
                Button { NSWorkspace.shared.activateFileViewerSelecting([ActivityLog.shared.fileURL]) } label: {
                    Text("Reveal").font(.system(size: 12)).foregroundStyle(Theme.textDim)
                        .padding(.horizontal, 10).padding(.vertical, 7)
                }.buttonStyle(.plain)
                Button { exportLogs() } label: { secondaryLabel("Export logs") }.buttonStyle(.plain)
            }
        }
        .padding(14).background(Theme.card.opacity(0.55), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.stroke))
    }

    /// Пишет журнал на Рабочий стол; если хелпер включён — подцепляет его root audit-log.
    private func exportLogs() {
        let write: (String?) -> Void = { audit in
            if let url = ActivityLog.shared.exportToDesktop(helperAudit: audit) {
                self.exportMsg = "Saved “\(url.lastPathComponent)” to your Desktop."
                NSWorkspace.shared.activateFileViewerSelecting([url])
            } else { self.exportMsg = "Couldn't write the log file." }
        }
        if helper.state == .enabled { helper.fetchAuditLog { audit in write(audit.isEmpty ? nil : audit) } }
        else { write(nil) }
    }

    private var uninstallSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Uninstall MacCleaner").font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.text)
                    Text("One click: removes the helper, MacCleaner's data and quarantine, then moves the app to the Trash and quits — leaving nothing behind.")
                        .font(.system(size: 11)).foregroundStyle(Theme.textMute).fixedSize(horizontal: false, vertical: true)
                    if let m = uninstallMsg { Text(m).font(.system(size: 11)).foregroundStyle(Theme.caution) }
                }
                Spacer(minLength: 8)
                Button { confirmUninstall = true } label: {
                    Text(uninstalling ? "Uninstalling…" : "Uninstall…").font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Theme.caution).padding(.horizontal, 12).padding(.vertical, 7)
                        .background(Theme.caution.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Theme.caution.opacity(0.3)))
                }.buttonStyle(.plain).disabled(uninstalling)
            }
        }
        .padding(14).background(Theme.card.opacity(0.55), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.stroke))
    }

    /// Шаг 1: если хелпер включён — root-очистка карантина+каталогов, затем разрегистрация демона. Затем шаг 2.
    private func uninstall() {
        guard !uninstalling else { return }
        uninstalling = true; uninstallMsg = nil
        ActivityLog.shared.log("uninstall", "uninstall requested (helper \(helper.state == .enabled ? "enabled" : "off"))")
        if helper.state == .enabled {
            helper.purgeAllForUninstall { result, err in
                if let err { self.uninstallMsg = "Helper cleanup: \(err) — continuing." }
                else if let r = result, !r.ok, let e = r.error { self.uninstallMsg = "Helper cleanup: \(e) — continuing." }
                if let r = result {
                    ActivityLog.shared.log("uninstall", "helper purge: ok=\(r.ok) items=\(r.itemsRemoved) freed=\(ByteFmt.string(r.bytesFreed))\(r.error.map { " err=\($0)" } ?? "")")
                }
                helper.remove()                 // разрегистрировать демон (BTM/launchd)
                self.finishUninstall()
            }
        } else {
            finishUninstall()                   // хелпер не ставился — чистить нечего на root-стороне
        }
    }

    /// Шаг 2 (app-side): убрать свои данные, перенести бандл в Корзину, выйти жёстко.
    /// ⚠️ Prefs-файлы (cfprefsd-домены) НЕЛЬЗЯ снести просто удалив .plist: пока приложение
    /// живо, AppKit дописывает рамку окна в домен, и cfprefsd ВОСКРЕШАЕТ .plist при выходе
    /// (воспроизведено эмпирически). Поэтому домены убираем авторитетно через `defaults delete`
    /// детач-процессом, который дожидается нашей смерти — тогда писать в домен уже некому.
    private func finishUninstall() {
        let fm = FileManager.default
        let lib = NSHomeDirectory() + "/Library"
        // bundle + НЕ-prefs данные → в Корзину (восстановимо). Prefs (cfprefsd) — отдельно, ниже.
        var toTrash: [URL] = [Bundle.main.bundleURL]
        for rel in ["Saved Application State/com.maccleaner.app.savedState",
                    "Caches/com.maccleaner.app",
                    "Application Support/MacCleaner"] {   // наш каталог (activity.log) — тоже убираем
            let u = URL(fileURLWithPath: lib + "/" + rel)
            if fm.fileExists(atPath: u.path) { toTrash.append(u) }
        }
        // CrashReporter оставляет MacCleaner_<UUID>.plist (ОС создаёт при аварийном/принудительном
        // выходе) — это тоже наш след. Сносим только наши (префикс "MacCleaner_", не "Mac Cleaner").
        let crashDir = lib + "/Application Support/CrashReporter"
        if let names = try? fm.contentsOfDirectory(atPath: crashDir) {
            for n in names where (n.hasPrefix("MacCleaner_") || n == "MacCleaner.plist") && n.hasSuffix(".plist") {
                toTrash.append(URL(fileURLWithPath: crashDir + "/" + n))
            }
        }
        // Best-effort: сбросить кэш cfprefs в нашем процессе (детач-очистка ниже — несущая).
        UserDefaults.standard.removePersistentDomain(forName: "com.maccleaner.app")
        UserDefaults.standard.removePersistentDomain(forName: "MacCleaner")
        NSWorkspace.shared.recycle(toTrash) { _, error in
            DispatchQueue.main.async {
                if let error {
                    // Не смогли сами утащить бандл (права/расположение) — честно показываем и подсвечиваем в Finder.
                    self.uninstalling = false
                    self.uninstallMsg = "Couldn't move the app automatically (\(error.localizedDescription)). Drag MacCleaner to the Trash yourself."
                    NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])
                } else {
                    Self.spawnPrefsCleanup()  // авторитетно снести cfprefsd-домены ПОСЛЕ нашего выхода
                    exit(0)                   // жёсткий выход
                }
            }
        }
    }

    /// Детач-процесс: ждёт смерти нашего pid, даёт cfprefsd осесть, затем `defaults delete` обоих
    /// доменов + удаляет осиротевшие .plist. Переживает наш exit(0). Обычные права пользователя,
    /// без shell-as-root и без внешнего ввода (пути/домены — литералы).
    private static func spawnPrefsCleanup() {
        let pid = getpid()
        let home = NSHomeDirectory()
        let a = "\(home)/Library/Preferences/com.maccleaner.app.plist"
        let b = "\(home)/Library/Preferences/MacCleaner.plist"
        let script = """
        while kill -0 \(pid) 2>/dev/null; do sleep 0.1; done
        sleep 0.4
        /usr/bin/defaults delete com.maccleaner.app >/dev/null 2>&1
        /usr/bin/defaults delete MacCleaner >/dev/null 2>&1
        /bin/rm -f "\(a)" "\(b)"
        """
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", script]
        try? p.run()
    }

    private var banner: some View {
        HStack(spacing: 11) {
            Image(systemName: "lock.shield").foregroundStyle(Theme.accentB)
            Text("Cleaning root-owned system caches & logs needs a tiny privileged helper. It runs only narrow, re-validated operations — no shell, no arbitrary commands — and only talks to MacCleaner (verified by code signature). Cleaning is recoverable: items move to a quarantine you can restore, and are deleted for good only when you empty it.")
                .font(.system(size: 12.5)).foregroundStyle(Color(hex: 0x8fb9c9)).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16).padding(.vertical, 13)
        .background(Theme.accentA.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.accentA.opacity(0.16)))
    }

    private var enableBody: some View {
        VStack(alignment: .leading, spacing: 14) {
            statusRow("Not enabled", "circle.dashed", Theme.textMute)
            Text("Enabling installs a background helper (com.maccleaner.helper). You'll confirm it once in System Settings.")
                .font(.system(size: 12)).foregroundStyle(Theme.textMute).fixedSize(horizontal: false, vertical: true)
            if let e = helper.lastError { Text(e).font(.system(size: 11)).foregroundStyle(Theme.caution) }
            HStack { Button { helper.enable() } label: { primaryLabel("Enable system cleaning", "lock.open") }.buttonStyle(.plain); Spacer() }
        }
        .padding(18).background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.stroke))
    }

    private var approvalBody: some View {
        VStack(alignment: .leading, spacing: 14) {
            statusRow("Waiting for your approval", "exclamationmark.triangle.fill", Theme.caution)
            Text("Approve “MacCleaner” in System Settings → General → Login Items & Extensions (Allow in the Background), then re-check.")
                .font(.system(size: 12)).foregroundStyle(Theme.textMute).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 10) {
                Button { SMAppService.openSystemSettingsLoginItems() } label: { primaryLabel("Open System Settings", "gearshape") }.buttonStyle(.plain)
                Button { helper.refreshStatus() } label: { secondaryLabel("Re-check") }.buttonStyle(.plain)
            }
        }
        .padding(18).background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.caution.opacity(0.25)))
    }

    private var enabledBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                statusRow("Helper enabled", "checkmark.shield.fill", Theme.safe)
                Spacer()
                Button { helper.remove() } label: { secondaryLabel("Remove helper") }.buttonStyle(.plain)
            }
            HStack(spacing: 12) {
                Button { scan() } label: { primaryLabel(scanning ? "Scanning…" : "Scan system", "magnifyingglass") }
                    .buttonStyle(.plain).disabled(scanning || busy)
                if reported && !report.isEmpty {
                    Button { toggleAll() } label: { secondaryLabel(allSelected ? "Clear all" : "Select all") }.buttonStyle(.plain)
                    Text("\(report.count) items · \(ByteFmt.string(report.reduce(0) { $0 + $1.bytes }))")
                        .font(.system(size: 12)).foregroundStyle(Theme.textMute)
                }
            }
            if let e = scanError { Text(e).font(.system(size: 12)).foregroundStyle(Theme.caution) }
            if let m = busyMsg { Text(m).font(.system(size: 12)).foregroundStyle(Theme.textDim) }
            if reported && report.isEmpty && scanError == nil {
                Text("No removable system caches found.").font(.system(size: 12)).foregroundStyle(Theme.textMute)
            }
            ForEach(report) { item in row(item) }
            if !report.isEmpty { quarantineBar }
            if !entries.isEmpty { quarantineSection }
            Text("Items move to /Library/Application Support/MacCleaner — root-owned and recoverable. Nothing leaves your Mac. Use Restore to put a file back, or Empty to delete for good.")
                .font(.system(size: 11)).foregroundStyle(Theme.textFaint).padding(.top, 4)
        }
        .padding(18).background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.safe.opacity(0.18)))
    }

    private var quarantineBar: some View {
        HStack(spacing: 12) {
            Spacer()
            Text("Selected \(selected.count)").font(.system(size: 11)).foregroundStyle(Theme.textMute)
            Text(ByteFmt.string(selectedBytes)).font(.system(size: 15, weight: .bold)).foregroundStyle(Theme.text)
            Button { moveToQuarantine() } label: {
                HStack(spacing: 8) {
                    Image(systemName: "tray.and.arrow.down").font(.system(size: 12, weight: .bold))
                    Text("Move to quarantine").font(.system(size: 13, weight: .bold))
                }
                .foregroundStyle(Theme.bg).padding(.horizontal, 16).padding(.vertical, 9)
                .background(selected.isEmpty || busy ? AnyShapeStyle(Theme.textFaint.opacity(0.3)) : AnyShapeStyle(Theme.accentGrad),
                            in: RoundedRectangle(cornerRadius: 9))
            }.buttonStyle(.plain).disabled(selected.isEmpty || busy)
        }
        .padding(.top, 4)
    }

    private var quarantineSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("QUARANTINE · RECOVERABLE").font(.system(size: 11, weight: .bold)).foregroundStyle(Color(hex: 0xaeb8c6))
                Spacer()
                Text("\(entries.count) · \(ByteFmt.string(entries.reduce(0) { $0 + $1.sizeBytes }))")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMute)
            }.padding(.top, 8)
            ForEach(entries) { e in quarantineRow(e) }
            HStack {
                Spacer()
                Button { confirmEmpty = true } label: {
                    HStack(spacing: 7) {
                        Image(systemName: "trash").font(.system(size: 11, weight: .bold))
                        Text("Empty all — permanent").font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(Theme.caution).padding(.horizontal, 12).padding(.vertical, 7)
                    .background(Theme.caution.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Theme.caution.opacity(0.3)))
                }.buttonStyle(.plain).disabled(busy)
            }.padding(.top, 2)
        }
    }

    private func row(_ item: SystemCleanupItem) -> some View {
        HStack(spacing: 12) {
            Image(systemName: selected.contains(item.path) ? "checkmark.square.fill" : "square")
                .foregroundStyle(selected.contains(item.path) ? Theme.safe : Theme.textFaint)
                .font(.system(size: 15)).frame(width: 20)
                .onTapGesture { toggle(item.path) }
            Image(systemName: "folder").foregroundStyle(Theme.textDim).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text((item.path as NSString).lastPathComponent).font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.text).lineLimit(1)
                Text(item.path).font(.system(size: 10, design: .monospaced)).foregroundStyle(Color(hex: 0x4f5868)).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            Text(item.category).font(.system(size: 9.5, weight: .semibold)).foregroundStyle(Theme.textFaint)
                .padding(.horizontal, 6).padding(.vertical, 1).background(Color.white.opacity(0.05), in: Capsule())
            Text(ByteFmt.string(item.bytes)).font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.textDim)
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .background(Color.white.opacity(0.02), in: RoundedRectangle(cornerRadius: 10))
        .contentShape(Rectangle())
        .onTapGesture { toggle(item.path) }
    }

    private func quarantineRow(_ e: QEntryReport) -> some View {
        HStack(spacing: 12) {
            Image(systemName: e.isDir ? "folder.badge.minus" : "doc").foregroundStyle(Theme.textDim).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text((e.originalPath as NSString).lastPathComponent).font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.text).lineLimit(1)
                Text(e.originalPath).font(.system(size: 10, design: .monospaced)).foregroundStyle(Color(hex: 0x4f5868)).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            if !e.valid { Text("incomplete").font(.system(size: 9.5, weight: .semibold)).foregroundStyle(Theme.caution) }
            Text(ByteFmt.string(e.sizeBytes)).font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.textDim)
            Button { restore(e.entryID) } label: {
                Text("Restore").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.safe)
                    .padding(.horizontal, 10).padding(.vertical, 5)
                    .background(Theme.safe.opacity(0.10), in: RoundedRectangle(cornerRadius: 7))
            }.buttonStyle(.plain).disabled(busy)
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .background(Theme.safe.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
    }

    // MARK: actions

    private var allSelected: Bool { !report.isEmpty && selected.count == report.count }
    private var selectedBytes: Int64 { report.filter { selected.contains($0.path) }.reduce(0) { $0 + $1.bytes } }
    private func toggle(_ p: String) { if selected.contains(p) { selected.remove(p) } else { selected.insert(p) } }
    private func toggleAll() { selected = allSelected ? [] : Set(report.map(\.path)) }

    private func scan() {
        scanning = true; scanError = nil; selected = []
        helper.fetchSystemSizes { items, err in
            scanning = false; reported = true
            if let items { report = items } else { scanError = err ?? "scan failed"; report = [] }
            refreshQuarantine()
        }
    }

    private func refreshQuarantine() {
        helper.listQuarantine { list, _ in if let list { entries = list } }
    }

    private func moveToQuarantine() {
        let paths = report.filter { selected.contains($0.path) }.map(\.path)
        guard !paths.isEmpty else { return }
        busy = true; busyMsg = nil
        helper.quarantine(paths) { results, err in
            busy = false
            let moved = Set((results ?? []).filter(\.ok).map(\.path))
            let failed = (results ?? []).filter { !$0.ok }
            report.removeAll { moved.contains($0.path) }
            selected.subtract(moved)
            if let f = failed.first { busyMsg = "Quarantined \(moved.count) · \(failed.count) failed (\(f.error ?? ""))" }
            else if let err { busyMsg = err }
            else { busyMsg = "Moved \(moved.count) item\(moved.count == 1 ? "" : "s") to quarantine — recoverable." }
            ActivityLog.shared.quarantineResults("system-quarantine", busyMsg ?? "quarantine", results ?? [])
            refreshQuarantine()
        }
    }

    private func restore(_ id: String) {
        busy = true; busyMsg = nil
        helper.restoreQuarantine([id]) { results, err in
            busy = false
            if let r = results?.first, r.ok { busyMsg = "Restored to \(r.path)"; entries.removeAll { $0.entryID == id } }
            else { busyMsg = results?.first?.error ?? err ?? "restore failed" }
            ActivityLog.shared.log("system-restore", busyMsg ?? "restore")
            refreshQuarantine()
        }
    }

    private func emptyAll() {
        let ids = entries.map(\.entryID)
        guard !ids.isEmpty else { return }
        busy = true; busyMsg = nil
        helper.emptyQuarantine(ids) { results, err in
            busy = false
            let done = (results ?? []).filter(\.ok).count
            let freed = (results ?? []).reduce(0) { $0 + $1.bytes }
            busyMsg = err ?? "Permanently removed \(done) item\(done == 1 ? "" : "s") · \(ByteFmt.string(freed)) freed."
            ActivityLog.shared.log("system-empty", busyMsg ?? "empty")
            refreshQuarantine()
        }
    }

    private func statusRow(_ t: String, _ icon: String, _ c: Color) -> some View {
        HStack(spacing: 9) {
            Image(systemName: icon).foregroundStyle(c)
            Text(t).font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
        }
    }
    private func primaryLabel(_ t: String, _ icon: String) -> some View {
        HStack(spacing: 8) { Image(systemName: icon).font(.system(size: 12, weight: .bold)); Text(t).font(.system(size: 13, weight: .bold)) }
            .foregroundStyle(Theme.bg).padding(.horizontal, 16).padding(.vertical, 9)
            .background(Theme.accentGrad, in: RoundedRectangle(cornerRadius: 9))
    }
    private func secondaryLabel(_ t: String) -> some View {
        Text(t).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textDim)
            .padding(.horizontal, 12).padding(.vertical, 8).background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
    }
}

// MARK: - Apps (uninstaller + leftovers)

private struct AppsView: View {
    @EnvironmentObject var model: CleanerModel
    @State private var expanded: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            banner
            if model.isFindingApps && model.apps.isEmpty {
                scanning
            } else if !model.appsScanned {
                HStack { Spacer(); Button("Scan installed apps") { model.findApps() }; Spacer() }.padding(40)
            } else {
                summary
                if !model.orphans.isEmpty { orphansSection }
                if !model.apps.isEmpty { installedSection }
                if model.apps.isEmpty && model.orphans.isEmpty {
                    Text("No third-party apps found.").foregroundStyle(Theme.textMute).padding(40)
                }
            }
            Color.clear.frame(height: 8)
        }
    }

    private var banner: some View {
        HStack(spacing: 11) {
            Image(systemName: "trash.square").foregroundStyle(Theme.accentB)
            Text("Deleting an app leaves caches, preferences and support files behind. Remove an app together with its leftovers — and clean folders left by apps you already deleted. Apple apps are excluded. Nothing is pre-selected; everything goes to Trash (recoverable).")
                .font(.system(size: 12.5)).foregroundStyle(Color(hex: 0x8fb9c9)).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16).padding(.vertical, 13)
        .background(Theme.accentA.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.accentA.opacity(0.16)))
    }

    private var scanning: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Spacer(); ProgressView().controlSize(.large); Spacer() }
            ProgressView(value: model.appsProgress).tint(Theme.accentA)
            Text(model.appsStage.isEmpty ? "Scanning apps…" : "\(model.appsStage)…")
                .font(.system(size: 12)).foregroundStyle(Theme.textMute)
        }.padding(.vertical, 24)
    }

    private var summary: some View {
        HStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 3) {
                Text("APPS & LEFTOVERS").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.textMute)
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text(ByteFmt.string(model.appsReclaimable)).font(.system(size: 32, weight: .bold)).foregroundStyle(Theme.text)
                    Text("· \(model.apps.count) apps\(model.orphans.isEmpty ? "" : " · \(model.orphans.count) removed")").font(.system(size: 13)).foregroundStyle(Theme.textMute)
                }
            }
            Spacer()
            Text("Check what to remove — apps and their data go to Trash.")
                .font(.system(size: 11.5)).foregroundStyle(Theme.textFaint).frame(width: 230).multilineTextAlignment(.trailing)
        }
        .padding(18).background(Theme.card, in: RoundedRectangle(cornerRadius: 15))
        .overlay(RoundedRectangle(cornerRadius: 15).strokeBorder(Theme.stroke))
    }

    private var orphansSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 9) {
                Image(systemName: "shippingbox").foregroundStyle(Theme.caution).font(.system(size: 13))
                Text("LEFTOVERS FROM REMOVED APPS").font(.system(size: 12.5, weight: .bold)).foregroundStyle(Color(hex: 0xcaa97a))
                Text("the app is gone, this data isn't").font(.system(size: 11.5)).foregroundStyle(Theme.textMute)
            }.padding(.top, 2)
            ForEach(model.orphans) { o in orphanCard(o) }
        }
    }

    private var installedSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 9) {
                Image(systemName: "square.grid.2x2").foregroundStyle(Theme.accentB).font(.system(size: 13))
                Text("INSTALLED APPS").font(.system(size: 12.5, weight: .bold)).foregroundStyle(Color(hex: 0xaeb8c6))
                Text("checking selects the app + its exact data").font(.system(size: 11.5)).foregroundStyle(Theme.textMute)
            }.padding(.top, 4)
            ForEach(model.apps) { a in appCard(a) }
        }
    }

    @ViewBuilder private func appCard(_ a: InstalledApp) -> some View {
        let isOpen = expanded.contains(a.path)
        let sel = model.isAppSelected(a)
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                Button { sel ? model.deselectApp(a) : model.selectAppWithData(a) } label: {
                    checkbox(sel, Theme.accentB)
                }.buttonStyle(.plain)
                Image(nsImage: NSWorkspace.shared.icon(forFile: a.path)).resizable().frame(width: 32, height: 32)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(a.name).font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                        Text("v\(a.version)").font(.system(size: 11)).foregroundStyle(Theme.textFaint)
                    }
                    Text(a.bundleId).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Color(hex: 0x4f5868)).lineLimit(1)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 1) {
                    Text(ByteFmt.string(a.totalBytes)).font(.system(size: 14, weight: .bold)).foregroundStyle(Color(hex: 0xcdd6e3))
                    if a.leftoverBytes > 0 {
                        Text("app \(ByteFmt.string(a.appSize)) + \(ByteFmt.string(a.leftoverBytes)) data")
                            .font(.system(size: 10)).foregroundStyle(Theme.textFaint)
                    }
                }
                Image(systemName: "chevron.down").font(.system(size: 12, weight: .bold)).foregroundStyle(Theme.textMute)
                    .rotationEffect(.degrees(isOpen ? 0 : -90))
            }
            .padding(.horizontal, 18).padding(.vertical, 13).contentShape(Rectangle())
            .onTapGesture { if isOpen { expanded.remove(a.path) } else { expanded.insert(a.path) } }
            if isOpen {
                Divider().overlay(Theme.strokeSoft)
                itemRow(path: a.path, kind: "Application", size: a.appSize, strong: true, trashable: a.trashableBundle, accent: Theme.accentB)
                ForEach(a.leftovers) { l in
                    itemRow(path: l.path, kind: l.kind, size: l.size, strong: l.strong, trashable: l.trashable, accent: Theme.accentB)
                }
            }
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(sel ? Theme.accentB.opacity(0.33) : Theme.stroke))
    }

    @ViewBuilder private func orphanCard(_ o: OrphanApp) -> some View {
        let key = "orphan:" + o.bundleId
        let isOpen = expanded.contains(key)
        let sel = model.isOrphanSelected(o)
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                Button { sel ? model.deselectOrphan(o) : model.selectOrphan(o) } label: {
                    checkbox(sel, Theme.caution)
                }.buttonStyle(.plain)
                RoundedRectangle(cornerRadius: 8).fill(Theme.caution.opacity(0.13)).frame(width: 32, height: 32)
                    .overlay(Image(systemName: "shippingbox").font(.system(size: 14)).foregroundStyle(Theme.caution))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(o.displayName).font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                        RiskBadge(color: Theme.caution, label: "removed app")
                    }
                    Text(o.bundleId).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Color(hex: 0x4f5868)).lineLimit(1)
                }
                Spacer()
                Text(ByteFmt.string(o.size)).font(.system(size: 14, weight: .bold)).foregroundStyle(Color(hex: 0xcdd6e3))
                Image(systemName: "chevron.down").font(.system(size: 12, weight: .bold)).foregroundStyle(Theme.textMute)
                    .rotationEffect(.degrees(isOpen ? 0 : -90))
            }
            .padding(.horizontal, 18).padding(.vertical, 13).contentShape(Rectangle())
            .onTapGesture { if isOpen { expanded.remove(key) } else { expanded.insert(key) } }
            if isOpen {
                Divider().overlay(Theme.strokeSoft)
                ForEach(o.items) { l in
                    itemRow(path: l.path, kind: l.kind, size: l.size, strong: l.strong, trashable: l.trashable, accent: Theme.caution)
                }
            }
        }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(sel ? Theme.caution.opacity(0.33) : Theme.stroke))
    }

    @ViewBuilder private func itemRow(path: String, kind: String, size: Int64, strong: Bool, trashable: Bool, accent: Color) -> some View {
        HStack(spacing: 13) {
            if trashable && strong {
                Button { model.appBinding(path).wrappedValue.toggle() } label: {
                    checkbox(model.appSelected.contains(path), accent, size: 18)
                }.buttonStyle(.plain)
            } else {
                // weak (by-name) хвосты — reveal-only: могут принадлежать ДРУГОМУ приложению (APP-1).
                Image(systemName: "lock.fill").foregroundStyle(Theme.textDim).frame(width: 18)
                    .help(trashable ? "Matched by name — reveal only" : "Protected — reveal only")
            }
            Text(kind).font(.system(size: 11, weight: .semibold)).foregroundStyle(accent).frame(width: 118, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 7) {
                    Text((path as NSString).lastPathComponent).font(.system(size: 12.5)).foregroundStyle(Color(hex: 0xdbe2ed)).lineLimit(1)
                    if !strong { tag("by name", Theme.caution) }
                }
                Text(path).font(.system(size: 10, design: .monospaced)).foregroundStyle(Color(hex: 0x4f5868)).lineLimit(1).truncationMode(.head)
            }
            Spacer()
            Text(ByteFmt.string(size)).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textDim)
            Button { LargeFiles.revealInFinder(path) } label: {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textDim)
                    .frame(width: 30, height: 30).background(Color.white.opacity(0.03), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.white.opacity(0.08)))
            }.buttonStyle(.plain).help("Reveal in Finder")
        }
        .padding(.horizontal, 18).padding(.vertical, 10)
        Divider().overlay(Color.white.opacity(0.03))
    }

    private func tag(_ t: String, _ c: Color) -> some View {
        Text(t).font(.system(size: 9.5, weight: .semibold)).foregroundStyle(c)
            .padding(.horizontal, 6).padding(.vertical, 1).background(c.opacity(0.13), in: Capsule())
    }
    private func checkbox(_ on: Bool, _ color: Color, size: CGFloat = 20) -> some View {
        RoundedRectangle(cornerRadius: 6).fill(on ? color : Color.white.opacity(0.02))
            .frame(width: size, height: size)
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(on ? color : Color.white.opacity(0.18), lineWidth: 1.5))
            .overlay(on ? Image(systemName: "checkmark").font(.system(size: size * 0.5, weight: .heavy)).foregroundStyle(Theme.bg) : nil)
    }
}

// MARK: - Processes

private struct ProcessesView: View {
    @EnvironmentObject var model: CleanerModel
    @Binding var killTarget: ProcInfo?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 16) {
                gauge("CPU Load", String(format: "%.0f", model.cpuHistory.last ?? 0), "%", Theme.accentA, model.cpuHistory)
                gauge("Memory", String(format: "%.1f", Double(model.mem.usedBytes) / 1_073_741_824),
                      "GB / \(String(format: "%.0f", Double(model.mem.totalBytes) / 1_073_741_824))", Theme.purple, model.memHistory)
            }
            VStack(spacing: 0) {
                HStack {
                    Picker("", selection: $model.procSort) { Text("By CPU").tag(ProcSort.cpu); Text("By Memory").tag(ProcSort.memory) }
                        .pickerStyle(.segmented).fixedSize().labelsHidden()
                    Spacer()
                    if let m = model.procMessage { Text(m).font(.system(size: 11.5)).foregroundStyle(Theme.textDim) }
                    else { Text("top 60").font(.system(size: 11)).foregroundStyle(Theme.textFaint) }
                }.padding(.horizontal, 18).padding(.vertical, 12)
                Divider().overlay(Theme.strokeSoft)
                ForEach(model.sortedProcs.prefix(60)) { p in procRow(p) }
                if !model.zombies.isEmpty {
                    Divider().overlay(Theme.strokeSoft)
                    HStack { Text("Zombies — already dead, can't (and needn't) be killed: \(model.zombies.count)")
                        .font(.system(size: 11)).foregroundStyle(Theme.textFaint); Spacer() }
                        .padding(.horizontal, 18).padding(.vertical, 10)
                }
            }
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(Theme.stroke))
            Color.clear.frame(height: 8)
        }
    }

    private func gauge(_ label: String, _ val: String, _ unit: String, _ color: Color, _ data: [Double]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack { Text(label).font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Color(hex: 0x7a8696)); Spacer()
                Circle().fill(color).frame(width: 7, height: 7).shadow(color: color, radius: 4) }
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(val).font(.system(size: 34, weight: .bold)).foregroundStyle(color)
                Text(unit).font(.system(size: 16, weight: .bold)).foregroundStyle(Color(hex: 0x7a8696))
            }
            Sparkline(data: data, color: color).frame(height: 80)
        }
        .padding(18).frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(Theme.stroke))
    }

    private func procRow(_ p: ProcInfo) -> some View {
        HStack(spacing: 11) {
            procIcon(p)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 5) {
                    if p.cpuPercent > 80 { Image(systemName: "flame.fill").font(.system(size: 10)).foregroundStyle(Theme.caution) }
                    Text(p.name).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color(hex: 0xdbe2ed)).lineLimit(1)
                }
                Text("pid \(p.pid)\(p.isOwn ? "" : " · system")\(p.isOrphan ? " · orphan" : "")")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMute)
            }
            Spacer()
            HStack(spacing: 9) {
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Color.white.opacity(0.06))
                        Capsule().fill(p.cpuPercent > 80 ? Theme.caution : Theme.accentA).frame(width: geo.size.width * CGFloat(min(1, p.cpuPercent / 100)))
                    }
                }.frame(width: 90, height: 5)
                Text(String(format: "%.0f%%", p.cpuPercent)).font(.system(size: 12)).foregroundStyle(Color(hex: 0x9aa6b8)).frame(width: 38, alignment: .trailing)
            }
            Text(ByteFmt.string(Int64(clamping: p.residentBytes))).font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Color(hex: 0xcdd6e3)).frame(width: 78, alignment: .trailing)
            if p.isOwn {
                Button { killTarget = p } label: {
                    Text("×").font(.system(size: 14, weight: .bold)).foregroundStyle(Color(hex: 0xff7a7a))
                        .frame(width: 26, height: 22).background(Theme.danger.opacity(0.08), in: RoundedRectangle(cornerRadius: 7))
                        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Theme.danger.opacity(0.16)))
                }.buttonStyle(.plain).help("Quit process")
            } else { Color.clear.frame(width: 26) }
        }
        .padding(.horizontal, 18).padding(.vertical, 11)
        .overlay(Rectangle().fill(Color.white.opacity(0.03)).frame(height: 1), alignment: .bottom)
    }

    /// Иконка процесса: реальная иконка приложения (для GUI-процессов) или цветной монограмм-fallback
    /// (для демонов/без иконки). Цвет стабилен по имени (детерминированный хэш) — как в макете.
    @ViewBuilder private func procIcon(_ p: ProcInfo) -> some View {
        if let icon = NSRunningApplication(processIdentifier: p.pid)?.icon {
            Image(nsImage: icon).resizable().interpolation(.high)
                .frame(width: 30, height: 30).clipShape(RoundedRectangle(cornerRadius: 7))
        } else {
            let c = Self.procColor(p.name)
            RoundedRectangle(cornerRadius: 8).fill(c.opacity(0.14)).frame(width: 30, height: 30)
                .overlay(Text(String(p.name.prefix(1)).uppercased())
                    .font(.system(size: 13, weight: .bold)).foregroundStyle(c))
        }
    }
    private static let procPalette: [Color] = [
        Color(hex: 0x2fd9c4), Color(hex: 0x5b9dff), Color(hex: 0xb98cff), Color(hex: 0x5fd27a),
        Color(hex: 0xffb35f), Color(hex: 0xff7a9c), Color(hex: 0x57c7e3), Color(hex: 0xe3c557),
    ]
    static func procColor(_ name: String) -> Color {
        let h = name.unicodeScalars.reduce(UInt32(0)) { $0 &+ $1.value }
        return procPalette[Int(h % UInt32(procPalette.count))]
    }
}

// MARK: - Full Disk Access

enum FDAStatus { case checking, granted, denied, unknown }

enum FullDiskAccess {
    static func check() -> FDAStatus {
        let probe = "/Library/Preferences/com.apple.TimeMachine.plist"
        guard FileManager.default.fileExists(atPath: probe) else { return .unknown }
        return (try? Data(contentsOf: URL(fileURLWithPath: probe))) != nil ? .granted : .denied
    }
    static func openSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") else { return }
        NSWorkspace.shared.open(url)
    }
}
