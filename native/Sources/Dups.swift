import Foundation
import CryptoKit

// Поиск точных дубликатов по контенту (одинаковые байты). Пайплайн «дёшево → дорого»:
//   размер → частичный хэш (голова+хвост) → наборы общих блоков (APFS-клоны) → полный SHA-256.
//
// ⭐ Учёт APFS-клонов. Клон (cp -c / clonefile) делит ФИЗИЧЕСКИЕ блоки с оригиналом: на диске одна
// копия, но два имени. Удаление клона освобождает 0 байт, пока жив хоть один родственник. Поэтому
// «сколько освободится» считаем честно: (число РАЗНЫХ физических копий − 1) × размер. Физическую
// идентичность определяем по карте экстентов (F_LOG2PHYS_EXT): у клонов экстенты совпадают
// побайтно — это доказательство общих блоков, а не догадка (проверено: clone.phys == orig.phys,
// independent-copy.phys != orig.phys). Совпали все экстенты → файлы заведомо идентичны, хэш не нужен.

struct DupFile: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let displayName: String
    let size: Int64        // allocated-байты этой копии (st_blocks*512)
    let cloneSet: Int      // индекс набора общих блоков внутри группы; одинаковый ⇒ это APFS-клоны
    let shared: Bool       // делит блоки с другим файлом группы (удаление в одиночку освободит 0)
    let trashable: Bool    // проходит SafetyPolicy ⇒ можно в Корзину (иначе только reveal в Finder)
}

struct DupGroup: Identifiable {
    var id: String { key }
    let key: String
    let size: Int64               // размер одной копии (allocated)
    let files: [DupFile]          // ≥2, отсортированы по (cloneSet, path)
    let cloneSets: Int            // сколько физически РАЗНЫХ копий (наборов блоков)
    var count: Int { files.count }
    var apparentTotal: Int64 { size * Int64(count) }          // сколько «как будто» занято
    /// Честно освобождаемое при «оставить 1, остальное в Корзину»: клоны места не дают.
    var reclaimable: Int64 { Int64(max(0, cloneSets - 1)) * size }
    var allClones: Bool { cloneSets <= 1 }                    // все копии — клоны (освободится 0)
}

enum Dups {
    static let headTail = 64 * 1024            // сколько байт головы и хвоста брать в частичный хэш
    static let defaultMinBytes: Int64 = 1 * 1024 * 1024

    /// Главный вход. Обходит root, возвращает группы дублей (по убыванию освобождаемого места).
    static func scan(root: String,
                     minBytes: Int64 = defaultMinBytes,
                     policy: SafetyPolicy,
                     progress: ((Double, String) -> Void)? = nil) -> [DupGroup] {
        progress?(0.02, "Indexing files")
        // 1) Индекс: обычные файлы ≥ minBytes, сгруппированы по ЛОГИЧЕСКОМУ размеру.
        //    Хардлинки (одинаковый dev:ino) схлопываем — это одно и то же содержимое под двумя именами.
        var bySize: [Int64: [String]] = [:]
        var seenInode = Set<String>()
        let url = URL(fileURLWithPath: root)
        let homeDev = Scanner.homeVolumeDevice()   // L4: чужой том (NAS/внешний) под ~ — не сканируем
        if let en = FileManager.default.enumerator(
            at: url, includingPropertiesForKeys: nil, options: [],
            errorHandler: { _, _ in true }) {
            for case let f as URL in en {
                let p = f.path
                if p.contains("/.Trash/") { continue }   // уже удалённое
                // M9: внутрь непрозрачных пакетов (медиатеки .photoslibrary/.lrcat, бандлы .app) не лезем —
                // там не общий мусор, а внутренности библиотек/приложений: читать байты = privacy, а «дубль»
                // внутри библиотеки — её собственный оригинал (нельзя предлагать в Корзину). NB: build-кэши и
                // зависимости (.build/node_modules/Caches) НЕ исключаем — именно там лежат настоящие дубли
                // (SwiftPM-чекауты и т.п.), это главный сценарий Dups. (переиспользуем предикат из SimilarPhotos)
                if SimilarPhotos.isOpaquePackagePath(p) { en.skipDescendants(); continue }
                var st = stat()
                if lstat(p, &st) != 0 { continue }
                if let hd = homeDev, st.st_dev != hd {            // L4: чужой том под ~ — не обходим/не читаем
                    if (st.st_mode & S_IFMT) == S_IFDIR { en.skipDescendants() }
                    continue
                }
                guard (st.st_mode & S_IFMT) == S_IFREG else { continue }   // только обычные файлы
                if Int64(st.st_blocks) * 512 < minBytes { continue }
                if st.st_nlink > 1 {
                    if !seenInode.insert("\(st.st_dev):\(st.st_ino)").inserted { continue }
                }
                bySize[Int64(st.st_size), default: []].append(p)
            }
        }
        let sizeGroups = bySize.filter { $0.value.count >= 2 }   // дубль возможен только при совпадении размера
        guard !sizeGroups.isEmpty else { progress?(1, "Done"); return [] }

        // 2) По каждой size-группе: частичный хэш → наборы клонов → (при нужде) полный хэш.
        var out: [DupGroup] = []
        let total = sizeGroups.count
        var done = 0
        for (logical, paths) in sizeGroups.sorted(by: { $0.key > $1.key }) {
            done += 1
            progress?(0.05 + 0.92 * Double(done) / Double(total), "Comparing \(ByteFmt.string(logical))")
            var byPartial: [String: [String]] = [:]
            for p in paths {
                if let k = partialKey(p, size: logical) { byPartial[k, default: []].append(p) }
            }
            for (_, sub) in byPartial where sub.count >= 2 {
                out.append(contentsOf: resolveSubgroup(sub, logical: logical, policy: policy))
            }
        }
        progress?(1, "Done")
        out.sort {
            $0.reclaimable != $1.reclaimable ? $0.reclaimable > $1.reclaimable
                                             : $0.apparentTotal > $1.apparentTotal
        }
        return out
    }

    // MARK: разбор одной подгруппы (одинаковый размер + одинаковый частичный хэш)

    private static func resolveSubgroup(_ paths: [String], logical: Int64,
                                        policy: SafetyPolicy) -> [DupGroup] {
        // Разбиваем на наборы ОБЩИХ БЛОКОВ. Файлы с одинаковой картой экстентов делят физику ⇒
        // заведомо идентичны (клоны). Кому экстенты недоступны — каждый сам по себе (решит хэш).
        var byClone: [String: [String]] = [:]
        var order: [String] = []
        for p in paths {
            let ck = cloneKey(p, size: logical) ?? "ino:\(identity(p) ?? p)"
            if byClone[ck] == nil { order.append(ck) }
            byClone[ck, default: []].append(p)
        }

        if order.count <= 1 {
            // Один набор блоков: все файлы делят физику (клоны) ⇒ контент идентичен без хэша.
            return [buildGroup(byClone, cloneOrder: order, logical: logical, policy: policy)]
        }

        // ≥2 набора блоков: это могут быть НЕЗАВИСИМЫЕ копии. Хэшируем по одному представителю на
        // набор и склеиваем наборы с одинаковым полным хэшем в одну контент-группу.
        var repHash: [String: String] = [:]
        for ck in order { if let rep = byClone[ck]?.first, let h = fullHash(rep) { repHash[ck] = h } }
        var byContent: [String: [String]] = [:]   // полный хэш → список cloneKey
        for ck in order { if let h = repHash[ck] { byContent[h, default: []].append(ck) } }

        var groups: [DupGroup] = []
        for (_, cks) in byContent {
            let fileCount = cks.reduce(0) { $0 + (byClone[$1]?.count ?? 0) }
            if fileCount < 2 { continue }   // после хэша остался одиночка — не дубль
            var sub: [String: [String]] = [:]
            for ck in cks { sub[ck] = byClone[ck] }
            groups.append(buildGroup(sub, cloneOrder: cks, logical: logical, policy: policy))
        }
        return groups
    }

    private static func buildGroup(_ byClone: [String: [String]], cloneOrder: [String],
                                   logical: Int64, policy: SafetyPolicy) -> DupGroup {
        let cloneSets = cloneOrder.count
        var files: [DupFile] = []
        for (i, ck) in cloneOrder.enumerated() {
            let members = (byClone[ck] ?? []).sorted()
            let shared = members.count > 1            // в этом наборе ≥2 имени — общие блоки
            for p in members {
                files.append(DupFile(
                    path: p,
                    displayName: (p as NSString).lastPathComponent,
                    size: allocated(p) ?? (Int64(logical / 4096 + 1) * 4096),
                    cloneSet: i,
                    shared: shared,
                    trashable: isTrashable(p, policy: policy)))
            }
        }
        files.sort { ($0.cloneSet, $0.path) < ($1.cloneSet, $1.path) }
        let repSize = files.first?.size ?? logical
        let key = "\(logical)|\(files.first?.path ?? "")"
        return DupGroup(key: key, size: repSize, files: files, cloneSets: cloneSets)
    }

    /// Гарантия дедупликатора: в КАЖДОЙ группе остаётся ≥1 копия. Если выбраны все копии группы —
    /// одну (первую) снимаем с удаления. Жёсткий бэкстоп перед переносом, не обойти через UI.
    static func enforceKeepOne(_ selected: Set<String>, groups: [DupGroup]) -> Set<String> {
        var result = selected
        for g in groups where !g.files.isEmpty {
            let survives = g.files.contains { !result.contains($0.path) }   // есть невыбранная копия?
            if !survives, let keep = g.files.first { result.remove(keep.path) }
        }
        return result
    }

    /// Пересобирает группы после удаления части файлов (после переноса в Корзину) — БЕЗ обхода диска,
    /// мгновенно. Группа с <2 оставшимися копиями перестаёт быть дублем и исчезает. Пересчитывает
    /// число физических наборов и флаг `shared` (набор «общий», только если в нём осталось ≥2 файла).
    static func prune(_ groups: [DupGroup], removing gone: Set<String>) -> [DupGroup] {
        var out: [DupGroup] = []
        for g in groups {
            let kept = g.files.filter { !gone.contains($0.path) }
            if kept.count < 2 { continue }
            var perSet: [Int: Int] = [:]
            for f in kept { perSet[f.cloneSet, default: 0] += 1 }
            let refreshed = kept.map { f in
                DupFile(path: f.path, displayName: f.displayName, size: f.size,
                        cloneSet: f.cloneSet, shared: (perSet[f.cloneSet] ?? 0) > 1, trashable: f.trashable)
            }
            out.append(DupGroup(key: g.key, size: g.size, files: refreshed, cloneSets: perSet.count))
        }
        return out
    }

    // MARK: хэши

    /// L6-fix: открыть ОБЫЧНЫЙ файл для чтения, не разыменовывая симлинк (O_NOFOLLOW) и не блокируясь
    /// на FIFO/устройстве (O_NONBLOCK). Иначе same-uid подмена regular→FIFO между индексом и чтением
    /// вешает скан дублей навсегда; симлинк-подмена увела бы хэш на другой файл. nil → не обычный файл/ошибка.
    /// (O_NONBLOCK на обычном файле не влияет на read — читаем как раньше.)
    static func openRegularFD(_ path: String) -> Int32? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { close(fd); return nil }
        return fd
    }

    /// Частичный ключ: размер + хэш головы и хвоста. Быстро отсеивает несовпадающий контент,
    /// не читая файл целиком (важно для многогигабайтных моделей).
    static func partialKey(_ path: String, size: Int64) -> String? {
        guard let fd = openRegularFD(path) else { return nil }
        let fh = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        defer { try? fh.close() }
        var hasher = SHA256()
        withUnsafeBytes(of: size.littleEndian) { hasher.update(data: Data($0)) }
        let head = min(Int(size), headTail)
        if let d = try? fh.read(upToCount: head) { hasher.update(data: d) }
        if size > Int64(headTail) {
            if (try? fh.seek(toOffset: UInt64(size) - UInt64(headTail))) != nil,
               let d = try? fh.read(upToCount: headTail) { hasher.update(data: d) }
        }
        return hex(hasher.finalize())
    }

    /// Полный SHA-256 потоком (4 МБ чанками — без загрузки файла в память целиком).
    static func fullHash(_ path: String) -> String? {
        guard let fd = openRegularFD(path) else { return nil }   // L6: не симлинк/FIFO
        let fh = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        defer { try? fh.close() }
        var hasher = SHA256()
        while let chunk = try? fh.read(upToCount: 4 * 1024 * 1024), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hex(hasher.finalize())
    }

    private static func hex(_ d: SHA256.Digest) -> String {
        d.compactMap { String(format: "%02x", $0) }.joined()
    }

    // MARK: физические блоки (APFS-клоны)

    /// Подпись карты физических экстентов файла. У клонов (общих блоков) она совпадает побайтно.
    /// nil — определить не удалось (не APFS / ошибка / слишком фрагментирован): решит полный хэш.
    static func cloneKey(_ path: String, size: Int64) -> String? {
        guard size > 0 else { return nil }
        guard let fd = openRegularFD(path) else { return nil }   // L6: O_NOFOLLOW|O_NONBLOCK + S_IFREG
        defer { close(fd) }
        var dev: Int64 = 0
        var st = stat(); if fstat(fd, &st) == 0 { dev = Int64(st.st_dev) }
        var sig = "d\(dev)"
        var logical: Int64 = 0
        var extents = 0
        while logical < size {
            var lp = log2phys()
            lp.l2p_contigbytes = size - logical
            lp.l2p_devoffset = logical
            if fcntl(fd, F_LOG2PHYS_EXT, &lp) != 0 { return nil }
            let len = Int64(lp.l2p_contigbytes)
            if len <= 0 { return nil }
            sig += ":\(lp.l2p_devoffset)/\(len)"
            logical += len
            extents += 1
            if extents > 8192 { return nil }   // запредельно фрагментирован — пусть решает хэш
        }
        return sig
    }

    // MARK: мелочи

    static func allocated(_ path: String) -> Int64? {
        var st = stat(); guard lstat(path, &st) == 0 else { return nil }
        return Int64(st.st_blocks) * 512
    }
    static func identity(_ path: String) -> String? {
        var st = stat(); guard lstat(path, &st) == 0 else { return nil }
        return "\(st.st_dev):\(st.st_ino)"
    }
    /// Можно ли вообще переносить этот файл в Корзину (личные папки/система/denylist — нельзя,
    /// плюс данные приложений Containers/Application Support/Group Containers — reveal-only).
    static func isTrashable(_ path: String, policy: SafetyPolicy) -> Bool {
        return policy.isScannerTrashable(path)
    }
}
