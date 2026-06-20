import Foundation

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// PrivilegedQuarantine — fd-anchored движок восстановимого системного карантина (Wave 3, Phase 1b/1c).
//
// ⭐ МОДЕЛЬ УГРОЗ (рой 7 агентов + security red-team, 2026-06-19):
//  • Хелпер — root. Звонящий пиннингован по Team ID C2UZK4DB2P, но в остальном НЕдоверенный: КАЖДОЕ
//    решение хелпер перевалидирует сам. Каноническая строка из SystemCleanGate.validate — СОВЕЩАТЕЛЬНАЯ:
//    реальный перенос/восстановление/удаление заново доходит до объекта СВЕЖИМ покомпонентным openat(O_NOFOLLOW)
//    и действует renameatx_np/unlinkat, привязанными к удержанному fd родителя + basename — НИКОГДА по строке-пути.
//  • O_NOFOLLOW влияет ТОЛЬКО на последний компонент пути → ходим по ОДНОМУ компоненту за раз (walkToParent),
//    тогда симлинк на любом промежуточном уровне даёт ELOOP и операция отвергается.
//  • st_dev — это проверка КОРРЕКТНОСТИ (EXDEV), НЕ граница безопасности: все safe-корни и /var/root делят один
//    st_dev тома Data → отличить allowlist от danger по st_dev нельзя. Единственная граница области — allowlist
//    (SystemCleanGate.checkCanonical), применённый и к ИСТОЧНИКУ, и к НАЗНАЧЕНИЮ restore.
//  • Корень карантина — `/Library/Application Support/MacCleaner/.MacCleanerQuarantine`, НЕ под /Library/Caches:
//    /Library/Caches имеет mode 1777 (world-writable+sticky) → атакующий мог бы засквотить корень. /Library и
//    /Library/Application Support — 0755 root:wheel (тот же том Data → renameat не EXDEV). Корень + каждая
//    запись всё равно открываются по fd и fstat-проверяются (uid==0, 0700, dir, не симлинк) — местоположению не доверяем.
//  • renameatx_np с RENAME_EXCL — НЕ затирает жертву при restore; RENAME_NOFOLLOW_ANY/RESOLVE_BENEATH — атомарно
//    отвергают симлинки/escape. ENOTSUP → отказ (НИКОГДА не падать в обычный renameat). EXDEV → отказ (НИКОГДА copy+delete).
//  • empty — ЕДИНСТВЕННАЯ необратимая операция: confirm + getuid==0 + fd-anchored рекурсия, которая не идёт по симлинкам.
//
// Движок НЕ предполагает root: все примитивы работают против переданного `prefix`+`managed` корня и `expectedUID`,
// поэтому тот же код тестируется headless под обычным пользователем на temp-каталоге (tests/main.swift).
// ═══════════════════════════════════════════════════════════════════════════════════════════════

// Флаги renameatx_np: EXCL (не затирать) | NOFOLLOW_ANY (нет симлинков нигде) | RESOLVE_BENEATH (под fd-родителем).
private let qRenameFlags = UInt32(RENAME_EXCL) | UInt32(RENAME_NOFOLLOW_ANY) | UInt32(RENAME_RESOLVE_BENEATH)
// Коммит sidecar'а: атомарная замена (без EXCL — pending→origin.json перезаписывает), без симлинков.
private let qCommitFlags = UInt32(RENAME_NOFOLLOW_ANY) | UInt32(RENAME_RESOLVE_BENEATH)
private let qMaxDepth = 64

/// Sidecar origin.json — единственный источник «откуда пришёл» (НЕдоверенный при restore: перепроверяется allowlist'ом).
struct QEntry: Codable {
    var schema: Int = 1
    var entryID: String
    var originalParentPath: String   // realpath-канон РОДИТЕЛЯ на момент карантина
    var originalBasename: String
    var isDir: Bool
    var srcParentDev: UInt64
    var srcParentIno: UInt64
    var payloadDev: UInt64
    var payloadIno: UInt64
    var nlinkAtCapture: UInt64
    var sizeBytes: Int64
    var capturedSeq: UInt64
    var capturedAtWall: Double        // только для показа, НИКОГДА не identity
}

struct PrivilegedQuarantine {
    /// Доверенный-по-местоположению существующий префикс (в prod — root-owned `/Library/Application Support`).
    let prefix: String
    /// Каталоги, которые СОЗДАЁМ и harden'им под префиксом; последний — сам корень карантина.
    let managed: [ManagedDir]
    /// Ожидаемый владелец наших каталогов: 0 в prod, getuid() в headless-тестах.
    let expectedUID: uid_t
    /// Валидатор ИСТОЧНИКА → канонический абсолютный путь (должен существовать). Бросает при отказе.
    let validateSource: (String) throws -> String
    /// Валидатор НАЗНАЧЕНИЯ restore: (originalParentPath, basename) → канон родителя. Бросает при отказе.
    let validateDest: (String, String) throws -> String
    /// Codex-2: поставщик eligible-набора (канонические пути) из СВЕЖЕГО SystemReport.scan() — в карантин
    /// идёт только то, что отчёт предложил бы СЕЙЧАС (rotated-only логи, keep-newest репорты, пропуск vault'ов).
    /// Даже подписанный, но сбойный клиент не обойдёт строгость отчёта. nil ⇒ проверка пропущена (headless-тесты).
    var eligibleSource: (() -> Set<String>)? = nil

    struct ManagedDir { let name: String; let createMode: mode_t; let requireMode: mode_t? }

    // Все мутирующие операции сериализуем: NSXPCListener может доставлять соединения конкурентно, а flock на .seq
    // сериализует лишь выдачу id, не критические секции rename/restore/empty.
    private static let serial = DispatchQueue(label: "com.maccleaner.helper.quarantine")

    // Продакшен-конфигурация (root): allowlist через SystemCleanGate.
    static func system(policy: SafetyPolicy) -> PrivilegedQuarantine {
        PrivilegedQuarantine(
            prefix: "/Library/Application Support",
            managed: [
                ManagedDir(name: "MacCleaner", createMode: 0o755, requireMode: 0o755),   // L10: пиннингуем режим (как у дочернего)
                ManagedDir(name: ".MacCleanerQuarantine", createMode: 0o700, requireMode: 0o700),
            ],
            expectedUID: 0,
            validateSource: { try SystemCleanGate.validate($0, policy: policy) },
            validateDest: { try SystemCleanGate.validateRestoreParent($0, basename: $1, policy: policy) },
            eligibleSource: { Set(SystemReport.scan().compactMap { try? SystemCleanGate.validate($0.path, policy: policy) }) }
        )
    }

    // MARK: - Публичные операции (каждая — на серийной очереди; результат по каждому элементу независим)

    func quarantine(_ paths: [String]) -> [QResult] {
        Self.serial.sync {
            guard let qrootFD = try? openQuarantineRoot() else {
                return paths.map { QResult(path: $0, entryID: nil, ok: false, bytes: 0, error: "quarantine store unavailable") }
            }
            defer { close(qrootFD) }
            var qrootSt = stat(); _ = fstat(qrootFD, &qrootSt)
            let eligible = eligibleSource?()   // Codex-2: nil ⇒ проверка пропущена (headless-тесты)
            return paths.map { quarantineOne($0, qrootFD: qrootFD, qrootDev: qrootSt.st_dev, eligible: eligible) }
        }
    }

    func list() -> [QEntryReport] {
        Self.serial.sync {
            guard let qrootFD = try? openQuarantineRoot() else { return [] }
            defer { close(qrootFD) }
            return enumerateEntries(qrootFD: qrootFD).compactMap { id -> QEntryReport? in
                guard let efd = try? openHardenedChild(qrootFD, id, requireMode: 0o700) else { return nil }
                defer { close(efd) }
                guard let entry = try? readSidecar(efd) else { return nil }
                let payloadOK = payloadMatches(efd, entry)
                let dest = entry.originalParentPath + "/" + entry.originalBasename
                return QEntryReport(entryID: id, originalPath: dest, sizeBytes: entry.sizeBytes,
                                    isDir: entry.isDir, capturedAt: entry.capturedAtWall,
                                    // каталог st_nlink≥2 (число подкаталогов) → nlink==1 истинен ТОЛЬКО для хардлинк-файлов;
                                    // у каталогов всегда считаем (du-размер корректен). Хардлинк-ФАЙЛЫ отвергаются ещё при захвате.
                                    valid: payloadOK, reclaimable: payloadOK && (entry.isDir || entry.nlinkAtCapture == 1))
            }
        }
    }

    func restore(_ ids: [String]) -> [QResult] {
        Self.serial.sync {
            guard let qrootFD = try? openQuarantineRoot() else {
                return ids.map { QResult(path: $0, entryID: $0, ok: false, bytes: 0, error: "quarantine store unavailable") }
            }
            defer { close(qrootFD) }
            return ids.map { restoreOne($0, qrootFD: qrootFD) }
        }
    }

    /// ⚠️ ЕДИНСТВЕННАЯ необратимая операция. confirm обязателен; getuid()==0 проверяет вызывающий (хелпер).
    func empty(_ ids: [String], confirm: Bool) -> [QResult] {
        guard confirm else {
            return ids.map { QResult(path: $0, entryID: $0, ok: false, bytes: 0, error: "refused: confirmation required") }
        }
        return Self.serial.sync {
            guard let qrootFD = try? openQuarantineRoot() else {
                return ids.map { QResult(path: $0, entryID: $0, ok: false, bytes: 0, error: "quarantine store unavailable") }
            }
            defer { close(qrootFD) }
            var qrootSt = stat(); _ = fstat(qrootFD, &qrootSt)
            return ids.map { emptyOne($0, qrootFD: qrootFD, qrootDev: qrootSt.st_dev) }
        }
    }

    /// ⚠️ АПТИНСТАЛЛ. НЕОБРАТИМО опустошает ВЕСЬ карантин и сносит наши управляемые каталоги (qroot и его
    /// родителей до prefix). Цель — «убрать всё о себе» при удалении приложения. confirm обязателен;
    /// getuid()==0 проверяет вызывающий (хелпер). БЕЗОПАСНО ПО КОНСТРУКЦИИ: НЕ принимает клиентских путей —
    /// трогает ТОЛЬКО hardcoded prefix+managed-цепочку, fd-anchored (O_NOFOLLOW), с проверкой uid/тип/режим
    /// на КАЖДОМ уровне; содержимое сносит проверенным recursiveUnlinkChildren; каталоги — unlinkat(AT_REMOVEDIR)
    /// (снимает только пустые). Симлинк-подмена любого уровня → ELOOP → отказ.
    func purgeAll(confirm: Bool) -> PurgeResult {
        guard confirm else { return PurgeResult(ok: false, itemsRemoved: 0, bytesFreed: 0, error: "confirmation required") }
        guard !managed.isEmpty else { return PurgeResult(ok: true, itemsRemoved: 0, bytesFreed: 0, error: nil) }
        return Self.serial.sync {
            // 1. Пройти по доверенному префиксу (как openQuarantineRoot, но БЕЗ создания управляемых каталогов).
            guard let prefixFD = try? walkToDir(prefix) else {
                return PurgeResult(ok: true, itemsRemoved: 0, bytesFreed: 0, error: nil)   // префикса нет — уже чисто
            }
            var openFDs: [Int32] = [prefixFD]
            defer { for fd in openFDs { close(fd) } }

            // 2. Открыть управляемую цепочку (без создания). Чего-то нет → ниже ничего быть не может.
            var chain: [(fd: Int32, name: String)] = []
            var parentFD = prefixFD
            var qrootPath = prefix
            for m in managed {
                let fd = openComponent(parentFD, m.name, dir: true)   // O_NOFOLLOW: симлинк-подмена → ELOOP
                if fd < 0 { break }                                  // уровня нет → останавливаемся
                var st = stat()
                guard fstat(fd, &st) == 0, st.st_uid == expectedUID, (st.st_mode & S_IFMT) == S_IFDIR else {
                    close(fd); return PurgeResult(ok: false, itemsRemoved: 0, bytesFreed: 0,
                                                  error: "managed dir \(m.name) hostile (uid/type)")
                }
                if let rm = m.requireMode, (st.st_mode & 0o777) != rm {
                    close(fd); return PurgeResult(ok: false, itemsRemoved: 0, bytesFreed: 0,
                                                  error: "managed dir \(m.name) mode mismatch")
                }
                openFDs.append(fd); chain.append((fd, m.name)); qrootPath += "/" + m.name; parentFD = fd
            }
            guard !chain.isEmpty else { return PurgeResult(ok: true, itemsRemoved: 0, bytesFreed: 0, error: nil) }

            // 3. Если открыли всю цепочку — последний это qroot: опустошаем его содержимое (записи+payload, .seq, .audit.log).
            var items = 0; var bytes: Int64 = 0
            if chain.count == managed.count {
                let qFD = chain.last!.fd
                var qSt = stat(); _ = fstat(qFD, &qSt)
                items = enumerateEntries(qrootFD: qFD).count
                bytes = Self.allocatedSize(qrootPath, isDir: true)     // считаем ДО сноса
                do { try recursiveUnlinkChildren(qFD, depth: 0, qrootDev: qSt.st_dev) }
                catch { return PurgeResult(ok: false, itemsRemoved: items, bytesFreed: 0,
                                           error: (error as? SafetyError)?.reason ?? error.localizedDescription) }
            }
            // 4. Снести управляемые каталоги снизу вверх (AT_REMOVEDIR трогает только ПУСТЫЕ — безопасно).
            //    Честно (как emptyOne/M12): если каталог не снёсся (ENOTEMPTY = выжил root-файл и т.п.) — рапортуем
            //    неполную очистку, а не «ok» вслепую (объекты/байты всё равно освобождены).
            var incomplete: String? = nil
            for i in stride(from: chain.count - 1, through: 0, by: -1) {
                let parent = (i == 0) ? prefixFD : chain[i - 1].fd
                if unlinkAt(parent, chain[i].name, AT_REMOVEDIR) != 0 {
                    let e = errno
                    if e != ENOENT && incomplete == nil {
                        incomplete = "could not remove \(chain[i].name): \(String(cString: strerror(e)))"
                    }
                }
            }
            return PurgeResult(ok: incomplete == nil, itemsRemoved: items, bytesFreed: bytes, error: incomplete)
        }
    }

    /// Read-only: содержимое .audit.log (под qroot) для экспорта журнала. БЕЗ side-effects — НЕ создаёт каталоги
    /// (walkToDir+openComponent, не openQuarantineRoot). Нет лога/каталога → "". Ограничение 4 МБ.
    func readAuditLog() -> String {
        Self.serial.sync {
            guard !managed.isEmpty, let prefixFD = try? walkToDir(prefix) else { return "" }
            var fds = [prefixFD]; var cur = prefixFD
            defer { for f in fds { close(f) } }
            for m in managed {
                let fd = openComponent(cur, m.name, dir: true)   // O_NOFOLLOW; нет каталога → ""
                guard fd >= 0 else { return "" }
                fds.append(fd); cur = fd
            }
            let lfd = ".audit.log".withCString { openat(cur, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
            guard lfd >= 0 else { return "" }
            defer { close(lfd) }
            var st = stat()
            guard fstat(lfd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return "" }
            let cap = min(Int(st.st_size), 4 << 20)
            guard cap > 0 else { return "" }
            var buf = [UInt8](repeating: 0, count: cap)
            let n = buf.withUnsafeMutableBytes { read(lfd, $0.baseAddress, cap) }
            return n > 0 ? String(decoding: buf[0..<n], as: UTF8.self) : ""
        }
    }

    // MARK: - Операция quarantine (один элемент, атомарно)

    private func quarantineOne(_ raw: String, qrootFD: Int32, qrootDev: dev_t, eligible: Set<String>?) -> QResult {
        do {
            // 1. allowlist-валидация → канонический источник (realpath, без симлинк-компонентов).
            let canonical = try validateSource(raw)
            // Codex-2: даже подписанный клиент не обходит строгость SystemReport — путь должен быть в свежем скане.
            if let eligible, !eligible.contains(canonical) {
                throw SafetyError(reason: "not offered by current system scan (stale or ineligible)")
            }
            let parentPath = (canonical as NSString).deletingLastPathComponent
            let basename = (canonical as NSString).lastPathComponent
            guard !basename.isEmpty, basename != "/", basename != "." else {
                throw SafetyError(reason: "bad source basename: \(canonical)")
            }

            // 2. fd-проход до родителя ИСТОЧНИКА (закрывает validate→act TOCTOU: дальше работаем по fd, не по строке).
            let (srcParentFD, leaf) = try walkToParent(canonical)
            defer { close(srcParentFD) }
            guard leaf == basename else { throw SafetyError(reason: "leaf mismatch") }

            // 3. lstat листа: отказ симлинку; для обычного файла отказ при nlink!=1 (хардлинк-фарм/учёт).
            var lst = stat()
            guard fstatatNoFollow(srcParentFD, leaf, &lst) == 0 else { throw errnoSafety("cannot stat source") }
            if (lst.st_mode & S_IFMT) == S_IFLNK { throw SafetyError(reason: "refusing to quarantine a symlink") }
            let isDir = (lst.st_mode & S_IFMT) == S_IFDIR
            if !isDir && lst.st_nlink != 1 { throw SafetyError(reason: "refusing hardlinked file (nlink=\(lst.st_nlink))") }
            let capDev = lst.st_dev, capIno = lst.st_ino, capNlink = UInt64(lst.st_nlink)

            // 4. EXDEV-предчек (корректность, не безопасность): renameat работает в пределах одного тома.
            var spSt = stat(); _ = fstat(srcParentFD, &spSt)
            guard spSt.st_dev == qrootDev else { throw SafetyError(reason: "cross-device (EXDEV) — refusing") }

            // 5. размер ДО переноса (честно, как du; хардлинки/корень учтены).
            let size = Self.allocatedSize(canonical, isDir: isDir)

            // 6. id из монотонного .seq; запись-каталог 0700 (mkdirat EEXIST → bump+retry, ≤16).
            let (entryID, entryFD, seq) = try mintEntryDir(qrootFD)
            defer { close(entryFD) }

            // 7. PENDING-sidecar ПЕРЕД переносом (crash-safe: payload без pending = переноса не было → отбросить).
            let entry = QEntry(entryID: entryID, originalParentPath: parentPath, originalBasename: basename,
                               isDir: isDir, srcParentDev: UInt64(spSt.st_dev), srcParentIno: UInt64(spSt.st_ino),
                               payloadDev: UInt64(capDev), payloadIno: UInt64(capIno), nlinkAtCapture: capNlink,
                               sizeBytes: size, capturedSeq: seq, capturedAtWall: Date().timeIntervalSince1970)
            try writeSidecar(entryFD, entry, pending: true)
            _ = fsync(entryFD)

            // 8. TOCTOU-перепроверка листа НЕПОСРЕДСТВЕННО перед move; затем renameatx_np (по fd, не по строке).
            var lst2 = stat()
            guard fstatatNoFollow(srcParentFD, leaf, &lst2) == 0,
                  lst2.st_dev == capDev, lst2.st_ino == capIno else {
                throw SafetyError(reason: "source changed before move — aborting")
            }
            try moveExcl(srcParentFD, leaf, entryFD, "payload")

            // 9. подтверждаем payload по dev/ino, КОММИТ sidecar (pending→origin.json).
            var plSt = stat()
            guard fstatatNoFollow(entryFD, "payload", &plSt) == 0,
                  plSt.st_dev == capDev, plSt.st_ino == capIno else {
                throw SafetyError(reason: "payload identity mismatch after move")
            }
            try commitSidecar(entryFD)
            _ = fsync(entryFD); _ = fsync(qrootFD)
            audit(qrootFD, "quarantine id=\(entryID) path=\(canonical) dev=\(capDev) ino=\(capIno) nlink=\(capNlink) bytes=\(size)")
            // bytes честно: каталоги всегда (du-размер), хардлинк-файлы → 0 (но они уже отвергнуты при захвате).
            return QResult(path: canonical, entryID: entryID, ok: true, bytes: (isDir || capNlink == 1) ? size : 0, error: nil)
        } catch let e as SafetyError {
            return QResult(path: raw, entryID: nil, ok: false, bytes: 0, error: e.reason)
        } catch {
            return QResult(path: raw, entryID: nil, ok: false, bytes: 0, error: error.localizedDescription)
        }
    }

    // MARK: - Операция restore (самая опасная: sidecar НЕдоверенный, allowlist по назначению — настоящий бэкстоп)

    private func restoreOne(_ id: String, qrootFD: Int32) -> QResult {
        do {
            guard Self.isValidID(id) else { throw SafetyError(reason: "invalid entry id") }
            let entryFD = try openHardenedChild(qrootFD, id, requireMode: 0o700)
            defer { close(entryFD) }
            let entry = try readSidecar(entryFD)

            // payload: не симлинк, dev/ino совпадают с записанными (анти-тампер).
            var plSt = stat()
            guard fstatatNoFollow(entryFD, "payload", &plSt) == 0 else { throw SafetyError(reason: "payload missing") }
            if (plSt.st_mode & S_IFMT) == S_IFLNK { throw SafetyError(reason: "payload is a symlink — refusing") }
            guard UInt64(plSt.st_dev) == entry.payloadDev, UInt64(plSt.st_ino) == entry.payloadIno else {
                throw SafetyError(reason: "payload tampered (dev/ino mismatch)")
            }

            // НАЗНАЧЕНИЕ: канонизируем СУЩЕСТВУЮЩЕГО родителя + reapply allowlist на реконструкцию (sidecar НЕдоверен).
            let parentCanon = try validateDest(entry.originalParentPath, entry.originalBasename)

            // fd-проход до родителя назначения (O_NOFOLLOW): пересоздан симлинком → ELOOP → отказ;
            // пересоздан НЕ-root каталогом → uid!=expectedUID → отказ.
            let dstParentFD = try walkToDir(parentCanon)
            defer { close(dstParentFD) }
            var dpSt = stat(); guard fstat(dstParentFD, &dpSt) == 0 else { throw errnoSafety("dst parent stat") }
            guard dpSt.st_uid == expectedUID, (dpSt.st_mode & S_IFMT) == S_IFDIR else {
                throw SafetyError(reason: "restore parent hostile (uid/type)")
            }

            // EXDEV-предчек + renameatx_np RENAME_EXCL: жертву на исходном месте НЕ затираем (EEXIST → оставляем в карантине).
            var qSt = stat(); _ = fstat(entryFD, &qSt)
            guard qSt.st_dev == dpSt.st_dev else { throw SafetyError(reason: "cross-device restore (EXDEV) — refusing") }
            try moveExcl(entryFD, "payload", dstParentFD, entry.originalBasename)
            _ = fsync(dstParentFD)

            // запись-каталог пуст → разбираем (origin.json[.pending] + сам каталог).
            _ = unlinkAt(entryFD, "origin.json", 0)
            _ = unlinkAt(entryFD, "origin.json.pending", 0)
            _ = unlinkAt(qrootFD, id, AT_REMOVEDIR)
            _ = fsync(qrootFD)
            let dest = parentCanon + "/" + entry.originalBasename
            audit(qrootFD, "restore id=\(id) -> \(dest)")
            return QResult(path: dest, entryID: id, ok: true, bytes: entry.sizeBytes, error: nil)
        } catch let e as SafetyError {
            return QResult(path: id, entryID: id, ok: false, bytes: 0, error: e.reason)
        } catch {
            return QResult(path: id, entryID: id, ok: false, bytes: 0, error: error.localizedDescription)
        }
    }

    // MARK: - Операция empty (необратимо; fd-anchored рекурсия, симлинки не идём)

    private func emptyOne(_ id: String, qrootFD: Int32, qrootDev: dev_t) -> QResult {
        do {
            guard Self.isValidID(id) else { throw SafetyError(reason: "invalid entry id") }
            let entryFD = try openHardenedChild(qrootFD, id, requireMode: 0o700)
            defer { close(entryFD) }   // закрываем на ВСЕХ путях (в т.ч. throw из recursiveUnlinkChildren); открытый fd не мешает rmdir
            // честный учёт места: читаем sidecar ДО удаления (каталоги считаем всегда; хардлинк-файлы → 0).
            let entry = try? readSidecar(entryFD)
            let bytes: Int64 = (entry == nil) ? 0 : ((entry!.isDir || entry!.nlinkAtCapture == 1) ? entry!.sizeBytes : 0)
            // рекурсивно сносим содержимое записи-каталога по fd, затем сам каталог.
            try recursiveUnlinkChildren(entryFD, depth: 0, qrootDev: qrootDev)
            // M12: НЕ рапортуем успех вслепую. Если корень записи не снёсся (ENOTEMPTY = выжил ребёнок,
            // EPERM/uchg и т.п.) — очистка НЕполная: возвращаем ok:false, байты НЕ считаем освобождёнными.
            // (запись останется в карантине и снова покажется в списке после refresh — честный сигнал.)
            if unlinkAt(qrootFD, id, AT_REMOVEDIR) != 0 {
                let e = errno
                audit(qrootFD, "empty INCOMPLETE id=\(id) errno=\(e)")
                return QResult(path: id, entryID: id, ok: false, bytes: 0,
                               error: "entry not fully emptied: \(String(cString: strerror(e)))")
            }
            _ = fsync(qrootFD)
            audit(qrootFD, "empty id=\(id) bytes=\(bytes)")
            return QResult(path: id, entryID: id, ok: true, bytes: bytes, error: nil)
        } catch let e as SafetyError {
            return QResult(path: id, entryID: id, ok: false, bytes: 0, error: e.reason)
        } catch {
            return QResult(path: id, entryID: id, ok: false, bytes: 0, error: error.localizedDescription)
        }
    }

    // MARK: - Низкоуровневые fd-anchored примитивы

    /// openat одного компонента (O_NOFOLLOW: симлинк → ELOOP; dir=true добавляет O_DIRECTORY: не-каталог → ENOTDIR).
    private func openComponent(_ parentFD: Int32, _ name: String, dir: Bool) -> Int32 {
        name.withCString { openat(parentFD, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (dir ? O_DIRECTORY : 0)) }
    }

    /// Покомпонентный проход (O_NOFOLLOW на каждом шаге) → fd РОДИТЕЛЯ + имя листа. Симлинк-промежуток → ELOOP → throw.
    private func walkToParent(_ canonicalAbs: String) throws -> (Int32, String) {
        let parts = canonicalAbs.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard !parts.isEmpty else { throw SafetyError(reason: "empty path") }
        if parts.contains("..") || parts.contains(".") { throw SafetyError(reason: "non-canonical path component") }
        var cur = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard cur >= 0 else { throw errnoSafety("open /") }
        for comp in parts.dropLast() {
            let next = openComponent(cur, comp, dir: true)
            let e = errno                                     // снимок ДО close (иначе close мог бы затереть errno симлинк-ELOOP)
            close(cur)
            guard next >= 0 else { throw errnoSafety("open component \(comp)", e) }
            cur = next
        }
        return (cur, parts.last!)
    }

    /// Полный fd-проход до КАТАЛОГА (для родителя назначения restore и префикса).
    private func walkToDir(_ canonicalAbs: String) throws -> Int32 {
        let (parentFD, leaf) = try walkToParent(canonicalAbs)
        defer { close(parentFD) }
        let fd = openComponent(parentFD, leaf, dir: true)
        guard fd >= 0 else { throw errnoSafety("open dir \(leaf)") }
        return fd
    }

    /// Корень карантина: проход по префиксу (O_NOFOLLOW, без uid-чека — системные/temp каталоги), затем СОЗДАНИЕ+
    /// hardening управляемых каталогов (uid==expectedUID, S_ISDIR, mode). НИКАКОГО self-heal (unlink+recreate = гонка).
    func openQuarantineRoot() throws -> Int32 {
        var cur = try walkToDir(prefix)
        for m in managed {
            let child: Int32
            do { child = try ensureHardenedDir(cur, m) }
            catch { close(cur); throw error }
            close(cur); cur = child
        }
        reconcile(cur)   // самолечение orphan/limbo-записей перед каждой операцией
        return cur
    }

    /// Делает реальной заявленную в дизайне crash-safety. Идемпотентно, best-effort, под serial-очередью.
    /// НИКОГДА не трогает закоммиченные записи (с origin.json) и НИКОГДА не удаляет запись с payload (восстановимые данные).
    ///  • payload + только pending → ДОкоммитим (pending→origin.json): сорванный коммит делаем видимым/восстановимым.
    ///  • нет payload (только pending или пусто) → переноса не было → сносим orphan-каталог.
    private func reconcile(_ qrootFD: Int32) {
        for id in enumerateEntries(qrootFD: qrootFD) {
            guard let efd = try? openHardenedChild(qrootFD, id, requireMode: 0o700) else { continue }
            var s = stat()
            if fstatatNoFollow(efd, "origin.json", &s) == 0 { close(efd); continue }   // валидная запись — не трогаем
            let hasPayload = fstatatNoFollow(efd, "payload", &s) == 0
            let hasPending = fstatatNoFollow(efd, "origin.json.pending", &s) == 0
            if hasPayload {
                if hasPending { try? commitSidecar(efd) }        // данные на месте, коммит сорвался → завершаем
                close(efd); continue                             // payload без pending: куда вернуть неизвестно → оставляем
            }
            _ = unlinkAt(efd, "origin.json.pending", 0)          // переноса не было → чистим orphan
            close(efd)
            _ = unlinkAt(qrootFD, id, AT_REMOVEDIR)
        }
    }

    private func ensureHardenedDir(_ parentFD: Int32, _ m: ManagedDir) throws -> Int32 {
        var fd = openComponent(parentFD, m.name, dir: true)
        if fd < 0 {
            let e = errno
            guard e == ENOENT else { throw errnoSafety("open \(m.name)", e) }   // ELOOP/ENOTDIR/EACCES → отказ, не лечим
            if m.name.withCString({ mkdirat(parentFD, $0, m.createMode) }) != 0 {
                let me = errno
                if me != EEXIST { throw errnoSafety("mkdir \(m.name)", me) }     // гонка создания — терпим EEXIST
            }
            fd = openComponent(parentFD, m.name, dir: true)
            guard fd >= 0 else { throw errnoSafety("reopen \(m.name)") }         // если стал симлинком после гонки → ELOOP → throw
        }
        var st = stat()
        guard fstat(fd, &st) == 0 else { let e = errno; close(fd); throw errnoSafety("fstat \(m.name)", e) }
        guard st.st_uid == expectedUID, (st.st_mode & S_IFMT) == S_IFDIR else {
            close(fd); throw SafetyError(reason: "hostile quarantine dir \(m.name) (uid=\(st.st_uid) type)")
        }
        if let rm = m.requireMode, (st.st_mode & 0o777) != rm {
            close(fd); throw SafetyError(reason: "quarantine dir \(m.name) mode \(String(st.st_mode & 0o777, radix: 8)) != \(String(rm, radix: 8))")
        }
        return fd
    }

    /// Открыть hardened-ребёнка (запись-каталог) под уже-открытым корнем.
    private func openHardenedChild(_ parentFD: Int32, _ name: String, requireMode: mode_t) throws -> Int32 {
        let fd = openComponent(parentFD, name, dir: true)
        guard fd >= 0 else { throw errnoSafety("open entry \(name)") }
        var st = stat()
        guard fstat(fd, &st) == 0 else { let e = errno; close(fd); throw errnoSafety("fstat entry", e) }
        guard st.st_uid == expectedUID, (st.st_mode & S_IFMT) == S_IFDIR, (st.st_mode & 0o777) == requireMode else {
            close(fd); throw SafetyError(reason: "hostile entry dir \(name)")
        }
        return fd
    }

    /// renameatx_np по fd (НЕ по строке). RENAME_EXCL не затирает; ENOTSUP → отказ; EXDEV → отказ. НИКОГДА copy+delete.
    private func moveExcl(_ srcFD: Int32, _ srcName: String, _ dstFD: Int32, _ dstName: String) throws {
        let rc = srcName.withCString { s in dstName.withCString { d in renameatx_np(srcFD, s, dstFD, d, qRenameFlags) } }
        if rc != 0 {
            let e = errno
            switch e {
            case EEXIST: throw SafetyError(reason: "destination occupied — not clobbering")
            case ENOTSUP, EINVAL: throw SafetyError(reason: "atomic exclusive rename unsupported — refusing")
            case EXDEV: throw SafetyError(reason: "cross-device (EXDEV) — refusing")
            default: throw errnoSafety("rename", e)
            }
        }
    }

    // MARK: id / .seq / sidecar / audit

    /// Точная проверка id (БЕЗ NSRegularExpression: ICU `$` матчит и перед хвостовым '\n' → пропускал бы id с переводом строки).
    static func isValidID(_ s: String) -> Bool {
        s.count == 16 && s.allSatisfy { ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f") }
    }

    /// Монотонный u64 из .seq (flock+pwrite+fsync) — без Date.now/random. Возвращает следующее значение.
    private func nextSeq(_ qrootFD: Int32) throws -> UInt64 {
        let fd = ".seq".withCString { openat(qrootFD, $0, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600) }
        guard fd >= 0 else { throw errnoSafety("open .seq") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw errnoSafety("flock .seq") }
        defer { _ = flock(fd, LOCK_UN) }
        var v: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &v) { pread(fd, $0.baseAddress, 8, 0) }   // 0 если новый/короткий
        let n = v &+ 1
        var out = n
        _ = withUnsafeBytes(of: &out) { pwrite(fd, $0.baseAddress, 8, 0) }
        _ = fsync(fd)
        return n
    }

    private func mintEntryDir(_ qrootFD: Int32) throws -> (String, Int32, UInt64) {
        for _ in 0..<16 {
            let seq = try nextSeq(qrootFD)
            let id = String(format: "%016llx", seq)
            guard Self.isValidID(id) else { continue }
            let rc = id.withCString { mkdirat(qrootFD, $0, 0o700) }
            if rc == 0 { return (id, try openHardenedChild(qrootFD, id, requireMode: 0o700), seq) }
            if errno != EEXIST { throw errnoSafety("mkdir entry") }   // EEXIST → bump seq и пробуем снова
        }
        throw SafetyError(reason: "could not allocate quarantine entry id")
    }

    private func writeSidecar(_ entryFD: Int32, _ entry: QEntry, pending: Bool) throws {
        let data = try JSONEncoder().encode(entry)
        let name = pending ? "origin.json.pending" : "origin.json"
        let fd = name.withCString { openat(entryFD, $0, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0o600) }
        guard fd >= 0 else { throw errnoSafety("open sidecar") }
        defer { close(fd) }
        try data.withUnsafeBytes { buf in
            var off = 0
            while off < buf.count {
                let n = write(fd, buf.baseAddress!.advanced(by: off), buf.count - off)
                if n <= 0 { throw errnoSafety("write sidecar") }
                off += n
            }
        }
        _ = fsync(fd)
    }

    private func commitSidecar(_ entryFD: Int32) throws {
        let rc = "origin.json.pending".withCString { s in "origin.json".withCString { d in renameatx_np(entryFD, s, entryFD, d, qCommitFlags) } }
        guard rc == 0 else { throw errnoSafety("commit sidecar") }
    }

    private func readSidecar(_ entryFD: Int32) throws -> QEntry {
        let fd = "origin.json".withCString { openat(entryFD, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
        guard fd >= 0 else { throw errnoSafety("open origin.json") }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else { throw errnoSafety("fstat origin.json") }
        guard st.st_uid == expectedUID, (st.st_mode & 0o777) == 0o600, (st.st_mode & S_IFMT) == S_IFREG, st.st_nlink == 1 else {
            throw SafetyError(reason: "sidecar integrity failed")
        }
        let cap = min(Int(st.st_size), 1 << 20)
        var buf = [UInt8](repeating: 0, count: cap)
        let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, cap) }
        guard n > 0 else { throw SafetyError(reason: "empty sidecar") }
        return try JSONDecoder().decode(QEntry.self, from: Data(buf[0..<n]))
    }

    private func payloadMatches(_ entryFD: Int32, _ entry: QEntry) -> Bool {
        var st = stat()
        guard fstatatNoFollow(entryFD, "payload", &st) == 0 else { return false }
        if (st.st_mode & S_IFMT) == S_IFLNK { return false }
        return UInt64(st.st_dev) == entry.payloadDev && UInt64(st.st_ino) == entry.payloadIno
    }

    /// Перечислить id-каталоги в корне (read-only; пропускаем .seq/.audit.log/pending).
    /// ⚠️ openat(".") а НЕ dup(): dup делит file-offset с исходным fd → второй обход того же fd стартовал бы с EOF.
    private func enumerateEntries(qrootFD: Int32) -> [String] {
        let dfd = openDirStream(qrootFD)
        guard dfd >= 0, let dp = fdopendir(dfd) else { if dfd >= 0 { close(dfd) }; return [] }
        defer { closedir(dp) }
        var out: [String] = []
        while let e = readdir(dp) {
            let name = Self.direntName(e)
            if Self.isValidID(name) { out.append(name) }
        }
        return out.sorted()
    }

    /// Свежий независимый fd на тот же каталог (собственный offset, в отличие от dup). Для fdopendir.
    private func openDirStream(_ dirFD: Int32) -> Int32 {
        ".".withCString { openat(dirFD, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
    }

    /// Рекурсивно сносим СОДЕРЖИМОЕ каталога по fd (снизу вверх). Симлинки — unlinkat(,0) (НЕ идём внутрь),
    /// каталоги — заходим только через openat(O_NOFOLLOW)+пере-проверка dev/ino+глубина. Swap dir→symlink → ELOOP → ошибка поддерева.
    private func recursiveUnlinkChildren(_ dirFD: Int32, depth: Int, qrootDev: dev_t) throws {
        guard depth < qMaxDepth else { throw SafetyError(reason: "quarantine tree too deep") }
        // снимок имён (читаем каталог отдельным dup-fd, т.к. fdopendir его поглощает).
        var names: [String] = []
        do {
            let dfd = openDirStream(dirFD)   // openat(".") а НЕ dup (независимый offset; см. enumerateEntries)
            guard dfd >= 0, let dp = fdopendir(dfd) else { let e = errno; if dfd >= 0 { close(dfd) }; throw errnoSafety("fdopendir", e) }
            while let e = readdir(dp) {
                let n = Self.direntName(e)
                if n == "." || n == ".." { continue }
                names.append(n)
            }
            closedir(dp)
        }
        for name in names {
            var st = stat()
            guard fstatatNoFollow(dirFD, name, &st) == 0 else { continue }
            if (st.st_mode & S_IFMT) == S_IFLNK {
                _ = unlinkAt(dirFD, name, 0)                  // удаляем ССЫЛКУ, не цель
            } else if (st.st_mode & S_IFMT) == S_IFDIR {
                let child = openComponent(dirFD, name, dir: true)
                guard child >= 0 else { throw errnoSafety("descend \(name)") }   // swap на симлинк → ELOOP
                var cst = stat(); _ = fstat(child, &cst)
                guard cst.st_dev == qrootDev, cst.st_dev == st.st_dev, cst.st_ino == st.st_ino else {
                    close(child); throw SafetyError(reason: "dir swapped under empty — aborting")
                }
                do { try recursiveUnlinkChildren(child, depth: depth + 1, qrootDev: qrootDev) }
                catch { close(child); throw error }
                close(child)
                _ = unlinkAt(dirFD, name, AT_REMOVEDIR)
            } else {
                _ = unlinkAt(dirFD, name, 0)                  // обычный файл/fifo/socket
            }
        }
    }

    /// Best-effort аудит-журнал (append-only, 0600) — не валит операцию при сбое.
    private func audit(_ qrootFD: Int32, _ line: String) {
        let fd = ".audit.log".withCString { openat(qrootFD, $0, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0o600) }
        guard fd >= 0 else { return }
        defer { close(fd) }
        let stamp = String(format: "%.0f ", Date().timeIntervalSince1970)
        let msg = stamp + line + "\n"
        msg.withCString { cstr in                                  // короткий write не должен обрезать запись аудита
            var p = cstr, remaining = strlen(cstr)
            while remaining > 0 {
                let n = write(fd, p, remaining)
                if n > 0 { p = p.advanced(by: n); remaining -= n }
                else if n < 0 && errno == EINTR { continue }
                else { break }                                     // best-effort: на жёсткой ошибке сдаёмся
            }
        }
    }

    // MARK: helpers

    private func fstatatNoFollow(_ fd: Int32, _ name: String, _ st: inout stat) -> Int32 {
        name.withCString { fstatat(fd, $0, &st, AT_SYMLINK_NOFOLLOW) }
    }
    private func unlinkAt(_ fd: Int32, _ name: String, _ flags: Int32) -> Int32 {
        name.withCString { unlinkat(fd, $0, flags) }
    }
    private func errnoSafety(_ what: String, _ e: Int32 = errno) -> SafetyError {
        SafetyError(reason: "\(what): \(String(cString: strerror(e)))")
    }

    private static func direntName(_ e: UnsafeMutablePointer<dirent>) -> String {
        var ee = e.pointee
        return withUnsafePointer(to: &ee.d_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
        }
    }

    /// Честный allocated-размер (st_blocks*512), хардлинки один раз, блоки самого корня — как Trasher.directorySize.
    static func allocatedSize(_ root: String, isDir: Bool) -> Int64 {
        var rootSt = stat()
        guard lstat(root, &rootSt) == 0 else { return 0 }
        if !isDir { return Int64(rootSt.st_blocks) * 512 }
        var total = Int64(rootSt.st_blocks) * 512
        var seen = Set<String>()
        let url = URL(fileURLWithPath: root)
        guard let en = FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil,
                                                      options: [], errorHandler: { _, _ in true }) else { return total }
        for case let child as URL in en {
            var st = stat()
            guard lstat(child.path, &st) == 0 else { continue }
            if st.st_dev != rootSt.st_dev {           // M7: граница тома (submount/NAS) — не пересекаем (как Trasher)
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
