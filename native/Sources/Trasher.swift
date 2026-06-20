import Foundation

// Безопасный перенос в Корзину через нативный FileManager.trashItem (источник истины — Swift).
//
// Инварианты:
//  • пер-файловый результат: падение одного пути не валит весь батч;
//  • нет публичного «сырого» удаления в обход проверок — единственный вход trashChecked(Batch);
//  • recheck перед самим переносом заново прогоняет ВСЮ политику + сверяет dev/ino (M1-fix).

struct FileIdentity: Equatable {
    let dev: dev_t
    let ino: ino_t
}

struct TrashOutcome {
    let path: String
    let movedBytes: Int64
    let error: String?   // nil = успешно перенесено в Корзину
    var moved: Bool { error == nil }
}

enum Trasher {

    /// Перенос одного пути. Бросает, если подготовка/проверка не прошла.
    static func trashChecked(_ path: String, policy: SafetyPolicy) throws -> Int64 {
        let outcomes = trashCheckedBatch([path], policy: policy)
        if let err = outcomes.first?.error { throw SafetyError(reason: err) }
        return outcomes.first?.movedBytes ?? 0
    }

    /// Перенос батча. Каждый путь обрабатывается независимо — результат по каждому.
    static func trashCheckedBatch(_ paths: [String], policy: SafetyPolicy) -> [TrashOutcome] {
        paths.map { path in
            do {
                let item = try prepare(path, policy: policy)
                try recheck(item, policy: policy)          // повторная полная проверка + dev/ino
                try FileManager.default.trashItem(
                    at: URL(fileURLWithPath: path), resultingItemURL: nil)
                return TrashOutcome(path: path, movedBytes: item.size, error: nil)
            } catch let e as SafetyError {
                return TrashOutcome(path: path, movedBytes: 0, error: e.reason)
            } catch {
                return TrashOutcome(path: path, movedBytes: 0, error: error.localizedDescription)
            }
        }
    }

    // MARK: - Внутреннее

    private struct PreparedItem {
        let path: String
        let size: Int64
        let identity: FileIdentity
        // M3: для ОБЫЧНЫХ файлов сверяем ещё size+mtime — ловит правку «на месте» (тот же inode,
        // изменился контент): dev/ino совпадут, а файл уже не тот, что был при скане/выборе.
        let isRegular: Bool
        let rawSize: off_t
        let mtimeSec: Int
        let mtimeNsec: Int
    }

    private static func prepare(_ path: String, policy: SafetyPolicy) throws -> PreparedItem {
        try policy.validateNoSymlinkComponents(path)

        var st = stat()
        guard lstat(path, &st) == 0 else {
            throw SafetyError(reason: "cannot stat: \(path)")
        }
        if (st.st_mode & S_IFMT) == S_IFLNK {
            throw SafetyError(reason: "refusing to trash symlink directly: \(path)")
        }
        // M4 fail-closed: identity обязана быть доступна.
        let id = FileIdentity(dev: st.st_dev, ino: st.st_ino)

        let isRegular = (st.st_mode & S_IFMT) == S_IFREG
        let size = (st.st_mode & S_IFMT) == S_IFDIR
            ? directorySize(path)
            : Int64(st.st_blocks) * 512   // честный allocated-размер, не apparent

        try policy.validatePath(path)
        return PreparedItem(path: path, size: size, identity: id,
                            isRegular: isRegular, rawSize: st.st_size,
                            mtimeSec: Int(st.st_mtimespec.tv_sec), mtimeNsec: Int(st.st_mtimespec.tv_nsec))
    }

    /// Повторная проверка прямо перед переносом: M1-fix — заново вся политика, затем dev/ino (+ M3: size/mtime).
    private static func recheck(_ item: PreparedItem, policy: SafetyPolicy) throws {
        try policy.validateNoSymlinkComponents(item.path)   // предок мог стать симлинком после prepare
        try policy.validatePath(item.path)
        var st = stat()
        guard lstat(item.path, &st) == 0 else {
            throw SafetyError(reason: "path vanished before Trash: \(item.path)")
        }
        let now = FileIdentity(dev: st.st_dev, ino: st.st_ino)
        if now != item.identity {
            throw SafetyError(reason: "path changed before Trash: \(item.path)")
        }
        // M3: обычный файл могли переписать «на месте» (inode тот же) — сверяем size+mtime и отказываем.
        // Каталоги пропускаем: их mtime естественно «дышит» при активной записи (False reject не нужен).
        if item.isRegular {
            if st.st_size != item.rawSize
                || Int(st.st_mtimespec.tv_sec) != item.mtimeSec
                || Int(st.st_mtimespec.tv_nsec) != item.mtimeNsec {
                throw SafetyError(reason: "file changed before Trash: \(item.path)")
            }
        }
    }

    /// Сумма allocated-размеров (st_blocks*512), как `du`: хардлинки считаем ОДИН раз (B5-fix).
    static func directorySize(_ root: String) -> Int64 {
        var seen = Set<String>()
        return directorySize(root, seen: &seen)
    }

    /// Вариант с ВНЕШНИМ seen-set: хардлинк, общий между НЕСКОЛЬКИМИ корнями, считается один раз
    /// СУММАРНО. Нужно для staged-установок симулятора (`Dead/temp.*`), где installd хардлинкает
    /// неизменные файлы между копиями — иначе один и тот же файл (один inode) считался бы N раз.
    static func directorySize(_ root: String, seen seenHardlinks: inout Set<String>) -> Int64 {
        var total: Int64 = 0
        var rootSt = stat()
        if lstat(root, &rootSt) == 0 { total += Int64(rootSt.st_blocks) * 512 }  // M4-fix: блоки самого корня
        let url = URL(fileURLWithPath: root)
        guard let en = FileManager.default.enumerator(
            at: url,
            includingPropertiesForKeys: nil,
            options: [],
            errorHandler: { _, _ in true }
        ) else {
            return 0
        }
        for case let child as URL in en {
            var st = stat()
            guard lstat(child.path, &st) == 0 else { continue }
            if st.st_dev != rootSt.st_dev {   // FS-1: не пересекаем границу тома (NAS/submount) — только оценка размера
                if (st.st_mode & S_IFMT) == S_IFDIR { en.skipDescendants() }
                continue
            }
            if st.st_nlink > 1 {
                let key = "\(st.st_dev):\(st.st_ino)"
                if !seenHardlinks.insert(key).inserted { continue }   // уже учтён
            }
            total += Int64(st.st_blocks) * 512
        }
        return total
    }
}
