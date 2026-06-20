import Foundation

// Областной гейт привилегированного хелпера. ⚠️ Внутри root-демона getuid()=0 → SafetyPolicy.home=/var/root,
// поэтому isPersonalData/isHomeRoot ИНЕРТНЫ для человека-пользователя. ПЕРВИЧНЫЙ страж области хелпера — этот
// ALLOWLIST, а не isPersonalData. SafetyPolicy всё равно прогоняется (defense in depth: '..', симлинк-компоненты,
// denylist, защищённые системные корни, регистр).
//
// Критическая поправка из аудита: современный unified log — это /private/var/db/diagnostics (logd, tracev3),
// а НЕ /private/var/log. «логи=удаляемы» — ошибка №1. /private/var/db в danger-списке (двойная защита).

enum SystemCleanGate {
    // Разрешённые корни (lowercased, со слешом — путь должен быть СТРОГО внутри, не равен корню).
    // Источник — вендорские рекомендации, не Apple-канон → консервативно (confidence: medium).
    static let safeRoots = ["/library/caches/", "/library/logs/", "/private/var/log/"]

    // Жёстко запрещённые префиксы — даже если как-то попали под allowlist.
    // (+4 из рой-вердикта 2026-06-19: vm/update/updates/install — defense-in-depth против будущего расширения.)
    static let dangerPrefixes = [
        "/system", "/bin", "/sbin",
        "/library/launchdaemons", "/library/launchagents",
        "/library/updates",       // SIP SoftwareUpdate staging (EPERM даже root)
        "/private/var/db",        // unified log / receipts / TCC / ConfigurationProfiles
        "/private/var/folders",   // per-boot scratch, dyld/font/trust caches — «Unapproved Caller»-риск
        "/private/var/audit",
        "/private/var/install",   // SIP installer scratch
        "/private/var/vm",        // swap/sleepimage (живой VM)
        "/system/volumes/preboot", "/system/volumes/vm",
        "/system/volumes/update", // запечатанный том стейджинга обновлений ОС — brick-boot
    ]

    static let quarantineDirName = ".MacCleanerQuarantine"

    /// ПУРЕ-проверка УЖЕ канонического пути (без симлинков, абсолютный). Тестируема без ФС. Бросает при отказе.
    static func checkCanonical(_ canonical: String) throws {
        let n = SafetyPolicy.norm(canonical)   // lexicalClean + lowercased (регистронезависимо, как APFS)
        guard safeRoots.contains(where: { n.hasPrefix($0) }) else {
            throw SafetyError(reason: "not under system allowlist: \(canonical)")
        }
        for d in dangerPrefixes where n == d || n.hasPrefix(d + "/") {
            throw SafetyError(reason: "dangerous prefix: \(canonical)")
        }
        // Глубина ≥3 → отвергаем САМ корень категории (/Library/Caches = 2). Элементы верхнего уровня под корнем
        // (/Library/Caches/<bundle> = 3 — именно их показывает SystemReport и их чистим) ДОЛЖНЫ проходить.
        // Strictly-inside уже гарантирует hasPrefix со слешом (см. safeRoots), depth — дополнительный пол.
        guard n.split(separator: "/").count >= 3 else {
            throw SafetyError(reason: "refusing shallow/category dir: \(canonical)")
        }
        guard !n.contains("/" + quarantineDirName.lowercased()) else {
            throw SafetyError(reason: "refusing quarantine path: \(canonical)")
        }
    }

    /// Полная проверка (с ФС). Порядок: симлинк-компоненты/'..' (C1) → политика → realpath-канонизация
    /// (снимает firmlink /System/Volumes/Data и '.') → checkCanonical. Возвращает КАНОНИЧЕСКИЙ путь.
    /// realpath безопасен здесь: validateNoSymlinkComponents уже доказал отсутствие симлинк-компонентов.
    static func validate(_ raw: String, policy: SafetyPolicy) throws -> String {
        try policy.validateNoSymlinkComponents(raw)   // C1: '..' до схлопывания + lstat-walk симлинков
        try policy.validatePath(raw)                   // denylist / home root / isProtected / isPersonalData
        var buf = [Int8](repeating: 0, count: Int(PATH_MAX))
        guard realpath(raw, &buf) != nil else {
            throw SafetyError(reason: "cannot canonicalize: \(raw)")
        }
        let canonical = String(cString: buf)
        try checkCanonical(canonical)
        return canonical
    }

    /// Валидатор НАЗНАЧЕНИЯ при restore (Phase 1b). ⚠️ Нельзя переиспользовать validate(): realpath() на
    /// ОТСУТСТВУЮЩЕМ финальном компоненте возвращает NULL/ENOENT — а при восстановлении исходный файл как раз
    /// отсутствует (мы его и кладём назад). Поэтому канонизируем СУЩЕСТВУЮЩЕГО родителя, пере-приклеиваем
    /// basename и прогоняем тот же checkCanonical по реконструированному назначению. Манифест/sidecar — НЕдоверенные:
    /// именно эта проверка allowlist'а — настоящий бэкстоп против записи root'ом куда угодно (LaunchDaemon-подсадка).
    /// Возвращает КАНОНИЧЕСКИЙ путь родителя (по нему движок идёт fd-проходом и делает renameat).
    static func validateRestoreParent(_ parentPath: String, basename: String, policy: SafetyPolicy) throws -> String {
        guard !basename.isEmpty, basename != ".", basename != "..", !basename.contains("/") else {
            throw SafetyError(reason: "invalid restore basename: \(basename)")
        }
        try policy.validateNoSymlinkComponents(parentPath)   // родитель существует: '..'-стоп + lstat-walk симлинков
        var buf = [Int8](repeating: 0, count: Int(PATH_MAX))
        guard realpath(parentPath, &buf) != nil else {
            throw SafetyError(reason: "restore parent cannot canonicalize: \(parentPath)")
        }
        let parentCanon = String(cString: buf)
        try checkCanonical(parentCanon + "/" + basename)     // allowlist/danger/depth по реконструированному назначению
        return parentCanon
    }
}
