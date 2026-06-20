import Foundation

// Общий XPC-контракт привилегированного root-хелпера. Компилируется в ОБА таргета (приложение + хелпер).
//
// ⭐ Безопасность по конструкции (обход классов CVE CleanMyMac/Jamf/Pearcleaner):
//  • Контракт УЗКИЙ и ТИПИЗИРОВАННЫЙ — никаких «выполни команду/скрипт», произвольных destination,
//    флага «безопасно ли». Клиент передаёт только КАНДИДАТЫ-пути; хелпер не доверяет ничему и
//    перепроверяет КАЖДОЕ решение сам (root).
//  • Только примитивы + [String] + Data(JSON) — никаких кастомных NSSecureCoding-классов (нет gadget-поверхности).
//  • Проверка подписи звонящего — по Team ID `C2UZK4DB2P` (НЕ по CN-токену), fail-closed; см. requirement-строки.
//
// Phase 1a (текущая) объявляет ТОЛЬКО версию + report-only размеры. Деструктивные методы добавим в 1b/1c,
// и только после живой проверки регистрации/одобрения/гейта подписи.

let kHelperMachServiceName = "com.maccleaner.helper"
let kHelperPlistName = "com.maccleaner.helper.plist"
let kHelperVersion = 1

// Requirement-строки пиннинга: anchor apple generic + конкретный bundle id + Team-ID OU (C2UZK4DB2P).
// kAppRequirement — хелпер пускает ТОЛЬКО это приложение. kHelperRequirement — приложение принимает
// ТОЛЬКО наш хелпер (взаимный пиннинг: отбивает устаревший/подменённый хелпер-бинарь app-side).
// NOTE: subject.OU is the Apple Team Identifier (from `codesign -dvvv`). Pin the Team ID, not the CN/member token.
let kAppRequirement =
    "anchor apple generic and identifier \"com.maccleaner.app\" and certificate leaf[subject.OU] = \"C2UZK4DB2P\""
let kHelperRequirement =
    "anchor apple generic and identifier \"com.maccleaner.helper\" and certificate leaf[subject.OU] = \"C2UZK4DB2P\""

@objc(MCHelperProtocol) protocol MCHelperProtocol {
    /// UX-хендшейк версии (НЕ защита — защита в пиннинге подписи). Хелпер обновляется на диске через
    /// SMAppService, но уже запущенный демон держит старый код → приложение по версии решает переподнять.
    func helperVersion(reply: @escaping (Int) -> Void)

    /// Phase 1a: report-only. Возвращает JSON [SystemCleanupItem] — размеры системного мусора, БЕЗ мутаций.
    func sizeSystemCleanup(reply: @escaping (Data) -> Void)

    // MARK: Phase 1b — восстановимый карантин (см. PrivilegedQuarantine.swift)
    // ⭐ Контракт НАМЕРЕННО узкий и типизированный: клиент передаёт только КАНДИДАТЫ-пути (для quarantine) или
    // id уже-карантинных записей (для restore/empty). НИКОГДА — назначение, флаг «force», shell/команду. Хелпер
    // (root) сам перевалидирует КАЖДОЕ решение по allowlist'у и делает все операции fd-anchored (renameat по fd,
    // НЕ по строке; НЕ rm-as-root). empty — единственная необратимая операция, требует confirm.

    /// Переносит каждый валидный системный путь в root-карантин (восстановимо). JSON-ответ — [QResult].
    func quarantineSystemPaths(_ paths: [String], reply: @escaping (Data) -> Void)
    /// Перечисляет записи карантина (read-only). JSON-ответ — [QEntryReport].
    func listQuarantine(reply: @escaping (Data) -> Void)
    /// Возвращает записи карантина на ИСХОДНОЕ место (не затирая существующее). JSON-ответ — [QResult].
    func restoreQuarantine(_ ids: [String], reply: @escaping (Data) -> Void)
    /// НЕОБРАТИМО удаляет записи карантина (fd-anchored). Требует confirm==true. JSON-ответ — [QResult].
    func emptyQuarantine(_ ids: [String], confirm: Bool, reply: @escaping (Data) -> Void)

    // MARK: Аптинсталл — «убрать всё о себе»
    /// ⚠️ НЕОБРАТИМО: опустошает ВЕСЬ карантин и сносит наши root-каталоги
    /// (/Library/Application Support/MacCleaner/.MacCleanerQuarantine + родителя). Требует confirm==true.
    /// Не принимает клиентских путей — трогает ТОЛЬКО свои управляемые каталоги. JSON-ответ — PurgeResult.
    func purgeAllForUninstall(confirm: Bool, reply: @escaping (Data) -> Void)

    /// Read-only: содержимое root audit-log (.audit.log карантина) — для экспорта журнала. Без мутаций. UTF-8 Data.
    func auditLog(reply: @escaping (Data) -> Void)
}

/// Итог аптинсталл-очистки root-следов (карантин + управляемые каталоги хелпера).
struct PurgeResult: Codable {
    let ok: Bool
    let itemsRemoved: Int    // сколько объектов карантина удалено безвозвратно
    let bytesFreed: Int64    // освобождено на диске
    let error: String?
}

/// Одна позиция отчёта о системном мусоре (Codable, кодируется хелпером — декодируется приложением).
struct SystemCleanupItem: Codable, Identifiable {
    var id: String { path }
    let path: String
    let bytes: Int64
    let category: String
}

/// Результат одной операции карантина/восстановления/очистки (по каждому пути/id — независимо).
struct QResult: Codable, Identifiable {
    var id: String { (entryID ?? "") + ":" + path }
    let path: String        // исходный путь (quarantine/restore) либо id (empty)
    let entryID: String?    // id записи карантина, если создана/затронута
    let ok: Bool
    let bytes: Int64        // освобождаемо/перенесено (честно: хардлинки/клоны → 0)
    let error: String?      // nil = успех
}

/// Одна запись карантина для UI (read-only снимок sidecar'а origin.json).
struct QEntryReport: Codable, Identifiable {
    var id: String { entryID }
    let entryID: String
    let originalPath: String   // куда вернётся при restore (originalParent + "/" + basename)
    let sizeBytes: Int64
    let isDir: Bool
    let capturedAt: Double      // wall-clock (только для показа)
    let valid: Bool            // payload на месте и dev/ino совпали
    let reclaimable: Bool      // nlink==1 → empty реально освободит место
}
