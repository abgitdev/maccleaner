import Foundation
import Combine
import ServiceManagement

// Сторона ПРИЛОЖЕНИЯ: управление привилегированным хелпером.
//  • Регистрация/статус через SMAppService.daemon (требует одобрения пользователя в Системных настройках).
//  • XPC-соединение со ВЗАИМНЫМ пиннингом подписи: приложение принимает ТОЛЬКО наш хелпер (kHelperRequirement),
//    хелпер — только наше приложение (kAppRequirement). Так устаревший/подменённый хелпер отбивается и app-side.
//
// Phase 1a: только статус/одобрение + report-only размеры. Деструктива тут нет.

@MainActor
final class PrivilegedHelper: ObservableObject {
    static let shared = PrivilegedHelper()

    enum State: Equatable { case notRegistered, requiresApproval, enabled, notFound, unknown }

    @Published var state: State = .unknown
    @Published var lastError: String?
    @Published var version: Int?

    private let service = SMAppService.daemon(plistName: kHelperPlistName)
    private var connection: NSXPCConnection?
    private let helperTimeout: TimeInterval = 12   // бэкстоп: если демон не ответил — не виснем

    func refreshStatus() {
        switch service.status {
        case .notRegistered: state = .notRegistered
        case .requiresApproval: state = .requiresApproval
        case .enabled: state = .enabled
        case .notFound: state = .notFound
        @unknown default: state = .unknown
        }
    }

    /// Регистрирует демон. Часто после register() статус = requiresApproval → ведём пользователя в настройки.
    func enable() {
        lastError = nil
        do {
            try service.register()
        } catch {
            // register может бросить именно потому, что нужен подтверждённый бэкграунд-айтем — это не фатально.
            lastError = "register: \(error.localizedDescription)"
        }
        refreshStatus()
        if state == .requiresApproval || state == .notRegistered {
            SMAppService.openSystemSettingsLoginItems()
        }
    }

    /// Полностью убрать хелпер (гигиена против устаревшего бинаря, класс CVE-2019-5011).
    func remove() {
        connection?.invalidate(); connection = nil
        do { try service.unregister() } catch { lastError = "unregister: \(error.localizedDescription)" }
        version = nil
        refreshStatus()
    }

    // MARK: XPC

    private func proxy(_ onError: @escaping (String) -> Void) -> MCHelperProtocol? {
        if connection == nil {
            let c = NSXPCConnection(machServiceName: kHelperMachServiceName, options: .privileged)
            c.remoteObjectInterface = NSXPCInterface(with: MCHelperProtocol.self)
            // App-side пиннинг: соединяемся только с хелпером нашего Team ID + id (отбивает подменённый бинарь).
            // Fail-closed (симметрично helper-side): не смогли выставить требование → не разговариваем с хелпером.
            do {
                try c.setCodeSigningRequirement(kHelperRequirement)
            } catch {
                onError("helper pin failed: \(error.localizedDescription)")
                c.invalidate()
                return nil
            }
            c.invalidationHandler = { [weak self] in
                DispatchQueue.main.async { self?.connection = nil }
            }
            c.interruptionHandler = { }
            c.resume()
            connection = c
        }
        return connection?.remoteObjectProxyWithErrorHandler { err in
            onError("helper unreachable: \(err.localizedDescription)")
        } as? MCHelperProtocol
    }

    /// Проверка связи + версия (косвенно доказывает, что гейт подписи нас принял).
    func ping(_ done: @escaping (Int?) -> Void) {
        var fired = false
        let finish: (Int?, String?) -> Void = { v, err in
            DispatchQueue.main.async {
                if fired { return }; fired = true
                if let err { self.lastError = err }
                if let v { self.version = v }
                done(v)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + helperTimeout) { finish(nil, "helper did not respond") }
        guard let p = proxy({ e in finish(nil, e) }) else { finish(nil, "no connection"); return }
        p.helperVersion { v in finish(v, nil) }
    }

    /// Phase 1a: получить размеры системного мусора (report-only). Колбэк: (items?, errorMessage?).
    /// ⭐ С ТАЙМАУТОМ: если демон не отвечает (напр. не стартовал из-за LWCR), UI не виснет навсегда.
    func fetchSystemSizes(_ done: @escaping ([SystemCleanupItem]?, String?) -> Void) {
        var fired = false
        let finish: ([SystemCleanupItem]?, String?) -> Void = { items, err in
            DispatchQueue.main.async {
                if fired { return }; fired = true
                done(items, err)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + helperTimeout) {
            finish(nil, "The background helper didn't respond — it may have failed to start. Try “Remove helper”, then “Enable system cleaning” again.")
        }
        guard let p = proxy({ e in finish(nil, e) }) else { finish(nil, "no connection"); return }
        p.sizeSystemCleanup { data in
            let items = (try? JSONDecoder().decode([SystemCleanupItem].self, from: data)) ?? []
            finish(items, nil)
        }
    }

    // MARK: Phase 1b/1c — карантин (восстановимый перенос системного мусора). Все вызовы с таймаутом-бэкстопом.

    private func call<R: Decodable>(_ type: R.Type, _ fallback: R, timeoutMsg: String,
                                    _ invoke: @escaping (MCHelperProtocol, @escaping (Data) -> Void) -> Void,
                                    _ done: @escaping (R?, String?) -> Void) {
        var fired = false
        let finish: (R?, String?) -> Void = { v, err in
            DispatchQueue.main.async { if fired { return }; fired = true; done(v, err) }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + helperTimeout) { finish(nil, timeoutMsg) }
        guard let p = proxy({ e in finish(nil, e) }) else { finish(nil, "no connection"); return }
        invoke(p) { data in
            if let v = try? JSONDecoder().decode(R.self, from: data) { finish(v, nil) }
            else { finish(fallback, nil) }
        }
    }

    /// Перенести системные пути в карантин (восстановимо). Колбэк: (results?, error?).
    func quarantine(_ paths: [String], _ done: @escaping ([QResult]?, String?) -> Void) {
        call([QResult].self, [], timeoutMsg: "The helper didn't respond while quarantining.",
             { p, r in p.quarantineSystemPaths(paths, reply: r) }, done)
    }
    /// Список записей карантина (read-only).
    func listQuarantine(_ done: @escaping ([QEntryReport]?, String?) -> Void) {
        call([QEntryReport].self, [], timeoutMsg: "The helper didn't respond while listing quarantine.",
             { p, r in p.listQuarantine(reply: r) }, done)
    }
    /// Восстановить записи на исходное место.
    func restoreQuarantine(_ ids: [String], _ done: @escaping ([QResult]?, String?) -> Void) {
        call([QResult].self, [], timeoutMsg: "The helper didn't respond while restoring.",
             { p, r in p.restoreQuarantine(ids, reply: r) }, done)
    }
    /// НЕОБРАТИМО очистить записи карантина (confirm обязателен).
    func emptyQuarantine(_ ids: [String], _ done: @escaping ([QResult]?, String?) -> Void) {
        call([QResult].self, [], timeoutMsg: "The helper didn't respond while emptying quarantine.",
             { p, r in p.emptyQuarantine(ids, confirm: true, reply: r) }, done)
    }

    /// ⚠️ Аптинсталл: опустошить весь карантин и снести наши root-каталоги (необратимо).
    func purgeAllForUninstall(_ done: @escaping (PurgeResult?, String?) -> Void) {
        call(PurgeResult.self, PurgeResult(ok: false, itemsRemoved: 0, bytesFreed: 0, error: "no response"),
             timeoutMsg: "The helper didn't respond while removing system data.",
             { p, r in p.purgeAllForUninstall(confirm: true, reply: r) }, done)
    }

    /// Read-only: root audit-log хелпера (для экспорта журнала). Пусто при сбое/таймауте.
    func fetchAuditLog(_ done: @escaping (String) -> Void) {
        var fired = false
        let finish: (String) -> Void = { s in DispatchQueue.main.async { if fired { return }; fired = true; done(s) } }
        DispatchQueue.main.asyncAfter(deadline: .now() + helperTimeout) { finish("") }
        guard let p = proxy({ _ in finish("") }) else { finish(""); return }
        p.auditLog { data in finish(String(decoding: data, as: UTF8.self)) }
    }
}
