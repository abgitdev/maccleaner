import Foundation

// Привилегированный root-хелпер MacCleaner. КРОШЕЧНЫЙ, только Foundation (никаких сторонних библиотек,
// никакого SwiftUI/AppKit). Запускается launchd по требованию (SMAppService.daemon), простаивает — выходит.
//
// ⭐ Единственный вход — XPC. КАЖДОЕ соединение проходит проверку подписи звонящего по Team ID
// (setCodeSigningRequirement, fail-closed) ДО экспорта интерфейса. Это прямая защита от класса CVE
// CleanMyMac/Pearcleaner (любой локальный процесс звонит root-хелперу). Phase 1a — только report-only.

final class HelperDelegate: NSObject, NSXPCListenerDelegate, MCHelperProtocol {
    static let shared = HelperDelegate()

    // Движок карантина (root): allowlist через SystemCleanGate, корень — /Library/Application Support/MacCleaner/...
    private let quarantine = PrivilegedQuarantine.system(policy: SafetyPolicy())

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // FAIL CLOSED: пускаем только клиента, чья подпись удовлетворяет kAppRequirement (наш Team ID + id).
        // На errSecCSNoSuchCode (приложение не в /Applications / подпись не читается с диска) — тоже отказ,
        // НИКОГДА не «catch-and-allow».
        do {
            try c.setCodeSigningRequirement(kAppRequirement)
        } catch {
            NSLog("[maccleaner-helper] connection REJECTED (code-signing requirement failed): \(error)")
            return false
        }
        c.exportedInterface = NSXPCInterface(with: MCHelperProtocol.self)
        c.exportedObject = self
        c.resume()
        return true
    }

    // MARK: MCHelperProtocol

    func helperVersion(reply: @escaping (Int) -> Void) { reply(kHelperVersion) }

    func sizeSystemCleanup(reply: @escaping (Data) -> Void) {
        let items = SystemReport.scan()
        reply((try? JSONEncoder().encode(items)) ?? Data())
    }

    // MARK: Phase 1b/1c — карантин (соединение уже прошло гейт подписи Team ID; контракт узкий и типизированный)

    func quarantineSystemPaths(_ paths: [String], reply: @escaping (Data) -> Void) {
        reply(encode(quarantine.quarantine(paths)))
    }
    func listQuarantine(reply: @escaping (Data) -> Void) {
        reply(encode(quarantine.list()))
    }
    func restoreQuarantine(_ ids: [String], reply: @escaping (Data) -> Void) {
        reply(encode(quarantine.restore(ids)))
    }
    func emptyQuarantine(_ ids: [String], confirm: Bool, reply: @escaping (Data) -> Void) {
        // empty — единственная необратимая операция: дополнительно требуем root (соединение пиннинговано по подписи).
        guard getuid() == 0 else {
            reply(encode(ids.map { QResult(path: $0, entryID: $0, ok: false, bytes: 0, error: "helper not privileged") }))
            return
        }
        reply(encode(quarantine.empty(ids, confirm: confirm)))
    }

    func purgeAllForUninstall(confirm: Bool, reply: @escaping (Data) -> Void) {
        // Как empty — необратимо: дополнительно требуем root (соединение уже пиннинговано по подписи Team ID).
        guard getuid() == 0 else {
            reply(encode(PurgeResult(ok: false, itemsRemoved: 0, bytesFreed: 0, error: "helper not privileged")))
            return
        }
        reply(encode(quarantine.purgeAll(confirm: confirm)))
    }

    func auditLog(reply: @escaping (Data) -> Void) {
        reply(Data(quarantine.readAuditLog().utf8))   // read-only; соединение уже пиннинговано по подписи
    }

    private func encode<T: Encodable>(_ v: T) -> Data { (try? JSONEncoder().encode(v)) ?? Data() }
}

let listener = NSXPCListener(machServiceName: kHelperMachServiceName)
listener.delegate = HelperDelegate.shared
listener.resume()
RunLoop.main.run()
