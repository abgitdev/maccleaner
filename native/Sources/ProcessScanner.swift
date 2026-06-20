import Foundation
import Darwin

// Список процессов через libproc. Исправлено по аудиту:
//  B7 — %CPU считается в наносекундах (mach-тики → ns через timebase), иначе на Apple Silicon врёт ×41.
//  B8 — статус берём из PROC_PIDTBSDINFO (работает и для зомби; PROC_PIDTASKALLINFO у зомби не отдаётся).
//  B9 — terminate реально ждёт завершения и при мягком сигнале честно сообщает, если процесс выжил.

struct ProcInfo: Identifiable {
    let pid: Int32
    let ppid: Int32
    let name: String
    let residentBytes: UInt64
    let cpuPercent: Double
    let isZombie: Bool
    let isOwn: Bool           // принадлежит текущему пользователю → можно завершить
    let startSec: UInt64      // время старта (сек) — защита от PID-reuse перед kill
    let startUsec: UInt32     // микросекунды старта — сужает окно PID-reuse в пределах одной секунды (M8)
    var isOrphan: Bool { ppid == 1 && !isZombie }   // справочно (для демонов ppid==1 — норма)
    var id: Int32 { pid }
}

enum ProcessScanner {
    private static let ALL_PIDS: UInt32 = 1     // PROC_ALL_PIDS
    private static let TASKINFO: Int32 = 4      // PROC_PIDTASKINFO
    private static let TBSDINFO: Int32 = 3      // PROC_PIDTBSDINFO
    private static let SZOMB: UInt32 = 5        // зомби

    // mach-тики → наносекунды (на Apple Silicon numer/denom ≈ 125/3)
    private static let timebase: (n: UInt64, d: UInt64) = {
        var tb = mach_timebase_info_data_t(); mach_timebase_info(&tb)
        return (UInt64(tb.numer), max(1, UInt64(tb.denom)))
    }()
    private static func nanos(_ ticks: UInt64) -> UInt64 { ticks &* timebase.n / timebase.d }

    private static func allPids() -> [Int32] {
        let needed = proc_listpids(ALL_PIDS, 0, nil, 0)
        guard needed > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(needed) / MemoryLayout<pid_t>.stride + 32)
        let got = proc_listpids(ALL_PIDS, 0, &pids, Int32(pids.count * MemoryLayout<pid_t>.stride))
        guard got > 0 else { return [] }
        return pids.prefix(Int(got) / MemoryLayout<pid_t>.stride).filter { $0 > 0 }
    }

    private static func bsdInfo(_ pid: Int32) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        return proc_pidinfo(pid, TBSDINFO, 0, &info, size) == size ? info : nil
    }
    private static func taskInfo(_ pid: Int32) -> proc_taskinfo? {
        var info = proc_taskinfo()
        let size = Int32(MemoryLayout<proc_taskinfo>.size)
        return proc_pidinfo(pid, TASKINFO, 0, &info, size) == size ? info : nil
    }
    private static func procName(_ pid: Int32) -> String {
        var buf = [CChar](repeating: 0, count: 256)
        return proc_name(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : "pid \(pid)"
    }
    private static func cpuNanos(_ pid: Int32) -> UInt64 {
        guard let t = taskInfo(pid) else { return 0 }
        return nanos(t.pti_total_user &+ t.pti_total_system)
    }

    /// Снимок: %CPU по дельте CPU-времени (ns) к реальному прошедшему времени (ns).
    static func snapshot(sampleMicros: UInt32 = 400_000) -> [ProcInfo] {
        let uid = getuid()
        let pids = allPids()
        var firstCPU: [Int32: UInt64] = [:]
        for p in pids { firstCPU[p] = cpuNanos(p) }

        let t0 = DispatchTime.now().uptimeNanoseconds
        usleep(sampleMicros)
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds &- t0)

        var out: [ProcInfo] = []
        for p in pids {
            guard let b = bsdInfo(p) else { continue }   // работает и для зомби
            let isZombie = b.pbi_status == SZOMB
            let task = taskInfo(p)                        // у зомби обычно nil
            let nowNs = task.map { nanos($0.pti_total_user &+ $0.pti_total_system) } ?? 0
            let prevNs = firstCPU[p] ?? nowNs
            let deltaNs = nowNs >= prevNs ? Double(nowNs - prevNs) : 0
            let cpu = elapsed > 0 ? deltaNs / elapsed * 100.0 : 0   // >100% = несколько ядер (норма)
            out.append(ProcInfo(
                pid: p, ppid: Int32(b.pbi_ppid), name: procName(p),
                residentBytes: task?.pti_resident_size ?? 0,
                cpuPercent: cpu, isZombie: isZombie, isOwn: b.pbi_uid == uid,
                startSec: UInt64(b.pbi_start_tvsec), startUsec: UInt32(truncatingIfNeeded: b.pbi_start_tvusec)))
        }
        return out
    }

    /// Завершить процесс и дождаться факта. force=false → SIGTERM; true → SIGKILL.
    /// Возвращает true, только если процесс реально исчез (а не «сигнал доставлен»).
    /// PID-reuse гард: перед сигналом сверяем, что pid — ТОТ ЖЕ процесс (тот же старт + наш uid),
    /// иначе ядро могло переиспользовать pid под чужой процесс между снимком и нажатием.
    @discardableResult
    static func terminate(_ pid: Int32, expectStartSec: UInt64, expectStartUsec: UInt32, force: Bool) -> Bool {
        if pid == getpid() { return false }   // M8: не убиваем сами себя (наш собственный процесс)
        guard let b = bsdInfo(pid), UInt64(b.pbi_start_tvsec) == expectStartSec,
              UInt32(truncatingIfNeeded: b.pbi_start_tvusec) == expectStartUsec,
              b.pbi_uid == getuid() else { return false }
        if kill(pid, force ? SIGKILL : SIGTERM) != 0 { return false }
        for _ in 0..<20 {              // ждём до ~2с фактического завершения
            usleep(100_000)
            if kill(pid, 0) != 0 { return errno == ESRCH }   // ESRCH = процесса больше нет
        }
        return false                    // ещё жив (для SIGTERM нормально — предложим принудительно)
    }
}
