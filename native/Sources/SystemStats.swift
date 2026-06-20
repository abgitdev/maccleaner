import Foundation
import Darwin
import IOKit

// Реальные системные метрики: диск, память, загрузка CPU. Без выдуманных чисел.

struct DiskInfo {
    let totalBytes: Int64
    let freeBytes: Int64
    var usedBytes: Int64 { max(0, totalBytes - freeBytes) }
}

struct MemInfo {
    let totalBytes: UInt64
    let usedBytes: UInt64
}

enum SystemStats {
    static func disk() -> DiskInfo {
        let url = URL(fileURLWithPath: "/")
        let v = try? url.resourceValues(forKeys: [.volumeTotalCapacityKey,
                                                   .volumeAvailableCapacityForImportantUsageKey])
        let total = Int64(v?.volumeTotalCapacity ?? 0)
        let free = v?.volumeAvailableCapacityForImportantUsage ?? 0
        return DiskInfo(totalBytes: total, freeBytes: free)
    }

    static func thermalStateString() -> String {
        switch ProcessInfo.processInfo.thermalState {
        case .nominal: return "Nominal"
        case .fair: return "Fair"
        case .serious: return "Serious"
        case .critical: return "Critical"
        @unknown default: return "—"
        }
    }

    /// Загрузка GPU в % (IOKit IOAccelerator → "Device Utilization %"). Реальное значение.
    static func gpuUsage() -> Double {
        let matching = IOServiceMatching("IOAccelerator")
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) == KERN_SUCCESS else { return 0 }
        defer { IOObjectRelease(iterator) }
        var util = 0.0
        var service = IOIteratorNext(iterator)
        while service != 0 {
            var props: Unmanaged<CFMutableDictionary>?
            if IORegistryEntryCreateCFProperties(service, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS,
               let dict = props?.takeRetainedValue() as? [String: Any],
               let perf = dict["PerformanceStatistics"] as? [String: Any],
               let u = perf["Device Utilization %"] as? Int {
                util = max(util, Double(u))
            }
            IOObjectRelease(service)
            service = IOIteratorNext(iterator)
        }
        return util
    }

    static func memory() -> MemInfo {
        let total = ProcessInfo.processInfo.physicalMemory
        var stats = vm_statistics64_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let r = withUnsafeMutablePointer(to: &stats) { p in
            p.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        }
        guard r == KERN_SUCCESS else { return MemInfo(totalBytes: total, usedBytes: 0) }
        var pageSize: vm_size_t = 0
        host_page_size(mach_host_self(), &pageSize)
        let ps = UInt64(pageSize)
        // ≈ как «Память использована» в Мониторинге системы
        let used = (UInt64(stats.active_count) + UInt64(stats.wire_count)
                    + UInt64(stats.compressor_page_count)) * ps
        return MemInfo(totalBytes: total, usedBytes: used)
    }
}

/// Загрузка CPU в % по дельте тиков между вызовами (нужно состояние).
final class CPUSampler {
    private var prev: (used: UInt64, total: UInt64)?

    func sample() -> Double {
        guard let t = ticks() else { return 0 }
        defer { prev = t }
        guard let p = prev else { return 0 }
        let dUsed = t.used >= p.used ? t.used - p.used : 0
        let dTotal = t.total >= p.total ? t.total - p.total : 0
        return dTotal > 0 ? min(100, Double(dUsed) / Double(dTotal) * 100) : 0
    }

    private func ticks() -> (used: UInt64, total: UInt64)? {
        var info = host_cpu_load_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info_data_t>.size / MemoryLayout<integer_t>.size)
        let r = withUnsafeMutablePointer(to: &info) { p in
            p.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, $0, &count)
            }
        }
        guard r == KERN_SUCCESS else { return nil }
        let user = UInt64(info.cpu_ticks.0), system = UInt64(info.cpu_ticks.1)
        let idle = UInt64(info.cpu_ticks.2), nice = UInt64(info.cpu_ticks.3)
        let used = user + system + nice
        return (used, used + idle)
    }
}
