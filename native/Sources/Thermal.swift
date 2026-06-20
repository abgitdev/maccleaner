import Foundation

// CPU die temperature. Apple Silicon has NO public API for it; the only way third-party tools read
// it is via PRIVATE IOHID symbols resolved by name and called through hand-written @convention(c)
// prototypes. Calling a private C ABI through a guessed signature is undefined behavior, and — per
// the cold security audit (C-1) — the most likely cause of the crash seen on a second Mac: the
// risky path executes ONLY on machines whose temp-sensor match returns services, which is exactly
// why it never fired on this dev machine (the probe returned nil) but could crash elsewhere. We
// refuse to ship that.
//
// The dashboard already degrades gracefully to ProcessInfo.thermalState whenever no °C is available
// (that is what this machine has always shown), so returning nil here changes nothing visible on a
// machine without a usable public sensor — and removes the undefined behavior everywhere.
enum Thermal {
    /// Always nil: we do NOT touch private IOHID symbols. The Temperature monitor falls back to the
    /// macOS thermal state (Nominal/Fair/Serious/Critical), shown identically on every machine.
    static func cpuTemperature() -> Double? { nil }
}
