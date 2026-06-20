## MacCleaner 1.1 (build 9)

A fast, native macOS cleaner that frees space safely — and never touches your personal files.
The whole app is **~5.5 MB**: 100% Swift + SwiftUI, no Electron, no bundled runtimes, no telemetry.

### Highlights
- Real-time, APFS-aware storage overview with live CPU / GPU / memory / thermals
- Cleanup of caches, logs and Trash — honest numbers, everything recoverable
- App uninstaller that also removes leftovers (Apple apps excluded; nothing pre-selected)
- Large Files, Duplicates and Similar Photos finders
- System cleanup of root-owned caches via a tiny, code-signed privileged helper (restorable quarantine)
- Process monitor to spot and stop CPU/memory hogs

### Safety
Nothing is pre-selected, everything goes to the Trash (no `rm -rf`, no permanent delete), personal data
(Documents, Photos, Mail, Keychains, containers) is protected, and nothing leaves your Mac.

### Install
MacCleaner is distributed as **source** (a signed binary would embed the signer's Apple ID in its
code signature). Build it yourself:

```bash
git clone https://github.com/abgitdev/maccleaner.git
cd maccleaner/native
export TEAM_ID=XXXXXXXXXX   # your Apple Developer Team ID
./build.sh && open build/MacCleaner.app
```

**Requirements:** macOS 14+ · Apple Silicon (M1–M4) · Full Disk Access.
