# Mac Cleaner

A private, safety-first macOS disk space inspector and cleaner.

## Purpose

Mac Cleaner helps you understand what is taking space on your Mac and move only selected safe cleanup candidates to Trash. It is not an aggressive system optimizer and not a public product. The intended flow is: scan first, review manually, then move selected items to Trash.

## Safety Model

- Deletion uses Finder Trash only.
- No permanent delete.
- No `rm -rf`.
- Before moving anything to Trash, the target is rescanned and the path must still be a current cleanable candidate.
- Direct symlinks and symlink components in parent paths are rejected.
- Protected system roots are blocked.
- Risky areas stay report-only.
- NAS/SMB/Synology volumes are not scanned automatically.
- Network paths are scanned only when manually selected by the user.
- No telemetry, analytics, marketing code, or auto-update.

## Features

- Internal disk space map.
- Home folder overview.
- Local external USB/APFS volume scan without NAS.
- Manual folder selection through Finder.
- Junk preview before cleanup.
- Move selected cleanable rows to Trash.
- Batch Trash for multiple rows, avoiding one Finder sound per file.
- Self-clean for old app reports.
- Go CLI core `mclean` with a SwiftUI `Mac Cleaner.app` wrapper.

## Typical Safe Targets

- Xcode DerivedData.
- Xcode device logs.
- CoreSimulator caches/logs.
- QuickLook cache.
- Browser caches.
- npm, Yarn, Bun, pip, Poetry, CocoaPods, Go build cache.
- Homebrew cache, only when `brew --cache` points to an expected Homebrew cache root.

## What It Does Not Do

- It does not automatically clean personal videos, photos, documents, or Downloads.
- It does not automatically clean Telegram, Mail, Photos, Docker volumes, or Application Support.
- It does not automatically scan NAS/SMB volumes.
- It does not delete files outside Trash.
- It does not send data anywhere.

## CLI

```bash
mclean targets
mclean space --root /
mclean space --root /Volumes/ExternalDisk --depth 3 --limit 100
mclean space --all-volumes --volumes-only
mclean scan --json
mclean clean --target xcode-derived --dry-run
mclean trash-candidate --target go-build --path ~/Library/Caches/go-build/example --json
mclean trash-candidates --target go-build --path path1 --path path2 --json
mclean report --last
mclean self-clean
```

## Local Privacy

Personal denylist entries live in the user's local config file and are not part of the source code. Build artifacts, audit handoff files, reports, and app bundles are not committed.
