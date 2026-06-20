#!/bin/bash
# Пересобирает Resources/MacCleaner.icns из вектора (make-gauge-icon.swift, вариант "Gauge").
# Каждый размер рендерится отдельно из Core Graphics → резко на всех масштабах.
set -euo pipefail
cd "$(dirname "$0")"

GEN="$(mktemp -d)/gen"
swiftc -O make-gauge-icon.swift -o "$GEN"

ICONSET="$(mktemp -d)/MacCleaner.iconset"
mkdir -p "$ICONSET"

emit() { "$GEN" "$ICONSET/$2" "$1" >/dev/null; }   # emit <px> <filename>
emit 16   icon_16x16.png
emit 32   icon_16x16@2x.png
emit 32   icon_32x32.png
emit 64   icon_32x32@2x.png
emit 128  icon_128x128.png
emit 256  icon_128x128@2x.png
emit 256  icon_256x256.png
emit 512  icon_256x256@2x.png
emit 512  icon_512x512.png
emit 1024 icon_512x512@2x.png

iconutil -c icns "$ICONSET" -o Resources/MacCleaner.icns

# 1024-PNG исходник иконки держим в assets (для README/предпросмотра).
"$GEN" assets/MacCleanerGauge.png 1024 >/dev/null
echo "icns готов: $(stat -f%z Resources/MacCleaner.icns) bytes"
