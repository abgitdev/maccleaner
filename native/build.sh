#!/bin/bash
# Воспроизводимая сборка нативного Swift-приложения MacCleaner (без Xcode-проекта).
# Компилирует исходники в .app-бандл и подписывает СТАБИЛЬНОЙ Apple Development identity
# (ad-hoc ЗАПРЕЩЁН — Wave 3 пиннингует подпись клиента по Team ID). Запуск: ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="MacCleaner"
BUILD_DIR="build"
APP="$BUILD_DIR/$APP_NAME.app"

echo "==> Чищу прошлую сборку"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "==> Компилирую Swift ($(swiftc --version | head -1))"
swiftc -O -parse-as-library \
    -framework SwiftUI -framework AppKit -framework IOKit -framework ServiceManagement \
    -o "$APP/Contents/MacOS/$APP_NAME" \
    Sources/*.swift Sources/Shared/*.swift

echo "==> Собираю бандл"
cp Resources/Info.plist "$APP/Contents/Info.plist"
[ -f Resources/MacCleaner.icns ] && cp Resources/MacCleaner.icns "$APP/Contents/Resources/MacCleaner.icns"
[ -f Resources/targets.json ] && cp Resources/targets.json "$APP/Contents/Resources/targets.json"
[ -f Resources/classification.json ] && cp Resources/classification.json "$APP/Contents/Resources/classification.json"
[ -f Resources/storage.json ] && cp Resources/storage.json "$APP/Contents/Resources/storage.json"

echo "==> Привилегированный хелпер (Wave 3)"
# Крошечный root-демон (только Foundation, без SwiftUI/AppKit). main.swift = точка входа (без -parse-as-library).
mkdir -p "$APP/Contents/Library/LaunchDaemons"
swiftc -O \
    -o "$APP/Contents/MacOS/com.maccleaner.helper" \
    Sources/Helper/*.swift Sources/Shared/*.swift Sources/SafetyPolicy.swift
cp Resources/com.maccleaner.helper.plist "$APP/Contents/Library/LaunchDaemons/com.maccleaner.helper.plist"

echo "==> Подпись (жёсткий рантайм на обоих; хелпер первым, контейнер последним)"
# ⚠️ Wave 3: ad-hoc ЗАПРЕЩЁН — без стабильного Team ID пиннинг подписи клиента невозможен (хелпер небезопасен).
# ИНВАРИАНТ: основное приложение НЕ sandbox (не добавлять com.apple.security.app-sandbox) — дизайн root-демона
# зависит от unsandboxed-приложения (macOS 14.2+: sandbox-приложению нужен sandbox-демон + спец-entitlement).
IDENTITY=$(security find-identity -v -p codesigning 2>/dev/null | awk 'match($0, /[0-9A-F]{40}/) {print substr($0, RSTART, 40); exit}')
if [ -z "${IDENTITY:-}" ]; then
    echo "    ОШИБКА: нужна стабильная Apple Development identity (ad-hoc запрещён для Wave 3)"; exit 1
fi
echo "    стабильная identity: $IDENTITY"
# Вложенное (хелпер) подписываем ПЕРВЫМ, контейнер — последним (внешняя подпись запечатывает хелпер+plist).
# ⚠️ --identifier ОБЯЗАТЕЛЕН: у голого Mach-O codesign по умолчанию отрезает «.helper» как расширение →
# Identifier=com.maccleaner, и app-side пиннинг (kHelperRequirement = identifier "com.maccleaner.helper") не совпадёт.
codesign --force --options runtime --timestamp=none --identifier "com.maccleaner.helper" --sign "$IDENTITY" "$APP/Contents/MacOS/com.maccleaner.helper"
codesign --force --options runtime --timestamp=none --sign "$IDENTITY" "$APP"
# Asserts: signed Team ID must equal $TEAM_ID + hardened runtime on BOTH binaries — else the build is invalid.
# (via case, not a pipe into grep -q: pipefail + grep's early exit would cause a false SIGPIPE failure.)
# The Team ID is taken from the TEAM_ID env var — never hardcode your Apple Developer Team ID in source.
: "${TEAM_ID:?Set TEAM_ID before building, e.g. export TEAM_ID=XXXXXXXXXX (your Apple Developer Team ID)}"
for B in "$APP" "$APP/Contents/MacOS/com.maccleaner.helper"; do
    INFO=$(codesign -dvvv "$B" 2>&1)
    case "$INFO" in *"TeamIdentifier=${TEAM_ID}"*) ;; *) echo "FAIL: TeamID ${TEAM_ID} not found on $B"; exit 1;; esac
    case "$INFO" in *"flags="*"runtime"*) ;;        *) echo "FAIL: нет hardened runtime на $B"; exit 1;; esac
done
# Идентификаторы должны ТОЧНО совпадать с requirement-строками пиннинга (иначе XPC «unreachable»).
AINFO=$(codesign -dvvv "$APP" 2>&1)
HINFO=$(codesign -dvvv "$APP/Contents/MacOS/com.maccleaner.helper" 2>&1)
case "$AINFO" in *"Identifier=com.maccleaner.app"*) ;;    *) echo "FAIL: app Identifier != com.maccleaner.app"; exit 1;; esac
case "$HINFO" in *"Identifier=com.maccleaner.helper"*) ;; *) echo "FAIL: helper Identifier != com.maccleaner.helper"; exit 1;; esac
codesign -vvv --strict "$APP" >/dev/null 2>&1 || { echo "FAIL: проверка подписи бандла"; exit 1; }
echo "    ✓ Team ID + hardened runtime подтверждены на app+helper"

echo "==> Готово: $APP"
