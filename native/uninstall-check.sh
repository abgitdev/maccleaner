#!/bin/bash
# uninstall-check.sh — проверка, что MacCleaner НЕ оставил следов на системе.
#
# READ-ONLY: ничего не удаляет, только смотрит и докладывает. Запускать ПОСЛЕ удаления
# (через встроенный «Uninstall MacCleaner» или вручную). Часть проверок требует sudo
# (TCC / BTM / launchd / root-карантин) — попросит пароль. Без sudo они помечаются «skipped».
#
# Цель: «убрать всё о себе». То, что macOS пишет в свой unified log, удалить нельзя — это помечено [OS].
#
# Запуск:  bash native/uninstall-check.sh          (user-level проверки)
#          sudo bash native/uninstall-check.sh     (включая root-следы: TCC/BTM/launchd/карантин)

set -u
BUNDLE="com.maccleaner.app"
HELPER="com.maccleaner.helper"
NAME="MacCleaner"
DEV_DIR="$HOME/Developer/maccleaner-main"   # папку разработки исключаем из поиска (это не «след»)
LEFT=0

c_red()  { printf '\033[31m%s\033[0m' "$1"; }
c_grn()  { printf '\033[32m%s\033[0m' "$1"; }
c_dim()  { printf '\033[2m%s\033[0m'  "$1"; }

# check_path "описание" "путь"
check_path() {
  local desc="$1" p="$2"
  if [ -e "$p" ]; then
    printf '  %s  %-42s %s\n' "$(c_red ✗)" "$desc" "$p"
    LEFT=$((LEFT+1))
  else
    printf '  %s  %-42s %s\n' "$(c_grn ✓)" "$desc" "$(c_dim clean)"
  fi
}

echo "=== MacCleaner uninstall check ==="
echo "(✓ = gone, ✗ = leftover; [OS] = macOS-owned, cannot be removed by any app)"
echo

echo "— Application & user data —"
check_path "App bundle"              "/Applications/$NAME.app"
check_path "App data + activity log" "$HOME/Library/Application Support/$NAME"
check_path "App preferences"         "$HOME/Library/Preferences/$BUNDLE.plist"
check_path "App preferences (byname)" "$HOME/Library/Preferences/$NAME.plist"
check_path "Saved window state"      "$HOME/Library/Saved Application State/$BUNDLE.savedState"
check_path "User caches"             "$HOME/Library/Caches/$BUNDLE"
check_path "HTTP storages"           "$HOME/Library/HTTPStorages/$BUNDLE"
check_path "WebKit data"             "$HOME/Library/WebKit/$BUNDLE"
check_path "User LaunchAgents"       "$HOME/Library/LaunchAgents/$HELPER.plist"
# CrashReporter throttle-state (ОС пишет MacCleaner_<UUID>.plist при аварийном выходе)
CR=$(find "$HOME/Library/Application Support/CrashReporter" -maxdepth 1 -iname "MacCleaner_*.plist" 2>/dev/null | head -1)
if [ -n "$CR" ]; then
  printf '  %s  %-42s %s\n' "$(c_red ✗)" "CrashReporter state" "$CR"; LEFT=$((LEFT+1))
else
  printf '  %s  %-42s %s\n' "$(c_grn ✓)" "CrashReporter state" "$(c_dim clean)"
fi

echo
echo "— Privileged helper & root-owned data —"
check_path "Quarantine root (root)"  "/Library/Application Support/$NAME"
check_path "Global LaunchDaemons"    "/Library/LaunchDaemons/$HELPER.plist"

# Запущенный демон
if pgrep -f "$HELPER" >/dev/null 2>&1; then
  printf '  %s  %-42s %s\n' "$(c_red ✗)" "Helper daemon running" "$(pgrep -fl "$HELPER" | head -1)"
  LEFT=$((LEFT+1))
else
  printf '  %s  %-42s %s\n' "$(c_grn ✓)" "Helper daemon running" "$(c_dim 'not running')"
fi

echo
echo "— Broad sweep (~/Library, excluding the dev folder) —"
HITS=$(find "$HOME/Library" -iname "*maccleaner*" 2>/dev/null | grep -vi "$DEV_DIR" | sort)
if [ -n "$HITS" ]; then
  echo "$HITS" | while IFS= read -r h; do printf '  %s  %s\n' "$(c_red ✗)" "$h"; done
  LEFT=$((LEFT + $(printf '%s\n' "$HITS" | grep -c .)))
else
  printf '  %s  %s\n' "$(c_grn ✓)" "$(c_dim 'no maccleaner traces under ~/Library')"
fi

echo
echo "— Privileged checks (need sudo; 'skipped' if not root) —"
if [ "$(id -u)" -eq 0 ]; then
  # launchd регистрация
  if launchctl print "system/$HELPER" >/dev/null 2>&1; then
    printf '  %s  %s\n' "$(c_red ✗)" "launchd: system/$HELPER still registered"
    LEFT=$((LEFT+1))
  else
    printf '  %s  %s\n' "$(c_grn ✓)" "$(c_dim "launchd: system/$HELPER not registered")"
  fi
  # BTM (Background Task Management) — SMAppService регистрация
  if command -v sfltool >/dev/null 2>&1; then
    if sfltool dumpbtm 2>/dev/null | grep -qi maccleaner; then
      printf '  %s  %s\n' "$(c_red ✗)" "BTM: a maccleaner background item is still registered"
      LEFT=$((LEFT+1))
    else
      printf '  %s  %s\n' "$(c_grn ✓)" "$(c_dim 'BTM: no maccleaner background item')"
    fi
  fi
  # TCC Full Disk Access грант
  TCC="/Library/Application Support/com.apple.TCC/TCC.db"
  if [ -r "$TCC" ] && command -v sqlite3 >/dev/null 2>&1; then
    if sqlite3 "$TCC" "select client from access where client like '%maccleaner%';" 2>/dev/null | grep -qi maccleaner; then
      printf '  %s  %s\n' "$(c_red ✗)" "TCC: Full Disk Access grant still present (remove it in System Settings ▸ Privacy)"
      LEFT=$((LEFT+1))
    else
      printf '  %s  %s\n' "$(c_grn ✓)" "$(c_dim 'TCC: no Full Disk Access grant')"
    fi
  fi
  # содержимое root-карантина (должно отсутствовать после аптинсталла)
  if [ -d "/Library/Application Support/$NAME" ]; then
    printf '  %s  %s\n' "$(c_red ✗)" "Quarantine tree still on disk:"
    ls -la "/Library/Application Support/$NAME" 2>/dev/null | sed 's/^/      /'
  fi
else
  printf '  %s  %s\n' "$(c_dim '–')" "$(c_dim 'skipped (re-run with: sudo bash native/uninstall-check.sh)')"
fi

echo
echo "— macOS-owned, cannot be removed [OS] —"
printf '  %s  unified log: NSLog lines from the helper persist (log show). Expected; not removable.\n' "[OS]"
printf '  %s  LaunchServices registry caches the app id until it self-heals / lsregister -kill.\n' "[OS]"

echo
if [ "$LEFT" -eq 0 ]; then
  echo "$(c_grn '✓ CLEAN')  — no removable MacCleaner traces found (besides the [OS] items above)."
  exit 0
else
  echo "$(c_red "✗ $LEFT leftover(s)")  — see ✗ lines above."
  exit 1
fi
