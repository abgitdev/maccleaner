#!/bin/bash
# Собирает и прогоняет тесты ядра безопасности (без UI). Запуск: ./test.sh
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p build
echo "==> Компилирую тесты"
swiftc -g \
    Sources/SafetyPolicy.swift Sources/Trasher.swift Sources/Targets.swift Sources/Scanner.swift Sources/Classifier.swift Sources/ProcessScanner.swift Sources/StorageMap.swift Sources/Dups.swift Sources/Apps.swift Sources/LargeFiles.swift Sources/ProjectCaches.swift Sources/Simulators.swift Sources/SimilarPhotos.swift Sources/Helper/SystemCleanGate.swift Sources/Helper/PrivilegedQuarantine.swift Sources/Helper/SystemReport.swift Sources/Shared/HelperProtocol.swift \
    tests/main.swift \
    -o build/tests

echo "==> Запуск тестов"
./build/tests
