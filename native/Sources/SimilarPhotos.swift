import Foundation
import ImageIO
import CoreGraphics

// Поиск ВИЗУАЛЬНО похожих картинок (пережатые/уменьшенные копии, скриншоты, серии AI-генераций).
// Точные байт-в-байт дубли ловит Dups.swift — здесь про «похоже, но не идентично».
//
// Пайплайн «дёшево → дорого»: обход дома → декод миниатюры (ImageIO) → перцептивный хэш
// (pHash + dHash) → банд-LSH кандидаты → попарная проверка → компоненты связности.
//
// ⭐ Главный грех — слить ДВЕ РАЗНЫЕ картинки в одну группу. Поэтому всё настроено консервативно:
//  • pHash (DCT) с ВЫКИНУТЫМ DC-коэффициентом → инвариантность к яркости; сплошная картинка → 0;
//  • строгий порог Хэмминга 6 для pHash И ≤12 для dHash И вето по соотношению сторон (все три ДОЛЖНЫ
//    совпасть, прежде чем нарисуется ребро между парой);
//  • near-flat / degenerate / экстремальный popcount режутся ДО группировки (убивает ложные кусты
//    из почти-сплошных скриншотов);
//  • banded-LSH из 11 полос > порога 6 → по принципу Дирихле любая истинная near-пара (≤6 бит) делит
//    минимум одну полосу → полная полнота отбора кандидатов для строгого порога.
//
// Безопасность (как в Dups): удаление ТОЛЬКО через Trasher (Корзина); ~/Pictures/~/Downloads/~/Desktop
// и т.п. → trashable=false (только reveal); медиатеки .photoslibrary и пакеты — непрозрачны (внутрь не
// лезем); в каждой группе всегда остаётся ≥1 копия; AI-серии — структурно неудаляемые (reveal-only).

enum SimilarKind { case nearDuplicate, relatedSeries }

struct SimilarPhoto: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let displayName: String     // (path as NSString).lastPathComponent
    let size: Int64             // allocated-байты этой копии (st_blocks*512)
    let width: Int             // оригинальный размер в пикселях (для выбора keeper + вето по AR)
    let height: Int
    let pHash: UInt64           // 63 AC-бита, DC-бит [0][0] зафиксирован в 0 (выставлен наружу для тестов)
    let dHash: UInt64           // 64-битный горизонтальный dHash
    let trashable: Bool         // прошёл SafetyPolicy ⇒ можно в Корзину (иначе только reveal)
    var isKeeper: Bool          // авто-выбранная «лучшая» копия в группе (ТОЛЬКО для показа)
}

struct SimilarGroup: Identifiable {
    var id: String { key }
    let key: String             // "sim|<путь keeper-копии>"
    let kind: SimilarKind
    let photos: [SimilarPhoto]  // ≥2; ИНВАРИАНТ: photos[0] — keeper, остальные по path
    var count: Int { photos.count }
    var keeper: SimilarPhoto? { photos.first }                    // инвариант: индекс 0
    /// Честно освобождаемое при «оставить keeper, остальное в Корзину»: только удаляемые не-keeper копии.
    var reclaimable: Int64 {
        photos.dropFirst().filter { $0.trashable }.reduce(0) { $0 + $1.size }
    }
}

enum SimilarPhotos {
    // Пороги. confidence:medium — выверить на реальных папках (см. §10 спека); pipeline/safety — high.
    static let pHashMax     = 6      // строгий первичный порог Хэмминга для pHash (ужат с 8 ради без-ложных)
    static let dHashMax     = 12     // вторичный подтверждающий порог
    static let relatedLo    = 9      // совещательная полоса AI-серий (reveal-only)
    static let relatedHi    = 16
    static let minDimension = 16     // короткая сторона: мельче — отвергаем (мусор/иконки)
    static let minStdDev    = 6.0    // порог stddev 32×32: ниже — near-flat, отвергаем
    static let popcountLo   = 6      // экстремально малый popcount pHash → отвергаем
    static let popcountHi   = 58     // экстремально большой popcount pHash → отвергаем
    static let aspectLogTol = 0.10   // |ln(arA)-ln(arB)| ≤ 0.10
    static let lshBands     = 11     // > pHashMax ⇒ полнота отбора кандидатов по принципу Дирихле

    static let imageExtensions: Set<String> =
        ["jpg", "jpeg", "png", "heic", "heif", "gif", "tiff", "tif", "bmp", "webp", "dng"]

    // Покомпонентно непрозрачные пакеты (lowercased-суффикс). Только реально существующие форматы.
    static let opaquePackageSuffixes: [String] = [
        ".app",
        ".photoslibrary", ".aplibrary", ".migratedaplibrary", ".photolibrary",
        ".lrcat", ".lrdata",
        ".fcpbundle", ".imovielibrary", ".theater", ".tvlibrary",
        ".aphotoproject",
    ]

    // Кэши сборки / зависимости / системные кэши (lowercased-имя НЕ-скрытого компонента). В них лежат
    // НЕ фото пользователя, а артефакты/примеры из пакетов (внутри «Похожие фото» давали бы шум и ложные
    // склейки шаблонных картинок). Это сознательно УЖЕ, чем у Duplicates: похожие ФОТО — про снимки юзера.
    // Скрытые dot-папки (.build/.claude/.codex/.git/.cache/…) ловятся отдельным правилом в isExcludedScanPath.
    static let excludedScanDirs: Set<String> = [
        "deriveddata", "sourcepackages", "node_modules", "pods",
        "caches", "__pycache__", "site-packages", "coresimulator",
    ]

    // MARK: - Главный вход

    static let minBytes: Int64 = 50 * 1024   // ниже — это иконки/превьюшки, а не фото (отсекаем шум)

    /// Обходит root, возвращает группы похожих картинок (near-duplicate выше, затем related-series).
    static func scan(root: String,
                     minBytes: Int64 = SimilarPhotos.minBytes,
                     policy: SafetyPolicy,
                     progress: ((Double, String) -> Void)? = nil) -> [SimilarGroup] {
        progress?(0.02, "Indexing images")
        // 1) Индекс: обычные файлы-картинки, пакеты/.Trash исключены, хардлинки схлопнуты.
        var urls: [URL] = []
        var seenInode = Set<String>()
        let rootURL = URL(fileURLWithPath: root)
        let homeDev = Scanner.homeVolumeDevice()   // L4: чужой том (NAS/внешний) под ~ — не декодируем/не обходим
        if let en = FileManager.default.enumerator(
            at: rootURL, includingPropertiesForKeys: nil, options: [],
            errorHandler: { _, _ in true }) {
            for case let f as URL in en {
                let p = f.path
                // Внутрь медиатек/пакетов и кэшей сборки/зависимостей не лезем (там не фото пользователя).
                if isOpaquePackagePath(p) || isExcludedScanPath(p) { en.skipDescendants(); continue }
                if p.contains("/.Trash/") { continue }
                var st = stat()
                if lstat(p, &st) != 0 { continue }
                if let hd = homeDev, st.st_dev != hd {            // L4: чужой том под ~ — пропускаем (и поддерево)
                    if (st.st_mode & S_IFMT) == S_IFDIR { en.skipDescendants() }
                    continue
                }
                let ext = (p as NSString).pathExtension.lowercased()
                if !imageExtensions.contains(ext) { continue }
                guard (st.st_mode & S_IFMT) == S_IFREG else { continue }
                if st.st_size < minBytes { continue }            // мелочь (иконки/превью) — не фото
                if st.st_nlink > 1 {
                    if !seenInode.insert("\(st.st_dev):\(st.st_ino)").inserted { continue }
                }
                urls.append(f)
            }
        }
        let n = urls.count
        guard n > 0 else { progress?(1, "Done"); return [] }

        // 2) Параллельный хэш (M4 = 10 ядер). Пишем по индексу в преаллоцированный буфер — без гонок.
        var results = [SimilarPhoto?](repeating: nil, count: n)
        let counter = Counter()
        results.withUnsafeMutableBufferPointer { buf in
            DispatchQueue.concurrentPerform(iterations: n) { i in
                // autoreleasepool прижимает пик памяти: CGImageSource/CGImage освобождаются сразу
                // после каждого файла, а не копятся в пуле потока до конца параллельного прохода.
                autoreleasepool { buf[i] = hashOne(url: urls[i], policy: policy) }
                let done = counter.inc()
                if done % 32 == 0 || done == n {
                    progress?(0.05 + 0.65 * Double(done) / Double(n), "Hashing \(done)/\(n)")
                }
            }
        }
        let photos = results.compactMap { $0 }

        // 3) Группировка.
        progress?(0.95, "Grouping similar images")
        let groups = group(photos)
        progress?(1, "Done")
        return groups
    }

    // MARK: - Декод + хэш одного файла

    /// Возвращает nil — файл пропущен (не картинка / мелкий / near-flat / degenerate / не декодится).
    static func hashOne(url: URL, policy: SafetyPolicy) -> SimilarPhoto? {
        let path = url.path
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        let allocated = Int64(st.st_blocks) * 512

        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil) else { return nil }

        // Размер БЕЗ полного декода (для keeper + вето по AR).
        var w = 0, h = 0
        if let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [CFString: Any] {
            if let pw = (props[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue { w = pw }
            if let ph = (props[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue { h = ph }
        }
        if w > 0 && h > 0 && min(w, h) < minDimension { return nil }

        // Миниатюра (с применением EXIF-ориентации), ограничена 64px по большей стороне.
        let opts: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: 64,
            kCGImageSourceShouldCacheImmediately: false,
        ]
        guard let cg = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else { return nil }
        if w == 0 || h == 0 { w = cg.width; h = cg.height; if min(w, h) < minDimension { return nil } }

        // pHash: рендер в 32×32 серый, отсев near-flat по stddev.
        guard let gray32 = render(cg, 32, 32) else { return nil }
        if stdDev(gray32) < minStdDev { return nil }
        let ph = pHash(gray32: gray32)
        if ph == 0 || ph == UInt64.max { return nil }
        let pc = ph.nonzeroBitCount
        if pc < popcountLo || pc > popcountHi { return nil }

        // dHash: рендер в 9×8 серый.
        guard let gray98 = render(cg, 9, 8) else { return nil }
        let dh = dHash(gray9x8: gray98)
        if dh == 0 || dh == UInt64.max { return nil }

        // Данные приложений (Containers/Application Support/...) — reveal-only, не дедуп-кандидаты.
        let trashable = policy.isScannerTrashable(path)

        return SimilarPhoto(
            path: path,
            displayName: (path as NSString).lastPathComponent,
            size: allocated, width: w, height: h,
            pHash: ph, dHash: dh, trashable: trashable, isKeeper: false)
    }

    /// Рисует CGImage в одноканальный серый буфер width×height. Весь жизненный цикл контекста —
    /// ВНУТРИ withUnsafeMutableBytes (иначе указатель-инаут «утечёт» и контекст запишет в мусор).
    static func render(_ cg: CGImage, _ width: Int, _ height: Int) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: width * height)
        let ok = buf.withUnsafeMutableBytes { raw -> Bool in
            guard let base = raw.baseAddress,
                  let ctx = CGContext(data: base, width: width, height: height,
                                      bitsPerComponent: 8, bytesPerRow: width,
                                      space: CGColorSpaceCreateDeviceGray(),
                                      bitmapInfo: CGImageAlphaInfo.none.rawValue) else { return false }
            ctx.interpolationQuality = .high
            ctx.draw(cg, in: CGRect(x: 0, y: 0, width: width, height: height))
            return true
        }
        return ok ? buf : nil
    }

    // MARK: - Перцептивные хэши (чистые функции)

    /// pHash через 2D DCT-II (раздельно по строкам/столбцам, неунифицированный — как imagehash).
    /// DC-коэффициент [0][0] ВЫКИНУТ: медиана берётся по 63 AC-коэффициентам, бит DC зафиксирован в 0.
    /// ⇒ инвариантность к яркости (сдвиг яркости меняет только DC) и сплошная картинка → 0.
    static func pHash(gray32: [UInt8]) -> UInt64 {
        // DCT по строкам, оставляем первые 8 выходов: rowOut[r*8 + k].
        var rowOut = [Double](repeating: 0, count: 32 * 8)
        for r in 0..<32 {
            let base = r * 32
            for k in 0..<8 {
                var s = 0.0
                let ck = cosTable[k]
                for n in 0..<32 { s += Double(gray32[base + n]) * ck[n] }
                rowOut[r * 8 + k] = s
            }
        }
        // DCT по столбцам, оставляем первые 8: coeffs[kc*8 + k], kc = верт. частота, k = гориз.
        var coeffs = [Double](repeating: 0, count: 64)
        for kc in 0..<8 {
            let ckc = cosTable[kc]
            for k in 0..<8 {
                var s = 0.0
                for r in 0..<32 { s += rowOut[r * 8 + k] * ckc[r] }
                // Округление до целого гасит микрошум ПТ (сплошная картинка → ровно 0, а не ±1e-11,
                // иначе медиана шума раскидывала бы пол-хэша). На реальные коэффициенты (сотни-тысячи)
                // влияния нет; у границы медианы это ещё и убирает дрожание.
                coeffs[kc * 8 + k] = s.rounded()
            }
        }
        // Медиана по AC (индексы 1..63, DC=индекс 0 исключён).
        var ac = [Double](); ac.reserveCapacity(63)
        for i in 1..<64 { ac.append(coeffs[i]) }
        let med = median(ac)
        var hash: UInt64 = 0
        for i in 1..<64 where coeffs[i] > med { hash |= (UInt64(1) << UInt64(i)) }  // бит 0 (DC) всегда 0
        return hash
    }

    /// dHash: 9 столбцов × 8 строк, бит = pixel[r][c] > pixel[r][c+1] (горизонтальный градиент).
    static func dHash(gray9x8: [UInt8]) -> UInt64 {
        var hash: UInt64 = 0
        for r in 0..<8 {
            for c in 0..<8 {
                let left = gray9x8[r * 9 + c]
                let right = gray9x8[r * 9 + c + 1]
                if left > right { hash |= (UInt64(1) << UInt64(r * 8 + c)) }
            }
        }
        return hash
    }

    static let cosTable: [[Double]] = {
        var t = [[Double]](repeating: [Double](repeating: 0, count: 32), count: 8)
        for k in 0..<8 {
            for n in 0..<32 { t[k][n] = cos(Double.pi / 32.0 * (Double(n) + 0.5) * Double(k)) }
        }
        return t
    }()

    static func median(_ xs: [Double]) -> Double {
        let s = xs.sorted()
        let c = s.count
        if c == 0 { return 0 }
        return c % 2 == 1 ? s[c / 2] : (s[c / 2 - 1] + s[c / 2]) / 2
    }

    static func stdDev(_ b: [UInt8]) -> Double {
        let n = Double(b.count)
        guard n > 0 else { return 0 }
        var sum = 0.0; for v in b { sum += Double(v) }
        let mean = sum / n
        var varSum = 0.0; for v in b { let d = Double(v) - mean; varSum += d * d }
        return (varSum / n).squareRoot()
    }

    // MARK: - Предикаты сходства (чистые функции)

    static func hamming(_ a: UInt64, _ b: UInt64) -> Int { (a ^ b).nonzeroBitCount }

    /// Near-duplicate: ВСЕ три гейта (pHash строго И dHash И соотношение сторон).
    static func isSimilar(_ a: SimilarPhoto, _ b: SimilarPhoto) -> Bool {
        hamming(a.pHash, b.pHash) <= pHashMax
            && hamming(a.dHash, b.dHash) <= dHashMax
            && aspectCompatible(a, b)
    }

    /// Совещательная полоса AI-серий: похожи, но НЕ near-duplicate (reveal-only, удалять нельзя).
    static func relatedBand(_ a: SimilarPhoto, _ b: SimilarPhoto) -> Bool {
        let d = hamming(a.pHash, b.pHash)
        return d >= relatedLo && d <= relatedHi && aspectCompatible(a, b) && !isSimilar(a, b)
    }

    static func aspectCompatible(_ a: SimilarPhoto, _ b: SimilarPhoto) -> Bool {
        guard a.width > 0, a.height > 0, b.width > 0, b.height > 0 else { return false }
        let la = log(Double(a.width) / Double(a.height))
        let lb = log(Double(b.width) / Double(b.height))
        return abs(la - lb) <= aspectLogTol
    }

    // MARK: - Банд-LSH ширины полос

    /// Ширины 11 полос, сумма ровно 64: первые `rem` полос на 1 бит шире (по 64/11 и остатку).
    static func bandWidths() -> [Int] {
        let base = 64 / lshBands     // 5
        let rem = 64 % lshBands      // 9
        return (0..<lshBands).map { $0 < rem ? base + 1 : base }   // 9×6 + 2×5 = 64
    }

    // MARK: - Группировка (чистая функция)

    /// ⭐ ЛИДЕР-кластеризация (а НЕ union-find): каждый член группы похож на ПРЕДСТАВИТЕЛЯ группы, а не
    /// «транзитивно через соседа». Это рвёт ложные цепочки: на реальных данных union-find склеивал разные
    /// картинки через общий шаблон (badge-фон, кадры диффузии A~B~C, где A и C уже непохожи). Здесь фото
    /// присоединяется только если похоже на самого ЛИДЕРА → группа остаётся «тесной».
    static func group(_ photos: [SimilarPhoto]) -> [SimilarGroup] {
        let n = photos.count
        guard n >= 2 else { return [] }
        let widths = bandWidths()
        var offsets = [Int](); var off = 0
        for w in widths { offsets.append(off); off += w }
        func bands(_ h: UInt64) -> [String] {
            (0..<widths.count).map { b in
                let mask = (UInt64(1) << UInt64(widths[b])) - 1
                return "\(b):\((h >> UInt64(offsets[b])) & mask)"
            }
        }
        // Порядок: крупные первыми (уменьшенные копии прилипают к самой большой), затем по пути.
        let order = photos.indices.sorted {
            let pa = photos[$0].width * photos[$0].height, pb = photos[$1].width * photos[$1].height
            if pa != pb { return pa > pb }
            return photos[$0].path < photos[$1].path
        }

        // Один проход лидер-кластеризации по предикату; banding даёт кандидатов-лидеров (быстро).
        func cluster(_ pool: [Int], _ similar: (Int, Int) -> Bool) -> (groups: [[Int]], leaderOf: [Int: Int]) {
            var leaders: [Int] = []
            var leaderBands: [String: [Int]] = [:]
            var members: [Int: [Int]] = [:]
            var leaderOf: [Int: Int] = [:]
            for i in pool {
                let bs = bands(photos[i].pHash)
                var cand = Set<Int>()
                for k in bs { for L in leaderBands[k] ?? [] { cand.insert(L) } }
                var best: Int? = nil; var bestD = Int.max
                for L in cand where similar(i, L) {       // присоединяемся к БЛИЖАЙШЕМУ похожему лидеру
                    let d = hamming(photos[i].pHash, photos[L].pHash)
                    if d < bestD { bestD = d; best = L }
                }
                if let L = best { members[L, default: [L]].append(i); leaderOf[i] = L }
                else {
                    leaders.append(i); members[i] = [i]; leaderOf[i] = i
                    for k in bs { leaderBands[k, default: []].append(i) }
                }
            }
            return (leaders.compactMap { members[$0] }.filter { $0.count >= 2 }, leaderOf)
        }

        // 1) near-duplicate: строгий предикат isSimilar.
        let near = cluster(order) { isSimilar(photos[$0], photos[$1]) }
        var claimed = Set<Int>()
        var nearGroups = near.groups.map { m -> SimilarGroup in
            m.forEach { claimed.insert($0) }
            return makeGroup(.nearDuplicate, m.map { photos[$0] })
        }

        // 2) related-series (совещательно, reveal-only): из ещё не занятых, по relatedBand.
        let pool = order.filter { !claimed.contains($0) }
        let related = cluster(pool) { relatedBand(photos[$0], photos[$1]) }
        var relatedGroups = related.groups.map { makeGroup(.relatedSeries, $0.map { photos[$0] }) }

        nearGroups.sort { $0.reclaimable != $1.reclaimable ? $0.reclaimable > $1.reclaimable
                                                           : $0.count > $1.count }
        relatedGroups.sort { $0.count > $1.count }
        return nearGroups + relatedGroups
    }

    /// Собирает группу: keeper (макс. пиксели → размер → лексикографически меньший путь) на индекс 0.
    static func makeGroup(_ kind: SimilarKind, _ members: [SimilarPhoto]) -> SimilarGroup {
        // Callers always pass ≥2 members; guard defensively so an unexpected empty slice can never
        // crash here (this used to force-unwrap `.max()!` — audit L-7).
        guard let keeper = members.max(by: { a, b in
            let pa = a.width * a.height, pb = b.width * b.height
            if pa != pb { return pa < pb }
            if a.size != b.size { return a.size < b.size }
            return a.path > b.path
        }) else {
            return SimilarGroup(key: "sim|empty", kind: kind, photos: [])
        }
        var head = keeper; head.isKeeper = true
        let rest = members.filter { $0.path != keeper.path }
            .sorted { $0.path < $1.path }
            .map { p -> SimilarPhoto in var q = p; q.isKeeper = false; return q }
        return SimilarGroup(key: "sim|" + keeper.path, kind: kind, photos: [head] + rest)
    }

    // MARK: - Бэкстопы безопасности / обновление после удаления (как в Dups)

    /// Только near-duplicate группы можно отдавать в удаление. related-series — структурно неудаляемы.
    static func trashableGroups(_ groups: [SimilarGroup]) -> [SimilarGroup] {
        groups.filter { $0.kind == .nearDuplicate }
    }

    /// В каждой группе остаётся ≥1 копия: если выбраны все — keeper (photos[0]) снимаем. Не обойти.
    static func enforceKeepOne(_ selected: Set<String>, groups: [SimilarGroup]) -> Set<String> {
        var result = selected
        for g in groups where !g.photos.isEmpty {
            let survives = g.photos.contains { !result.contains($0.path) }
            if !survives, let keep = g.photos.first { result.remove(keep.path) }
        }
        return result
    }

    /// Какую копию группы сохранить при bulk-выборе («оставить одну» / select-all): ВСЕГДА лучшую
    /// (keeper = photos[0], выбран по качеству). Если лучшая trashable — её и оставляем (НЕ удаляем
    /// лучшую копию). Если лучшая защищена (личная папка) — она и так выживает, остальные trashable
    /// можно удалить → возврат nil. Чинит Codex-6: «удалить лучшую, оставить худшую защищённую».
    static func keepPath(_ g: SimilarGroup) -> String? {
        guard let best = g.photos.first else { return nil }
        return best.trashable ? best.path : nil
    }

    /// Мгновенно (без рескана диска) убирает удалённые из групп; группа <2 копий исчезает; keeper
    /// пересчитывается и снова кладётся на индекс 0.
    static func prune(_ groups: [SimilarGroup], removing gone: Set<String>) -> [SimilarGroup] {
        var out: [SimilarGroup] = []
        for g in groups {
            let kept = g.photos.filter { !gone.contains($0.path) }
            if kept.count < 2 { continue }
            out.append(makeGroup(g.kind, kept))
        }
        return out
    }

    // MARK: - Имя-основа (ТОЛЬКО для показа; на группировку НЕ влияет)

    /// "step_004" → "step", "grid-12" → "grid", "portrait" → nil. Убирает хвост [._-]?\d{1,6}.
    static func sharedStem(_ name: String) -> String? {
        var s = Substring(name)
        let digits = s.reversed().prefix { $0.isNumber }
        guard digits.count >= 1, digits.count <= 6 else { return nil }
        s = s.dropLast(digits.count)
        if let last = s.last, last == "_" || last == "." || last == "-" { s = s.dropLast() }
        return s.isEmpty ? nil : String(s)
    }

    // MARK: - Исключения пути

    /// Лежит ли путь ВНУТРИ непрозрачного пакета (медиатека/.app/…). Покомпонентно: ловит глубокие
    /// файлы …/X.photoslibrary/originals/0/IMG.heic независимо от firmlink-префикса и личной папки.
    static func isOpaquePackagePath(_ path: String) -> Bool {
        for comp in path.split(separator: "/") {
            let c = comp.lowercased()
            if opaquePackageSuffixes.contains(where: { c.hasSuffix($0) }) { return true }
        }
        return false
    }

    /// Лежит ли путь внутри кэша сборки / зависимости / системного кэша или СКРЫТОЙ dot-папки
    /// (.build/.claude/.codex/.git/.cache/… — тулинг/конфиг, не фото пользователя). ~/Library НЕ скрыта
    /// этим правилом (там лежат реальные данные приложений, напр. сгенерированные картинки).
    static func isExcludedScanPath(_ path: String) -> Bool {
        for comp in path.split(separator: "/") {
            if excludedScanDirs.contains(comp.lowercased()) { return true }
            if comp.hasPrefix("."), comp != ".", comp != ".." { return true }   // скрытая dot-папка
        }
        return false
    }
}

// MARK: - Вспомогательное

/// Потокобезопасный счётчик для прогресса из concurrentPerform.
private final class Counter {
    private var v = 0
    private let lock = NSLock()
    func inc() -> Int { lock.lock(); v += 1; let r = v; lock.unlock(); return r }
}
