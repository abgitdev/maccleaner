import Foundation

// Ядро безопасности. ИСТОЧНИК ИСТИНЫ — этот Swift-код (раньше комментарии врали про «1:1 из Go»).
// Инварианты закреплены тестами в native/tests/main.swift (в т.ч. обходы C1 '..' и C2 регистра).

struct SafetyError: Error, CustomStringConvertible {
    let reason: String
    var description: String { reason }
}

struct Denylist { var pathContains: [String] = [] }

struct SafetyPolicy {
    var home: String
    var denylist: Denylist

    init(home: String? = nil, denylist: Denylist = Denylist()) {
        if let h = home {
            self.home = h
        } else if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            // pw_dir надёжнее NSHomeDirectory() (под App Sandbox тот вернёт контейнер, а не реальный ~)
            self.home = String(cString: dir)
        } else {
            self.home = NSHomeDirectory()
        }
        self.denylist = denylist
    }

    // MARK: раскрытие / резолв

    func expand(_ path: String) -> String {
        if path == "~" { return home }
        if path.hasPrefix("~/") { return home + "/" + String(path.dropFirst(2)) }
        return path
    }

    func resolve(_ path: String) -> String {
        let expanded = expand(path)
        var buffer = [Int8](repeating: 0, count: Int(PATH_MAX))
        if realpath(expanded, &buffer) != nil { return String(cString: buffer) }
        return absolute(expanded)
    }

    private func absolute(_ path: String) -> String {
        if path.hasPrefix("/") { return Self.lexicalClean(path) }
        return Self.lexicalClean(FileManager.default.currentDirectoryPath + "/" + path)
    }

    // MARK: главная проверка перед удалением

    func validatePath(_ path: String) throws {
        // M3-fix: без известной домашней папки удалять нельзя (fail-CLOSED, не fail-open).
        if home.isEmpty { throw SafetyError(reason: "home directory unknown — refusing to delete") }
        if isDenied(path) { throw SafetyError(reason: "blocked by hard denylist") }
        try validateNoSymlinkComponents(path)            // отвергает '..' (C1) и симлинк-компоненты
        let resolved = resolve(path)
        if isDenied(resolved) { throw SafetyError(reason: "blocked by hard denylist") }
        if isHomeRoot(resolved) { throw SafetyError(reason: "protected home root") }
        if Self.isProtected(resolved) { throw SafetyError(reason: "protected system path") }
        if isPersonalData(resolved) || isPersonalData(expand(path)) {
            throw SafetyError(reason: "protected personal data")  // и по нерезолвленному — для несущ. путей
        }
    }

    func isHomeRoot(_ path: String) -> Bool {
        if home.isEmpty { return false }
        return Self.norm(path) == Self.norm(home)
    }

    /// C1-fix: отвергаем любой '..'-компонент ДО схлопывания, затем lstat каждого компонента.
    func validateNoSymlinkComponents(_ path: String) throws {
        let expanded = expand(path)
        let abs = expanded.hasPrefix("/") ? expanded
            : FileManager.default.currentDirectoryPath + "/" + expanded
        let parts = abs.split(separator: "/", omittingEmptySubsequences: true)
        if parts.contains("..") {
            throw SafetyError(reason: "refusing path with '..' component: \(path)")
        }
        var current = ""
        for part in parts where part != "." {
            current += "/" + part
            var st = stat()
            if lstat(current, &st) != 0 {
                throw SafetyError(reason: "cannot stat path component (\(String(cString: strerror(errno)))): \(current)")
            }
            if (st.st_mode & S_IFMT) == S_IFLNK {
                throw SafetyError(reason: "refusing path with symlink component: \(current)")
            }
        }
    }

    func isDenied(_ path: String) -> Bool {
        let p = Self.norm(expand(path))
        for bit in denylist.pathContains where !bit.isEmpty && p.contains(Self.norm(expand(bit))) {
            return true
        }
        return false
    }

    // MARK: защищённые / личные / ручные области (C2: регистронезависимо через norm)

    func isPersonalData(_ path: String) -> Bool {
        if home.isEmpty { return false }
        let clean = Self.norm(path)
        for root in personalDataRoots() where clean == root || clean.hasPrefix(root + "/") {
            return true
        }
        return false
    }

    func personalDataRoots() -> [String] {
        guard !home.isEmpty else { return [] }
        let names = [
            "Documents", "Desktop", "Downloads", "Pictures", "Movies", "Music", "Public",
            "Library/Mobile Documents", "Library/Mail", "Library/Messages",
            "Library/Keychains",   // секреты (пароли/ключи/сертификаты) — НИКОГДА не цель чистки
            ".ssh", ".gnupg", ".aws",                // SSH/GPG/AWS ключи и креды — секреты
            "Library/Safari", "Library/Cookies",     // история/закладки/куки — личное
            // I1 (аудит 2): расширяем жёсткий блок ещё на личное/секретное. Эти корни НИКОГДА не цели
            // чистки (каталог их не трогает), но whole-home сканер Dups мог бы предложить дубль изнутри.
            ".config", ".kube", ".netrc",            // личные конфиги/кластер-креды (gh/gcloud токены)/логин
            ".zsh_history", ".bash_history",         // история команд — личное
            "Library/Calendars", "Library/Reminders",          // PIM: календари/напоминания
            "Library/Application Support/AddressBook",          // Контакты
        ]
        return names.map { Self.norm(home + "/" + $0) }
    }

    static func isProtected(_ path: String) -> Bool {
        let clean = norm(path)          // norm = lexicalClean + lowercased
        if clean == "/" { return true }
        let exact = ["/applications", "/library", "/users"]
        if exact.contains(clean) { return true }
        let prefixes = ["/system", "/bin", "/sbin", "/private/var/db", "/private/var/root",
                        "/system/volumes/preboot", "/system/volumes/vm"]
        for p in prefixes where clean == p || clean.hasPrefix(p + "/") { return true }
        if clean == "/usr" || clean.hasPrefix("/usr/") {
            return !(clean == "/usr/local" || clean.hasPrefix("/usr/local/"))
        }
        return false
    }

    /// Области, которыми управляет КОНКРЕТНОЕ приложение или сама macOS: sandbox-контейнеры,
    /// Application Support, Group Containers, LaunchAgents — И OS-managed индекс/стейт-области
    /// (Spotlight-индекс, поведенческие БД Apple Intelligence/Siri, восстановление окон, web-стораджи).
    /// Это НЕ жёсткий блок удаления — аптинсталлер (экран Apps) намеренно удаляет Container/
    /// Application Support конкретного приложения при деинсталляции (он идёт через validatePath).
    /// Но whole-home сканеры (Duplicates / Similar Photos) держат это reveal-only: файл здесь —
    /// это данные приложения или регенерируемый индекс/стейт ОС, а не общий мусор для дедупа.
    /// Без этого Duplicates мог предложить, например, два компонента индекса Spotlight
    /// (~/Library/Metadata/CoreSpotlight/.../live.4.indexArrays vs .../live.4.shadowIndexArrays),
    /// которые сейчас просто совпали побайтно как APFS-клоны (0 freed) — это не пользовательский дубль.
    /// ⚠️ Набор выверен состязательным роем: НЕ включает реальные места дублей (Library/Caches,
    /// Library/Sounds, Library/Fonts, ~/.cache, .build/node_modules/target/Pods) — они остаются удаляемыми.
    static func isManualArea(_ path: String) -> Bool {
        let clean = norm(path)
        let roots = [
            // Данные конкретного приложения (sandbox/поддержка/агенты)
            "/library/containers", "/library/application support",
            "/library/launchagents", "/library/group containers",
            "/library/daemon containers", "/library/containermanager",
            "/library/application support/mobilesync/backup", "/library/mail downloads",
            // OS-managed индекс/метадата (Spotlight и его компоненты)
            "/library/metadata", "/library/spotlight",
            // Поведенческие / ML / knowledge БД (Apple Intelligence, Siri, CoreDuet, проактивность)
            "/library/biome", "/library/suggestions", "/library/assistant",
            "/library/corefollowup", "/library/duetexpertcenter", "/library/personalizationportrait",
            "/library/intelligenceplatform", "/library/languagemodeling", "/library/responsekit",
            "/library/statuskit", "/library/trial", "/library/translation",
            // Регенерируемый стейт/реестры ОС (восстановление окон, web, аккаунты, шаринг, ввод)
            "/library/saved application state", "/library/webkit", "/library/httpstorages",
            "/library/accounts", "/library/sharing", "/library/identityservices",
            "/library/keyboardservices", "/library/homekit", "/library/frontboard",
            "/library/autosave information",
        ]
        for root in roots where clean == root || clean.hasSuffix(root) || clean.contains(root + "/") {
            return true
        }
        return false
    }

    /// True, если путь — данные, которыми управляет приложение (см. isManualArea), с резолвом пути.
    func isAppManagedData(_ path: String) -> Bool {
        return Self.isManualArea(resolve(path))
    }

    /// Можно ли whole-home сканеру (Duplicates / Similar Photos) предлагать путь в Корзину.
    /// Строже validatePath: вдобавок ко всем жёстким блокам держит данные приложений
    /// (Containers / Application Support / Group Containers) reveal-only — их трогает только
    /// аптинсталлер при явной деинсталляции, не дедуп/похожие-фото.
    func isScannerTrashable(_ path: String) -> Bool {
        do { try validatePath(path) } catch { return false }
        return !isAppManagedData(path)
    }

    // MARK: нормализация для сравнения

    static func norm(_ path: String) -> String { lexicalClean(path).lowercased() }

    static func lexicalClean(_ path: String) -> String {
        if path.isEmpty { return "." }
        let rooted = path.hasPrefix("/")
        var out: [Substring] = []
        for c in path.split(separator: "/", omittingEmptySubsequences: true) {
            if c == "." { continue }
            if c == ".." {
                if let last = out.last, last != ".." { out.removeLast() }
                else if !rooted { out.append(c) }
            } else { out.append(c) }
        }
        let joined = out.joined(separator: "/")
        if rooted { return "/" + joined }
        return joined.isEmpty ? "." : joined
    }
}
