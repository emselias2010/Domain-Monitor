<?php

if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set("session.use_strict_mode", "1");
    ini_set("session.use_only_cookies", "1");
    session_set_cookie_params([
        "httponly" => true,
        "secure" => !empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off",
        "samesite" => "Lax"
    ]);
    session_start();
}

$host = getenv("DB_HOST") ?: "127.0.0.1";
$port = (int)(getenv("DB_PORT") ?: 3306);
$db   = getenv("DB_NAME") ?: "domain_monitor";
$user = getenv("DB_USER") ?: "root";
$pass = getenv("DB_PASS") ?: "";

try {

    $pdo = new PDO(
        "mysql:host=$host;port=$port;dbname=$db;charset=utf8mb4",
        $user,
        $pass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]
    );

} catch (PDOException $e) {

    http_response_code(500);

    header("Content-Type: application/json");

    echo json_encode([
        "success" => false,
        "error" => "Database connection failed"
    ]);

    exit;
}

$pdo->exec("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)");

$pdo->exec("CREATE TABLE IF NOT EXISTS user_scan_jobs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'starting',
    pid INT NULL,
    progress_file VARCHAR(500) NOT NULL,
    log_file VARCHAR(500) NOT NULL,
    started_at DATETIME NOT NULL,
    finished_at DATETIME NULL,
    INDEX (user_id),
    CONSTRAINT fk_user_scan_jobs_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
)");

$pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    attempted_at DATETIME NOT NULL,
    INDEX (ip_address, attempted_at)
)");

$pdo->exec("CREATE TABLE IF NOT EXISTS app_settings (
    setting_key VARCHAR(64) PRIMARY KEY,
    setting_value VARCHAR(255) NOT NULL
)");
$pdo->exec("INSERT IGNORE INTO app_settings (setting_key, setting_value) VALUES ('registration_enabled', '1')");
$pdo->exec("INSERT IGNORE INTO app_settings (setting_key, setting_value) VALUES ('notifications_enabled', '0')");
foreach ([
    "smtp_host" => "",
    "smtp_port" => "587",
    "smtp_user" => "",
    "smtp_password" => "",
    "smtp_from" => "",
    "smtp_tls" => "1"
] as $settingKey => $settingValue) {
    $stmt = $pdo->prepare("INSERT IGNORE INTO app_settings (setting_key, setting_value) VALUES (?, ?)");
    $stmt->execute([$settingKey, $settingValue]);
}

foreach ([
    "protected_domains" => "user_id INT NULL",
    "excluded_domains" => "user_id INT NULL",
    "domains" => "user_id INT NULL",
    "scans" => "user_id INT NULL",
    "scan_settings" => "user_id INT NULL"
] as $table => $definition) {

    try {
        $pdo->exec(
            "ALTER TABLE {$table} ADD COLUMN {$definition}"
        );
    } catch (PDOException $error) {
        if ((string)$error->errorInfo[1] !== "1060") {
            throw $error;
        }
    }

try {
    $pdo->exec("ALTER TABLE scan_results ADD COLUMN finding_fingerprint CHAR(64) NULL");
} catch (PDOException $error) {
    if ((string)$error->errorInfo[1] !== "1060") {
        throw $error;
    }
}
}

try {
    $pdo->exec("CREATE TABLE IF NOT EXISTS muted_domains (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        domain_id BIGINT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_muted_user_domain (user_id, domain_id),
        KEY idx_muted_domain (domain_id)
    )");
} catch (PDOException $error) {
    throw $error;
}

$pdo->exec("CREATE TABLE IF NOT EXISTS threat_intelligence (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    domain_id BIGINT NOT NULL,
    source VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    category VARCHAR(64) NULL,
    detections INT NOT NULL DEFAULT 0,
    reference_url VARCHAR(500) NULL,
    checked_at DATETIME NOT NULL,
    UNIQUE KEY uq_threat_domain_source (domain_id, source),
    KEY idx_threat_domain_checked (domain_id, checked_at)
)");

try {
    $indexStmt = $pdo->query("SHOW INDEX FROM protected_domains");
    $hasLegacyDomainIndex = false;
    $hasUserDomainIndex = false;
    foreach ($indexStmt->fetchAll(PDO::FETCH_ASSOC) as $index) {
        if ($index["Key_name"] === "domain") {
            $hasLegacyDomainIndex = true;
        }
        if ($index["Key_name"] === "uq_protected_domains_user_domain") {
            $hasUserDomainIndex = true;
        }
    }
    if ($hasLegacyDomainIndex && !$hasUserDomainIndex) {
        $pdo->exec("ALTER TABLE protected_domains DROP INDEX `domain`");
    }
    if (!$hasUserDomainIndex) {
        $pdo->exec(
            "ALTER TABLE protected_domains
             ADD UNIQUE KEY uq_protected_domains_user_domain (user_id, domain)"
        );
    }
} catch (PDOException $error) {
    if (!in_array((string)$error->errorInfo[1], ["1061", "1831"], true)) {
        throw $error;
    }
}

try {
    $indexStmt = $pdo->query("SHOW INDEX FROM domains");
    $hasLegacyDomainIndex = false;
    $hasUserDomainIndex = false;
    foreach ($indexStmt->fetchAll(PDO::FETCH_ASSOC) as $index) {
        if ($index["Key_name"] === "domain") {
            $hasLegacyDomainIndex = true;
        }
        if ($index["Key_name"] === "uq_domains_user_domain") {
            $hasUserDomainIndex = true;
        }
    }
    if ($hasLegacyDomainIndex && !$hasUserDomainIndex) {
        $pdo->exec("ALTER TABLE domains DROP INDEX `domain`");
    }
    if (!$hasUserDomainIndex) {
        $pdo->exec(
            "ALTER TABLE domains
             ADD UNIQUE KEY uq_domains_user_domain (user_id, domain)"
        );
    }
} catch (PDOException $error) {
    if (!in_array((string)$error->errorInfo[1], ["1061", "1831"], true)) {
        throw $error;
    }
}

foreach ([
    "scan_settings" => [
        "timezone" => "VARCHAR(64) NOT NULL DEFAULT 'Europe/Vienna'",
        "pause_weekends" => "TINYINT(1) NOT NULL DEFAULT 0",
        "max_domains" => "INT NOT NULL DEFAULT 50000",
        "threat_intelligence_enabled" => "TINYINT(1) NOT NULL DEFAULT 0"
    ],
    "users" => [
        "valid_until" => "DATETIME NULL"
    ]
] as $table => $columns) {
    foreach ($columns as $column => $definition) {
        try {
            $pdo->exec("ALTER TABLE {$table} ADD COLUMN {$column} {$definition}");
        } catch (PDOException $error) {
            if ((string)$error->errorInfo[1] !== "1060") {
                throw $error;
            }
        }
    }
}

try {
    $pdo->exec("ALTER TABLE users ADD COLUMN email VARCHAR(254) NULL");
} catch (PDOException $error) {
    if ((string)$error->errorInfo[1] !== "1060") {
        throw $error;
    }
}

try {
    $indexStmt = $pdo->query("SHOW INDEX FROM users");
    $hasEmailIndex = false;
    foreach ($indexStmt->fetchAll(PDO::FETCH_ASSOC) as $index) {
        if ($index["Key_name"] === "uq_users_email") {
            $hasEmailIndex = true;
            break;
        }
    }
    if (!$hasEmailIndex) {
        $pdo->exec("ALTER TABLE users ADD UNIQUE KEY uq_users_email (email)");
    }
} catch (PDOException $error) {
    if (!in_array((string)$error->errorInfo[1], ["1061", "1831"], true)) {
        throw $error;
    }
}

try {
    $pdo->exec("ALTER TABLE users ADD COLUMN language ENUM('de', 'en') NOT NULL DEFAULT 'de'");
} catch (PDOException $error) {
    if ((string)$error->errorInfo[1] !== "1060") {
        throw $error;
    }
}

try {
    $pdo->exec("ALTER TABLE users ADD COLUMN notifications_enabled TINYINT(1) NOT NULL DEFAULT 0");
} catch (PDOException $error) {
    if ((string)$error->errorInfo[1] !== "1060") {
        throw $error;
    }
}

try {
    $pdo->exec("ALTER TABLE users ADD COLUMN plan ENUM('free', 'pro') NOT NULL DEFAULT 'free'");
} catch (PDOException $error) {
    if ((string)$error->errorInfo[1] !== "1060") {
        throw $error;
    }
}

try {
    $pdo->exec("ALTER TABLE scan_results ADD COLUMN ips_snapshot TEXT NULL");
} catch (PDOException $error) {
    if ((string)$error->errorInfo[1] !== "1060") {
        throw $error;
    }
}

try {
    $pdo->exec("ALTER TABLE users ADD COLUMN pro_until DATETIME NULL");
} catch (PDOException $error) {
    if ((string)$error->errorInfo[1] !== "1060") {
        throw $error;
    }
}
