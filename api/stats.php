<?php

header("Content-Type: application/json");

require_once "database.php";
require_once "auth.php";

$currentUser = require_auth();
$userId = (int)$currentUser["id"];

try {

    $pdo->exec("CREATE TABLE IF NOT EXISTS excluded_domains (
        id INT AUTO_INCREMENT PRIMARY KEY,
        domain VARCHAR(253) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");

    $domainExclusion = "
        NOT EXISTS (
            SELECT 1
            FROM muted_domains m
            WHERE m.domain_id = domains.id
              AND m.user_id = domains.user_id
        )
        AND NOT EXISTS (
            SELECT 1
            FROM excluded_domains e
            WHERE LOWER(domains.domain) = LOWER(e.domain)
               OR LOWER(domains.domain) LIKE CONCAT('%.', LOWER(e.domain))
        )
    ";

    $stmt = $pdo->query("
        SELECT COUNT(*) AS count
        FROM protected_domains
        WHERE active = 1
        AND user_id = {$userId}
    ");

    $protectedDomains = (int)$stmt->fetch()["count"];

    $stmt = $pdo->query("
        SELECT COUNT(*) AS count
        FROM domains
        WHERE user_id = {$userId}
        AND $domainExclusion
    ");

    $totalDomains = (int)$stmt->fetch()["count"];

    $stmt = $pdo->query("
        SELECT COUNT(*) AS count
        FROM domains
        WHERE dns_active = 1
        AND user_id = {$userId}
        AND $domainExclusion
    ");

    $registeredDomains = (int)$stmt->fetch()["count"];

    $stmt = $pdo->query("
        SELECT COUNT(*) AS count
        FROM domains
        WHERE website_active = 1
        AND user_id = {$userId}
        AND $domainExclusion
    ");

    $activeWebsites = (int)$stmt->fetch()["count"];

    $stmt = $pdo->query("
        SELECT

            SUM(
                CASE
                    WHEN risk_score >= 80
                    THEN 1
                    ELSE 0
                END
            ) AS critical,

            SUM(
                CASE
                    WHEN risk_score >= 60
                    AND risk_score < 80
                    THEN 1
                    ELSE 0
                END
            ) AS high,

            SUM(
                CASE
                    WHEN risk_score >= 30
                    AND risk_score < 60
                    THEN 1
                    ELSE 0
                END
            ) AS medium,

            SUM(
                CASE
                    WHEN risk_score < 30
                    THEN 1
                    ELSE 0
                END
            ) AS low

        FROM domains
        WHERE user_id = {$userId}
        AND $domainExclusion
    ");

    $risk = $stmt->fetch();

    $stmt = $pdo->query("
        SELECT
            id,
            started_at,
            finished_at,
            candidates_count,
            registered_count,
            active_count
        FROM scans
        WHERE user_id = {$userId}
        AND finished_at IS NOT NULL
        ORDER BY id DESC
        LIMIT 1
    ");

    $lastScan = $stmt->fetch();

    $jobStmt = $pdo->prepare(
        "SELECT id, pid, progress_file, status, started_at
         FROM user_scan_jobs
         WHERE user_id = ? AND status IN ('starting', 'running')"
    );
    $jobStmt->execute([$userId]);
    foreach ($jobStmt->fetchAll(PDO::FETCH_ASSOC) as $job) {
        $progressStatus = "";
        if (is_file((string)$job["progress_file"])) {
            $progress = json_decode((string)file_get_contents($job["progress_file"]), true);
            $progressStatus = is_array($progress) ? (string)($progress["status"] ?? "") : "";
        }

        $pid = (int)$job["pid"];
        $processExists = false;
        if ($pid > 0 && function_exists("exec")) {
            if (PHP_OS_FAMILY === "Windows") {
                $taskOutput = [];
                exec("tasklist /FI \"PID eq " . $pid . "\" /FO CSV /NH", $taskOutput);
                foreach ($taskOutput as $line) {
                    if (strpos($line, '"' . $pid . '"') !== false) {
                        $processExists = true;
                        break;
                    }
                }
            } else {
                exec("kill -0 " . $pid . " 2>/dev/null", $unusedOutput, $returnCode);
                $processExists = $returnCode === 0;
            }
        }

        $staleStartingJob = $job["status"] === "starting"
            && strtotime((string)$job["started_at"]) < time() - 30;
        $processCheckAvailable = function_exists("exec") || $pid <= 0;
        if (in_array($progressStatus, ["finished", "cancelled", "error"], true) || $staleStartingJob || ($processCheckAvailable && $job["status"] === "running" && !$processExists)) {
            $recoveredStatus = in_array($progressStatus, ["finished", "cancelled"], true)
                ? $progressStatus
                : "error";
            $cleanup = $pdo->prepare(
                "UPDATE user_scan_jobs SET status = ?, finished_at = COALESCE(finished_at, NOW())
                 WHERE id = ? AND user_id = ? AND status IN ('starting', 'running')"
            );
            $cleanup->execute([$recoveredStatus, (int)$job["id"], $userId]);
        }
    }

    $stmt = $pdo->prepare(
        "SELECT COUNT(*)
         FROM user_scan_jobs
         WHERE user_id = ?
         AND status IN ('starting', 'running')"
    );
    $stmt->execute([$userId]);
    $scanRunning = (int)$stmt->fetchColumn() > 0;

    echo json_encode([

        "success" => true,

        "protected_domains" =>
            $protectedDomains,

        "total_domains" =>
            $totalDomains,

        "registered_domains" =>
            $registeredDomains,

        "active_websites" =>
            $activeWebsites,

        "risk" => [

            "critical" =>
                (int)$risk["critical"],

            "high" =>
                (int)$risk["high"],

            "medium" =>
                (int)$risk["medium"],

            "low" =>
                (int)$risk["low"]
        ],

        "scan_running" =>
            $scanRunning,

        "last_scan" =>
            $lastScan ?: null
    ]);

} catch (Exception $e) {

    http_response_code(500);

    echo json_encode([

        "success" => false,

        "error" =>
            $e->getMessage()
    ]);
}
