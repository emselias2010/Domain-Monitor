<?php

if (PHP_SAPI !== "cli") {
    http_response_code(403);
    exit("CLI only\n");
}

require_once __DIR__ . "/api/database.php";

date_default_timezone_set("Europe/Vienna");

$php = PHP_BINARY;
$startScan = __DIR__ . DIRECTORY_SEPARATOR . "api" . DIRECTORY_SEPARATOR . "start_scan.php";

try {
    $stmt = $pdo->query(
        "SELECT s.user_id, s.next_scan, s.timezone, s.pause_weekends
         FROM scan_settings s
         JOIN users u ON u.id = s.user_id
                 WHERE s.enabled = 1
           AND (u.role = 'admin' OR u.plan = 'pro' OR (u.pro_until IS NOT NULL AND u.pro_until >= NOW()))
           AND u.active = 1
           AND (u.valid_until IS NULL OR u.valid_until >= NOW())
         ORDER BY s.user_id ASC"
    );

    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $settings) {
        $timezoneName = in_array(
            $settings["timezone"],
            ["Europe/Vienna", "Europe/Berlin", "UTC"],
            true
        ) ? $settings["timezone"] : "Europe/Vienna";
        $timezone = new DateTimeZone($timezoneName);
        $now = new DateTimeImmutable("now", $timezone);

        if (!$settings["next_scan"]) {
            continue;
        }
        if ((bool)$settings["pause_weekends"] && (int)$now->format("N") >= 6) {
            continue;
        }

        $nextScan = new DateTimeImmutable($settings["next_scan"], $timezone);
        if ($now < $nextScan) {
            continue;
        }

        $userId = (int)$settings["user_id"];
        $command =
            escapeshellarg($php) . " " . escapeshellarg($startScan) . " --user-id " . $userId . " 2>&1";
        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);
        echo "user {$userId}: " . implode(" ", $output) . PHP_EOL;
    }
} catch (Throwable $error) {
    fwrite(STDERR, "Automatic scan worker failed: " . $error->getMessage() . PHP_EOL);
    exit(1);
}
