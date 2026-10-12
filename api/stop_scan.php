<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";

$user = require_auth();
$userId = (int)$user["id"];

try {
    $stmt = $pdo->prepare(
        "SELECT id, pid, progress_file
         FROM user_scan_jobs
         WHERE user_id = ? AND status IN ('starting', 'running')
         ORDER BY id DESC LIMIT 1"
    );
    $stmt->execute([$userId]);
    $job = $stmt->fetch(PDO::FETCH_ASSOC);
    $pid = $job ? (int)$job["pid"] : 0;
    $processExists = false;
    $isWindows = PHP_OS_FAMILY === "Windows";

    if ($pid > 0 && function_exists("exec")) {
        $taskOutput = [];
        $taskReturnCode = 0;
        if ($isWindows) {
            exec("tasklist /FI \"PID eq " . $pid . "\" /FO CSV /NH", $taskOutput, $taskReturnCode);
            foreach ($taskOutput as $line) {
                if (strpos($line, '"' . $pid . '"') !== false) {
                    $processExists = true;
                    break;
                }
            }
        } else {
            exec("kill -0 " . $pid . " 2>/dev/null", $taskOutput, $taskReturnCode);
            $processExists = $taskReturnCode === 0;
        }
    }

    if ($pid > 0 && function_exists("exec")) {
        $killOutput = [];
        $killReturnCode = 0;
        $killCommand = $isWindows
            ? "taskkill /PID " . $pid . " /T /F"
            : "kill " . $pid;
        exec($killCommand, $killOutput, $killReturnCode);
        if ($killReturnCode === 0) {
            $processExists = true;
        }
    }

    if ($job) {
        $stmt = $pdo->prepare(
            "UPDATE user_scan_jobs SET status = 'cancelled', finished_at = NOW()
             WHERE id = ? AND user_id = ?"
        );
        $stmt->execute([(int)$job["id"], $userId]);

        $progress = [
            "status" => "cancelled",
            "current" => 0,
            "total" => 0,
            "percentage" => 0,
            "domain" => "",
            "message" => "Scan cancelled by user.",
            "protected_current" => 0,
            "protected_total" => 0,
            "updated_at" => date("c")
        ];
        $progressFile = $job["progress_file"];
        $progressTempFile = $progressFile . ".tmp";
        file_put_contents($progressTempFile, json_encode($progress, JSON_PRETTY_PRINT), LOCK_EX);
        @rename($progressTempFile, $progressFile);
    }

    $stmt = $pdo->prepare(
        "SELECT id, enabled, interval_hours, timezone
         FROM scan_settings WHERE user_id = ? ORDER BY id ASC LIMIT 1"
    );
    $stmt->execute([$userId]);
    $settings = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($settings && (bool)$settings["enabled"]) {
        $timezoneName = in_array($settings["timezone"], ["Europe/Vienna", "Europe/Berlin", "UTC"], true)
            ? $settings["timezone"]
            : "Europe/Vienna";
        $nextScan = (new DateTimeImmutable("now", new DateTimeZone($timezoneName)))
            ->modify("+" . (int)$settings["interval_hours"] . " hours")
            ->format("Y-m-d H:i:s");
        $stmt = $pdo->prepare(
            "UPDATE scan_settings SET next_scan = ?, updated_at = NOW()
             WHERE id = ? AND user_id = ?"
        );
        $stmt->execute([$nextScan, (int)$settings["id"], $userId]);
    }

    echo json_encode([
        "success" => true,
        "message" => $processExists ? "Scan stopped" : "No active scanner process found"
    ]);
} catch (Throwable $error) {
    http_response_code(500);
    echo json_encode(["success" => false, "error" => $error->getMessage()]);
}
