<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";

$user = require_auth();
$userId = (int)$user["id"];

$emptyProgress = [
    "status" => "idle",
    "current" => 0,
    "total" => 0,
    "percentage" => 0,
    "domain" => "",
    "message" => "Scanner ready",
    "protected_current" => 0,
    "protected_total" => 0
];

try {
    $stmt = $pdo->prepare(
        "SELECT progress_file, status FROM user_scan_jobs
         WHERE user_id = ? ORDER BY id DESC LIMIT 1"
    );
    $stmt->execute([$userId]);
    $job = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$job || !in_array($job["status"], ["starting", "running"], true)) {
        echo json_encode(["success" => true, "progress" => $emptyProgress]);
        exit;
    }

    if (!is_file($job["progress_file"])) {
        $emptyProgress["status"] = $job["status"];
        $emptyProgress["message"] = "Starting scan...";
        echo json_encode(["success" => true, "progress" => $emptyProgress]);
        exit;
    }

    $content = file_get_contents($job["progress_file"]);
    $data = json_decode($content, true);

    echo json_encode([
        "success" => true,
        "progress" => is_array($data) ? $data : $emptyProgress
    ]);

} catch (Throwable $error) {
    http_response_code(500);
    echo json_encode(["success" => false, "error" => $error->getMessage()]);
}
