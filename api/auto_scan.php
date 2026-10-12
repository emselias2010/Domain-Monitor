<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";

$user = require_auth();
$userId = (int)$user["id"];
if (!has_pro_access($user)) {
    echo json_encode(["success" => true, "action" => "plan_disabled", "next_scan" => null]);
    exit;
}
date_default_timezone_set("Europe/Vienna");

try {
    $stmt = $pdo->prepare(
        "SELECT enabled, next_scan, timezone, pause_weekends
         FROM scan_settings
         WHERE user_id = ? ORDER BY id ASC LIMIT 1"
    );
    $stmt->execute([$userId]);
    $settings = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($settings && in_array($settings["timezone"], ["Europe/Vienna", "Europe/Berlin", "UTC"], true)) {
        date_default_timezone_set($settings["timezone"]);
    }

    if (!$settings || !(bool)$settings["enabled"]) {
        echo json_encode([
            "success" => true,
            "action" => "disabled",
            "next_scan" => $settings["next_scan"] ?? null
        ]);
        exit;
    }

    $nextScan = strtotime((string)$settings["next_scan"]);
    if ((bool)$settings["pause_weekends"] && in_array((int)date("N"), [6, 7], true)) {
        echo json_encode(["success" => true, "action" => "weekend_pause", "next_scan" => $settings["next_scan"]]);
        exit;
    }
    if ($nextScan === false || time() < $nextScan) {
        echo json_encode([
            "success" => true,
            "action" => "waiting",
            "next_scan" => $settings["next_scan"]
        ]);
        exit;
    }

    require __DIR__ . "/start_scan.php";
} catch (Throwable $error) {
    http_response_code(500);
    echo json_encode(["success" => false, "error" => $error->getMessage()]);
}
