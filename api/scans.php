<?php

header("Content-Type: application/json");

require_once "database.php";
require_once "auth.php";

$currentUser = require_auth();
$userId = (int)$currentUser["id"];

try {

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
        ORDER BY id DESC
        LIMIT 20
    ");

    $scans = $stmt->fetchAll();

    echo json_encode([
        "success" => true,
        "scans" => $scans
    ]);

} catch (Exception $e) {

    http_response_code(500);

    echo json_encode([
        "success" => false,
        "error" => $e->getMessage()
    ]);
}
