<?php

header(
    "Content-Type: application/json; charset=utf-8"
);

require_once "database.php";
require_once "auth.php";

$currentUser = require_auth();
$userId = (int)$currentUser["id"];

try {

    $pdo->beginTransaction();

    $pdo->exec(
        "DELETE FROM domain_ips WHERE domain_id IN (SELECT id FROM domains WHERE user_id = {$userId})"
    );

    $pdo->exec(
        "DELETE FROM scan_results WHERE domain_id IN (SELECT id FROM domains WHERE user_id = {$userId})"
    );

    $pdo->exec(
        "DELETE FROM muted_domains WHERE user_id = {$userId}"
    );

    $pdo->exec(
        "DELETE FROM domains WHERE user_id = {$userId}"
    );

    $pdo->exec(
        "DELETE FROM scans WHERE user_id = {$userId}"
    );

    $pdo->commit();

    echo json_encode([
        "success" => true,
        "message" =>
            "All scan data deleted."
    ]);

} catch (Throwable $error) {

    $runningStmt = $pdo->prepare(
        "SELECT id FROM user_scan_jobs
         WHERE user_id = ? AND status IN ('starting', 'running')
         ORDER BY id DESC LIMIT 1"
    );
    $runningStmt->execute([$userId]);
    if ($runningStmt->fetchColumn()) {
        http_response_code(409);
        echo json_encode([
            "success" => false,
            "error" => "Stop the running scan before deleting scan data."
        ]);
        exit;
    }
    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();
    }

    http_response_code(500);

    echo json_encode([
        "success" => false,
        "error" =>
            $error->getMessage()
    ]);
}
