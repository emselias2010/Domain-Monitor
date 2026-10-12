<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";
require_admin();

try {
    $stmt = $pdo->query(
        "SELECT s.id, s.started_at, s.finished_at, s.candidates_count,
            s.registered_count, s.active_count, pd.domain, u.username
         FROM scans s
         JOIN users u ON u.id = s.user_id
         LEFT JOIN protected_domains pd ON pd.id = s.protected_domain_id
         ORDER BY s.id DESC LIMIT 100"
    );

    echo json_encode([
        "success" => true,
        "scans" => $stmt->fetchAll(PDO::FETCH_ASSOC)
    ]);

} catch (Throwable $error) {
    http_response_code(500);
    echo json_encode(["success" => false, "error" => $error->getMessage()]);
}
