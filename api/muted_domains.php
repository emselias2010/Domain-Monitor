<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";

$user = require_auth();
$userId = (int)$user["id"];
$method = $_SERVER["REQUEST_METHOD"];

try {
    if ($method === "GET") {
        $stmt = $pdo->prepare(
            "SELECT m.id, m.domain_id, d.domain, m.created_at
             FROM muted_domains m
             JOIN domains d ON d.id = m.domain_id
             WHERE m.user_id = ?
             ORDER BY m.id DESC"
        );
        $stmt->execute([$userId]);
        echo json_encode(["success" => true, "domains" => $stmt->fetchAll(PDO::FETCH_ASSOC)], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if ($method === "POST") {
        $input = json_decode(file_get_contents("php://input"), true);
        $domainId = (int)($input["domain_id"] ?? 0);
        if ($domainId <= 0) {
            http_response_code(400);
            echo json_encode(["success" => false, "error" => "Invalid domain ID"]);
            exit;
        }

        $check = $pdo->prepare("SELECT id FROM domains WHERE id = ? AND user_id = ? LIMIT 1");
        $check->execute([$domainId, $userId]);
        if (!$check->fetch()) {
            http_response_code(404);
            echo json_encode(["success" => false, "error" => "Domain not found"]);
            exit;
        }

        $stmt = $pdo->prepare("INSERT INTO muted_domains (user_id, domain_id) VALUES (?, ?)");
        $stmt->execute([$userId, $domainId]);
        echo json_encode(["success" => true, "id" => (int)$pdo->lastInsertId()]);
        exit;
    }

    if ($method === "DELETE") {
        $domainId = (int)($_GET["domain_id"] ?? 0);
        if ($domainId <= 0) {
            http_response_code(400);
            echo json_encode(["success" => false, "error" => "Invalid domain ID"]);
            exit;
        }
        $stmt = $pdo->prepare("DELETE FROM muted_domains WHERE domain_id = ? AND user_id = ?");
        $stmt->execute([$domainId, $userId]);
        echo json_encode(["success" => true]);
        exit;
    }

    http_response_code(405);
    echo json_encode(["success" => false, "error" => "Method not allowed"]);
} catch (PDOException $error) {
    http_response_code($error->getCode() === "23000" ? 409 : 500);
    echo json_encode([
        "success" => false,
        "error" => $error->getCode() === "23000" ? "Domain is already monitored silently" : "Silent monitoring failed"
    ]);
}
