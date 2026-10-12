<?php

header(
    "Content-Type: application/json; charset=utf-8"
);

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

    $method = $_SERVER["REQUEST_METHOD"];

    if ($method === "GET") {

        $stmt = $pdo->prepare("SELECT id, domain, created_at
            FROM excluded_domains
            WHERE user_id = ?
            ORDER BY id ASC");

        $stmt->execute([$userId]);

        $domains = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($domains as &$domain) {
            $domain["id"] = (int)$domain["id"];
        }

        unset($domain);

        echo json_encode([
            "success" => true,
            "domains" => $domains
        ], JSON_UNESCAPED_UNICODE);

        exit;
    }

    if ($method === "POST") {

        $input = json_decode(
            file_get_contents("php://input"),
            true
        );

        $domain = isset($input["domain"])
            ? strtolower(trim($input["domain"]))
            : "";

        $domain = preg_replace(
            "#^https?://#i",
            "",
            $domain
        );

        $domain = explode("/", $domain)[0];
        $domain = explode(":", $domain)[0];
        $domain = rtrim($domain, ".");

        if (
            !$domain ||
            !preg_match(
                '/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/',
                $domain
            )
        ) {
            http_response_code(400);

            echo json_encode([
                "success" => false,
                "error" => "Invalid domain"
            ]);

            exit;
        }

        $stmt = $pdo->prepare(
            "INSERT INTO excluded_domains (domain, user_id) VALUES (?, ?)"
        );

        try {
            $stmt->execute([$domain, $userId]);
        } catch (PDOException $error) {
            if ($error->getCode() === "23000") {
                http_response_code(409);

                echo json_encode([
                    "success" => false,
                    "error" => "Domain already excluded"
                ]);

                exit;
            }

            throw $error;
        }

        echo json_encode([
            "success" => true,
            "domain" => [
                "id" => (int)$pdo->lastInsertId(),
                "domain" => $domain
            ]
        ], JSON_UNESCAPED_UNICODE);

        exit;
    }

    if ($method === "DELETE") {

        $id = isset($_GET["id"])
            ? (int)$_GET["id"]
            : 0;

        if ($id <= 0) {
            http_response_code(400);

            echo json_encode([
                "success" => false,
                "error" => "Invalid domain ID"
            ]);

            exit;
        }

        $stmt = $pdo->prepare(
            "DELETE FROM excluded_domains WHERE id = ? AND user_id = ?"
        );

        $stmt->execute([$id, $userId]);

        echo json_encode([
            "success" => true
        ]);

        exit;
    }

    http_response_code(405);

    echo json_encode([
        "success" => false,
        "error" => "Method not allowed"
    ]);

} catch (Throwable $error) {

    http_response_code(500);

    echo json_encode([
        "success" => false,
        "error" => $error->getMessage()
    ], JSON_UNESCAPED_UNICODE);
}
