<?php

header(
    "Content-Type: application/json; charset=utf-8"
);

require_once "database.php";
require_once "auth.php";

$currentUser = require_auth();
$userId = (int)$currentUser["id"];
$limits = plan_limits($currentUser);

try {

    $method =
        $_SERVER["REQUEST_METHOD"];

    if ($method === "GET") {

        $stmt = $pdo->query("
            SELECT
                pd.id,
                pd.domain,
                pd.active,
                pd.created_at,
                (
                    SELECT MAX(s.finished_at)
                    FROM scans s
                    WHERE s.protected_domain_id = pd.id
                ) AS last_scan
            FROM protected_domains pd
            WHERE pd.user_id = {$userId}
            ORDER BY pd.id ASC
        ");

        $domains =
            $stmt->fetchAll(
                PDO::FETCH_ASSOC
            );

        foreach ($domains as &$domain) {

            $domain["id"] =
                (int)$domain["id"];

            $domain["active"] =
                (bool)$domain["active"];
        }

        unset(
            $domain
        );

        echo json_encode(
            [
                "success" => true,
                "domains" => $domains
            ],
            JSON_UNESCAPED_UNICODE
        );

        exit;
    }

    if ($method === "POST") {

        $input =
            json_decode(
                file_get_contents(
                    "php://input"
                ),
                true
            );

        if (!is_array($input)) {

            http_response_code(
                400
            );

            echo json_encode(
                [
                    "success" => false,
                    "error" => "Invalid JSON"
                ]
            );

            exit;
        }

        $countStmt = $pdo->prepare("SELECT COUNT(*) FROM protected_domains WHERE user_id = ?");
        $countStmt->execute([$userId]);
        if ((int)$countStmt->fetchColumn() >= $limits["max_protected_domains"]) {
            http_response_code(403);
            echo json_encode([
                "success" => false,
                "error" => "Your plan allows up to " . $limits["max_protected_domains"] . " protected domains"
            ]);
            exit;
        }

        $domain =
            isset(
                $input["domain"]
            )

                ? strtolower(
                    trim(
                        $input["domain"]
                    )
                )

                : "";

        $domain =
            preg_replace(
                "#^https?://#i",
                "",
                $domain
            );

        $domain =
            preg_replace(
                "#^www\.#i",
                "",
                $domain
            );

        $domain =
            explode(
                "/",
                $domain
            )[0];

        $domain =
            explode(
                ":",
                $domain
            )[0];

        if (
            empty($domain) ||
            !preg_match(
                '/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/',
                $domain
            )
        ) {

            http_response_code(
                400
            );

            echo json_encode(
                [
                    "success" => false,
                    "error" => "Invalid domain"
                ]
            );

            exit;
        }

        $countStmt = $pdo->prepare("SELECT COUNT(*) FROM protected_domains WHERE user_id = ?");
        $countStmt->execute([$userId]);
        if ((int)$countStmt->fetchColumn() >= $limits["max_protected_domains"]) {
            http_response_code(403);
            echo json_encode([
                "success" => false,
                "error" => "Your plan allows up to " . $limits["max_protected_domains"] . " protected domains"
            ]);
            exit;
        }

        $stmt =
            $pdo->prepare("
                SELECT id
                FROM protected_domains
                WHERE domain = ?
                AND user_id = ?
                LIMIT 1
            ");

        $stmt->execute([
            $domain,
            $userId
        ]);

        if ($stmt->fetch()) {

            http_response_code(
                409
            );

            echo json_encode(
                [
                    "success" => false,
                    "error" => "Domain already exists"
                ]
            );

            exit;
        }

        $stmt =
            $pdo->prepare("
                INSERT INTO protected_domains
                (
                    domain,
                    active,
                    user_id
                )
                VALUES
                (
                    ?,
                    1,
                    ?
                )
            ");

        try {
            $stmt->execute([
                $domain,
                $userId
            ]);
        } catch (PDOException $error) {
            if ($error->getCode() === "23000") {
                http_response_code(409);
                echo json_encode([
                    "success" => false,
                    "error" => "Domain already exists"
                ]);
                exit;
            }
            throw $error;
        }

        echo json_encode(
            [
                "success" => true,

                "message" =>
                    "Domain added",

                "domain" => [
                    "id" =>
                        (int)$pdo->lastInsertId(),

                    "domain" =>
                        $domain,

                    "active" =>
                        true
                ]
            ],
            JSON_UNESCAPED_UNICODE
        );

        exit;
    }

    if ($method === "PUT") {

        $input =
            json_decode(
                file_get_contents(
                    "php://input"
                ),
                true
            );

        if (!is_array($input)) {

            http_response_code(
                400
            );

            echo json_encode(
                [
                    "success" => false,
                    "error" => "Invalid JSON"
                ]
            );

            exit;
        }

        $id =
            isset(
                $input["id"]
            )

                ? (int)$input["id"]

                : 0;

        $active =
            isset(
                $input["active"]
            )
            &&
            (
                $input["active"] === true ||
                $input["active"] === 1 ||
                $input["active"] === "1"
            );

        if ($id <= 0) {

            http_response_code(
                400
            );

            echo json_encode(
                [
                    "success" => false,
                    "error" => "Invalid domain ID"
                ]
            );

            exit;
        }

        $stmt =
            $pdo->prepare("
                UPDATE protected_domains
                SET active = ?
                WHERE id = ?
                AND user_id = ?
            ");

        $stmt->execute(
            [
                $active ? 1 : 0,
                $id,
                $userId
            ]
        );

        if (
            $stmt->rowCount() === 0
        ) {

            $check =
                $pdo->prepare("
                    SELECT id
                    FROM protected_domains
                    WHERE id = ?
                    AND user_id = ?
                ");

            $check->execute(
                [
                    $id,
                    $userId
                ]
            );

            if (!$check->fetch()) {

                http_response_code(
                    404
                );

                echo json_encode(
                    [
                        "success" => false,
                        "error" => "Domain not found"
                    ]
                );

                exit;
            }
        }

        echo json_encode(
            [
                "success" => true,

                "message" =>
                    "Domain status updated",

                "active" =>
                    $active
            ]
        );

        exit;
    }

    if ($method === "DELETE") {

        $id = 0;

        if (
            isset(
                $_GET["id"]
            )
        ) {

            $id =
                (int)$_GET["id"];

        } else {

            $input =
                json_decode(
                    file_get_contents(
                        "php://input"
                    ),
                    true
                );

            if (is_array($input)) {

                $id =
                    isset(
                        $input["id"]
                    )

                        ? (int)$input["id"]

                        : 0;
            }
        }

        if ($id <= 0) {

            http_response_code(
                400
            );

            echo json_encode(
                [
                    "success" => false,
                    "error" => "Invalid domain ID"
                ]
            );

            exit;
        }

        $stmt =
            $pdo->prepare("
                SELECT domain
                FROM protected_domains
                WHERE id = ?
                AND user_id = ?
            ");

        $stmt->execute(
            [
                $id,
                $userId
            ]
        );

        $domain =
            $stmt->fetch(
                PDO::FETCH_ASSOC
            );

        if (!$domain) {

            http_response_code(
                404
            );

            echo json_encode(
                [
                    "success" => false,
                    "error" => "Domain not found"
                ]
            );

            exit;
        }

        $stmt =
            $pdo->prepare("
                DELETE FROM protected_domains
                WHERE id = ?
                AND user_id = ?
            ");

        $stmt->execute(
            [
                $id,
                $userId
            ]
        );

        echo json_encode(
            [
                "success" => true,
                "message" => "Domain deleted"
            ]
        );

        exit;
    }

    http_response_code(
        405
    );

    echo json_encode(
        [
            "success" => false,
            "error" => "Method not allowed"
        ]
    );

} catch (Throwable $error) {

    http_response_code(
        500
    );

    echo json_encode(
        [
            "success" => false,
            "error" =>
                $error->getMessage()
        ],
        JSON_UNESCAPED_UNICODE
    );
}
