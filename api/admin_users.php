<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";

$user = require_admin();

try {
    if ($_SERVER["REQUEST_METHOD"] === "GET") {
        $registrationEnabled = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'registration_enabled'")->fetchColumn() === "1";
        $notificationsEnabled = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'notifications_enabled'")->fetchColumn() === "1";
        $stmt = $pdo->query(
            "SELECT u.id, u.username, u.email, u.role, u.plan, u.pro_until, u.active, u.valid_until, u.created_at,
                    COUNT(DISTINCT s.id) AS scan_count,
                    MAX(s.started_at) AS last_scan,
                    SUM(CASE WHEN s.finished_at IS NULL THEN 1 ELSE 0 END) AS running_scans
             FROM users u
             LEFT JOIN scans s ON s.user_id = u.id
             GROUP BY u.id, u.username, u.email, u.role, u.plan, u.pro_until, u.active, u.valid_until, u.created_at
             ORDER BY u.id ASC"
        );
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($users as &$item) {
            $item["id"] = (int)$item["id"];
            $item["active"] = (bool)$item["active"];
            $item["scan_count"] = (int)$item["scan_count"];
            $item["running_scans"] = (int)$item["running_scans"];
        }
        unset($item);
        echo json_encode(["success" => true, "users" => $users, "registration_enabled" => $registrationEnabled, "notifications_enabled" => $notificationsEnabled, "language" => $user["language"] ?? "de"]);
        exit;
    }

    if ($_SERVER["REQUEST_METHOD"] === "DELETE") {
        $input = json_decode(file_get_contents("php://input"), true);
        $userId = (int)($input["id"] ?? $_GET["id"] ?? 0);

        if ($userId <= 0 || $userId === (int)$user["id"]) {
            http_response_code(400);
            echo json_encode(["success" => false, "error" => "Invalid user or self-deletion is not allowed"]);
            exit;
        }

        $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ? LIMIT 1");
        $stmt->execute([$userId]);
        if (!$stmt->fetch()) {
            http_response_code(404);
            echo json_encode(["success" => false, "error" => "User not found"]);
            exit;
        }

        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        echo json_encode(["success" => true]);
        exit;
    }

    if ($_SERVER["REQUEST_METHOD"] === "POST") {
        $input = json_decode(file_get_contents("php://input"), true);
        $username = trim((string)($input["username"] ?? ""));
        $password = (string)($input["password"] ?? "");
        $role = ($input["role"] ?? "user") === "admin" ? "admin" : "user";
        $plan = ($input["plan"] ?? "free") === "pro" ? "pro" : "free";
        $proUntil = trim((string)($input["pro_until"] ?? ""));
        $proUntil = $proUntil === "" ? null : $proUntil . " 23:59:59";
        $validUntil = trim((string)($input["valid_until"] ?? ""));
        $validUntil = $validUntil === "" ? null : $validUntil . " 23:59:59";

        if ($username === "" || strlen($password) < 10) {
            http_response_code(400);
            echo json_encode([
                "success" => false,
                "error" => "Username required and password must have at least 10 characters"
            ]);
            exit;
        }

        $stmt = $pdo->prepare(
            "INSERT INTO users (username, password_hash, role, plan, pro_until, valid_until) VALUES (?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([$username, password_hash($password, PASSWORD_DEFAULT), $role, $plan, $plan === "pro" ? $proUntil : null, $validUntil]);

        echo json_encode([
            "success" => true,
            "user_id" => (int)$pdo->lastInsertId()
        ]);
        exit;
    }

    if ($_SERVER["REQUEST_METHOD"] === "PATCH") {
        $input = json_decode(file_get_contents("php://input"), true);
        if (array_key_exists("registration_enabled", $input)) {
            $stmt = $pdo->prepare("UPDATE app_settings SET setting_value = ? WHERE setting_key = 'registration_enabled'");
            $stmt->execute([$input["registration_enabled"] ? "1" : "0"]);
            echo json_encode(["success" => true]);
            exit;
        }
        if (array_key_exists("notifications_enabled", $input)) {
            $notificationsEnabled = in_array($input["notifications_enabled"], [true, 1, "1"], true);
            $pdo->beginTransaction();
            try {
                $stmt = $pdo->prepare("UPDATE app_settings SET setting_value = ? WHERE setting_key = 'notifications_enabled'");
                $stmt->execute([$notificationsEnabled ? "1" : "0"]);
                if (!$notificationsEnabled) {
                    $pdo->exec("UPDATE users SET notifications_enabled = 0");
                }
                $pdo->commit();
            } catch (Throwable $error) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $error;
            }
            echo json_encode(["success" => true]);
            exit;
        }
        $targetId = (int)($input["id"] ?? 0);
        if ($targetId <= 0) {
            http_response_code(400);
            echo json_encode(["success" => false, "error" => "Invalid user ID"]);
            exit;
        }

        $fields = [];
        $values = [];
        if (array_key_exists("active", $input)) {
            $fields[] = "active = ?";
            $values[] = in_array($input["active"], [true, 1, "1"], true) ? 1 : 0;
        }
        if (array_key_exists("role", $input)) {
            $fields[] = "role = ?";
            $values[] = $input["role"] === "admin" ? "admin" : "user";
        }
        if (array_key_exists("plan", $input)) {
            $fields[] = "plan = ?";
            $values[] = $input["plan"] === "pro" ? "pro" : "free";
        }
        if (array_key_exists("pro_until", $input)) {
            $proUntil = trim((string)$input["pro_until"]);
            $fields[] = "pro_until = ?";
            $values[] = $proUntil === "" ? null : $proUntil . " 23:59:59";
        } elseif (array_key_exists("plan", $input) && $input["plan"] !== "pro") {
            $fields[] = "pro_until = NULL";
        }
        if (array_key_exists("valid_until", $input)) {
            $validUntil = trim((string)$input["valid_until"]);
            $fields[] = "valid_until = ?";
            $values[] = $validUntil === "" ? null : $validUntil . " 23:59:59";
        }
        if (!empty($input["password"])) {
            if (strlen((string)$input["password"]) < 10) {
                http_response_code(400);
                echo json_encode(["success" => false, "error" => "Password must have at least 10 characters"]);
                exit;
            }
            $fields[] = "password_hash = ?";
            $values[] = password_hash((string)$input["password"], PASSWORD_DEFAULT);
        }
        if (!$fields) {
            http_response_code(400);
            echo json_encode(["success" => false, "error" => "No changes supplied"]);
            exit;
        }
        $values[] = $targetId;
        $stmt = $pdo->prepare("UPDATE users SET " . implode(", ", $fields) . " WHERE id = ?");
        $stmt->execute($values);
        echo json_encode(["success" => true]);
        exit;
    }

    http_response_code(405);
    echo json_encode(["success" => false, "error" => "Method not allowed"]);

} catch (PDOException $error) {
    http_response_code($error->getCode() === "23000" ? 409 : 500);
    echo json_encode([
        "success" => false,
        "error" => $error->getCode() === "23000" ? "Username already exists" : $error->getMessage()
    ]);
}
