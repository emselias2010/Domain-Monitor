<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";

$user = require_auth();
$userId = (int)$user["id"];

try {
    if ($_SERVER["REQUEST_METHOD"] === "GET") {
        $stmt = $pdo->prepare("SELECT id, username, email, language, notifications_enabled, role, plan, pro_until, active, valid_until, created_at FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $account = $stmt->fetch(PDO::FETCH_ASSOC);
        $account["notifications_available"] = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'notifications_enabled'")->fetchColumn() === "1";
        $account["limits"] = plan_limits($account);
        $account["plan"] = $account["role"] === "admin" ? "admin" : (has_pro_access($account) ? "pro" : "free");
        if (!has_pro_access($account)) {
            $account["notifications_enabled"] = 0;
        }
        echo json_encode(["success" => true, "account" => $account]);
        exit;
    }

    if ($_SERVER["REQUEST_METHOD"] !== "PATCH") {
        http_response_code(405);
        echo json_encode(["success" => false, "error" => "Method not allowed"]);
        exit;
    }

    $input = json_decode(file_get_contents("php://input"), true);
    $fields = [];
    $values = [];
    $username = trim((string)($input["username"] ?? ""));
    $email = strtolower(trim((string)($input["email"] ?? "")));
    $language = (string)($input["language"] ?? "");
    $notificationsEnabled = null;
    if (array_key_exists("notifications_enabled", $input)) {
        if (!has_pro_access($user) && in_array($input["notifications_enabled"], [true, 1, "1"], true)) {
            http_response_code(403);
            echo json_encode(["success" => false, "error" => "Notifications are not available on the Free plan"]);
            exit;
        }
        $notificationsAvailable = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'notifications_enabled'")->fetchColumn() === "1";
        if (!$notificationsAvailable && in_array($input["notifications_enabled"], [true, 1, "1"], true)) {
            http_response_code(403);
            echo json_encode(["success" => false, "error" => "Notifications are not available"]);
            exit;
        }
        $notificationsEnabled = in_array($input["notifications_enabled"], [true, 1, "1"], true) ? 1 : 0;
    }
    if ($username !== "") {
        $fields[] = "username = ?";
        $values[] = $username;
    }
    if ($email !== "") {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(["success" => false, "error" => "Invalid email address"]);
            exit;
        }
        $fields[] = "email = ?";
        $values[] = $email;
    }
    if ($language !== "") {
        if (!in_array($language, ["de", "en"], true)) {
            http_response_code(400);
            echo json_encode(["success" => false, "error" => "Invalid language"]);
            exit;
        }
        $fields[] = "language = ?";
        $values[] = $language;
    }
    if ($notificationsEnabled !== null) {
        $fields[] = "notifications_enabled = ?";
        $values[] = $notificationsEnabled;
    }
    if (!empty($input["password"])) {
        if (!valid_password((string)$input["password"])) {
            http_response_code(400);
            echo json_encode(["success" => false, "error" => "Password must have 10 characters, letters and numbers"]);
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
    $values[] = $userId;
    $stmt = $pdo->prepare("UPDATE users SET " . implode(", ", $fields) . " WHERE id = ?");
    $stmt->execute($values);
    if ($username !== "") {
        $_SESSION["user"]["username"] = $username;
    }
    if ($email !== "") {
        $_SESSION["user"]["email"] = $email;
    }
    if ($language !== "") {
        $_SESSION["user"]["language"] = $language;
    }
    if ($notificationsEnabled !== null) {
        $_SESSION["user"]["notifications_enabled"] = (bool)$notificationsEnabled;
    }
    echo json_encode(["success" => true, "user" => $_SESSION["user"]]);
} catch (PDOException $error) {
    http_response_code($error->getCode() === "23000" ? 409 : 500);
    echo json_encode(["success" => false, "error" => $error->getCode() === "23000" ? "Username or email already exists" : "Account update failed"]);
}
