<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";

try {
    if ($_SERVER["REQUEST_METHOD"] === "GET") {
        $registrationEnabled = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'registration_enabled'")->fetchColumn() === "1";
        echo json_encode([
            "success" => true,
            "user" => current_user(),
            "registration_enabled" => $registrationEnabled
        ]);
        exit;
    }

    if ($_SERVER["REQUEST_METHOD"] !== "POST") {
        http_response_code(405);
        echo json_encode(["success" => false, "error" => "Method not allowed"]);
        exit;
    }

    $input = json_decode(file_get_contents("php://input"), true);
    $username = trim((string)($input["username"] ?? ""));
    $password = (string)($input["password"] ?? "");
    $ipAddress = substr((string)($_SERVER["REMOTE_ADDR"] ?? "unknown"), 0, 45);

    $pdo->prepare("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 15 MINUTE)")->execute();
    $attempts = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND attempted_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
    $attempts->execute([$ipAddress]);
    if ((int)$attempts->fetchColumn() >= 10) {
        http_response_code(429);
        echo json_encode(["success" => false, "error" => "Too many login attempts. Try again later."]);
        exit;
    }

    $stmt = $pdo->prepare(
        "SELECT id, username, email, language, password_hash, role, plan, pro_until, active, valid_until FROM users WHERE username = ? LIMIT 1"
    );
    $stmt->execute([$username]);
    $record = $stmt->fetch(PDO::FETCH_ASSOC);

    if (
        !$record ||
        !(bool)$record["active"] ||
        ($record["valid_until"] !== null && strtotime($record["valid_until"]) < time()) ||
        !password_verify($password, $record["password_hash"])
    ) {
        $recordAttempt = $pdo->prepare("INSERT INTO login_attempts (ip_address, attempted_at) VALUES (?, NOW())");
        $recordAttempt->execute([$ipAddress]);
        http_response_code(401);
        echo json_encode(["success" => false, "error" => "Invalid credentials"]);
        exit;
    }

    session_regenerate_id(true);
    $pdo->prepare("DELETE FROM login_attempts WHERE ip_address = ?")->execute([$ipAddress]);
    $_SESSION["user"] = [
        "id" => (int)$record["id"],
        "username" => $record["username"],
        "email" => $record["email"],
        "language" => $record["language"],
        "role" => $record["role"],
        "plan" => $record["plan"],
        "pro_until" => $record["pro_until"],
        "valid_until" => $record["valid_until"]
    ];

    echo json_encode([
        "success" => true,
        "user" => $_SESSION["user"]
    ]);

} catch (Throwable $error) {
    http_response_code(500);
    echo json_encode(["success" => false, "error" => "Login temporarily unavailable"]);
}
