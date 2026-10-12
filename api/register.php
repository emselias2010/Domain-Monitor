<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["success" => false, "error" => "Method not allowed"]);
    exit;
}

try {
    $setting = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'registration_enabled'")->fetchColumn();
    if ($setting !== "1") {
        http_response_code(403);
        echo json_encode(["success" => false, "error" => "Registration is currently disabled"]);
        exit;
    }

    $input = json_decode(file_get_contents("php://input"), true);
    $username = trim((string)($input["username"] ?? ""));
    $email = strtolower(trim((string)($input["email"] ?? "")));
    $password = (string)($input["password"] ?? "");
    $requestedPlan = ($input["plan"] ?? "free") === "pro" ? "pro" : "free";

    if (!preg_match('/^[A-Za-z0-9_.-]{3,120}$/', $username)) {
        http_response_code(400);
        echo json_encode(["success" => false, "error" => "Invalid username"]);
        exit;
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
        http_response_code(400);
        echo json_encode(["success" => false, "error" => "Invalid email address"]);
        exit;
    }
    if (!valid_password($password)) {
        http_response_code(400);
        echo json_encode(["success" => false, "error" => "Password must have 10 characters, letters and numbers"]);
        exit;
    }

    $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash, role, plan, pro_until) VALUES (?, ?, ?, 'user', ?, ?)");
    $stmt->execute([$username, $email, password_hash($password, PASSWORD_DEFAULT), $requestedPlan, $requestedPlan === "pro" ? date("Y-m-d H:i:s", time() + 14 * 86400) : null]);
    session_regenerate_id(true);
    $_SESSION["user"] = user_response($pdo, (int)$pdo->lastInsertId());
    echo json_encode(["success" => true, "user" => $_SESSION["user"]]);
} catch (PDOException $error) {
    http_response_code($error->getCode() === "23000" ? 409 : 500);
    echo json_encode(["success" => false, "error" => $error->getCode() === "23000" ? "Username or email already exists" : "Registration failed"]);
}
