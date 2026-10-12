<?php

header("Content-Type: application/json; charset=utf-8");
require_once "database.php";
require_once "auth.php";

require_admin();

try {
    if ($_SERVER["REQUEST_METHOD"] === "GET") {
        $stmt = $pdo->query("SELECT setting_key, setting_value FROM app_settings WHERE setting_key IN ('smtp_host', 'smtp_port', 'smtp_user', 'smtp_from', 'smtp_tls')");
        $settings = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $item) {
            $settings[$item["setting_key"]] = $item["setting_value"];
        }
        echo json_encode(["success" => true, "settings" => [
            "host" => $settings["smtp_host"] ?? "",
            "port" => (int)($settings["smtp_port"] ?? 587),
            "user" => $settings["smtp_user"] ?? "",
            "from" => $settings["smtp_from"] ?? "",
            "tls" => ($settings["smtp_tls"] ?? "1") === "1",
            "password_configured" => ($settings["smtp_password"] ?? "") !== ""
        ]]);
        exit;
    }

    if ($_SERVER["REQUEST_METHOD"] !== "POST") {
        http_response_code(405);
        echo json_encode(["success" => false, "error" => "Method not allowed"]);
        exit;
    }

    $input = json_decode(file_get_contents("php://input"), true);
    if (!is_array($input)) {
        http_response_code(400);
        echo json_encode(["success" => false, "error" => "Invalid JSON"]);
        exit;
    }

    $host = trim((string)($input["host"] ?? ""));
    $port = (int)($input["port"] ?? 587);
    $user = trim((string)($input["user"] ?? ""));
    $from = trim((string)($input["from"] ?? ""));
    $tls = in_array($input["tls"] ?? true, [true, 1, "1"], true) ? "1" : "0";
    if ($port < 1 || $port > 65535 || ($from !== "" && !filter_var($from, FILTER_VALIDATE_EMAIL))) {
        http_response_code(400);
        echo json_encode(["success" => false, "error" => "Invalid mail settings"]);
        exit;
    }

    $values = ["smtp_host" => $host, "smtp_port" => (string)$port, "smtp_user" => $user, "smtp_from" => $from, "smtp_tls" => $tls];
    if (array_key_exists("password", $input) && (string)$input["password"] !== "") {
        $values["smtp_password"] = (string)$input["password"];
    }
    $stmt = $pdo->prepare("INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)");
    foreach ($values as $key => $value) {
        $stmt->execute([$key, $value]);
    }
    echo json_encode(["success" => true]);
} catch (Throwable $error) {
    http_response_code(500);
    echo json_encode(["success" => false, "error" => "Mail settings unavailable"]);
}
