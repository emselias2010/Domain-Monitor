<?php

function current_user(): ?array
{
    return $_SESSION["user"] ?? null;
}

function require_auth(): array
{
    $user = current_user();

    if (!$user || !isset($user["id"])) {
        http_response_code(401);
        echo json_encode([
            "success" => false,
            "error" => "Authentication required"
        ]);
        exit;
    }

    global $pdo;
    $freshUser = user_response($pdo, (int)$user["id"]);
    if (!$freshUser) {
        session_unset();
        http_response_code(401);
        echo json_encode([
            "success" => false,
            "error" => "Authentication required"
        ]);
        exit;
    }

    $_SESSION["user"] = $freshUser;
    return $freshUser;
}

function require_admin(): array
{
    $user = require_auth();

    if (($user["role"] ?? "user") !== "admin") {
        http_response_code(403);
        echo json_encode([
            "success" => false,
            "error" => "Administrator access required"
        ]);
        exit;
    }

    return $user;
}

function plan_limits(array $user): array
{
    if (($user["role"] ?? "user") === "admin") {
        return ["max_domains" => PHP_INT_MAX, "max_protected_domains" => PHP_INT_MAX];
    }

    if (has_pro_access($user)) {
        return ["max_domains" => 1000000, "max_protected_domains" => 15];
    }

    return ["max_domains" => 50000, "max_protected_domains" => 2];
}

function has_pro_access(array $user): bool
{
    if (($user["role"] ?? "user") === "admin") {
        return true;
    }
    if (($user["plan"] ?? "free") !== "pro") {
        return false;
    }
    return empty($user["pro_until"]) || strtotime($user["pro_until"]) >= time();
}

function user_response(PDO $pdo, int $id): ?array
{
    $stmt = $pdo->prepare(
        "SELECT id, username, email, language, notifications_enabled, role, plan, pro_until, active, valid_until FROM users WHERE id = ?"
    );
    $stmt->execute([$id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (
        !$user ||
        !(bool)$user["active"] ||
        ($user["valid_until"] !== null && strtotime($user["valid_until"]) < time())
    ) {
        return null;
    }

    $user["id"] = (int)$user["id"];
    return $user;
}

function valid_password(string $password): bool
{
    return strlen($password) >= 10
        && preg_match('/[A-Za-z]/', $password)
        && preg_match('/\d/', $password);
}
