<?php

ini_set("display_errors", "0");
set_time_limit(0);
ignore_user_abort(true);
header("Content-Type: application/json; charset=utf-8");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("X-Accel-Buffering: no");

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["success" => false, "error" => "Method not allowed"]);
    exit;
}

function guest_domain(string $value): string
{
    $value = strtolower(trim($value));
    $value = preg_replace("#^https?://#i", "", $value);
    $value = explode("/", $value)[0];
    $value = explode(":", $value)[0];
    return rtrim($value, ".");
}

function guest_is_valid_domain(string $domain): bool
{
    return strlen($domain) <= 253 && preg_match(
        '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i',
        $domain
    ) === 1;
}

function guest_has_dns(string $domain): bool
{
    $records = @dns_get_record($domain, DNS_A | DNS_AAAA);
    return is_array($records) && count($records) > 0;
}

function guest_candidates(string $domain, int $limit): array
{
    $parts = explode(".", $domain);
    $name = array_shift($parts);
    $suffix = implode(".", $parts);
    $words = ["login", "secure", "account", "support", "service", "online", "verify", "portal", "mail", "admin", "help", "auth", "billing", "alert", "update", "official", "team", "cloud", "app", "check", "access"];
    $candidates = [];
    foreach ($words as $word) {
        foreach (["{$name}-{$word}.{$suffix}", "{$word}-{$name}.{$suffix}", "{$name}.{$word}.{$suffix}"] as $candidate) {
            $candidates[$candidate] = true;
            if (count($candidates) >= $limit) {
                return array_keys($candidates);
            }
        }
    }
    for ($index = 1; count($candidates) < $limit; $index++) {
        $candidates[$name . "-" . $index . "." . $suffix] = true;
    }
    return array_keys($candidates);
}

try {
    $guestMaxDomains = 15000;
    $input = json_decode(file_get_contents("php://input"), true);
    $domain = guest_domain((string)($input["domain"] ?? ""));
    if (!guest_is_valid_domain($domain)) {
        http_response_code(400);
        echo json_encode(["success" => false, "error" => "Please enter a valid domain"]);
        exit;
    }

    $worker = dirname(__DIR__) . DIRECTORY_SEPARATOR . "guest_scan_worker.py";
    $pythonCandidates = PHP_OS_FAMILY === "Windows"
        ? [dirname(__DIR__) . "\\venv\\Scripts\\python.exe", "py", "python"]
        : [dirname(__DIR__) . "/venv/bin/python3", dirname(__DIR__) . "/venv/bin/python", "python3", "python"];
    $python = "";
    foreach ($pythonCandidates as $candidate) {
        $isPath = str_contains($candidate, "/") || str_contains($candidate, "\\");
        $commandLookup = PHP_OS_FAMILY === "Windows"
            ? "where.exe " . escapeshellarg($candidate) . " 2>NUL"
            : "command -v " . escapeshellarg($candidate) . " 2>/dev/null";
        if (($isPath && is_file($candidate)) || (!$isPath && trim((string)shell_exec($commandLookup)) !== "")) {
            $python = $candidate;
            break;
        }
    }
    if (!is_file($worker) || $python === "") {
        throw new RuntimeException("Guest scanner unavailable");
    }
    header("Content-Type: application/x-ndjson; charset=utf-8");
    $command = [$python, "-u", $worker, $domain];
    $descriptors = [1 => ["pipe", "w"], 2 => ["pipe", "w"]];
    $process = proc_open($command, $descriptors, $pipes, dirname(__DIR__), null, ["bypass_shell" => true]);
    if (!is_resource($process)) {
        throw new RuntimeException("Guest scan failed");
    }
    while (($line = fgets($pipes[1])) !== false) {
        $event = json_decode(trim($line), true);
        if (!is_array($event)) {
            continue;
        }
        $event["domain"] = $domain;
        $event["scanned_at"] = gmdate("c");
        $event["max_domains"] = $guestMaxDomains;
        echo json_encode($event, JSON_UNESCAPED_SLASHES) . "\n";
        if (function_exists("ob_flush")) {
            @ob_flush();
        }
        flush();
    }
    fclose($pipes[1]);
    $errorOutput = trim((string)stream_get_contents($pipes[2]));
    fclose($pipes[2]);
    $returnCode = proc_close($process);
    if ($returnCode !== 0) {
        throw new RuntimeException($errorOutput !== "" ? $errorOutput : "Guest scan failed");
    }
} catch (Throwable $error) {
    if (!headers_sent()) {
        header("Content-Type: application/json; charset=utf-8");
    }
    http_response_code(500);
    if (headers_sent()) {
        echo json_encode(["type" => "error", "message" => "Guest scan unavailable"]) . "\n";
    } else {
        echo json_encode(["success" => false, "error" => "Guest scan unavailable"]);
    }
}
