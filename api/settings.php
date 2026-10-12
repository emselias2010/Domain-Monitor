<?php

header(
    "Content-Type: application/json; charset=utf-8"
);

require_once "database.php";
require_once "auth.php";

$currentUser = require_auth();
$userId = (int)$currentUser["id"];
$limits = plan_limits($currentUser);

date_default_timezone_set("Europe/Vienna");

$allowedTimezones = ["Europe/Vienna", "Europe/Berlin", "UTC"];

try {

    if (
        $_SERVER["REQUEST_METHOD"] === "GET"
    ) {

        $stmt = $pdo->query("
            SELECT
                id,
                enabled,
                interval_hours,
                next_scan,
                updated_at,
                timezone,
                pause_weekends,
                max_domains,
                threat_intelligence_enabled
            FROM scan_settings
            WHERE user_id = {$userId}
            ORDER BY id ASC
            LIMIT 1
        ");

        $settings =
            $stmt->fetch(
                PDO::FETCH_ASSOC
            );

        if (!$settings) {

            $stmt =
                $pdo->prepare("
                    INSERT INTO scan_settings
                    (
                        enabled,
                        interval_hours,
                        next_scan,
                        max_domains,
                        threat_intelligence_enabled,
                        user_id
                    )
                    VALUES
                    (
                        0,
                        24,
                        NULL,
                        50000,
                        0,
                        ?
                    )
                ");

            $stmt->execute([$userId]);

            $settings = [

                "id" =>
                    $pdo->lastInsertId(),

                "enabled" =>
                    0,

                "interval_hours" =>
                    24,

                "next_scan" =>
                    null,

                "updated_at" =>
                    date(
                        "Y-m-d H:i:s"
                    ),
                "timezone" => "Europe/Vienna",
                "pause_weekends" => 0,
                "max_domains" => 50000
                ,"threat_intelligence_enabled" => 0
            ];
        }

        $freePlan = !has_pro_access($currentUser);
        $effectiveMaxDomains = min((int)($settings["max_domains"] ?? 50000), $limits["max_domains"]);

        echo json_encode([

            "success" =>
                true,

            "settings" => [

                "id" =>
                    (int)$settings["id"],

                "enabled" =>
                    $freePlan ? false : (bool)$settings["enabled"],

                "interval_hours" =>
                    (int)$settings["interval_hours"],

                "next_scan" =>
                    $settings["next_scan"],

                "updated_at" =>
                    $settings["updated_at"],

                "timezone" =>
                    $settings["timezone"] ?? "Europe/Vienna",

                "pause_weekends" =>
                    (bool)($settings["pause_weekends"] ?? false),

                "max_domains" =>
                    $effectiveMaxDomains,

                "threat_intelligence_enabled" =>
                    (bool)($settings["threat_intelligence_enabled"] ?? false)

                ,"plan" => $currentUser["role"] === "admin" ? "admin" : (has_pro_access($currentUser) ? "pro" : "free")

                ,"limits" => $limits

            ]

        ]);

        exit;
    }

    if (
        $_SERVER["REQUEST_METHOD"] === "POST"
    ) {

        $input =
            json_decode(
                file_get_contents(
                    "php://input"
                ),
                true
            );

        if (!is_array($input)) {

            http_response_code(400);

            echo json_encode([

                "success" =>
                    false,

                "error" =>
                    "Invalid JSON"

            ]);

            exit;
        }

        $enabled = (

            isset(
                $input["enabled"]
            )

            &&

            (
                $input["enabled"] === true

                ||

                $input["enabled"] === 1

                ||

                $input["enabled"] === "1"
            )

        );
        if (!has_pro_access($currentUser)) {
            $enabled = false;
        }

        $intervalHours =
            isset(
                $input["interval_hours"]
            )

            ? (int)$input[
                "interval_hours"
            ]

            : 24;

        $timezone = (string)($input["timezone"] ?? "Europe/Vienna");
        if (!in_array($timezone, $allowedTimezones, true)) {
            $timezone = "Europe/Vienna";
        }
        $pauseWeekends = in_array($input["pause_weekends"] ?? false, [true, 1, "1"], true);
        $maxDomains = (int)($input["max_domains"] ?? min(50000, $limits["max_domains"]));
        $threatIntelligenceEnabled = in_array($input["threat_intelligence_enabled"] ?? false, [true, 1, "1"], true);
        if ($maxDomains < 1000 || $maxDomains > $limits["max_domains"]) {
            http_response_code(400);
            echo json_encode(["success" => false, "error" => "Your plan allows up to " . $limits["max_domains"] . " generated domains"]);
            exit;
        }

        $allowedIntervals = [

            1,
            6,
            12,
            24,
            48,
            168

        ];

        if (
            !in_array(
                $intervalHours,
                $allowedIntervals,
                true
            )
        ) {

            http_response_code(400);

            echo json_encode([

                "success" =>
                    false,

                "error" =>
                    "Invalid scan interval"

            ]);

            exit;
        }

        date_default_timezone_set($timezone);

        $nextScan = null;

        if ($enabled) {

            $nextScan =
                date(
                    "Y-m-d H:i:s",
                    time()
                    +
                    (
                        $intervalHours
                        * 3600
                    )
                );
        }

        $stmt =
            $pdo->query("
                SELECT id
                FROM scan_settings
                WHERE user_id = {$userId}
                ORDER BY id ASC
                LIMIT 1
            ");

        $existing =
            $stmt->fetch(
                PDO::FETCH_ASSOC
            );

        if ($existing) {

            $stmt =
                $pdo->prepare("
                    UPDATE scan_settings

                    SET

                        enabled = ?,

                        interval_hours = ?,

                        timezone = ?,

                        pause_weekends = ?,

                        max_domains = ?,

                        threat_intelligence_enabled = ?,

                        next_scan = ?,

                        updated_at = NOW()

                    WHERE id = ?
                    AND user_id = ?
                ");

            $stmt->execute([

                $enabled
                    ? 1
                    : 0,

                $intervalHours,

                $timezone,

                $pauseWeekends ? 1 : 0,

                $maxDomains,

                $threatIntelligenceEnabled ? 1 : 0,

                $nextScan,

                $existing["id"],
                $userId

            ]);

        }

        else {

            $stmt =
                $pdo->prepare("
                    INSERT INTO scan_settings
                    (
                        enabled,
                        interval_hours,
                        timezone,
                        pause_weekends,
                        max_domains,
                        threat_intelligence_enabled,
                        next_scan,
                        user_id
                    )
                    VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?)
                ");

            $stmt->execute([

                $enabled
                    ? 1
                    : 0,

                $intervalHours,

                $timezone,

                $pauseWeekends ? 1 : 0,

                $maxDomains,

                $threatIntelligenceEnabled ? 1 : 0,

                $nextScan,
                $userId

            ]);
        }

        echo json_encode([

            "success" =>
                true,

            "message" =>
                "Settings saved",

            "settings" => [

                "enabled" =>
                    $enabled,

                "interval_hours" =>
                    $intervalHours,

                "timezone" => $timezone,

                "pause_weekends" => $pauseWeekends,

                "max_domains" => $maxDomains,

                "threat_intelligence_enabled" => $threatIntelligenceEnabled,

                "plan" => $currentUser["role"] === "admin" ? "admin" : ($currentUser["plan"] ?? "free"),

                "limits" => $limits,

                "next_scan" =>
                    $nextScan

            ]

        ]);

        exit;
    }

    http_response_code(405);

    echo json_encode([

        "success" =>
            false,

        "error" =>
            "Method not allowed"

    ]);

} catch (Throwable $e) {

    http_response_code(500);

    echo json_encode([

        "success" =>
            false,

        "error" =>
            $e->getMessage()

    ]);

}
