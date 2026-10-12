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

    $stmt = $pdo->query(
        "
        SELECT

            d.id,

            d.protected_domain_id,

            d.domain,

            d.first_seen,

            d.last_seen,

            d.dns_active,

            d.website_active,

            d.http_status,

            d.title,

            d.risk_score,

            d.domain_for_sale,

            d.final_url,

            d.redirected_to_protected,

            d.login_found,

            d.company_name_found,

            d.company_name_header,

            d.registration_date,

            d.registrar,

            (
                SELECT ti.status
                FROM threat_intelligence ti
                WHERE ti.domain_id = d.id
                ORDER BY CASE ti.status WHEN 'REPORTED' THEN 0 WHEN 'UNKNOWN' THEN 1 ELSE 2 END, ti.checked_at DESC
                LIMIT 1
            ) AS threat_status,

            (
                SELECT ti.source
                FROM threat_intelligence ti
                WHERE ti.domain_id = d.id
                ORDER BY CASE ti.status WHEN 'REPORTED' THEN 0 WHEN 'UNKNOWN' THEN 1 ELSE 2 END, ti.checked_at DESC
                LIMIT 1
            ) AS threat_source,

            (
                SELECT ti.detections
                FROM threat_intelligence ti
                WHERE ti.domain_id = d.id
                ORDER BY CASE ti.status WHEN 'REPORTED' THEN 0 WHEN 'UNKNOWN' THEN 1 ELSE 2 END, ti.checked_at DESC
                LIMIT 1
            ) AS threat_detections,

            (
                SELECT ti.reference_url
                FROM threat_intelligence ti
                WHERE ti.domain_id = d.id
                ORDER BY CASE ti.status WHEN 'REPORTED' THEN 0 WHEN 'UNKNOWN' THEN 1 ELSE 2 END, ti.checked_at DESC
                LIMIT 1
            ) AS threat_reference_url,

            (
                SELECT ti.checked_at
                FROM threat_intelligence ti
                WHERE ti.domain_id = d.id
                ORDER BY CASE ti.status WHEN 'REPORTED' THEN 0 WHEN 'UNKNOWN' THEN 1 ELSE 2 END, ti.checked_at DESC
                LIMIT 1
            ) AS threat_checked_at

        FROM domains d

        WHERE d.user_id = {$userId}
                AND NOT EXISTS (
                        SELECT 1
                        FROM muted_domains m
                        WHERE m.domain_id = d.id
                            AND m.user_id = d.user_id
                )
        AND NOT EXISTS (
            SELECT 1
            FROM excluded_domains e
            WHERE LOWER(d.domain) = LOWER(e.domain)
               OR LOWER(d.domain) LIKE CONCAT('%.', LOWER(e.domain))
        )

        ORDER BY
            d.risk_score DESC,
            d.last_seen DESC
        "
    );

    $domains =
        $stmt->fetchAll(
            PDO::FETCH_ASSOC
        );

    $historyStmt = $pdo->prepare(
        "SELECT sr.domain_id, sr.scan_id, s.protected_domain_id,
            sr.dns_active, sr.website_active, sr.http_status, sr.risk_score,
            sr.ips_snapshot,
            s.finished_at
         FROM scan_results sr
         JOIN scans s ON s.id = sr.scan_id
         WHERE s.user_id = ? AND s.finished_at IS NOT NULL
         ORDER BY sr.domain_id ASC, s.finished_at DESC, sr.id DESC"
    );
    $historyStmt->execute([$userId]);
    $domainHistory = [];
    $latestScanByProtectedDomain = [];
    foreach ($historyStmt->fetchAll(PDO::FETCH_ASSOC) as $historyRow) {
        $protectedDomainId = (int)$historyRow["protected_domain_id"];
        if (!isset($latestScanByProtectedDomain[$protectedDomainId])) {
            $latestScanByProtectedDomain[$protectedDomainId] = (int)$historyRow["scan_id"];
        }
        $domainId = (int)$historyRow["domain_id"];
        if (!isset($domainHistory[$domainId])) {
            $domainHistory[$domainId] = [];
        }
        if (count($domainHistory[$domainId]) < 2) {
            $domainHistory[$domainId][] = $historyRow;
        }
    }

    $threatStmt = $pdo->prepare(
        "SELECT ti.domain_id, ti.source, ti.status, ti.category, ti.detections,
                ti.reference_url, ti.checked_at
         FROM threat_intelligence ti
         JOIN domains d ON d.id = ti.domain_id
         WHERE d.user_id = ?
         ORDER BY ti.domain_id ASC, ti.checked_at DESC"
    );
    $threatStmt->execute([$userId]);
    $threatByDomain = [];
    foreach ($threatStmt->fetchAll(PDO::FETCH_ASSOC) as $threatRow) {
        $threatByDomain[(int)$threatRow["domain_id"]][] = [
            "source" => $threatRow["source"],
            "status" => strtoupper((string)$threatRow["status"]),
            "category" => $threatRow["category"],
            "detections" => (int)$threatRow["detections"],
            "reference_url" => $threatRow["reference_url"],
            "checked_at" => $threatRow["checked_at"]
        ];
    }

    foreach ($domains as &$domain) {

        $history = $domainHistory[(int)$domain["id"]] ?? [];
        $isLatestCompletedScan = $history
            && (int)$history[0]["scan_id"] === $latestScanByProtectedDomain[(int)$domain["protected_domain_id"]];
        $domain["change_type"] = $isLatestCompletedScan && count($history) === 1 ? "new" : null;
        $domain["changes"] = [];
        if ($isLatestCompletedScan && count($history) >= 2) {
            $currentFinding = $history[0];
            $previousFinding = $history[1];
            $comparisonFields = [
                "risk_score" => "Risk score",
                "dns_active" => "DNS status",
                "website_active" => "Website status",
                "http_status" => "HTTP status",
                "ips_snapshot" => "IP addresses"
            ];
            foreach ($comparisonFields as $field => $label) {
                if ($field === "ips_snapshot") {
                    $currentValue = json_decode((string)$currentFinding[$field], true) ?: [];
                    $previousValue = json_decode((string)$previousFinding[$field], true) ?: [];
                    sort($currentValue);
                    sort($previousValue);
                } else {
                    $currentValue = $currentFinding[$field] === null ? null : (int)$currentFinding[$field];
                    $previousValue = $previousFinding[$field] === null ? null : (int)$previousFinding[$field];
                }
                if ($currentValue !== $previousValue) {
                    $domain["changes"][] = [
                        "field" => $field,
                        "label" => $label,
                        "before" => $previousValue,
                        "after" => $currentValue
                    ];
                }
            }
            if ($domain["changes"]) {
                $changedFields = array_column($domain["changes"], "field");
                $domain["change_type"] = in_array("website_active", $changedFields, true)
                    ? "website_changed"
                    : (in_array("ips_snapshot", $changedFields, true) ? "ip_changed" : "changed");
            }
        }

        $domainThreats = $threatByDomain[(int)$domain["id"]] ?? [];
        $domain["threat_sources"] = $domainThreats;
        $domain["threat_source"] = implode(", ", array_column($domainThreats, "source"));
        $domain["threat_detections"] = array_sum(array_column($domainThreats, "detections"));

        $score =
            (int)$domain[
                "risk_score"
            ];

        if ($score >= 80) {

            $riskLevel =
                "CRITICAL";

        } elseif ($score >= 60) {

            $riskLevel =
                "HIGH";

        } elseif ($score >= 30) {

            $riskLevel =
                "MEDIUM";

        } else {

            $riskLevel =
                "LOW";
        }

        $domain[
            "id"
        ] =
            (int)$domain[
                "id"
            ];

        $domain[
            "protected_domain_id"
        ] =
            (int)$domain[
                "protected_domain_id"
            ];

        $domain[
            "risk_score"
        ] =
            $score;

        $domain[
            "risk_level"
        ] =
            $riskLevel;

        $domain[
            "dns_active"
        ] =
            (bool)$domain[
                "dns_active"
            ];

        $domain[
            "website_active"
        ] =
            (bool)$domain[
                "website_active"
            ];

        $domain[
            "redirected_to_protected"
        ] =
            (bool)$domain[
                "redirected_to_protected"
            ];

        $domain[
            "login_found"
        ] =
            (bool)$domain[
                "login_found"
            ];

        $domain[
            "company_name_found"
        ] =
            (bool)$domain[
                "company_name_found"
            ];

        $domain[
            "company_name_header"
        ] =
            (bool)$domain[
                "company_name_header"
            ];

        if (
            $domain[
                "http_status"
            ] !== null
        ) {

            $domain[
                "http_status"
            ] =
                (int)$domain[
                    "http_status"
                ];

        } else {

            $domain[
                "http_status"
            ] = null;

        }

        $domain[
            "registration_date"
        ] =
            $domain[
                "registration_date"
            ];

        $domain[
            "registrar"
        ] =
            $domain[
                "registrar"
            ];

    }

    unset(
        $domain
    );

    $ipStmt =
        $pdo->query(
            "
            SELECT
                domain_id,
                ip_address
            FROM domain_ips
            ORDER BY domain_id ASC
            "
        );

    $ipRows =
        $ipStmt->fetchAll(
            PDO::FETCH_ASSOC
        );

    $ipsByDomain = [];

    foreach ($ipRows as $row) {

        $domainId =
            (int)$row[
                "domain_id"
            ];

        if (
            !isset(
                $ipsByDomain[
                    $domainId
                ]
            )
        ) {

            $ipsByDomain[
                $domainId
            ] = [];

        }

        $ipsByDomain[
            $domainId
        ][] =
            $row[
                "ip_address"
            ];

    }

    foreach ($domains as &$domain) {

        $id =
            (int)$domain[
                "id"
            ];

        $domain[
            "ips"
        ] =
            $ipsByDomain[
                $id
            ]
            ?? [];

    }

    unset(
        $domain
    );

    echo json_encode(
        [
            "success" => true,
            "domains" => $domains
        ],
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
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
