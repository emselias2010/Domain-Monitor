<?php

header(
    "Content-Type: application/json; charset=utf-8"
);

require_once "database.php";
require_once "auth.php";

if (PHP_SAPI === "cli") {
    $userId = 0;
    foreach ($argv ?? [] as $argumentIndex => $argument) {
        if ($argument === "--user-id" && isset($argv[$argumentIndex + 1])) {
            $userId = (int)$argv[$argumentIndex + 1];
            break;
        }
    }
    if ($userId <= 0) {
        fwrite(STDERR, "Missing or invalid --user-id\n");
        exit(1);
    }
} else {
    $currentUser = require_auth();
    $userId = (int)$currentUser["id"];
}

$projectPath = dirname(__DIR__);
$isWindows = PHP_OS_FAMILY === "Windows";
$pathSeparator = DIRECTORY_SEPARATOR;

$pythonCandidates = $isWindows
    ? [$projectPath . "\\venv\\Scripts\\python.exe"]
    : [
        $projectPath . "/venv/bin/python3",
        $projectPath . "/venv/bin/python",
        "/usr/bin/python3",
        "/usr/local/bin/python3"
    ];
$python = "";
foreach ($pythonCandidates as $candidate) {
    if (is_file($candidate) && is_executable($candidate)) {
        $python = $candidate;
        break;
    }
}
if ($python === "" && !$isWindows) {
    $python = trim((string)shell_exec("command -v python3 2>/dev/null"));
    if ($python === "") {
        $python = trim((string)shell_exec("command -v python 2>/dev/null"));
    }
}

$scanner = $projectPath . $pathSeparator . "scanner.py";
$jobsPath = $projectPath . $pathSeparator . "jobs";

try {

    if (!function_exists("exec")) {
        throw new RuntimeException("Der Server darf keine Hintergrundprozesse starten: PHP exec() ist deaktiviert");
    }

    $scanLock = $pdo->prepare("SELECT GET_LOCK(?, 0)");
    $scanLock->execute(["domain_monitor_scan_" . $userId]);
    if ((int)$scanLock->fetchColumn() !== 1) {
        http_response_code(409);
        echo json_encode([
            "success" => false,
            "error" => "A scan is already being started"
        ]);
        exit;
    }

    if ($python === "" || (!str_contains($python, "/") && !str_contains($python, "\\") && !is_executable($python))) {

        http_response_code(500);

        echo json_encode([
            "success" => false,
            "error" =>
                "Python executable not found"
        ]);

        exit;
    }

    if (!file_exists($scanner)) {

        http_response_code(500);

        echo json_encode([
            "success" => false,
            "error" =>
                "scanner.py not found"
        ]);

        exit;
    }

    $stmt = $pdo->prepare("SELECT id, pid, progress_file, status
        FROM user_scan_jobs
        WHERE user_id = ?
        AND status IN ('starting', 'running')
        ORDER BY id DESC
        LIMIT 1");

    $stmt->execute([$userId]);

    $runningScan =
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );

    if ($runningScan) {
        $progressStatus = "";
        $progressFile = (string)$runningScan["progress_file"];

        if (is_file($progressFile)) {
            $progressData = json_decode(
                (string)file_get_contents($progressFile),
                true
            );
            $progressStatus = is_array($progressData)
                ? (string)($progressData["status"] ?? "")
                : "";
        }

        $terminalStatus = in_array(
            $progressStatus,
            ["finished", "cancelled", "error"],
            true
        );
        $pid = (int)$runningScan["pid"];
        $processExists = false;

        if ($pid > 0 && $isWindows) {
            $taskOutput = [];
            $taskReturnCode = 0;
            exec("tasklist /FI \"PID eq " . $pid . "\" /FO CSV /NH", $taskOutput, $taskReturnCode);
            foreach ($taskOutput as $line) {
                if (strpos($line, '"' . $pid . '"') !== false) {
                    $processExists = true;
                    break;
                }
            }
        } elseif ($pid > 0) {
            $processCheckCode = 1;
            exec("kill -0 " . $pid . " 2>/dev/null", $unusedOutput, $processCheckCode);
            $processExists = $processCheckCode === 0;
        }

        if ($terminalStatus || !$processExists) {
            $recoveredStatus = $progressStatus === "finished"
                ? "finished"
                : ($progressStatus === "cancelled" ? "cancelled" : "error");
            $cleanup = $pdo->prepare(
                "UPDATE user_scan_jobs
                 SET status = ?, finished_at = COALESCE(finished_at, NOW())
                 WHERE id = ? AND user_id = ?"
            );
            $cleanup->execute([
                $recoveredStatus,
                (int)$runningScan["id"],
                $userId
            ]);
            $runningScan = null;
        }
    }

    if ($runningScan) {

        http_response_code(409);

        echo json_encode([
            "success" => false,
            "error" =>
                "A scan is already running",
            "job_id" =>
                (int)$runningScan["id"],
            "progress_file" =>
                $runningScan["progress_file"]
        ]);

        exit;
    }

    if (!is_dir($jobsPath)) {
        if (!mkdir($jobsPath, 0775, true) && !is_dir($jobsPath)) {
            throw new RuntimeException("Job-Verzeichnis kann nicht erstellt werden");
        }
    }

    $stmt = $pdo->prepare(
        "INSERT INTO user_scan_jobs
            (user_id, status, progress_file, log_file, started_at)
         VALUES (?, 'starting', '', '', NOW())"
    );
    $stmt->execute([$userId]);
    $jobId = (int)$pdo->lastInsertId();

    $jobPath = $jobsPath . $pathSeparator . "user_{$userId}_job_{$jobId}";
    if (!mkdir($jobPath, 0775, true) && !is_dir($jobPath)) {
        throw new RuntimeException("Scan-Verzeichnis kann nicht erstellt werden");
    }

    $logFile = $jobPath . $pathSeparator . "scan.log";
    $pidFile = $jobPath . $pathSeparator . "scanner.pid";
    $progressFile = $jobPath . $pathSeparator . "scan_progress.json";
    $progressTempFile = $jobPath . $pathSeparator . "scan_progress.tmp";

    $stmt = $pdo->prepare(
        "UPDATE user_scan_jobs
         SET progress_file = ?, log_file = ?
         WHERE id = ? AND user_id = ?"
    );
    $stmt->execute([$progressFile, $logFile, $jobId, $userId]);

    $startingProgress = [

        "status" =>
            "starting",

        "current" =>
            0,

        "total" =>
            0,

        "percentage" =>
            0,

        "domain" =>
            "",

        "message" =>
            "Starting scan...",

        "protected_current" =>
            0,

        "protected_total" =>
            0,

        "updated_at" =>
            date("c")
    ];

    $progressWritten = file_put_contents(
        $progressTempFile,
        json_encode(
            $startingProgress,
            JSON_PRETTY_PRINT
        ),
        LOCK_EX
    );
    if ($progressWritten === false || !rename($progressTempFile, $progressFile)) {
        throw new RuntimeException("Scanstatus kann nicht gespeichert werden");
    }

    $arguments =
        " -u " . escapeshellarg($scanner) .
        " --user-id " . $userId .
        " --job-id " . $jobId .
        " --progress-file " . escapeshellarg($progressFile) .
        " --pid-file " . escapeshellarg($pidFile) .
        " --log-file " . escapeshellarg($logFile);
    $returnCode = 0;
    if ($isWindows) {
        $command = "start /B \"\" " . escapeshellarg($python) . $arguments .
            " > " . escapeshellarg($logFile) . " 2>&1";
        $processPipe = popen($command, "r");
        if ($processPipe === false) {
            throw new RuntimeException("Scanner konnte auf dem Server nicht gestartet werden (popen fehlgeschlagen)");
        }
        pclose($processPipe);
    } else {
        $command = "cd " . escapeshellarg($projectPath) . " && nohup " . escapeshellarg($python) . $arguments .
            " > " . escapeshellarg($logFile) . " 2>&1 < /dev/null & echo $!";
        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);
    }

    if ($returnCode !== 0) {
        throw new RuntimeException("Scanner konnte auf dem Server nicht gestartet werden (Exit-Code {$returnCode})");
    }

    $detectedPid = null;

    $progressStatus = "starting";
    $progressMessage = "Starting scan...";
    for ($attempt = 0; $attempt < 100; $attempt++) {
        usleep(100000);

        if (file_exists($pidFile)) {
            $candidatePid = (int)trim(file_get_contents($pidFile));

            if ($candidatePid > 0) {
                $detectedPid = $candidatePid;
                break;
            }
        }

        if (is_file($progressFile)) {
            $progressData = json_decode((string)file_get_contents($progressFile), true);
            if (is_array($progressData)) {
                $progressStatus = (string)($progressData["status"] ?? $progressStatus);
                $progressMessage = (string)($progressData["message"] ?? $progressMessage);
            }
            if (in_array($progressStatus, ["finished", "cancelled", "error"], true)) {
                break;
            }
        }
    }

    if (!$detectedPid) {
        $stmt = $pdo->prepare(
            "UPDATE user_scan_jobs SET status = ?, finished_at = NOW()
             WHERE id = ? AND user_id = ?"
        );
        $jobStatus = $progressStatus === "finished" ? "finished" : "error";
        $stmt->execute([$jobStatus, $jobId, $userId]);
        if ($progressStatus === "finished") {
            echo json_encode([
                "success" => true,
                "message" => "Scan finished",
                "job_id" => $jobId
            ]);
            exit;
        }
        throw new RuntimeException($progressStatus === "error" && $progressMessage !== ""
            ? $progressMessage
            : "Scanner process did not start");
    }

    $stmt = $pdo->prepare(
        "UPDATE user_scan_jobs SET status = 'running', pid = ?
         WHERE id = ? AND user_id = ?"
    );
    $stmt->execute([$detectedPid, $jobId, $userId]);

    echo json_encode([
        "success" => true,
        "message" => "Scan started",
        "job_id" => $jobId,
        "pid" => $detectedPid
    ]);

} catch (Throwable $error) {

    http_response_code(500);

    echo json_encode([
        "success" => false,
        "error" =>
            $error->getMessage()
    ]);
}
