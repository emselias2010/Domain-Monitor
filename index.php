<?php

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

require_once __DIR__ . "/api/database.php";
require_once __DIR__ . "/api/auth.php";
$pageUser = current_user();
$registrationEnabled = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'registration_enabled'")->fetchColumn() === "1";
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Monitor</title>
    <link rel="stylesheet" href="css/style.css?v=<?php echo rawurlencode((string)filemtime(__DIR__ . '/css/style.css')); ?>">
    <link rel="stylesheet" href="css/mobile-overrides.css?v=<?php echo rawurlencode((string)filemtime(__DIR__ . '/css/mobile-overrides.css')); ?>">
</head>
<body>
<section id="guest-screen" class="guest-screen">
    <nav class="guest-nav"><span class="brand-wordmark brand-logo-guest">Domain Monitor</span><button type="button" class="guest-login-button" data-open-auth data-guest-i18n="login">Einloggen</button></nav>
    <main class="guest-main">
        <section class="guest-hero">
            <div class="guest-hero-copy">
                <p class="guest-kicker" data-guest-i18n="kicker">IT-SICHERHEIT / DOMAIN MONITORING</p>
                <h1 data-guest-i18n="headline">Schützen Sie, was wirklich zählt.</h1>
                <p data-guest-i18n="intro">Prüfen Sie jetzt kostenlos, ob Lookalike-Domains Ihre Marke imitieren. Der Gastscan bleibt privat und wird nach dem Aktualisieren gelöscht.</p>
                <form id="guest-scan-form" class="guest-scan-form">
                    <label for="guest-domain" data-guest-i18n="domainLabel">Ihre Domain</label>
                    <small class="guest-scan-scope" data-guest-i18n="scanScope">Demo-Scan: verkürzter Schnellcheck mit bis zu 15.000 Kandidaten. Nicht alle Funktionen des echten Scans sind enthalten; die Ergebnisse können ungenau sein.</small>
                    <div><input id="guest-domain" type="text" placeholder="ihre-firma.at" data-guest-placeholder="domainPlaceholder" autocomplete="url" required><button type="submit" data-guest-i18n="scan">Scan starten</button></div>
                    <div class="guest-progress" id="guest-progress" hidden><div class="guest-progress-bar"><span id="guest-progress-fill"></span></div><small id="guest-progress-label">0 / 15.000</small></div>
                    <div class="guest-phase-list" id="guest-phase-list" hidden><span data-phase="candidates">1 <b data-phase-label="phaseCandidates">Kandidaten</b></span><span data-phase="dns">2 <b data-phase-label="phaseDns">DNS-Prüfung</b></span><span data-phase="websites">3 <b data-phase-label="phaseWebsites">Websites &amp; Report</b></span></div>
                </form>
            </div>
            <section class="guest-dashboard-preview" aria-label="Dashboard preview">
                <div class="guest-preview-topbar"><button class="guest-preview-menu" type="button" aria-label="Open dashboard menu"><span></span><span></span><span></span></button><span class="brand-wordmark brand-logo-preview">Domain Monitor</span><span>DOMAIN MONITOR</span></div>
                <div class="guest-preview-body">
                    <aside class="guest-preview-sidebar"><b data-i18n="dashboard">Dashboard</b><span data-i18n="protectedDomains">Geschützte Domains</span><span data-i18n="discoveredDomains">Gefundene Domains</span><span data-i18n="scanHistory">Scanverlauf</span><span data-i18n="settings">Einstellungen</span></aside>
                    <div class="guest-preview-main">
                        <div class="guest-preview-heading"><div><small data-i18n="dashboardLabel">DASHBOARD</small><h2 data-i18n="dashboard">Dashboard</h2><p data-i18n="dashboardSubtitle">Monitor your domains.</p></div><button type="button" data-i18n="startScan">Scan starten</button></div>
                        <div class="guest-preview-stats"><div><small data-i18n="protectedDomains">Geschützte Domains</small><strong>1</strong><span data-i18n="protectedDescription">Domains unter Überwachung</span></div><div><small data-i18n="discoveredDomains">Gefundene Domains</small><strong>5.259</strong><span data-i18n="discoveredDescription">Gefundene ähnliche Domains</span></div><div><small data-i18n="activeWebsites">Aktive Websites</small><strong>4.402</strong><span data-i18n="activeWebsitesDescription">Derzeit online erreichbare Websites</span></div><div class="is-risk"><small data-i18n="highRisk">Hohes Risiko</small><strong>2</strong><span data-i18n="highRiskDescription">Domains mit Handlungsbedarf</span></div></div>
                        <div class="guest-preview-grid"><div class="guest-preview-panel"><h3 data-i18n="riskOverview">Risikoübersicht</h3><div class="guest-preview-bars"><span><i></i><span data-i18n="critical">Kritisch</span> <b>1</b></span><span><i></i><span data-i18n="high">Hoch</span> <b>1</b></span><span><i></i><span data-i18n="medium">Mittel</span> <b>5.066</b></span><span><i></i><span data-i18n="low">Niedrig</span> <b>191</b></span></div></div><div class="guest-preview-panel guest-preview-chart"><h3 data-i18n="lastScan">Letzter Scan</h3><div><strong>7.000</strong><span data-i18n="candidates">Kandidaten</span></div><dl><div><dt data-i18n="dnsActive">DNS aktiv</dt><dd>21</dd></div><div><dt data-i18n="websitesOnline">Websites online</dt><dd>17</dd></div></dl></div></div>
                        <div class="guest-preview-panel guest-preview-table"><div class="guest-preview-panel-protected-domain"><strong>example.com</strong><span data-i18n="active">AKTIV</span><small data-i18n="lastScanToday">Letzter Scan: heute, 17:02</small></div></div>
                    </div>
                </div>
            </section>
        </section>
        <section id="guest-results" class="guest-results" hidden><div class="guest-results-heading"><div><p class="guest-kicker" data-guest-i18n="report">SCAN REPORT</p><h2 id="guest-results-title" data-guest-i18n="result">Ergebnis</h2><p class="guest-report-intro" data-guest-i18n="reportIntro">Klare Trefferübersicht für Ihre Domain.</p></div><button type="button" data-open-plans data-guest-i18n="save">Ergebnis speichern</button></div><div class="guest-result-summary"><div><strong id="guest-result-count">0</strong><span data-guest-i18n="similar">ähnliche Domains geprüft</span></div><div><strong id="guest-result-risk">0</strong><span data-guest-i18n="registered">mit aktivem DNS</span></div><div><strong id="guest-result-websites">0</strong><span data-guest-i18n="websites">Websites aktiv</span></div><div><strong id="guest-result-logins">0</strong><span data-guest-i18n="loginPages">Login-Seiten erkannt</span></div></div><div class="guest-risk-legend"><span data-guest-i18n="riskLegend">Risiko</span><b class="guest-risk-badge guest-risk-critical" data-guest-i18n="criticalRiskLabel">Kritisch</b><b class="guest-risk-badge guest-risk-high" data-guest-i18n="highRiskLabel">Hoch</b><b class="guest-risk-badge guest-risk-medium" data-guest-i18n="mediumRiskLabel">Mittel</b><b class="guest-risk-badge guest-risk-low" data-guest-i18n="lowRiskLabel">Niedrig</b></div><div id="guest-result-list" class="guest-result-list"></div></section>
        <section class="guest-capabilities"><div class="guest-section-heading"><p class="guest-kicker" data-guest-i18n="capabilitiesKicker">MEHR ALS EIN DOMAIN-CHECK</p><h2 data-guest-i18n="capabilitiesTitle">Von der ersten Ähnlichkeit bis zum verwertbaren Sicherheitsbefund.</h2><p data-guest-i18n="capabilitiesIntro">Domain Monitor verbindet Kandidatengenerierung, technische Prüfungen und klare Priorisierung in einem Arbeitsbereich.</p></div><div class="guest-capability-grid"><article><span>01</span><h3 data-guest-i18n="capabilityCandidates">Lookalike-Domains finden</h3><p data-guest-i18n="capabilityCandidatesText">Schreibvarianten, Bindestriche, Subdomains, Wörterbuchbegriffe und verschiedene TLDs machen auch schwer erkennbare Nachahmungen sichtbar.</p></article><article><span>02</span><h3 data-guest-i18n="capabilitySignals">Technische Signale prüfen</h3><p data-guest-i18n="capabilitySignalsText">DNS, IP-Adressen, Erreichbarkeit, HTTP-Status, Seitentitel und Weiterleitungen zeigen, welche Treffer tatsächlich aktiv sind.</p></article><article><span>03</span><h3 data-guest-i18n="capabilityRisk">Risiken priorisieren</h3><p data-guest-i18n="capabilityRiskText">Login-Erkennung, Markenname in HTML oder Headern, Weiterleitungen und Domainalter fließen in einen nachvollziehbaren Risikoscore ein.</p></article><article><span>04</span><h3 data-guest-i18n="capabilityWorkflow">Treffer dauerhaft bearbeiten</h3><p data-guest-i18n="capabilityWorkflowText">Speichern Sie Scanverläufe, vergleichen Sie Veränderungen, blenden Sie bekannte Domains aus oder überwachen Sie Treffer still weiter.</p></article><article><span>05</span><h3 data-guest-i18n="capabilitySchedule">Automatisch überwachen</h3><p data-guest-i18n="capabilityScheduleText">Professional plant Scans in Ihrem Intervall, berücksichtigt Zeitzone und Wochenendpause und hält den nächsten Lauf transparent fest.</p></article><article><span>06</span><h3 data-guest-i18n="capabilityAlerts">Bei Veränderungen reagieren</h3><p data-guest-i18n="capabilityAlertsText">Benachrichtigungen machen auf kritische neue Domains und relevante Veränderungen aufmerksam, statt dass Teams Listen manuell prüfen müssen.</p></article></div></section>
        <section class="guest-how-it-works"><div class="guest-section-heading"><p class="guest-kicker" data-guest-i18n="workflowKicker">SO FUNKTIONIERT ES</p><h2 data-guest-i18n="workflowTitle">Ein klarer Ablauf für wiederholbare Entscheidungen.</h2></div><div class="guest-workflow"><div><strong>01</strong><h3 data-guest-i18n="workflowOne">Domain schützen</h3><p data-guest-i18n="workflowOneText">Hinterlegen Sie Ihre wichtigste Unternehmensdomain und optional weitere Marken- oder Unternehmensdomains.</p></div><div><strong>02</strong><h3 data-guest-i18n="workflowTwo">Kandidaten scannen</h3><p data-guest-i18n="workflowTwoText">Der Scanner erzeugt Varianten und prüft sie parallel auf DNS, Websites und verdächtige Merkmale.</p></div><div><strong>03</strong><h3 data-guest-i18n="workflowThree">Befund einordnen</h3><p data-guest-i18n="workflowThreeText">Risikostufen, Details und Scanverlauf zeigen, wo zuerst gehandelt werden sollte.</p></div><div><strong>04</strong><h3 data-guest-i18n="workflowFour">Monitoring automatisieren</h3><p data-guest-i18n="workflowFourText">Mit Professional laufen Prüfungen regelmäßig und Änderungen erreichen Ihr Team per Alert.</p></div></div></section>
        <section class="guest-plans"><div><p class="guest-kicker" data-guest-i18n="plans">PLANBARE KOSTEN</p><h2 data-guest-i18n="plansTitle">Monitoring, das mit Ihrem Unternehmen wächst.</h2><p data-guest-i18n="plansIntro">Starten Sie mit einem Check und behalten Sie Ihre wichtigsten Domains dauerhaft im Blick.</p></div><div class="plan-grid"><article><span>CHECK</span><h3 data-guest-i18n="free">Free</h3><strong>0 EUR</strong><ul><li data-guest-i18n="freeBenefit1">Bis zu 50.000 Kandidaten</li><li data-guest-i18n="freeBenefit2">2 Protected Domains</li><li data-guest-i18n="freeBenefit3">Manuelle Scans</li></ul><button type="button" data-open-register data-plan="free" data-guest-i18n="try">Jetzt testen</button></article><article class="plan-featured"><span data-guest-i18n="protection">PROTECTION</span><em data-guest-i18n="proRecommended">EMPFOHLEN FÜR LAUFENDEN SCHUTZ</em><h3 data-guest-i18n="professional">Professional</h3><strong>29 EUR <small>/ Monat</small></strong><p data-guest-i18n="proPitch">Für Teams, die nicht erst nach einem Vorfall von einer neuen Domain erfahren wollen.</p><ul><li data-guest-i18n="proBenefit1">Bis zu 1.000.000 Kandidaten</li><li data-guest-i18n="proBenefit2">15 geschützte Domains</li><li data-guest-i18n="proBenefit3">Automatische Scans und Alerts</li><li data-guest-i18n="proBenefit4">Threat-Intelligence-Prüfungen</li><li data-guest-i18n="proBenefit5">Veränderungen und stille Überwachung</li></ul><button type="button" data-open-register data-plan="pro" data-guest-i18n="account">Konto anlegen</button></article></div></section>
        <section class="guest-plan-details"><div class="guest-section-heading"><p class="guest-kicker" data-guest-i18n="comparisonKicker">WAS IST ENTHALTEN?</p><h2 data-guest-i18n="comparisonTitle">Der Unterschied liegt im laufenden Schutz.</h2><p data-guest-i18n="comparisonIntro">Free ist der unkomplizierte Einstieg. Professional wird zur kontinuierlichen Schutzschicht für Marken und Unternehmen.</p></div><div class="guest-comparison"><div class="guest-comparison-row guest-comparison-head"><strong data-guest-i18n="comparisonFeature">Funktion</strong><strong>Free</strong><strong class="guest-pro-column">Professional</strong></div><div class="guest-comparison-row"><span data-guest-i18n="compareScan">Manuelle Lookalike-Scans</span><b>✓</b><b class="guest-pro-column">✓</b></div><div class="guest-comparison-row"><span data-guest-i18n="compareCandidates">Kandidaten pro Scan</span><b>50.000</b><b class="guest-pro-column">1.000.000</b></div><div class="guest-comparison-row"><span data-guest-i18n="compareProtected">Geschützte Domains</span><b>2</b><b class="guest-pro-column">15</b></div><div class="guest-comparison-row"><span data-guest-i18n="compareHistory">Scanverlauf und Veränderungen</span><b>✓</b><b class="guest-pro-column">✓</b></div><div class="guest-comparison-row"><span data-guest-i18n="compareAutomation">Automatische Scans</span><b>-</b><b class="guest-pro-column">✓</b></div><div class="guest-comparison-row"><span data-guest-i18n="compareAlerts">Sicherheitsbenachrichtigungen</span><b>-</b><b class="guest-pro-column">✓</b></div><div class="guest-comparison-row"><span data-guest-i18n="compareThreat">Threat-Intelligence-Prüfungen</span><b>-</b><b class="guest-pro-column">✓</b></div><div class="guest-comparison-row"><span data-guest-i18n="compareMuted">Treffer ausblenden und weiter überwachen</span><b>-</b><b class="guest-pro-column">✓</b></div></div></section>
    </main>
</section>
<section id="login-screen" class="login-screen">
    <form id="login-form" class="login-card">
        <button type="button" class="auth-modal-close" data-close-auth aria-label="Schließen">×</button>
        <div class="auth-heading"><div><p class="auth-kicker" data-i18n="authKicker">DOMAIN MONITOR</p><h1 data-i18n="loginTitle">Domain Monitor</h1></div></div>
        <p class="auth-subtitle" data-i18n="loginSubtitle">Sign in to your security dashboard.</p>
        <div class="auth-mode" id="auth-mode"><strong id="auth-mode-title" data-i18n="loginMode">Anmelden</strong><span id="auth-mode-description" data-i18n="loginModeDescription">Öffne dein bestehendes Sicherheitsdashboard.</span></div>
        <input id="login-username" type="text" autocomplete="username" placeholder="Username" data-i18n-placeholder="username" required>
        <div id="registration-fields" hidden>
            <div class="auth-plan-picker"><span data-i18n="choosePlan">Plan für dein neues Konto</span><div><button type="button" class="auth-plan-option" data-plan-choice="free"><b>Free</b><small data-i18n="freePlanShort">50.000 Kandidaten · 2 Domains</small></button><button type="button" class="auth-plan-option is-selected" data-plan-choice="pro"><b>Professional</b><small data-i18n="proPlanShort">1.000.000 Kandidaten · Automatisierung</small></button></div><p id="selected-plan-label" data-i18n="selectedPro">Professional ausgewählt: laufender Schutz mit Automatisierung und Alerts.</p></div>
            <input id="register-email" type="email" autocomplete="email" placeholder="E-Mail" data-i18n-placeholder="email">
        </div>
        <input id="login-password" type="password" autocomplete="current-password" placeholder="Password" data-i18n-placeholder="password" required>
        <input id="register-plan" type="hidden" value="free">
        <input id="register-password-confirm" class="registration-only" type="password" autocomplete="new-password" placeholder="Passwort wiederholen" data-i18n-placeholder="confirmPassword" hidden>
        <button type="submit" class="scan-button" data-i18n="loginButton">Sign in</button>
        <p id="login-error" class="login-error"></p>
        <?php if ($registrationEnabled): ?>
            <a href="#registration-fields" id="registration-toggle" class="text-button" data-i18n="register">Registrieren</a>
        <?php endif; ?>
    </form>
</section>
<button type="button" class="login-language-toggle" onclick="toggleLanguage()">
    <span data-i18n="languageLabel">Sprache</span>
    <span class="language-toggle-track"><span class="language-toggle-current">DE</span><span class="language-toggle-target">EN</span></span>
</button>
<div class="app">
    <header class="mobile-topbar">
        <button class="mobile-menu-button" id="mobile-menu-button" type="button" aria-label="Open menu" aria-expanded="false"><span></span><span></span><span></span></button>
        <strong data-i18n="loginTitle">Domain Monitor</strong>
    </header>
    <aside class="sidebar" id="main-sidebar">
        <div class="logo"><span class="brand-wordmark">Domain Monitor</span></div>
        <nav>
            <a href="#" class="nav-item page-nav active" data-page="dashboard">Dashboard</a>
            <a
                href="settings.php"
                class="nav-item"
                data-i18n="settings"
            >
                Einstellungen
            </a>

            <?php if ($pageUser && ($pageUser["role"] ?? "user") === "admin"): ?>
                <a
                    href="admin.php"
                    class="nav-item admin-nav"
                    data-i18n="adminPanel"
                >
                    Admin Panel
                </a>
            <?php endif; ?>

        </nav>

        <div class="sidebar-bottom">

            <button
                type="button"
                id="language-toggle"
                class="language-toggle"
                onclick="toggleLanguage()"
            >
                <span class="language-toggle-label" data-i18n="languageLabel">Sprache</span>
                <span class="language-toggle-track">
                    <span class="language-toggle-current">DE</span>
                    <span class="language-toggle-target">EN</span>
                </span>
            </button>

            <button
                type="button"
                id="logout-button"
                class="logout-button"
                onclick="logout()"
                data-i18n="logout"
            >
                Abmelden
            </button>

        </div>

    </aside>

    <main class="main">

        <header class="header standalone-header">

            <div>
                <p class="eyebrow dashboard-eyebrow" data-i18n="dashboardLabel">DASHBOARD</p>
                <h1 id="dashboard-title">
                    Dashboard
                </h1>
                <p class="dashboard-subtitle" data-i18n="dashboardSubtitle">Monitor your domains.</p>

            </div>

            <div class="header-actions">

                <div class="last-scan">

                    Last scan

                    <strong id="last-scan">
                        Loading...
                    </strong>

                </div>

                <div class="scan-controls">

                    <button
                        class="scan-button"
                        id="start-scan-button"
                        onclick="startScan()"
                    >
                        ↻ Start Scan
                    </button>

                    <button
                        class="stop-scan-button"
                        id="stop-scan-button"
                        onclick="stopScan()"
                        disabled
                    >
                        ■ Stop Scan
                    </button>

                </div>

            </div>

        </header>

        <section
            class="scan-progress-panel"
            id="scan-progress-panel"
        >

            <div class="scan-progress-header">

                <div>

                    <strong
                        id="scan-progress-title"
                    >
                        Scanner ready
                    </strong>

                    <span
                        id="scan-progress-domain"
                    >
                        No scan running
                    </span>

                </div>

                <strong
                    id="scan-progress-percent"
                >
                    0%
                </strong>

            </div>

            <div class="progress-bar">

                <div
                    class="progress-fill"
                    id="scan-progress-fill"
                ></div>

            </div>

            <div class="scan-progress-footer">

                <span
                    id="scan-progress-count"
                >
                    0 / 0
                </span>

                <span
                    id="scan-progress-message"
                >
                    Ready
                </span>

            </div>

        </section>

        <div
            id="dashboard-notice"
            class="dashboard-notice"
            role="status"
            aria-live="polite"
            hidden
        ></div>

        <section class="stats-grid">

            <div class="stat-card">

                <div class="stat-label">
                    Protected Domains
                </div>

                <div
                    class="stat-value"
                    id="protected-domains-count"
                >
                    -
                </div>

                <div class="stat-description">
                    Domains under monitoring
                </div>

            </div>

            <div class="stat-card">

                <div class="stat-label">
                    Discovered Domains
                </div>

                <div
                    class="stat-value"
                    id="total-domains"
                >
                    -
                </div>

                <div class="stat-description">
                    Lookalike domains found
                </div>

            </div>

            <div class="stat-card">

                <div class="stat-label">
                    Active Websites
                </div>

                <div
                    class="stat-value"
                    id="active-websites"
                >
                    -
                </div>

                <div class="stat-description">
                    Websites currently online
                </div>

            </div>

            <div class="stat-card danger">

                <div class="stat-label">
                    High Risk
                </div>

                <div
                    class="stat-value"
                    id="high-risk"
                >
                    -
                </div>

                <div class="stat-description">
                    Domains requiring attention
                </div>

            </div>

        </section>

        <section class="content-grid">

            <div class="panel">

                <div class="panel-header">

                    <div>

                        <h2>
                            Risk Overview
                        </h2>

                        <p>
                            Current threat distribution
                        </p>

                    </div>

                </div>

                <div class="risk-list">

                    <div class="risk-row">

                        <div class="risk-name">

                            <span
                                class="risk-indicator critical"
                            ></span>

                            Critical

                        </div>

                        <strong id="critical">
                            0
                        </strong>

                    </div>

                    <div class="risk-row">

                        <div class="risk-name">

                            <span
                                class="risk-indicator high"
                            ></span>

                            High

                        </div>

                        <strong id="high">
                            0
                        </strong>

                    </div>

                    <div class="risk-row">

                        <div class="risk-name">

                            <span
                                class="risk-indicator medium"
                            ></span>

                            Medium

                        </div>

                        <strong id="medium">
                            0
                        </strong>

                    </div>

                    <div class="risk-row">

                        <div class="risk-name">

                            <span
                                class="risk-indicator low"
                            ></span>

                            Low

                        </div>

                        <strong id="low">
                            0
                        </strong>

                    </div>

                </div>

            </div>

            <div class="panel">

                <div class="panel-header">

                    <div>

                        <h2>
                            Last Scan
                        </h2>

                        <p>
                            Scan statistics
                        </p>

                    </div>

                </div>

                <div class="scan-info">

                    <div class="scan-donut-area">

                        <div
                            class="scan-donut"
                            id="scan-donut"
                        >

                            <div class="scan-donut-center">

                                <strong
                                    id="scan-donut-total"
                                >
                                    0
                                </strong>

                                <span>
                                    Candidates
                                </span>

                            </div>

                        </div>

                    </div>

                    <div class="scan-summary">

                        <div class="scan-info-stat">

                            <div class="scan-stat-label">

                                <span
                                    class="scan-stat-dot candidates"
                                ></span>

                                Candidates

                            </div>

                            <strong
                                id="scan-candidates"
                                class="scan-stat-value candidates-value"
                            >
                                -
                            </strong>

                        </div>

                        <div class="scan-info-stat">

                            <div class="scan-stat-label">

                                <span
                                    class="scan-stat-dot dns"
                                ></span>

                                DNS Active

                            </div>

                            <strong
                                id="scan-registered"
                                class="scan-stat-value dns-value"
                            >
                                -
                            </strong>

                        </div>

                        <div class="scan-info-stat">

                            <div class="scan-stat-label">

                                <span
                                    class="scan-stat-dot websites"
                                ></span>

                                Websites Online

                            </div>

                            <strong
                                id="scan-websites"
                                class="scan-stat-value websites-value"
                            >
                                -
                            </strong>

                        </div>

                    </div>

                </div>

            </div>

        </section>

        <section
            class="panel protected-domains-panel"
            id="protected-domains"
        >

            <div class="panel-header">

                <div>

                    <h2>
                        Protected Domains
                    </h2>

                    <p>
                        Domains monitored for impersonation and phishing
                    </p>

                </div>

            </div>

            <div class="protected-domain-form">

                <input
                    type="text"
                    id="new-domain"
                    placeholder="example.com"
                    autocomplete="off"
                >

                <button
                    class="add-domain-button"
                    onclick="addProtectedDomain()"
                >
                    + Add Domain
                </button>

            </div>

            <div
                id="protected-domain-message"
                class="protected-domain-message"
            ></div>

            <div class="table-container">

                <table>

                    <thead>

                        <tr>

                            <th>
                                Domain
                            </th>

                            <th>
                                Status
                            </th>

                            <th>
                                Added
                            </th>

                            <th>
                                Last Scan
                            </th>

                            <th>
                                Actions
                            </th>

                        </tr>

                    </thead>

                    <tbody
                        id="protected-domains-table"
                    >

                        <tr>

                            <td
                                colspan="5"
                                class="loading"
                            >
                                Loading...
                            </td>

                        </tr>

                    </tbody>

                </table>

            </div>

        </section>

        <section
            class="panel domains-panel"
            id="domains"
        >

            <div class="panel-header">

                <div>

                    <h2>
                        Discovered Domains
                    </h2>

                    <p>
                        Potentially suspicious domains
                    </p>

                </div>

                <div class="table-actions">

                    <input
                        type="text"
                        id="search"
                        placeholder="Search domain..."
                        oninput="filterDomains()"
                    >

                    <select
                        id="risk-filter"
                        onchange="filterDomains()"
                    >

                        <option value="ALL">
                            All Risk Levels
                        </option>

                        <option value="CRITICAL">
                            Critical
                        </option>

                        <option value="HIGH">
                            High
                        </option>

                        <option value="MEDIUM">
                            Medium
                        </option>

                        <option value="LOW">
                            Low
                        </option>

                    </select>

                </div>

            </div>

            <div class="table-container">

                <table>

                    <thead>

                        <tr>

                            <th>
                                Domain
                            </th>

                            <th>
                                Risk
                            </th>

                            <th>
                                Score
                            </th>

                            <th>
                                Meldestatus
                            </th>

                            <th>
                                DNS
                            </th>

                            <th>
                                Website
                            </th>

                            <th>
                                Login
                            </th>

                            <th>
                                Company
                            </th>

                            <th>
                                For Sale
                            </th>

                            <th>
                                HTTP
                            </th>

                            <th>
                                Last Seen
                            </th>

                            <th>
                                Actions
                            </th>

                        </tr>

                    </thead>

                    <tbody id="domains-table">

                        <tr>

                            <td
                                colspan="12"
                                class="loading"
                            >
                                Loading...
                            </td>

                        </tr>

                    </tbody>

                </table>

            </div>

        </section>

        <section
            class="panel"
            id="scans"
        >

            <div class="panel-header">

                <div>

                    <h2>
                        Scan History
                    </h2>

                    <p>
                        Previous monitoring scans
                    </p>

                </div>

                <button
                    class="delete-button"
                    onclick="deleteAllData()"
                >
                    Delete all scans
                </button>

            </div>

            <div class="table-container">

                <table>

                    <thead>

                        <tr>

                            <th>
                                Scan
                            </th>

                            <th>
                                Started
                            </th>

                            <th>
                                Finished
                            </th>

                            <th>
                                Candidates
                            </th>

                            <th>
                                DNS Active
                            </th>

                            <th>
                                Websites
                            </th>

                        </tr>

                    </thead>

                    <tbody id="scans-table">

                        <tr>

                            <td
                                colspan="6"
                                class="loading"
                            >
                                Loading...
                            </td>

                        </tr>

                    </tbody>

                </table>

            </div>

        </section>

    </main>

</div>

<div
    id="domain-modal"
    class="domain-modal"
>

    <div
        class="domain-modal-overlay"
        onclick="closeDomainDetails()"
    ></div>

    <div
        class="domain-modal-content"
        onclick="event.stopPropagation()"
    >

        <div class="domain-modal-header">

            <div>

                <h2 id="detail-domain">
                    Domain
                </h2>

                <div id="detail-change" class="domain-change-note"></div>

                <div class="domain-detail-title-row">

                    <span
                        id="detail-risk"
                        class="risk-badge risk-low"
                    >
                        LOW
                    </span>

                    <button
                        id="detail-copy-button"
                        class="copy-domain-button"
                        type="button"
                        onclick="
                            event.stopPropagation();
                            copyCurrentDetailDomain();
                        "
                    >
                        Copy Domain
                    </button>

                </div>

            </div>

            <button
                class="domain-modal-close"
                type="button"
                onclick="closeDomainDetails()"
            >
                ×
            </button>

        </div>

        <div class="domain-detail-grid">

            <div class="detail-section">

                <h3>
                    Risk
                </h3>

                <div class="detail-row">

                    <span>
                        Risk Score
                    </span>

                    <strong id="detail-risk-score">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Risk Level
                    </span>

                    <strong id="detail-risk-level">
                        -
                    </strong>

                </div>

            </div>

            <div class="detail-section">

                <h3>
                    Registration
                </h3>

                <div class="detail-row">

                    <span>
                        Registered
                    </span>

                    <strong id="detail-registration-date">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Domain Age
                    </span>

                    <strong id="detail-domain-age">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Registrar
                    </span>

                    <strong id="detail-registrar">
                        -
                    </strong>

                </div>

            </div>

            <div class="detail-section">

                <h3>
                    DNS
                </h3>

                <div class="detail-row">

                    <span>
                        Status
                    </span>

                    <strong id="detail-dns">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        IP Addresses
                    </span>

                    <strong id="detail-ips">
                        -
                    </strong>

                </div>

            </div>

            <div class="detail-section">

                <h3>
                    Website
                </h3>

                <div class="detail-row">

                    <span>
                        Status
                    </span>

                    <strong id="detail-website">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        HTTP
                    </span>

                    <strong id="detail-http">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Final URL
                    </span>

                    <strong
                        id="detail-url"
                        class="detail-url"
                    >
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Redirect
                    </span>

                    <strong id="detail-redirect">
                        -
                    </strong>

                </div>

            </div>

            <div class="detail-section">

                <h3>
                    Detection
                </h3>

                <div class="detail-row">

                    <span>
                        Login
                    </span>

                    <strong id="detail-login">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Company in HTML
                    </span>

                    <strong id="detail-company">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Company in Header
                    </span>

                    <strong id="detail-header">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        For Sale
                    </span>

                    <strong id="detail-for-sale">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Page Title
                    </span>

                    <strong id="detail-title">
                        -
                    </strong>

                </div>

            </div>

            <div class="detail-section">

                <h3>
                    Monitoring
                </h3>

                <div class="detail-row">

                    <span>
                        First Seen
                    </span>

                    <strong id="detail-first-seen">
                        -
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Last Seen
                    </span>

                    <strong id="detail-last-seen">
                        -
                    </strong>

                </div>

            </div>

            <div class="detail-section">

                <h3>
                    Threat Intelligence
                </h3>

                <div class="detail-row">
                    <span>Report Status</span>
                    <strong id="detail-threat-status">-</strong>
                </div>

                <div class="detail-row">
                    <span>Source</span>
                    <strong id="detail-threat-source">-</strong>
                </div>

                <div class="detail-row">
                    <span>Detections</span>
                    <strong id="detail-threat-detections">-</strong>
                </div>

                <div class="detail-row">
                    <span>Checked</span>
                    <strong id="detail-threat-checked">-</strong>
                </div>

            </div>

        </div>

    </div>

</div>

<script
    src="js/app.js?v=<?php echo rawurlencode((string)filemtime(__DIR__ . '/js/app.js')); ?>&r=<?php echo rawurlencode((string)time()); ?>"
></script>

</body>

</html>
