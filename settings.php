<?php
require_once __DIR__ . "/api/database.php";
require_once __DIR__ . "/api/auth.php";
$pageUser = require_auth();
$notificationsAvailable = $pdo->query("SELECT setting_value FROM app_settings WHERE setting_key = 'notifications_enabled'")->fetchColumn() === "1";
?>
<!doctype html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title data-i18n="settingsTitle">Einstellungen</title>
    <link rel="stylesheet" href="css/style.css?v=<?php echo rawurlencode((string)filemtime(__DIR__ . '/css/style.css')); ?>">
    <link rel="stylesheet" href="css/mobile-overrides.css?v=<?php echo rawurlencode((string)filemtime(__DIR__ . '/css/mobile-overrides.css')); ?>">
</head>
<body class="standalone-page<?= ($pageUser["role"] ?? "user") === "admin" ? " admin-user" : "" ?>">
<div class="app">
    <header class="mobile-topbar"><button class="mobile-menu-button" id="mobile-menu-button" type="button" aria-label="Open menu" aria-expanded="false"><span></span><span></span><span></span></button><strong data-i18n="settings">Einstellungen</strong></header>
    <aside class="sidebar" id="main-sidebar">
        <div class="logo"><span class="brand-wordmark">Domain Monitor</span></div>
        <nav>
            <a href="index.php" class="nav-item" data-i18n="dashboard">Dashboard</a>
            <a href="settings.php" class="nav-item active" data-i18n="settings">Einstellungen</a>
            <?php if (($pageUser["role"] ?? "user") === "admin"): ?>
                <a href="admin.php" class="nav-item admin-nav" data-admin-only data-i18n="adminSettings">Admin Bereich</a>
            <?php endif; ?>
        </nav>
        <div class="sidebar-bottom">
            <button type="button" class="language-toggle" id="language-toggle"><span data-i18n="language">Sprache</span><span class="language-toggle-track"><span class="language-toggle-current">DE</span><span class="language-toggle-target">EN</span></span></button>
            <button type="button" class="logout-button" id="logout-button" data-i18n="logout">Abmelden</button>
        </div>
    </aside>
    <main class="main standalone-main">
        <header class="standalone-header"><div><p class="eyebrow" data-i18n="accountAndAutomation">Konto und Automatisierung</p><h1 data-i18n="settingsTitle">Einstellungen</h1><p data-i18n="settingsIntro">Verwalte dein Konto und die Scanplanung an einem Ort.</p></div></header>
        <section class="settings-layout">
            <article class="panel settings-card">
                <div class="panel-header"><div><h2 data-i18n="account">Konto</h2><p data-i18n="accountDescription">Deine Zugangsdaten und Kontoinformationen.</p></div></div>
                <div class="form-grid">
                    <label><span data-i18n="username">Benutzername</span><input id="account-username" type="text"></label>
                    <label><span data-i18n="email">E-Mail</span><input id="account-email" type="email" autocomplete="email"></label>
                    <label><span data-i18n="role">Rolle</span><input id="account-role" type="text" disabled></label>
                    <label><span data-i18n="newPassword">Neues Passwort</span><input id="account-password" type="password" autocomplete="new-password"></label>
                    <label><span data-i18n="validUntil">Gültig bis</span><input id="account-valid-until" type="text" disabled></label>
                    <label><span data-i18n="plan">Plan</span><input id="account-plan" type="text" disabled></label>
                </div>
                <div class="settings-actions"><button class="save-settings-button" id="save-account" data-i18n="saveAccount">Konto speichern</button><span class="settings-message" id="account-message"></span></div>
            </article>
            <article class="panel settings-card">
                <div class="panel-header"><div><h2 data-i18n="automaticScanning">Automatische Scans</h2><p data-i18n="automaticDescription">Lege fest, wann und in welcher Zeitzone gescannt wird.</p></div></div>
                <div class="setting-row"><div class="setting-info"><strong data-i18n="automaticScanning">Automatische Scans</strong><span data-i18n="automaticHint">Scans automatisch im Intervall starten.</span></div><label class="switch"><input id="scan-enabled" type="checkbox"><span class="slider"></span></label></div>
                <div class="form-grid settings-form-grid">
                    <label><span data-i18n="scanInterval">Scanintervall</span><select id="scan-interval"><option value="1">1 <span data-i18n="hour">Stunde</span></option><option value="6">6 <span data-i18n="hours">Stunden</span></option><option value="12">12 <span data-i18n="hours">Stunden</span></option><option value="24">24 <span data-i18n="hours">Stunden</span></option><option value="48">48 <span data-i18n="hours">Stunden</span></option><option value="168">7 <span data-i18n="days">Tage</span></option></select></label>
                    <label><span data-i18n="timezone">Zeitzone</span><select id="scan-timezone"><option value="Europe/Vienna" data-i18n="viennaBerlin">Wien / Berlin</option><option value="UTC">UTC</option></select></label>
                </div>
                <div class="setting-row"><div class="setting-info"><strong data-i18n="weekendPause">Wochenendpause</strong><span data-i18n="weekendHint">Automatische Scans am Wochenende pausieren.</span></div><label class="switch"><input id="scan-pause-weekends" type="checkbox"><span class="slider"></span></label></div>
                <div class="setting-row"><div class="setting-info"><strong data-i18n="nextScan">Nächster Scan</strong><span data-i18n="nextScanHint">Der nächste geplante automatische Scan.</span></div><strong class="next-scan" id="next-scan">-</strong></div>
                <div class="settings-actions"><button class="save-settings-button" id="save-settings" data-i18n="saveSettings">Einstellungen speichern</button><span class="settings-message" id="settings-message"></span></div>
            </article>
            <article class="panel settings-card notification-settings-card">
                <div class="panel-header"><div><h2 data-i18n="notifications">Benachrichtigungen</h2><p data-i18n="notificationsDescription">Über neue kritische Domains oder Veränderungen alarmieren.</p></div></div>
                <div class="setting-row"><div class="setting-info"><strong data-i18n="criticalNotifications">Kritische Sicherheitsbenachrichtigungen</strong><span data-i18n="notificationsHint">Benachrichtigungen über neue kritische Domains oder Veränderungen.</span></div><label class="switch"><input id="notifications-enabled" type="checkbox"<?= $notificationsAvailable ? "" : " disabled" ?>><span class="slider"></span></label></div>
                <div class="settings-actions notification-actions"><button class="save-settings-button" id="save-notifications" type="button" data-i18n="saveNotifications">Benachrichtigungen speichern</button><span class="settings-message" id="notification-message"></span></div>
            </article>
            <article class="panel settings-card max-domains-settings-card">
                <div class="panel-header"><div><h2 data-i18n="maxDomains">Maximale generierte Domains</h2><p data-i18n="maxDomainsDescription">Legt fest, wie viele Kandidaten pro Scan erzeugt werden.</p></div></div>
                <div class="form-grid"><label><span data-i18n="maxDomainsValue">Anzahl Domains</span><input id="scan-max-domains" type="number" min="1000" max="1000000" step="1" value="50000"></label></div>
                <div class="setting-row"><div class="setting-info"><strong data-i18n="threatIntelligenceSetting">Gemeldete Seiten prüfen</strong><span data-i18n="threatIntelligenceDescription">Wenn aktiviert, werden gefundene Domains zusätzlich bei Malware- und Phishing-Datenbanken geprüft. Dadurch dauert der Scan länger.</span></div><label class="switch"><input id="threat-intelligence-enabled" type="checkbox"><span class="slider"></span></label></div>
                <div class="settings-actions"><button class="save-settings-button" id="save-max-domains" type="button" data-i18n="saveMaxDomains">Domainanzahl speichern</button><span class="settings-message" id="max-domains-message"></span></div>
            </article>
            <article class="panel settings-card excluded-settings-card">
                <div class="panel-header"><div><h2 data-i18n="excludedDomains">Ausgeschlossene Unternehmensdomains</h2><p data-i18n="excludedDescription">Diese Domains und Subdomains werden von Scans ausgeschlossen.</p></div></div>
                <div class="protected-domain-form settings-domain-form"><input id="new-excluded-domain" type="text" placeholder="company.com" autocomplete="off"><button class="add-domain-button" id="add-excluded-domain" type="button" data-i18n="excludeDomain">Domain ausschließen</button></div>
                <div id="excluded-domain-message" class="protected-domain-message"></div>
                <div class="table-container"><table><thead><tr><th data-i18n="domain">Domain</th><th data-i18n="added">Hinzugefügt</th><th data-i18n="actions">Aktionen</th></tr></thead><tbody id="excluded-domains-table"><tr><td colspan="3" class="loading">-</td></tr></tbody></table></div>
            </article>
            <article class="panel settings-card excluded-settings-card">
                <div class="panel-header"><div><h2 data-i18n="mutedDomains">Ausgeblendete, weiter überwachte Domains</h2><p data-i18n="mutedDescription">Diese Domains werden weiter geprüft, aber bis zu einer Änderung aus Trefferliste und Statistiken ausgeblendet.</p></div></div>
                <div class="table-container"><table><thead><tr><th data-i18n="domain">Domain</th><th data-i18n="added">Hinzugefügt</th><th data-i18n="actions">Aktionen</th></tr></thead><tbody id="muted-domains-table"><tr><td colspan="3" class="loading">-</td></tr></tbody></table></div>
            </article>
        </section>
    </main>
</div>
<script src="js/settings-page.js?v=<?php echo rawurlencode((string)filemtime(__DIR__ . '/js/settings-page.js')); ?>"></script>
</body>
</html>
