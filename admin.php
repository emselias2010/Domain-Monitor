<?php
require_once __DIR__ . "/api/database.php";
require_once __DIR__ . "/api/auth.php";
$pageUser = current_user();
if (!$pageUser || ($pageUser["role"] ?? "user") !== "admin") {
    http_response_code(404);
    header("Content-Type: text/html; charset=utf-8");
    exit("<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>Not Found</title></head><body><h1>Not Found</h1></body></html>");
}
?>
<!doctype html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title data-i18n="adminTitle">Adminbereich</title>
    <link rel="stylesheet" href="css/style.css?v=<?php echo rawurlencode((string)filemtime(__DIR__ . '/css/style.css')); ?>">
    <link rel="stylesheet" href="css/mobile-overrides.css?v=<?php echo rawurlencode((string)filemtime(__DIR__ . '/css/mobile-overrides.css')); ?>">
</head>
<body class="standalone-page admin-user">
<div class="app">
    <header class="mobile-topbar"><button class="mobile-menu-button" id="mobile-menu-button" type="button" aria-label="Open menu" aria-expanded="false"><span></span><span></span><span></span></button></header>
    <aside class="sidebar" id="main-sidebar">
        <div class="logo"><span class="brand-wordmark">Domain Monitor</span></div>
        <nav>
            <a href="index.php" class="nav-item" data-i18n="dashboard">Dashboard</a>
            <a href="settings.php" class="nav-item" data-i18n="settings">Einstellungen</a>
            <a href="admin.php" class="nav-item active" data-i18n="adminPanel">Admin Panel</a>
        </nav>
        <div class="sidebar-bottom"><button type="button" class="language-toggle" id="language-toggle"><span data-i18n="language">Sprache</span><span class="language-toggle-track"><span class="language-toggle-current">DE</span><span class="language-toggle-target">EN</span></span></button><button type="button" class="logout-button" id="logout-button" data-i18n="logout">Abmelden</button></div>
    </aside>
    <main class="main standalone-main">
        <header class="standalone-header"><div><p class="eyebrow" data-i18n="administration">Administration</p><h1 data-i18n="adminTitle">Adminbereich</h1><p data-i18n="adminIntro">Benutzer, Zugänge und Scanaktivität zentral verwalten.</p></div><button class="add-domain-button" id="open-user-modal" data-i18n="addUser">Benutzer hinzufügen</button></header>
        <section class="admin-summary" id="admin-summary"></section>
        <section class="panel admin-page-card registration-setting"><div class="setting-row"><div class="setting-info"><strong data-i18n="publicRegistration">Öffentliche Registrierung</strong><span data-i18n="publicRegistrationHint">Neue Benutzer dürfen sich selbst registrieren.</span></div><label class="switch"><input id="registration-enabled" type="checkbox"><span class="slider"></span></label></div></section>
        <section class="panel admin-page-card notification-setting"><div class="setting-row"><div class="setting-info"><strong data-i18n="notificationAvailability">Benachrichtigungen freigeben</strong><span data-i18n="notificationAvailabilityHint">Erlaubt Benutzern, Sicherheitsbenachrichtigungen einzuschalten.</span></div><label class="switch"><input id="notifications-enabled" type="checkbox"><span class="slider"></span></label></div></section>
        <section class="panel admin-page-card"><div class="panel-header"><div><h2 data-i18n="mailSettings">E-Mail-Server</h2><p data-i18n="mailSettingsHint">Serverdaten für Sicherheitsbenachrichtigungen.</p></div></div><div class="form-grid"><label><span data-i18n="smtpHost">SMTP-Server</span><input id="smtp-host" type="text" autocomplete="off"></label><label><span data-i18n="smtpPort">Port</span><input id="smtp-port" type="number" min="1" max="65535" value="587"></label><label><span data-i18n="smtpUser">SMTP-Benutzer</span><input id="smtp-user" type="text" autocomplete="off"></label><label><span data-i18n="smtpPassword">SMTP-Passwort</span><input id="smtp-password" type="password" autocomplete="new-password"></label><label><span data-i18n="smtpFrom">Absender</span><input id="smtp-from" type="email" autocomplete="off"></label><label class="modal-check"><input id="smtp-tls" type="checkbox" checked><span data-i18n="smtpTls">STARTTLS verwenden</span></label></div><div class="settings-actions"><button class="save-settings-button" id="save-mail-settings" type="button" data-i18n="save">Speichern</button><span class="settings-message" id="mail-message"></span></div></section>
        <section class="panel admin-page-card"><div class="panel-header"><div><h2 data-i18n="users">Benutzer</h2><p data-i18n="usersDescription">Konten, Rollen, Gültigkeit und Aktivität.</p></div><input class="admin-search" id="user-search" type="search" placeholder="Benutzer suchen..." data-i18n-placeholder="searchUsers"></div><div class="table-container"><table><thead><tr><th data-i18n="user">Benutzer</th><th data-i18n="role">Rolle</th><th data-i18n="validUntil">Gültig bis</th><th data-i18n="scans">Scans</th><th data-i18n="lastScan">Letzter Scan</th><th data-i18n="status">Status</th><th data-i18n="actions">Aktionen</th></tr></thead><tbody id="users-table"></tbody></table></div></section>
        <section class="panel admin-page-card"><div class="panel-header"><div><h2 data-i18n="scanActivity">Scanaktivität</h2><p data-i18n="scanActivityDescription">Die letzten Scans aller Benutzer.</p></div></div><div class="table-container"><table><thead><tr><th data-i18n="user">Benutzer</th><th data-i18n="domain">Domain</th><th data-i18n="started">Gestartet</th><th data-i18n="finished">Beendet</th><th data-i18n="candidates">Kandidaten</th><th data-i18n="dns">DNS</th><th data-i18n="websites">Websites</th></tr></thead><tbody id="scans-table"></tbody></table></div></section>
    </main>
</div>
<div class="page-modal" id="user-modal" aria-hidden="true"><div class="page-modal-overlay" data-close-modal></div><form class="page-modal-content" id="user-form"><div class="page-modal-header"><div><p class="eyebrow" data-i18n="userAccount">Benutzerkonto</p><h2 id="modal-title" data-i18n="addUser">Benutzer hinzufügen</h2></div><button type="button" class="domain-modal-close" data-close-modal>×</button></div><div class="form-grid"><input type="hidden" id="user-id"><label><span data-i18n="username">Benutzername</span><input id="user-username" required></label><label><span data-i18n="password">Passwort</span><input id="user-password" type="password" minlength="10"><small data-i18n="passwordHint">Mindestens 10 Zeichen.</small></label><label><span data-i18n="role">Rolle</span><select id="user-role"><option value="user" data-i18n="userRole">Benutzer</option><option value="admin" data-i18n="adminRole">Administrator</option></select></label><label><span data-i18n="validUntil">Gültig bis</span><input id="user-valid-until" type="date"><small data-i18n="validityHint">Leer lassen für unbegrenzt.</small></label><label class="modal-check"><input id="user-active" type="checkbox" checked><span data-i18n="activeAccount">Konto aktiv</span></label></div><div class="settings-actions"><button class="save-settings-button" type="submit" data-i18n="save">Speichern</button><button class="delete-button" type="button" data-close-modal data-i18n="cancel">Abbrechen</button><span class="settings-message" id="user-message"></span></div></form></div>
<script src="js/admin-page.js?v=<?php echo rawurlencode((string)filemtime(__DIR__ . '/js/admin-page.js')); ?>"></script>
</body>
</html>
