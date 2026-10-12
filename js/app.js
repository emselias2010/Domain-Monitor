let allDomains = [];
let allProtectedDomains = [];
let renderedDomainsSignature = "";

let currentDetailDomain = "";

let displayedProgress = 0;

let lastProgressStatus = "";

let dashboardScanRunning = null;

const SCAN_SESSION_KEY = "domain-monitor-scan-running";

let scanStartRequested =
    sessionStorage.getItem(
        SCAN_SESSION_KEY
    ) === "1";

let currentUser = null;
let dashboardNoticeTimeout = null;

function updateEasterEggState(domains) {
    const unlocked = domains.some(domain => String(domain.domain || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "") === "eliasems.egg");
    document.getElementById("dashboard-title")?.classList.toggle("easter-egg-dashboard-title", unlocked);
    document.querySelectorAll(".app .nav-item.active").forEach(item => item.classList.toggle("easter-egg-nav-item", unlocked));
}

console.log(atob("ZGV2ZWxvcGVkIGJ5IEVsaWFzIEVtcyAoZWxpYXNlbXMuZWdnKQ=="));

function showDashboardNotice(message, type = "success") {
    const notice = document.getElementById("dashboard-notice");
    if (!notice) return;

    notice.textContent = message;
    notice.className = `dashboard-notice ${type}`;
    notice.hidden = false;

    window.clearTimeout(dashboardNoticeTimeout);
    dashboardNoticeTimeout = window.setTimeout(() => {
        notice.hidden = true;
    }, 4500);
}

function openAuthModal() {
    const plansDialog = document.getElementById("guest-plans-dialog");
    plansDialog?.close();
    plansDialog?.remove();
    const fields = document.getElementById("registration-fields");
    if (fields && !fields.hidden) {
        fields.hidden = true;
        document.getElementById("register-password-confirm").hidden = true;
        document.getElementById("register-email").required = false;
        document.getElementById("register-password-confirm").required = false;
        document.querySelector("#login-form button[type=submit]").textContent = translations[language].loginButton;
        document.getElementById("registration-toggle").textContent = translations[language].register;
        document.getElementById("auth-mode-title").textContent = translations[language].loginMode;
        document.getElementById("auth-mode-description").textContent = translations[language].loginModeDescription;
        document.getElementById("auth-mode").classList.remove("is-registering");
    }
    document.body.classList.add("auth-modal-open");
}

function closeAuthModal() {
    document.body.classList.remove("auth-modal-open");
}

function showPlanStatus(user) {
    const trialEnd = user.pro_until ? new Date(String(user.pro_until).replace(" ", "T")) : null;
    const trialActive = user.role !== "admin" && user.plan === "pro" && trialEnd && trialEnd.getTime() > Date.now();
    if (!trialActive || trialEnd.getTime() - Date.now() > 14 * 86400000) return;
    const existing = document.getElementById("plan-status-dialog");
    existing?.remove();
    const dialog = document.createElement("dialog");
    dialog.id = "plan-status-dialog";
    const days = trialActive ? Math.max(1, Math.ceil((trialEnd.getTime() - Date.now()) / 86400000)) : 0;
    const title = language === "de" ? "Professional ist aktiv" : "Professional is active";
    const text = language === "de" ? `Dein kostenloser Pro-Test läuft noch ${days} ${days === 1 ? "Tag" : "Tage"}. Danach wirst du auf Free zurückgestuft. Schreibe dem Support für ein dauerhaftes Angebot.` : `Your free Pro trial has ${days} ${days === 1 ? "day" : "days"} left. You will move to Free afterwards. Contact support for a permanent offer.`;
    dialog.innerHTML = `<button type="button" class="plan-status-close" aria-label="Close">×</button><p class="guest-kicker">PLAN STATUS</p><h2>${title}</h2><p>${text}</p><a class="support-link" href="mailto:support@example.com?subject=Professional%20Upgrade">support@example.com</a>`;
    document.body.append(dialog);
    dialog.querySelector("button").onclick = () => dialog.close();
    dialog.onclose = () => dialog.remove();
    dialog.showModal();
}

function showPlansDialog() {
    document.getElementById("guest-plans-dialog")?.remove();
    const dialog = document.createElement("dialog");
    dialog.id = "guest-plans-dialog";
    dialog.innerHTML = `<button type="button" class="plan-status-close" aria-label="Close">×</button><p class="guest-kicker">${guestText("plans")}</p><h2>${guestText("afterScan")}</h2><div class="plan-dialog-grid"><article><span class="plan-dialog-label">CHECK</span><h3>${guestText("free")}</h3><strong>0 EUR</strong><p>${guestText("freeDescription")}</p><ul><li>${guestText("freeBenefit1")}</li><li>${guestText("freeBenefit2")}</li><li>${guestText("freeBenefit3")}</li></ul><button type="button" data-dialog-register="free">${guestText("try")}</button></article><article class="plan-dialog-pro"><span class="plan-dialog-label">${guestText("protection")}</span><em>${guestText("proRecommended")}</em><h3>${guestText("professional")}</h3><strong>29 EUR <small>/ Monat</small></strong><p>${guestText("proPitch")}</p><ul><li>${guestText("proBenefit1")}</li><li>${guestText("proBenefit2")}</li><li>${guestText("proBenefit3")}</li><li>${guestText("proBenefit4")}</li><li>${guestText("proBenefit5")}</li></ul><button type="button" data-dialog-register="pro">${guestText("account")}</button></article></div>`;
    document.body.append(dialog);
    dialog.querySelector(".plan-dialog-pro strong small")?.replaceChildren(guestText("priceMonth"));
    dialog.querySelector(".plan-status-close").onclick = () => dialog.close();
    dialog.querySelectorAll("[data-dialog-register]").forEach(button => button.onclick = () => { dialog.close(); openRegistration(button.dataset.dialogRegister); });
    dialog.onclose = () => dialog.remove();
    dialog.showModal();
}

function openRegistration(plan = "free") {
    openAuthModal();
    document.getElementById("register-plan").value = plan;
    const fields = document.getElementById("registration-fields");
    if (fields?.hidden) document.getElementById("registration-toggle")?.click();
    updateAuthPlanSelection(plan);
}

function updateAuthPlanSelection(plan) {
    const selectedPlan = plan === "pro" ? "pro" : "free";
    document.getElementById("register-plan").value = selectedPlan;
    document.querySelectorAll("[data-plan-choice]").forEach(button => {
        button.classList.toggle("is-selected", button.dataset.planChoice === selectedPlan);
    });
    const label = document.getElementById("selected-plan-label");
    if (label) {
        label.textContent = translations[language][selectedPlan === "pro" ? "selectedPro" : "selectedFree"];
    }
}

function renderGuestResults(data) {
    const results = document.getElementById("guest-result-list");
    document.getElementById("guest-results-title").textContent = data.domain;
    document.getElementById("guest-result-count").textContent = data.candidates;
    document.getElementById("guest-result-risk").textContent = data.registered;
    document.getElementById("guest-result-websites").textContent = data.results.filter(result => result.website_active).length;
    document.getElementById("guest-result-logins").textContent = data.results.filter(result => result.login_found).length;
    results.innerHTML = renderGuestTable(data.results);
    document.getElementById("guest-results").hidden = false;
}

function renderGuestTable(scanResults) {
    const riskOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    const sortedResults = [...scanResults].sort((left, right) => (riskOrder[right.risk_level] || 2) - (riskOrder[left.risk_level] || 2));
    return sortedResults.length ? `<div class="guest-table-wrap"><table><thead><tr><th>${guestText("domain")}</th><th>${guestText("risk")}</th><th>${guestText("dns")}</th><th>${guestText("website")}</th><th>${guestText("http")}</th><th>${guestText("title")}</th><th>${guestText("loginLabel")}</th></tr></thead><tbody>${sortedResults.slice(0, 250).map(result => { const riskLevel = ["critical", "high", "medium", "low"].includes(result.risk_level) ? result.risk_level : "medium"; const risk = guestText(`${riskLevel}RiskLabel`); return `<tr><td><strong>${escapeHtml(result.domain)}</strong></td><td><span class="guest-risk-badge guest-risk-${riskLevel}">${risk}</span></td><td><span class="guest-status guest-status-good">${guestText("active")}</span></td><td><span class="guest-status guest-status-${result.website_active ? "good" : "muted"}">${result.website_active ? guestText("yes") : guestText("no")}</span></td><td>${result.http_status || "-"}</td><td class="guest-title-cell">${escapeHtml(result.title || guestText("noTitle"))}</td><td><span class="guest-status guest-status-${result.login_found ? "warning" : "muted"}">${result.login_found ? guestText("yes") : guestText("no")}</span></td></tr>`; }).join("")}</tbody></table></div>${sortedResults.length > 250 ? `<p class="guest-result-limit">${guestText("showingFirst")} 250</p>` : ""}` : `<div class="guest-empty-result"><strong>${guestText("nothingFound")}</strong><span>${guestText("nothingFoundHint")}</span></div>`;
}

function setupGuestExperience() {
    document.querySelectorAll("[data-open-auth]").forEach(button => button.addEventListener("click", openAuthModal));
    document.querySelectorAll("[data-open-plans]").forEach(button => button.addEventListener("click", showPlansDialog));
    document.querySelector("[data-close-auth]")?.addEventListener("click", closeAuthModal);
    document.addEventListener("click", event => {
        const registerButton = event.target.closest("[data-open-register]");
        if (registerButton) openRegistration(registerButton.dataset.plan || "free");
    });
    document.getElementById("guest-scan-form")?.addEventListener("submit", async event => {
        event.preventDefault();
        const form = event.currentTarget;
        const button = form.querySelector("button");
        const progress = document.getElementById("guest-progress");
        const progressFill = document.getElementById("guest-progress-fill");
        const progressLabel = document.getElementById("guest-progress-label");
        const phaseList = document.getElementById("guest-phase-list");
        const scanResults = [];
        progress.hidden = false;
        phaseList.hidden = false;
        progressFill.style.width = "2%";
        progressLabel.textContent = guestText("preparing");
        button.disabled = true;
        button.classList.add("scanning-active");
        try {
            const response = await fetch("api/guest_scan.php", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: document.getElementById("guest-domain").value }) });
            if (!response.ok || !response.body) throw new Error((await response.text()) || "Scan failed");
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";
            let complete = null;
            const handleEvent = event => {
                if (event.type === "phase") {
                    const phase = event.phase;
                    document.querySelectorAll("#guest-phase-list [data-phase]").forEach(item => item.classList.toggle("is-active", item.dataset.phase === phase));
                    const labels = { candidates: "phaseCandidates", dns: "phaseDns", websites: "phaseWebsites", report: "phaseReport" };
                    const current = Number(event.current || 0);
                    const total = Number(event.total || 1);
                    const phaseProgress = Math.min(1, current / total);
                    const ranges = { candidates: [2, 12], dns: [12, 58], websites: [58, 94], report: [94, 99] };
                    const range = ranges[phase] || [2, 99];
                    progressFill.style.width = `${range[0] + (range[1] - range[0]) * phaseProgress}%`;
                    progressLabel.textContent = phase === "websites" ? `${current.toLocaleString()} / ${total.toLocaleString()} · ${guestText("websitesChecked")}` : `${current.toLocaleString()} / ${total.toLocaleString()} · ${guestText("stillChecking")}`;
                } else if (event.type === "result") {
                    scanResults.push(event.result);
                    document.getElementById("guest-results").hidden = false;
                    document.getElementById("guest-results-title").textContent = event.domain;
                    document.getElementById("guest-result-list").innerHTML = renderGuestTable(scanResults);
                    document.getElementById("guest-result-risk").textContent = scanResults.length;
                    document.getElementById("guest-result-websites").textContent = scanResults.filter(result => result.website_active).length;
                    document.getElementById("guest-result-logins").textContent = scanResults.filter(result => result.login_found).length;
                } else if (event.type === "error") {
                    throw new Error(event.message || guestText("scanFailed"));
                } else if (event.type === "complete") {
                    complete = event;
                }
            };
            while (true) {
                const chunk = await reader.read();
                buffer += decoder.decode(chunk.value || new Uint8Array(), { stream: !chunk.done });
                const lines = buffer.split("\n");
                buffer = lines.pop();
                lines.forEach(line => {
                    if (!line.trim()) return;
                    try {
                        handleEvent(JSON.parse(line));
                    } catch (error) {
                        throw new Error(error.message || guestText("scanFailed"));
                    }
                });
                if (chunk.done) break;
            }
            if (buffer.trim()) {
                try {
                    handleEvent(JSON.parse(buffer));
                } catch (error) {
                    throw new Error(error.message || guestText("scanFailed"));
                }
            }
            if (!complete) throw new Error("Scan failed");
            complete.results = complete.results || scanResults;
            renderGuestResults(complete);
            progressFill.style.width = "100%";
            progressLabel.textContent = `${complete.candidates.toLocaleString()} / ${complete.candidates.toLocaleString()}`;
            document.querySelectorAll("#guest-phase-list [data-phase]").forEach(item => item.classList.add("is-complete"));
            document.getElementById("guest-results").scrollIntoView({ behavior: "smooth", block: "start" });
            document.querySelector(".guest-plans")?.classList.add("guest-plans-highlight");
            showPlansDialog();
        } catch (error) {
            progressLabel.textContent = language === "de"
                ? "Scan fehlgeschlagen, bitte erneut versuchen."
                : "Scan failed, try again.";
        } finally {
            button.disabled = false;
            button.classList.remove("scanning-active");
        }
    });
}

setupGuestExperience();

(() => {
    const key = "domain-monitor-toggle-state";
    const text = value => atob(value);
    const show = () => {
        document.getElementById("dashboard-title")?.classList.add("easter-egg-dashboard-title");
        const dialog = document.createElement("dialog");
        dialog.className = "site-notice-dialog";
        dialog.innerHTML = `<div class="site-notice-icon">✦</div><p class="site-notice-label">SECRET UNLOCKED</p><h2>You found the Easter Egg</h2><p>${text("ZGV2ZWxvcGVkIGJ5IGVsaWFzIGVtcw==")}</p><button type="button">Awesome</button>`;
        const style = document.createElement("style");
        style.textContent = `.site-notice-dialog{position:fixed;top:50vh;left:50vw;transform:translate(-50%,-50%);margin:0;width:min(360px,calc(100vw - 40px));padding:32px 28px 26px;border:1px solid #007aff;border-radius:12px;color:#1d1d1f;background:#fff;box-shadow:0 12px 32px rgba(0,0,0,.16);font-family:inherit;text-align:center;animation:site-notice-pop .22s ease-out}.site-notice-dialog::backdrop{background:rgba(29,29,31,.38)}.site-notice-icon{display:grid;place-items:center;width:54px;height:54px;margin:0 auto 18px;border-radius:50%;color:#fff;background:#007aff;font-size:28px}.site-notice-label{margin:0 0 8px;color:#005ecb;font-size:11px;font-weight:700;letter-spacing:2px}.site-notice-dialog h2{margin:0;font-size:23px}.site-notice-dialog p:not(.site-notice-label){margin:10px 0 24px;color:#6e6e73}.site-notice-dialog button{border:0;border-radius:8px;padding:11px 22px;color:#fff;background:#007aff;cursor:pointer;font:inherit;font-weight:700}.site-notice-dialog button:hover{background:#005ecb}@keyframes site-notice-pop{from{opacity:0;transform:translate(-50%,-50%) scale(.94)}to{opacity:1;transform:translate(-50%,-50%) scale(1)}}`;
        document.head.append(style); document.body.append(dialog);
        dialog.querySelector("button").onclick = () => dialog.close();
        dialog.onclose = () => { dialog.remove(); style.remove(); };
        dialog.showModal();
    };
    window.showEasterEgg = show;
})();

const translations = {
    de: {
        loginTitle: "Domain Monitor",
        loginSubtitle: "Melde dich an, um dein Sicherheitsdashboard zu öffnen.",
        authKicker: "DOMAIN MONITOR",
        loginMode: "Anmelden",
        loginModeDescription: "Öffne dein bestehendes Sicherheitsdashboard.",
        registerMode: "Konto anlegen",
        registerModeDescription: "Wähle deinen Plan und starte mit dem Schutz deiner Domains.",
        choosePlan: "Plan für dein neues Konto",
        freePlanShort: "50.000 Kandidaten · 2 Domains",
        proPlanShort: "1.000.000 Kandidaten · Automatisierung",
        selectedFree: "Free ausgewählt: manuelle Scans für den unkomplizierten Einstieg.",
        selectedPro: "Professional ausgewählt: laufender Schutz mit Automatisierung und Alerts.",
        loginButton: "Anmelden",
        register: "Registrieren",
        email: "E-Mail",
        confirmPassword: "Passwort wiederholen",
        username: "Benutzername",
        password: "Passwort",
        logout: "Abmelden",
        adminTitle: "Adminpanel",
        adminPanel: "Admin Bereich",
        adminSettings: "Admin Bereich",
        adminSubtitle: "Benutzer und Scanaktivität",
        createUser: "Benutzer anlegen",
        languageLabel: "Sprache",
        logout: "Abmelden",
        dashboard: "Dashboard",
        dashboardLabel: "DASHBOARD",
        dashboardSubtitle: "Monitor your domains.",
        critical: "Kritisch",
        high: "Hoch",
        medium: "Mittel",
        low: "Niedrig",
        riskOverview: "Risikoübersicht",
        lastScan: "Letzter Scan",
        candidates: "Kandidaten",
        dnsActive: "DNS aktiv",
        websitesOnline: "Websites online",
        lastScanToday: "Letzter Scan: heute, 17:02",
        protectedDomains: "Geschützte Domains",
        excludedDomains: "Ausgeschlossene Domains",
        discoveredDomains: "Gefundene Domains",
        scanHistory: "Scanverlauf",
        settings: "Einstellungen",
        startScan: "Scan starten",
        stopScan: "Scan stoppen",
        settingsTitle: "Automatische Scans",
        settingsSubtitle: "Automatische Domain-Scans konfigurieren",
        timezoneSetting: "Zeitzone",
        timezoneDescription: "Wird für die Planung automatischer Scans verwendet.",
        weekendSetting: "Wochenendpause",
        weekendDescription: "Automatische Scans am Samstag und Sonntag pausieren.",
        hour: "Stunde",
        hours: "Stunden",
        monitoringActive: "Überwachung aktiv",
        protectedDescription: "Domains unter Überwachung",
        discoveredDescription: "Gefundene ähnliche Domains",
        activeWebsites: "Aktive Websites",
        activeWebsitesDescription: "Derzeit online erreichbare Websites",
        highRisk: "Hohes Risiko",
        highRiskDescription: "Domains mit Handlungsbedarf",
        websiteStatus: "Websites online",
        scanStarting: "Scan wird gestartet...",
        preparingScanner: "Scanner wird vorbereitet",
        starting: "Wird gestartet...",
        generatingCandidates: "Kandidaten werden erzeugt...",
        dnsChecks: "Phase 1/3 | DNS-Prüfungen",
        websiteChecks: "Phase 2/3 | Website-Prüfungen",
        rdapChecks: "Phase 3/3 | RDAP",
        scanFinished: "Scan abgeschlossen",
        scanCancelled: "Scan abgebrochen",
        scanError: "Scanfehler",
        noScanRunning: "Kein Scan aktiv",
        ready: "Bereit",
        scannerReady: "Scanner bereit"
        ,noProtectedDomains: "Scan abgeschlossen. Bitte zuerst eine Protected Domain hinzufügen."
    },
    en: {
        loginTitle: "Domain Monitor",
        loginSubtitle: "Sign in to your security dashboard.",
        authKicker: "DOMAIN MONITOR",
        loginMode: "Sign in",
        loginModeDescription: "Open your existing security dashboard.",
        registerMode: "Create account",
        registerModeDescription: "Choose your plan and start protecting your domains.",
        choosePlan: "Plan for your new account",
        freePlanShort: "50,000 candidates · 2 domains",
        proPlanShort: "1,000,000 candidates · automation",
        selectedFree: "Free selected: manual scans for a simple start.",
        selectedPro: "Professional selected: continuous protection with automation and alerts.",
        loginButton: "Sign in",
        register: "Register",
        email: "Email",
        confirmPassword: "Repeat password",
        username: "Username",
        password: "Password",
        logout: "Logout",
        adminTitle: "Admin Panel",
        adminPanel: "Admin Panel",
        adminSettings: "Admin Area",
        adminSubtitle: "Users and scan activity",
        createUser: "Create User",
        languageLabel: "Language",
        dashboard: "Dashboard",
        dashboardLabel: "DASHBOARD",
        dashboardSubtitle: "Monitor your domains.",
        critical: "Critical",
        high: "High",
        medium: "Medium",
        low: "Low",
        riskOverview: "Risk overview",
        lastScan: "Last scan",
        candidates: "Candidates",
        dnsActive: "DNS active",
        websitesOnline: "Websites online",
        lastScanToday: "Last scan: today, 17:02",
        protectedDomains: "Protected Domains",
        excludedDomains: "Excluded Domains",
        discoveredDomains: "Discovered Domains",
        scanHistory: "Scan History",
        settings: "Settings",
        startScan: "Start Scan",
        stopScan: "Stop Scan",
        settingsTitle: "Automatic Scanning",
        settingsSubtitle: "Configure automatic domain scans",
        timezoneSetting: "Time zone",
        timezoneDescription: "Used for scheduling automatic scans.",
        weekendSetting: "Weekend pause",
        weekendDescription: "Pause automatic scans on Saturday and Sunday.",
        hour: "Hour",
        hours: "Hours",
        monitoringActive: "Monitoring active",
        protectedDescription: "Domains under monitoring",
        discoveredDescription: "Lookalike domains found",
        activeWebsites: "Active websites",
        activeWebsitesDescription: "Websites currently online",
        highRisk: "High risk",
        highRiskDescription: "Domains requiring attention",
        websiteStatus: "Websites online",
        scanStarting: "Starting scan...",
        preparingScanner: "Preparing scanner",
        starting: "Starting...",
        generatingCandidates: "Generating candidates...",
        dnsChecks: "Phase 1/3 | DNS checks",
        websiteChecks: "Phase 2/3 | Website checks",
        rdapChecks: "Phase 3/3 | RDAP",
        scanFinished: "Scan finished",
        scanCancelled: "Scan cancelled",
        scanError: "Scan error",
        noScanRunning: "No scan running",
        ready: "Ready",
        scannerReady: "Scanner ready"
        ,noProtectedDomains: "Scan finished. Add a protected domain first."
    }
};

let language = localStorage.getItem("domain-monitor-language") || "de";

const mobileMenuButton = document.getElementById("mobile-menu-button");
const mainSidebar = document.getElementById("main-sidebar");

mobileMenuButton?.addEventListener("click", () => {
    const isOpen = document.body.classList.toggle("mobile-menu-open");
    mobileMenuButton.setAttribute("aria-expanded", String(isOpen));
});

mainSidebar?.addEventListener("click", event => {
    if (event.target.closest("a")) {
        document.body.classList.remove("mobile-menu-open");
        mobileMenuButton?.setAttribute("aria-expanded", "false");
    }
});

document.addEventListener("click", event => {
    if (
        document.body.classList.contains("mobile-menu-open") &&
        !event.target.closest("#main-sidebar") &&
        !event.target.closest("#mobile-menu-button")
    ) {
        document.body.classList.remove("mobile-menu-open");
        mobileMenuButton?.setAttribute("aria-expanded", "false");
    }
});

function applyLanguage() {
    const dictionary = translations[language];
    document.documentElement.lang = language;

    document.querySelectorAll("[data-i18n]").forEach(element => {
        const key = element.dataset.i18n;
        if (dictionary[key]) element.textContent = dictionary[key];
    });

    document.querySelectorAll("[data-i18n-placeholder]").forEach(element => {
        const key = element.dataset.i18nPlaceholder;
        if (dictionary[key]) element.placeholder = dictionary[key];
    });

    document.querySelectorAll(".language-toggle-current").forEach(element => element.textContent = language.toUpperCase());
    document.querySelectorAll(".language-toggle-target").forEach(element => element.textContent = language === "de" ? "EN" : "DE");
    document.querySelectorAll("[data-guest-i18n]").forEach(element => {
        const value = guestText(element.dataset.guestI18n);
        if (value) element.textContent = value;
    });
    document.querySelectorAll("[data-guest-placeholder]").forEach(element => {
        element.placeholder = guestText(element.dataset.guestPlaceholder);
    });
    document.querySelectorAll("[data-phase-label]").forEach(element => {
        element.textContent = guestText(element.dataset.phaseLabel);
    });
    const guestDomainInput = document.getElementById("guest-domain");
    if (guestDomainInput) guestDomainInput.placeholder = guestText("domainPlaceholder");
    const registrationFields = document.getElementById("registration-fields");
    const registrationToggle = document.getElementById("registration-toggle");
    const loginSubmit = document.querySelector("#login-form button[type=submit]");
    if (registrationFields && registrationToggle && loginSubmit) {
        const registering = !registrationFields.hidden;
        loginSubmit.textContent = registering ? dictionary.register : dictionary.loginButton;
        registrationToggle.textContent = registering ? dictionary.loginButton : dictionary.register;
        const modeTitle = document.getElementById("auth-mode-title");
        const modeDescription = document.getElementById("auth-mode-description");
        document.getElementById("auth-mode")?.classList.toggle("is-registering", registering);
        if (modeTitle) modeTitle.textContent = registering ? dictionary.registerMode : dictionary.loginMode;
        if (modeDescription) modeDescription.textContent = registering ? dictionary.registerModeDescription : dictionary.loginModeDescription;
        if (registering) updateAuthPlanSelection(document.getElementById("register-plan")?.value || "pro");
    }

    const textPairs = {
        "Dashboard": dictionary.dashboard,
        "Protected Domains": dictionary.protectedDomains,
        "Geschützte Domains": dictionary.protectedDomains,
        "Excluded Domains": dictionary.excludedDomains,
        "Ausgeschlossene Domains": dictionary.excludedDomains,
        "Discovered Domains": dictionary.discoveredDomains,
        "Gefundene Domains": dictionary.discoveredDomains,
        "Scan History": dictionary.scanHistory,
        "Scanverlauf": dictionary.scanHistory,
        "Settings": dictionary.settings,
        "Einstellungen": dictionary.settings,
        "Monitoring active": dictionary.monitoringActive,
        "Überwachung aktiv": dictionary.monitoringActive,
        "↻ Start Scan": `↻ ${dictionary.startScan}`,
        "↻ Scan starten": `↻ ${dictionary.startScan}`,
        "■ Stop Scan": `■ ${dictionary.stopScan}`,
        "■ Scan stoppen": `■ ${dictionary.stopScan}`,
        "Last scan": language === "de" ? "Letzter Scan" : "Last scan",
        "Risk Overview": language === "de" ? "Risikoübersicht" : "Risk Overview",
        "Current threat distribution": language === "de" ? "Aktuelle Risikoverteilung" : "Current threat distribution",
        "Last Scan": language === "de" ? "Letzter Scan" : "Last Scan",
        "Scan statistics": language === "de" ? "Scanstatistik" : "Scan statistics",
        "Candidates": language === "de" ? "Kandidaten" : "Candidates",
        "DNS Active": language === "de" ? "DNS aktiv" : "DNS Active",
        "Websites Online": language === "de" ? "Websites online" : "Websites Online",
        "Websites currently online": language === "de" ? "Derzeit online erreichbare Websites" : "Websites currently online",
        "Domains under monitoring": language === "de" ? "Domains unter Überwachung" : "Domains under monitoring",
        "Lookalike domains found": language === "de" ? "Gefundene ähnliche Domains" : "Lookalike domains found",
        "Active Websites": language === "de" ? "Aktive Websites" : "Active Websites",
        "High Risk": language === "de" ? "Hohes Risiko" : "High Risk",
        "Domains requiring attention": language === "de" ? "Domains mit Handlungsbedarf" : "Domains requiring attention",
        "Domain": language === "de" ? "Domain" : "Domain",
        "Risk": language === "de" ? "Risiko" : "Risk",
        "Score": language === "de" ? "Punktzahl" : "Score",
        "Website": language === "de" ? "Website" : "Website",
        "Login": language === "de" ? "Login" : "Login",
        "Company": language === "de" ? "Unternehmen" : "Company",
        "For Sale": language === "de" ? "Zu verkaufen" : "For Sale",
        "HTTP": language === "de" ? "HTTP" : "HTTP",
        "Last Seen": language === "de" ? "Zuletzt gesehen" : "Last Seen",
        "Added": language === "de" ? "Hinzugefügt" : "Added",
        "Registered": language === "de" ? "Registriert" : "Registered",
        "Registration": language === "de" ? "Registrierung" : "Registration",
        "Domain Age": language === "de" ? "Domainalter" : "Domain Age",
        "Registrar": language === "de" ? "Registrar" : "Registrar",
        "IP Addresses": language === "de" ? "IP-Adressen" : "IP Addresses",
        "Final URL": language === "de" ? "Endgültige URL" : "Final URL",
        "Redirect": language === "de" ? "Weiterleitung" : "Redirect",
        "Detection": language === "de" ? "Erkennung" : "Detection",
        "Company in HTML": language === "de" ? "Unternehmen im HTML" : "Company in HTML",
        "Company in Header": language === "de" ? "Unternehmen im Header" : "Company in Header",
        "Page Title": language === "de" ? "Seitentitel" : "Page Title",
        "Monitoring": language === "de" ? "Überwachung" : "Monitoring",
        "First Seen": language === "de" ? "Zuerst gesehen" : "First Seen",
        "Status": language === "de" ? "Status" : "Status",
        "Scan": language === "de" ? "Scan" : "Scan",
        "Critical": language === "de" ? "Kritisch" : "Critical",
        "High": language === "de" ? "Hoch" : "High",
        "Medium": language === "de" ? "Mittel" : "Medium",
        "Low": language === "de" ? "Niedrig" : "Low",
        "Domains monitored for impersonation and phishing": language === "de" ? "Domains auf Nachahmung und Phishing überwachen" : "Domains monitored for impersonation and phishing",
        "Excluded Company Domains": language === "de" ? "Ausgeschlossene Unternehmensdomains" : "Excluded Company Domains",
        "These domains and their subdomains are excluded from scans": language === "de" ? "Diese Domains und Subdomains werden von Scans ausgeschlossen" : "These domains and their subdomains are excluded from scans",
        "Automatic Scanning": language === "de" ? "Automatische Scans" : "Automatic Scanning",
        "Configure automatic domain scans": language === "de" ? "Automatische Domain-Scans konfigurieren" : "Configure automatic domain scans",
        "Automatic scanning": language === "de" ? "Automatische Überwachung" : "Automatic scanning",
        "Automatically start scans at the configured interval.": language === "de" ? "Scans automatisch im festgelegten Intervall starten." : "Automatically start scans at the configured interval.",
        "Scan interval": language === "de" ? "Scanintervall" : "Scan interval",
        "How often the scanner runs.": language === "de" ? "Wie oft der Scanner läuft." : "How often the scanner runs.",
        "Next scheduled scan": language === "de" ? "Nächster geplanter Scan" : "Next scheduled scan",
        "Next automatic scan.": language === "de" ? "Nächster automatischer Scan." : "Next automatic scan.",
        "Save Settings": language === "de" ? "Einstellungen speichern" : "Save Settings",
        "Discovered Domains": language === "de" ? "Gefundene Domains" : "Discovered Domains",
        "Potentially suspicious domains": language === "de" ? "Potenziell verdächtige Domains" : "Potentially suspicious domains",
        "Search domain...": language === "de" ? "Domain suchen..." : "Search domain...",
        "All Risk Levels": language === "de" ? "Alle Risikostufen" : "All Risk Levels",
        "Scan History": language === "de" ? "Scanverlauf" : "Scan History",
        "Previous monitoring scans": language === "de" ? "Frühere Überwachungsscans" : "Previous monitoring scans",
        "Delete all scans": language === "de" ? "Alle Scans löschen" : "Delete all scans",
        "Started": language === "de" ? "Gestartet" : "Started",
        "Finished": language === "de" ? "Beendet" : "Finished",
        "Websites": language === "de" ? "Websites" : "Websites",
        "Loading...": language === "de" ? "Wird geladen..." : "Loading...",
        "Ready": language === "de" ? "Bereit" : "Ready",
        "No scan running": language === "de" ? "Kein Scan aktiv" : "No scan running",
        "Scanner ready": language === "de" ? "Scanner bereit" : "Scanner ready",
        "No domains found.": language === "de" ? "Keine Domains gefunden." : "No domains found.",
        "No protected domains configured.": language === "de" ? "Keine geschützten Domains konfiguriert." : "No protected domains configured.",
        "No company domains excluded.": language === "de" ? "Keine Unternehmensdomains ausgeschlossen." : "No company domains excluded.",
        "Failed to load domains.": language === "de" ? "Domains konnten nicht geladen werden." : "Failed to load domains.",
        "Failed to load protected domains.": language === "de" ? "Geschützte Domains konnten nicht geladen werden." : "Failed to load protected domains.",
        "Failed to load excluded domains.": language === "de" ? "Ausgeschlossene Domains konnten nicht geladen werden." : "Failed to load excluded domains.",
        "No scans yet.": language === "de" ? "Noch keine Scans vorhanden." : "No scans yet.",
        "Please enter a domain.": language === "de" ? "Bitte eine Domain eingeben." : "Please enter a domain.",
        "Domain excluded from scans.": language === "de" ? "Domain von Scans ausgeschlossen." : "Domain excluded from scans.",
        "Security Intelligence": language === "de" ? "Sicherheitsinformationen" : "Security Intelligence",
        "Risk Score": language === "de" ? "Risikoscore" : "Risk Score",
        "Risk Level": language === "de" ? "Risikostufe" : "Risk Level"
        ,"/ Monat": language === "de" ? "/ Monat" : "/ month"
    };

    Object.assign(textPairs, {
        "User": language === "de" ? "Benutzer" : "User",
        "Role": language === "de" ? "Rolle" : "Role",
        "Created": language === "de" ? "Erstellt" : "Created",
        "Actions": language === "de" ? "Aktionen" : "Actions",
        "Status": language === "de" ? "Status" : "Status",
        "Running": language === "de" ? "Läuft" : "Running",
        "Temporary password": language === "de" ? "Temporäres Passwort" : "Temporary password",
        "Create User": language === "de" ? "Benutzer anlegen" : "Create User",
        "Add Domain": language === "de" ? "Domain hinzufügen" : "Add Domain",
        "Exclude Domain": language === "de" ? "Domain ausschließen" : "Exclude Domain",
        "Every hour": language === "de" ? "Jede Stunde" : "Every hour",
        "Every 6 hours": language === "de" ? "Alle 6 Stunden" : "Every 6 hours",
        "Every 12 hours": language === "de" ? "Alle 12 Stunden" : "Every 12 hours",
        "Every 24 hours": language === "de" ? "Alle 24 Stunden" : "Every 24 hours",
        "Every 48 hours": language === "de" ? "Alle 48 Stunden" : "Every 48 hours",
        "Once a week": language === "de" ? "Einmal pro Woche" : "Once a week",
        "ACTIVE": language === "de" ? "AKTIV" : "ACTIVE",
        "OFFLINE": language === "de" ? "OFFLINE" : "OFFLINE",
        "ONLINE": language === "de" ? "ONLINE" : "ONLINE",
        "FOUND": language === "de" ? "GEFUNDEN" : "FOUND",
        "NONE": language === "de" ? "KEINE" : "NONE",
        "FOR SALE?": language === "de" ? "ZU VERKAUFEN?" : "FOR SALE?",
        "NO": language === "de" ? "NEIN" : "NO"
    });

    if (language === "en") {
        Object.assign(textPairs, {
            "Letzter Scan": "Last scan",
            "Risikoübersicht": "Risk Overview",
            "Aktuelle Risikoverteilung": "Current threat distribution",
            "Scanstatistik": "Scan statistics",
            "Kandidaten": "Candidates",
            "DNS aktiv": "DNS Active",
            "Kritisch": "Critical",
            "Hoch": "High",
            "Mittel": "Medium",
            "Niedrig": "Low",
            "Domains auf Nachahmung und Phishing überwachen": "Domains monitored for impersonation and phishing",
            "Ausgeschlossene Unternehmensdomains": "Excluded Company Domains",
            "Automatische Scans": "Automatic Scanning",
            "Automatische Domain-Scans konfigurieren": "Configure automatic domain scans",
            "Automatische Überwachung": "Automatic scanning",
            "Scans automatisch im festgelegten Intervall starten.": "Automatically start scans at the configured interval.",
            "Scanintervall": "Scan interval",
            "Wie oft der Scanner läuft.": "How often the scanner runs.",
            "Nächster geplanter Scan": "Next scheduled scan",
            "Nächster automatischer Scan.": "Next automatic scan.",
            "Einstellungen speichern": "Save Settings",
            "Potenziell verdächtige Domains": "Potentially suspicious domains",
            "Domain suchen...": "Search domain...",
            "Alle Risikostufen": "All Risk Levels",
            "Frühere Überwachungsscans": "Previous monitoring scans",
            "Alle Scans löschen": "Delete all scans",
            "Gestartet": "Started",
            "Beendet": "Finished",
            "Wird geladen...": "Loading...",
            "Bereit": "Ready",
            "Kein Scan aktiv": "No scan running",
            "Scanner bereit": "Scanner ready"
        });
    }

    document.querySelectorAll("body *").forEach(element => {
        element.childNodes.forEach(node => {
            if (node.nodeType === Node.TEXT_NODE) {
                const value = node.nodeValue.trim();
                if (textPairs[value]) node.nodeValue = node.nodeValue.replace(value, textPairs[value]);
            }
        });
    });
}

const guestTranslations = {
    de: { login: "Einloggen", kicker: "IT-SICHERHEIT / DOMAIN MONITORING", headline: "Schützen Sie, was wirklich zählt.", intro: "Prüfen Sie jetzt kostenlos, ob Lookalike-Domains Ihre Marke imitieren. Der Gastscan bleibt privat und wird nach dem Aktualisieren gelöscht.", domainLabel: "Ihre Domain", scan: "Scan starten", guestHint: "Kein Konto erforderlich. Gastscans prüfen bis zu 15.000 Domains.", live: "LIVE CHECK", risk: "Markenrisiko", signals: "DNS, Login- und Support-Muster", report: "SCAN REPORT", result: "Ergebnis", save: "Ergebnis speichern", similar: "ähnliche Domains geprüft", active: "mit aktivem DNS", plans: "IHRE SCHUTZOPTIONEN", plansTitle: "Monitoring, das mit Ihrem Unternehmen wächst.", plansIntro: "Starten Sie mit einem Check und behalten Sie Ihre wichtigsten Domains dauerhaft im Blick.", free: "Free", freeDescription: "Bis zu 50.000 Kandidaten und 2 geschützte Domains.", try: "Kostenlos registrieren", protection: "PROTECTION", professional: "Professional", professionalDescription: "14 Tage gratis testen: bis zu 1.000.000 Kandidaten, 15 geschützte Domains und automatische Scans.", account: "Pro ausprobieren", scanning: "Scan läuft...", reportReady: "Report erstellt. Speichern Sie ihn mit einem Konto.", dnsActive: "DNS aktiv", noDns: "Keine DNS-Antwort", more: "Mehr als ein Check?", moreDescription: "Speichern Sie Reports oder starten Sie dauerhaftes Monitoring.", buy: "An support@example.com schreiben", contact: "Professional anfragen" },
    en: { login: "Sign in", kicker: "IT SECURITY / DOMAIN MONITORING", headline: "Protect what matters most.", intro: "Check for lookalike domains impersonating your brand. Guest scans stay private and disappear after refresh.", domainLabel: "Your domain", scan: "Start scan", guestHint: "No account required. Guest scans check up to 15,000 domains.", live: "LIVE CHECK", risk: "Brand risk", signals: "DNS, login and support patterns", report: "SCAN REPORT", result: "Result", reportIntro: "A clear result overview for your domain.", save: "Save result", similar: "similar domains checked", registered: "with active DNS", loginPages: "login pages found", active: "with active DNS", plans: "YOUR PROTECTION OPTIONS", plansTitle: "Monitoring that grows with your business.", plansIntro: "Start with a check and keep your most important domains in view.", free: "Free", freeDescription: "Up to 50,000 candidates and 2 protected domains.", try: "Register for free", protection: "PROTECTION", professional: "Professional", professionalDescription: "Try free for 14 days: up to 1,000,000 candidates, 15 protected domains and automatic scans.", account: "Try Pro", scanning: "Scan running...", reportReady: "Report ready. Save it with an account.", dnsActive: "DNS active", noDns: "No DNS response", more: "More than a check?", moreDescription: "Save reports or start continuous monitoring.", buy: "Write to support@example.com", contact: "Contact Professional" }
};
function guestText(key) { const fallback = { domainPlaceholder: language === "de" ? "ihre-firma.at" : "your-company.com", websiteActive: language === "de" ? "Website aktiv:" : "Website active:", dnsOnly: language === "de" ? "DNS aktiv" : "DNS active", nothingFound: language === "de" ? "Nichts gefunden" : "Nothing found", nothingFoundHint: language === "de" ? "Probieren Sie den Free-Plan für mehr Domains." : "Try the Free plan for more domains.", noTitle: language === "de" ? "Kein Seitentitel" : "No page title", loginFound: language === "de" ? "Login gefunden" : "Login found", noLogin: language === "de" ? "Kein Login" : "No login", preparing: language === "de" ? "Scanner wird vorbereitet" : "Preparing scanner", stillChecking: language === "de" ? "Prüfung läuft" : "Still checking", websitesChecked: language === "de" ? "Websites geprüft" : "Websites checked", phaseCandidates: language === "de" ? "Phase 1/3 · Kandidaten" : "Phase 1/3 · Candidates", phaseDns: language === "de" ? "Phase 2/3 · DNS-Prüfungen" : "Phase 2/3 · DNS checks", phaseWebsites: language === "de" ? "Phase 3/3 · Websites prüfen" : "Phase 3/3 · Checking websites", phaseReport: language === "de" ? "Report wird erstellt" : "Building report", scanFailed: language === "de" ? "Gastscan fehlgeschlagen" : "Guest scan failed", domain: language === "de" ? "Domain" : "Domain", dns: "DNS", website: language === "de" ? "Website" : "Website", http: "HTTP", title: language === "de" ? "Seitentitel" : "Page title", yes: language === "de" ? "Ja" : "Yes", no: language === "de" ? "Nein" : "No", websites: language === "de" ? "Websites aktiv" : "Websites active", afterScan: language === "de" ? "Schützen Sie Ihre Ergebnisse dauerhaft." : "Keep your results protected.", freeBenefit1: language === "de" ? "Bis zu 50.000 Kandidaten" : "Up to 50,000 candidates", freeBenefit2: language === "de" ? "2 Protected Domains" : "2 protected domains", freeBenefit3: language === "de" ? "Manuelle Scans" : "Manual scans", proBenefit1: language === "de" ? "Bis zu 1.000.000 Kandidaten" : "Up to 1,000,000 candidates", proBenefit2: language === "de" ? "15 Protected Domains" : "15 protected domains", proBenefit3: language === "de" ? "Automatische Scans und Alerts" : "Automatic scans and alerts" }; return guestTranslations[language]?.[key] || fallback[key] || guestTranslations.de[key] || key; }

guestTranslations.de.reportIntro = "Klare Trefferübersicht für Ihre Domain.";
guestTranslations.en.reportIntro = "A clear result overview for your domain.";
guestTranslations.de.registered = "mit aktivem DNS";
guestTranslations.en.registered = "with active DNS";
guestTranslations.de.loginPages = "Login-Seiten erkannt";
guestTranslations.en.loginPages = "login pages found";
guestTranslations.de.highRiskLabel = "Hohes Risiko";
guestTranslations.en.highRiskLabel = "High risk";
guestTranslations.de.mediumRiskLabel = "Mittleres Risiko";
guestTranslations.en.mediumRiskLabel = "Medium risk";
guestTranslations.de.showingFirst = "Angezeigt werden die ersten";
guestTranslations.en.showingFirst = "Showing the first";
guestTranslations.de.risk = "Risiko";
guestTranslations.en.risk = "Risk";
guestTranslations.de.active = "Aktiv";
guestTranslations.en.active = "Active";
guestTranslations.de.scanScope = "Demo-Scan: verkürzter Schnellcheck mit bis zu 15.000 Kandidaten. Nicht alle Funktionen des echten Scans sind enthalten; die Ergebnisse können ungenau sein.";
guestTranslations.en.scanScope = "Demo scan: shortened quick check with up to 15,000 candidates. It does not include all features of the full scan, so results may be inaccurate.";
guestTranslations.de.riskLegend = "Risiko";
guestTranslations.en.riskLegend = "Risk";
guestTranslations.de.criticalRiskLabel = "Kritisch";
guestTranslations.en.criticalRiskLabel = "Critical";
guestTranslations.de.lowRiskLabel = "Niedrig";
guestTranslations.en.lowRiskLabel = "Low";
guestTranslations.de.loginLabel = "Login";
guestTranslations.en.loginLabel = "Login";
guestTranslations.de.capabilitiesKicker = "MEHR ALS EIN DOMAIN-CHECK";
guestTranslations.en.capabilitiesKicker = "MORE THAN A DOMAIN CHECK";
guestTranslations.de.capabilitiesTitle = "Von der ersten Ähnlichkeit bis zum verwertbaren Sicherheitsbefund.";
guestTranslations.en.capabilitiesTitle = "From the first lookalike to an actionable security finding.";
guestTranslations.de.capabilitiesIntro = "Domain Monitor verbindet Kandidatengenerierung, technische Prüfungen und klare Priorisierung in einem Arbeitsbereich.";
guestTranslations.en.capabilitiesIntro = "Domain Monitor combines candidate generation, technical checks and clear prioritization in one workspace.";
guestTranslations.de.capabilityCandidates = "Lookalike-Domains finden";
guestTranslations.en.capabilityCandidates = "Find lookalike domains";
guestTranslations.de.capabilityCandidatesText = "Schreibvarianten, Bindestriche, Subdomains, Wörterbuchbegriffe und verschiedene TLDs machen auch schwer erkennbare Nachahmungen sichtbar.";
guestTranslations.en.capabilityCandidatesText = "Spelling variants, hyphens, subdomains, dictionary terms and different TLDs reveal hard-to-spot impersonations.";
guestTranslations.de.capabilitySignals = "Technische Signale prüfen";
guestTranslations.en.capabilitySignals = "Check technical signals";
guestTranslations.de.capabilitySignalsText = "DNS, IP-Adressen, Erreichbarkeit, HTTP-Status, Seitentitel und Weiterleitungen zeigen, welche Treffer tatsächlich aktiv sind.";
guestTranslations.en.capabilitySignalsText = "DNS, IP addresses, reachability, HTTP status, page titles and redirects show which findings are actually active.";
guestTranslations.de.capabilityRisk = "Risiken priorisieren";
guestTranslations.en.capabilityRisk = "Prioritize risk";
guestTranslations.de.capabilityRiskText = "Login-Erkennung, Markenname in HTML oder Headern, Weiterleitungen und Domainalter fließen in einen nachvollziehbaren Risikoscore ein.";
guestTranslations.en.capabilityRiskText = "Login detection, brand names in HTML or headers, redirects and domain age contribute to a transparent risk score.";
guestTranslations.de.capabilityWorkflow = "Treffer dauerhaft bearbeiten";
guestTranslations.en.capabilityWorkflow = "Work findings over time";
guestTranslations.de.capabilityWorkflowText = "Speichern Sie Scanverläufe, vergleichen Sie Veränderungen, blenden Sie bekannte Domains aus oder überwachen Sie Treffer still weiter.";
guestTranslations.en.capabilityWorkflowText = "Save scan history, compare changes, exclude known domains or keep monitoring findings silently.";
guestTranslations.de.capabilitySchedule = "Automatisch überwachen";
guestTranslations.en.capabilitySchedule = "Monitor automatically";
guestTranslations.de.capabilityScheduleText = "Professional plant Scans in Ihrem Intervall, berücksichtigt Zeitzone und Wochenendpause und hält den nächsten Lauf transparent fest.";
guestTranslations.en.capabilityScheduleText = "Professional schedules scans at your interval, respects time zones and weekend pauses, and keeps the next run visible.";
guestTranslations.de.capabilityAlerts = "Bei Veränderungen reagieren";
guestTranslations.en.capabilityAlerts = "React to changes";
guestTranslations.de.capabilityAlertsText = "Benachrichtigungen machen auf kritische neue Domains und relevante Veränderungen aufmerksam, statt dass Teams Listen manuell prüfen müssen.";
guestTranslations.en.capabilityAlertsText = "Alerts highlight critical new domains and relevant changes, so teams do not have to inspect lists manually.";
guestTranslations.de.workflowKicker = "SO FUNKTIONIERT ES";
guestTranslations.en.workflowKicker = "HOW IT WORKS";
guestTranslations.de.workflowTitle = "Ein klarer Ablauf für wiederholbare Entscheidungen.";
guestTranslations.en.workflowTitle = "A clear process for repeatable decisions.";
guestTranslations.de.workflowOne = "Domain schützen";
guestTranslations.en.workflowOne = "Protect a domain";
guestTranslations.de.workflowOneText = "Hinterlegen Sie Ihre wichtigste Unternehmensdomain und optional weitere Marken- oder Unternehmensdomains.";
guestTranslations.en.workflowOneText = "Add your primary company domain and optionally more brand or company domains.";
guestTranslations.de.workflowTwo = "Kandidaten scannen";
guestTranslations.en.workflowTwo = "Scan candidates";
guestTranslations.de.workflowTwoText = "Der Scanner erzeugt Varianten und prüft sie parallel auf DNS, Websites und verdächtige Merkmale.";
guestTranslations.en.workflowTwoText = "The scanner generates variants and checks them in parallel for DNS, websites and suspicious signals.";
guestTranslations.de.workflowThree = "Befund einordnen";
guestTranslations.en.workflowThree = "Assess findings";
guestTranslations.de.workflowThreeText = "Risikostufen, Details und Scanverlauf zeigen, wo zuerst gehandelt werden sollte.";
guestTranslations.en.workflowThreeText = "Risk levels, details and scan history show where action should happen first.";
guestTranslations.de.workflowFour = "Monitoring automatisieren";
guestTranslations.en.workflowFour = "Automate monitoring";
guestTranslations.de.workflowFourText = "Mit Professional laufen Prüfungen regelmäßig und Änderungen erreichen Ihr Team per Alert.";
guestTranslations.en.workflowFourText = "With Professional, checks run regularly and changes reach your team through alerts.";
guestTranslations.de.proRecommended = "EMPFOHLEN FÜR LAUFENDEN SCHUTZ";
guestTranslations.en.proRecommended = "RECOMMENDED FOR CONTINUOUS PROTECTION";
guestTranslations.de.priceMonth = "/ Monat";
guestTranslations.en.priceMonth = "/ month";
guestTranslations.de.proPitch = "Automatischer Schutz, der neue Risiken früh sichtbar macht.";
guestTranslations.en.proPitch = "Automatic protection that makes new risks visible early.";
guestTranslations.de.proBenefit4 = "Threat-Intelligence-Prüfungen";
guestTranslations.en.proBenefit4 = "Threat intelligence checks";
guestTranslations.de.proBenefit5 = "Veränderungen und stille Überwachung";
guestTranslations.en.proBenefit5 = "Change tracking and silent monitoring";
guestTranslations.de.comparisonKicker = "WAS IST ENTHALTEN?";
guestTranslations.en.comparisonKicker = "WHAT IS INCLUDED?";
guestTranslations.de.comparisonTitle = "Der Unterschied liegt im laufenden Schutz.";
guestTranslations.en.comparisonTitle = "The difference is continuous protection.";
guestTranslations.de.comparisonIntro = "Free ist der unkomplizierte Einstieg. Professional wird zur kontinuierlichen Schutzschicht für Marken und Unternehmen.";
guestTranslations.en.comparisonIntro = "Free is the simple starting point. Professional becomes a continuous protection layer for brands and businesses.";
guestTranslations.de.comparisonFeature = "Funktion";
guestTranslations.en.comparisonFeature = "Feature";
guestTranslations.de.compareScan = "Manuelle Lookalike-Scans";
guestTranslations.en.compareScan = "Manual lookalike scans";
guestTranslations.de.compareCandidates = "Kandidaten pro Scan";
guestTranslations.en.compareCandidates = "Candidates per scan";
guestTranslations.de.compareProtected = "Geschützte Domains";
guestTranslations.en.compareProtected = "Protected domains";
guestTranslations.de.compareHistory = "Scanverlauf und Veränderungen";
guestTranslations.en.compareHistory = "Scan history and changes";
guestTranslations.de.compareAutomation = "Automatische Scans";
guestTranslations.en.compareAutomation = "Automatic scans";
guestTranslations.de.compareAlerts = "Sicherheitsbenachrichtigungen";
guestTranslations.en.compareAlerts = "Security alerts";
guestTranslations.de.compareThreat = "Threat-Intelligence-Prüfungen";
guestTranslations.en.compareThreat = "Threat intelligence checks";
guestTranslations.de.compareMuted = "Treffer ausblenden und weiter überwachen";
guestTranslations.en.compareMuted = "Hide findings while monitoring continues";

function toggleLanguage() {
    language = language === "de" ? "en" : "de";
    localStorage.setItem("domain-monitor-language", language);
    applyLanguage();
    renderedDomainsSignature = "";
    renderDomains(allDomains);
    renderProtectedDomains(allProtectedDomains);
    if (currentUser) {
        fetch("api/account.php", {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ language })
        }).catch(() => {});
    }
}

async function initAuth() {
    applyLanguage();

    const response = await fetch("api/login.php?t=" + Date.now(), {
        cache: "no-store"
    });
    const data = await response.json();
    const registrationToggle = document.getElementById("registration-toggle");
    if (registrationToggle && !data.registration_enabled) {
        registrationToggle.remove();
    }

    if (data.user) {
        currentUser = data.user;
        language = data.user.language === "en" ? "en" : "de";
        localStorage.setItem("domain-monitor-language", language);
        applyLanguage();
        document.body.classList.remove("auth-required");
        document.body.classList.toggle("admin-user", data.user.role === "admin");
        updateAdminNavigation(data.user.role === "admin");
        showPlanStatus(data.user);
        return true;
    }

    document.body.classList.add("auth-required");
    updateAdminNavigation(false);
    return false;
}

async function login(event) {
    event.preventDefault();

    const errorElement = document.getElementById("login-error");
    const registrationFields = document.getElementById("registration-fields");
    const isRegistering = registrationFields && !registrationFields.hidden;
    const body = {
        username: document.getElementById("login-username").value,
        password: document.getElementById("login-password").value
    };
    if (isRegistering) {
        body.email = document.getElementById("register-email").value;
        body.plan = document.getElementById("register-plan").value;
        if (body.password !== document.getElementById("register-password-confirm").value) {
            errorElement.textContent = "Passwörter stimmen nicht überein";
            return;
        }
    }

    const response = await fetch(isRegistering ? "api/register.php" : "api/login.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
        errorElement.textContent = data.error || "Login failed";
        return;
    }

    currentUser = data.user;
    language = data.user.language === "en" ? "en" : "de";
    localStorage.setItem("domain-monitor-language", language);
    applyLanguage();
    document.body.classList.remove("auth-required");
    closeAuthModal();
    document.body.classList.toggle("admin-user", currentUser.role === "admin");
    updateAdminNavigation(currentUser.role === "admin");
    await initDashboard();
    showPlanStatus(currentUser);
}

async function logout() {
    await fetch("api/logout.php", { method: "POST" });
    window.location.reload();
}

async function loadAdminPanel() {
    if (!currentUser || currentUser.role !== "admin") return;

    const usersResponse = await fetch("api/admin_users.php?t=" + Date.now());
    const usersData = await usersResponse.json();
    const usersTable = document.getElementById("admin-users-table");

    if (usersTable && usersData.success) {
        usersTable.innerHTML = usersData.users.map(user => `
            <tr>
                <td><strong>${escapeHtml(user.username)}</strong><small>#${user.id}</small></td>
                <td>${escapeHtml(user.role)}</td>
                <td>${user.scan_count}</td>
                <td>${formatDate(user.last_scan)}</td>
                <td><span class="admin-status ${user.running_scans ? "is-running" : ""}">${user.running_scans ? "Running" : "Ready"}</span></td>
                <td><button class="table-icon-button danger" type="button" title="Delete user" onclick="deleteUser(${user.id}, '${escapeHtml(user.username)}')">×</button></td>
            </tr>
        `).join("");
    }

    const scansResponse = await fetch("api/admin_scans.php?t=" + Date.now());
    const scansData = await scansResponse.json();
    const scansTable = document.getElementById("admin-scans-table");

    if (scansTable && scansData.success) {
        scansTable.innerHTML = scansData.scans.map(scan => `
            <tr>
                <td>${escapeHtml(scan.username)}</td>
                <td>${escapeHtml(scan.domain || "-")}</td>
                <td>${formatDate(scan.started_at)}</td>
                <td>${formatDate(scan.finished_at)}</td>
                <td>${Number(scan.candidates_count || 0).toLocaleString()}</td>
                <td>${Number(scan.registered_count || 0).toLocaleString()}</td>
                <td>${Number(scan.active_count || 0).toLocaleString()}</td>
            </tr>
        `).join("");
    }
}

async function createUser() {
    const response = await fetch("api/admin_users.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username: document.getElementById("admin-new-username").value,
            password: document.getElementById("admin-new-password").value,
            role: document.getElementById("admin-new-role").value
        })
    });

    const data = await response.json();
    if (!response.ok || !data.success) {
        alert(data.error || "Could not create user");
        return;
    }

    await loadAdminPanel();
}

async function deleteUser(userId, username) {
    if (!confirm(`Delete user ${username} and all associated data?`)) return;

    const response = await fetch("api/admin_users.php", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: userId })
    });
    const data = await response.json();

    if (!response.ok || !data.success) {
        alert(data.error || "Could not delete user");
        return;
    }

    await loadAdminPanel();
}

function showPage(page) {
    const isAdminPage = page === "admin";
    if (isAdminPage && (!currentUser || currentUser.role !== "admin")) {
        page = "dashboard";
    }

    document.querySelectorAll(".main > section").forEach(section => {
        const pagePanel = section.dataset.pagePanel;
        section.style.display = pagePanel && pagePanel !== page ? "none" : "";
    });

    document.querySelectorAll(".nav-item").forEach(item => {
        item.classList.remove("active");
    });
    document.querySelectorAll(".page-nav").forEach(item => {
        item.classList.toggle("active", item.dataset.page === page);
    });

    if (page === "settings") loadSettings();
    if (page === "admin") loadAdminPanel();
}

function setupPageNavigation() {
    document.querySelectorAll(".page-nav").forEach(item => {
        item.addEventListener("click", event => {
            event.preventDefault();
            showPage(item.dataset.page);
            if (item.dataset.page === "dashboard") {
                window.scrollTo({ top: 0, behavior: "smooth" });
            }
            history.replaceState(null, "", item.getAttribute("href"));
        });
    });
}

function setScanStartRequested(
    requested
) {

    scanStartRequested =
        requested;

    if (requested) {

        sessionStorage.setItem(
            SCAN_SESSION_KEY,
            "1"
        );

    } else {

        sessionStorage.removeItem(
            SCAN_SESSION_KEY
        );
    }
}

function applyTheme(
    theme
) {

    theme = theme === "dark" ? "dark" : "light";

    document.body.dataset.theme = theme;

    localStorage.setItem(
        "domain-monitor-theme",
        theme
    );

    updateThemeButton(
        theme
    );
}

function updateThemeButton(
    theme
) {

    const icon =
        document.getElementById(
            "theme-toggle-icon"
        );

    const text =
        document.getElementById(
            "theme-toggle-text"
        );

    if (
        !icon ||
        !text
    ) {

        return;
    }

    if (
        theme ===
        "dark"
    ) {

        icon.textContent =
            "☀";

        text.textContent =
            "Light Design";

    } else {

        icon.textContent =
            "☾";

        text.textContent =
            "Dark Design";
    }
}

function toggleTheme() {

    const currentTheme =
        localStorage.getItem(
            "domain-monitor-theme"
        ) ||
        "light";

    const newTheme =
        currentTheme ===
        "dark"
            ? "light"
            : "dark";

    applyTheme(
        newTheme
    );
}

function loadTheme() {
    applyTheme(localStorage.getItem("domain-monitor-theme") || "light");
}

function updateScanDonut(
    candidates,
    dnsActive,
    websites
) {

    const donut =
        document.getElementById(
            "scan-donut"
        );

    const totalElement =
        document.getElementById(
            "scan-donut-total"
        );

    if (
        !donut
    ) {

        return;
    }

    candidates =
        Math.max(
            0,
            Number(
                candidates ||
                0
            )
        );

    dnsActive =
        Math.max(
            0,
            Number(
                dnsActive ||
                0
            )
        );

    websites =
        Math.max(
            0,
            Number(
                websites ||
                0
            )
        );

    const total =
        candidates +
        dnsActive +
        websites;

    if (
        totalElement
    ) {

        totalElement.textContent =
            candidates;
    }

    if (
        total <=
        0
    ) {

        donut.style.background =
            "conic-gradient(var(--gray-chart) 0deg 360deg)";

        return;
    }

    const values = [
        websites,
        dnsActive,
        candidates
    ];

    const visibleValues = values.filter(
        value => value > 0
    ).length;

    const minimumDegrees = 8;
    const reservedDegrees =
        visibleValues * minimumDegrees;
    const proportionalDegrees =
        Math.max(
            0,
            360 - reservedDegrees
        );

    const degrees = values.map(
        value => value > 0
            ? minimumDegrees + (
                value / total
            ) * proportionalDegrees
            : 0
    );

    const websitesDegrees = degrees[0];
    const dnsDegrees = degrees[1];
    const candidatesDegrees = degrees[2];

    const websitesEnd =
        websitesDegrees;

    const dnsEnd =
        websitesEnd +
        dnsDegrees;

    const candidatesEnd =
        dnsEnd +
        candidatesDegrees;

    donut.style.background =
        `
            conic-gradient(

                var(--scan-red)
                0deg
                ${websitesEnd}deg,

                var(--scan-orange)
                ${websitesEnd}deg
                ${dnsEnd}deg,

                var(--gray-chart)
                ${dnsEnd}deg
                ${candidatesEnd}deg

            )
        `;
}

async function loadDashboard() {

    try {

        const response =
            await fetch(
                "api/stats.php?t=" +
                Date.now(),
                {
                    cache:
                        "no-store"
                }
            );

        const data =
            await response.json();

        if (
            !data.success
        ) {

            throw new Error(
                data.error ||
                "API error"
            );
        }

        const protectedDomains =
            document.getElementById(
                "protected-domains-count"
            );

        if (
            protectedDomains
        ) {

            protectedDomains.textContent =
                data.protected_domains;
        }

        document.getElementById(
            "total-domains"
        ).textContent =
            data.total_domains;

        document.getElementById(
            "active-websites"
        ).textContent =
            data.active_websites;

        document.getElementById(
            "high-risk"
        ).textContent =
            data.risk.high +
            data.risk.critical;

        document.getElementById(
            "critical"
        ).textContent =
            data.risk.critical;

        document.getElementById(
            "high"
        ).textContent =
            data.risk.high;

        document.getElementById(
            "medium"
        ).textContent =
            data.risk.medium;

        document.getElementById(
            "low"
        ).textContent =
            data.risk.low;

        if (
            data.last_scan
        ) {

            const candidates =
                Number(
                    data.last_scan.candidates_count ||
                    0
                );

            const registered =
                Number(
                    data.last_scan.registered_count ||
                    0
                );

            const websites =
                Number(
                    data.last_scan.active_count ||
                    0
                );

            document.getElementById(
                "last-scan"
            ).textContent =
                formatDate(
                    data.last_scan.finished_at
                );

            document.getElementById(
                "scan-candidates"
            ).textContent =
                candidates;

            document.getElementById(
                "scan-registered"
            ).textContent =
                registered;

            document.getElementById(
                "scan-websites"
            ).textContent =
                websites;

            updateScanDonut(
                candidates,
                registered,
                websites
            );

        } else {

            document.getElementById(
                "last-scan"
            ).textContent =
                "No scans yet";

            document.getElementById(
                "scan-candidates"
            ).textContent =
                "0";

            document.getElementById(
                "scan-registered"
            ).textContent =
                "0";

            document.getElementById(
                "scan-websites"
            ).textContent =
                "0";

            updateScanDonut(
                0,
                0,
                0
            );
        }

        dashboardScanRunning = Boolean(
            data.scan_running
        );

        if (dashboardScanRunning) {

            setScanStartRequested(
                true
            );

            updateScanButton(
                true
            );
        }

        if (!dashboardScanRunning) {

            setScanStartRequested(
                false
            );

            updateScanButton(
                false
            );

            const progressPanel = document.getElementById(
                "scan-progress-panel"
            );

            if (progressPanel) {
                progressPanel.classList.remove("visible");
            }

            lastProgressStatus = "";
        }

    } catch (
        error
    ) {

        console.error(
            "Dashboard error:",
            error
        );
    }
}

async function loadProtectedDomains() {

    const table =
        document.getElementById(
            "protected-domains-table"
        );

    if (
        !table
    ) {

        return;
    }

    try {

        const response =
            await fetch(
                "api/protected_domains.php?t=" +
                Date.now(),
                {
                    cache:
                        "no-store"
                }
            );

        const text =
            await response.text();

        let data;

        try {

            data =
                JSON.parse(
                    text
                );

        } catch {

            throw new Error(
                "Protected Domains API returned invalid JSON:\n" +
                text
            );
        }

        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Could not load protected domains"
            );
        }

        const domains =
            Array.isArray(
                data.domains
            )
                ? data.domains
                : [];

        allProtectedDomains = domains;

        updateEasterEggState(domains);

        renderProtectedDomains(
            domains
        );

    } catch (
        error
    ) {

        console.error(
            "Protected Domains error:",
            error
        );

        table.innerHTML = `

            <tr>

                <td
                    colspan="5"
                    class="loading"
                >

                    Failed to load protected domains.

                </td>

            </tr>

        `;
    }
}

function renderProtectedDomains(
    domains
) {

    const table =
        document.getElementById(
            "protected-domains-table"
        );

    if (
        !table
    ) {

        return;
    }

    if (
        !domains ||
        domains.length ===
        0
    ) {

        table.innerHTML = `

            <tr>

                <td
                    colspan="5"
                    class="loading"
                >

                    No protected domains configured.

                </td>

            </tr>

        `;

        return;
    }

    table.innerHTML =
        domains.map(
            domain => {

                const status =
                    domain.active

                        ? `
                            <span class="online">
                                ${language === "de" ? "AKTIV" : "ACTIVE"}
                            </span>
                          `

                        : `
                            <span class="offline">
                                ${language === "de" ? "DEAKTIVIERT" : "DISABLED"}
                            </span>
                          `;

                const toggleText =
                    domain.active
                        ? (language === "de" ? "Deaktivieren" : "Disable")
                        : (language === "de" ? "Aktivieren" : "Enable");

                const lastScan =
                    domain.last_scan
                        ? formatDate(
                            domain.last_scan
                        )
                        : (language === "de" ? "Nie" : "Never");

                return `

                    <tr>

                        <td>

                            <strong>

                                ${escapeHtml(
                                    domain.domain
                                )}

                            </strong>

                        </td>

                        <td>

                            ${status}

                        </td>

                        <td>

                            ${formatDate(
                                domain.created_at
                            )}

                        </td>

                        <td>

                            ${lastScan}

                        </td>

                        <td>

                            <div
                                class="protected-domain-actions"
                            >

                                <button
                                    type="button"
                                    class="protected-domain-action-button"
                                    onclick="
                                        event.stopPropagation();

                                        toggleProtectedDomain(
                                            ${Number(domain.id)},
                                            ${domain.active ? "false" : "true"}
                                        );
                                    "
                                >

                                    ${toggleText}

                                </button>

                                <button
                                    type="button"
                                    class="protected-domain-delete-button"
                                    onclick="
                                        event.stopPropagation();

                                        deleteProtectedDomain(
                                            ${Number(domain.id)}
                                        );
                                    "
                                >

                                    Delete

                                </button>

                            </div>

                        </td>

                    </tr>

                `;
            }
        ).join("");
}

async function addProtectedDomain() {

    const input =
        document.getElementById(
            "new-domain"
        );

    const message =
        document.getElementById(
            "protected-domain-message"
        );

    const button =
        document.querySelector(
            ".add-domain-button"
        );

    if (
        !input
    ) {

        return;
    }

    const domain =
        input.value.trim();

    if (
        !domain
    ) {

        if (
            message
        ) {

            message.textContent =
                "Please enter a domain.";

            message.className =
                "protected-domain-message error";
        }

        return;
    }

    button.disabled =
        true;

    button.textContent =
        "Adding...";

    if (
        message
    ) {

        message.textContent =
            "";

        message.className =
            "protected-domain-message";
    }

    try {

        const response =
            await fetch(
                "api/protected_domains.php",
                {

                    method:
                        "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:
                        JSON.stringify({

                            domain:
                                domain

                        })

                }
            );

        const text =
            await response.text();

        let data;

        try {

            data =
                JSON.parse(
                    text
                );

        } catch {

            throw new Error(
                "Protected Domains API returned invalid JSON:\n" +
                text
            );
        }

        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Domain could not be added"
            );
        }

        input.value =
            "";

        if (
            message
        ) {

            message.textContent =
                "✓ Domain added successfully.";

            message.className =
                "protected-domain-message success";
        }

        const normalizedDomain = domain.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
        if (normalizedDomain === "eliasems.egg") {
            window.showEasterEgg?.();
        }

        await loadProtectedDomains();

        await loadDashboard();

        setTimeout(
            () => {

                if (
                    message
                ) {

                    message.textContent =
                        "";

                    message.className =
                        "protected-domain-message";
                }

            },
            2500
        );

    } catch (
        error
    ) {

        console.error(
            "Add protected domain error:",
            error
        );

        if (
            message
        ) {

            message.textContent =
                "✕ " +
                error.message;

            message.className =
                "protected-domain-message error";
        }

    } finally {

        button.disabled =
            false;

        button.textContent =
            "+ Add Domain";
    }
}

async function toggleProtectedDomain(
    id,
    active
) {

    try {

        const response =
            await fetch(
                "api/protected_domains.php",
                {

                    method:
                        "PUT",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:
                        JSON.stringify({

                            id:
                                Number(
                                    id
                                ),

                            active:
                                Boolean(
                                    active
                                )

                        })

                }
            );

        const text =
            await response.text();

        let data;

        try {

            data =
                JSON.parse(
                    text
                );

        } catch {

            throw new Error(
                "Protected Domains API returned invalid JSON:\n" +
                text
            );
        }

        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Domain status could not be changed"
            );
        }

        await loadProtectedDomains();

        await loadDashboard();

    } catch (
        error
    ) {

        console.error(
            "Toggle protected domain error:",
            error
        );

        alert(
            "Domain status could not be changed:\n\n" +
            error.message
        );
    }
}

async function deleteProtectedDomain(
    id
) {

    if (
        !confirm(
            "Do you really want to delete this protected domain?"
        )
    ) {

        return;
    }

    try {

        const response =
            await fetch(

                "api/protected_domains.php?id=" +
                encodeURIComponent(
                    id
                ),

                {
                    method:
                        "DELETE"
                }

            );

        const text =
            await response.text();

        let data;

        try {

            data =
                JSON.parse(
                    text
                );

        } catch {

            throw new Error(
                "Protected Domains API returned invalid JSON:\n" +
                text
            );
        }

        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Domain could not be deleted"
            );
        }

        await loadProtectedDomains();

        await loadDashboard();

    } catch (
        error
    ) {

        console.error(
            "Delete protected domain error:",
            error
        );

        alert(
            "Domain could not be deleted:\n\n" +
            error.message
        );
    }
}

async function loadExcludedDomains() {

    const table = document.getElementById(
        "excluded-domains-table"
    );

    if (!table) {
        return;
    }

    try {

        const response = await fetch(
            "api/excluded_domains.php?t=" + Date.now(),
            { cache: "no-store" }
        );

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Could not load excluded domains");
        }

        const domains = Array.isArray(data.domains)
            ? data.domains
            : [];

        if (!domains.length) {
            table.innerHTML = `
                <tr>
                    <td colspan="3" class="loading">
                        No company domains excluded.
                    </td>
                </tr>
            `;

            return;
        }

        table.innerHTML = domains.map(domain => `
            <tr>
                <td>${escapeHtml(domain.domain)}</td>
                <td>${formatDate(domain.created_at)}</td>
                <td>
                    <button
                        class="protected-domain-delete-button"
                        type="button"
                        onclick="deleteExcludedDomain(${Number(domain.id)})"
                    >
                        Remove
                    </button>
                </td>
            </tr>
        `).join("");

    } catch (error) {

        table.innerHTML = `
            <tr>
                <td colspan="3" class="loading">
                    Failed to load excluded domains.
                </td>
            </tr>
        `;
    }
}

async function addExcludedDomain() {

    const input = document.getElementById(
        "new-excluded-domain"
    );

    const message = document.getElementById(
        "excluded-domain-message"
    );

    const button = document.querySelector(
        "#excluded-domains .add-domain-button"
    );

    if (!input || !input.value.trim()) {

        if (message) {
            message.textContent = "Please enter a domain.";
            message.className = "protected-domain-message error";
        }

        return;
    }

    button.disabled = true;

    try {

        const response = await fetch(
            "api/excluded_domains.php",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    domain: input.value.trim()
                })
            }
        );

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Could not exclude domain");
        }

        input.value = "";

        if (message) {
            message.textContent = "Domain excluded from scans.";
            message.className = "protected-domain-message success";
        }

        await loadExcludedDomains();

    } catch (error) {

        if (message) {
            message.textContent = error.message;
            message.className = "protected-domain-message error";
        }

    } finally {

        button.disabled = false;
    }
}

async function excludeDiscoveredDomain(domain) {
    if (!domain) return;

    try {
        const response = await fetch("api/excluded_domains.php", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain })
        });
        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Could not exclude domain");
        }

        renderedDomainsSignature = "";
        await loadDomains();
    } catch (error) {
        alert(
            language === "de"
                ? `Domain konnte nicht ausgeschlossen werden:\n\n${error.message}`
                : `Could not exclude domain:\n\n${error.message}`
        );
    }
}

async function deleteExcludedDomain(id) {

    if (!confirm("Remove this domain from the scan exclusions?")) {
        return;
    }

    try {

        const response = await fetch(
            "api/excluded_domains.php?id=" + encodeURIComponent(id),
            { method: "DELETE" }
        );

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Could not remove domain");
        }

        await loadExcludedDomains();

    } catch (error) {
        alert(error.message);
    }
}

async function loadSettings() {

    if (!document.getElementById("scan-enabled")) {
        return;
    }

    try {

        const response =
            await fetch(
                "api/settings.php?t=" +
                Date.now(),
                {
                    cache:
                        "no-store"
                }
            );

        const data =
            await response.json();

        if (
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Settings API error"
            );
        }

        document.getElementById(
            "scan-enabled"
        ).checked =
            Boolean(
                data.settings.enabled
            );

        document.getElementById(
            "scan-interval"
        ).value =
            String(
                data.settings.interval_hours
            );

        document.getElementById("scan-timezone").value = data.settings.timezone || "Europe/Vienna";
        document.getElementById("scan-pause-weekends").checked = Boolean(data.settings.pause_weekends);

        updateNextScan(
            data.settings.next_scan
        );

    } catch (
        error
    ) {

        console.error(
            "Settings load error:",
            error
        );
    }
}

async function saveSettings() {

    const enabledElement =
        document.getElementById(
            "scan-enabled"
        );

    const intervalElement =
        document.getElementById(
            "scan-interval"
        );

    const messageElement =
        document.getElementById(
            "settings-message"
        );

    const button =
        document.querySelector(
            ".save-settings-button"
        );

    const enabled =
        enabledElement.checked;

    const intervalHours =
        parseInt(
            intervalElement.value,
            10
        );

    const timezone = document.getElementById("scan-timezone").value;
    const pauseWeekends = document.getElementById("scan-pause-weekends").checked;

    button.disabled =
        true;

    button.textContent =
        "Saving...";

    messageElement.textContent =
        "";

    try {

        const response =
            await fetch(
                "api/settings.php",
                {

                    method:
                        "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:
                        JSON.stringify({

                            enabled:
                                enabled,

                            interval_hours:
                                intervalHours,

                            timezone,

                            pause_weekends: pauseWeekends

                        })

                }
            );

        const text =
            await response.text();

        let data;

        try {

            data =
                JSON.parse(
                    text
                );

        } catch {

            throw new Error(
                "Settings API returned invalid JSON:\n" +
                text
            );
        }

        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Settings could not be saved"
            );
        }

        updateNextScan(
            data.settings.next_scan
        );

        messageElement.textContent =
            "✓ Settings saved";

        messageElement.style.color =
            "";

        button.textContent =
            "Saved";

        setTimeout(
            () => {

                button.disabled =
                    false;

                button.textContent =
                    "Save Settings";

            },
            1500
        );

    } catch (
        error
    ) {

        console.error(
            "Save settings error:",
            error
        );

        messageElement.textContent =
            "✕ " +
            error.message;

        messageElement.style.color =
            "#ff3b30";

        button.disabled =
            false;

        button.textContent =
            "Save Settings";
    }
}

function updateNextScan(
    nextScan
) {

    const element =
        document.getElementById(
            "next-scan"
        );

    if (
        !element
    ) {

        return;
    }

    if (
        !nextScan
    ) {

        element.textContent =
            "Disabled";

        return;
    }

    element.textContent =
        formatDate(
            nextScan
        );
}

async function loadDomains() {

    try {

        const response =
            await fetch(
                "api/domains.php?t=" +
                Date.now(),
                {
                    cache:
                        "no-store"
                }
            );

        const data =
            await response.json();

        if (
            !data.success
        ) {

            throw new Error(
                data.error ||
                "API error"
            );
        }

        allDomains =
            Array.isArray(
                data.domains
            )
                ? data.domains
                : [];

        renderDomains(
            allDomains
        );

    } catch (
        error
    ) {

        console.error(
            "Domain API error:",
            error
        );

        const table =
            document.getElementById(
                "domains-table"
            );

        if (
            table
        ) {

            table.innerHTML = `

                <tr>

                    <td
                        colspan="11"
                        class="loading"
                    >

                        Failed to load domains.

                    </td>

                </tr>

            `;
        }
    }
}

function renderDomains(
    domains
) {

    const table =
        document.getElementById(
            "domains-table"
        );

    if (
        !table
    ) {

        return;
    }

    const domainsSignature = JSON.stringify(domains);
    if (domainsSignature === renderedDomainsSignature) {
        return;
    }
    renderedDomainsSignature = domainsSignature;

    if (
        !domains ||
        domains.length ===
        0
    ) {

        table.innerHTML = `

            <tr>

                <td
                    colspan="11"
                    class="loading"
                >

                    No domains found.

                </td>

            </tr>

        `;

        return;
    }

    table.innerHTML =
        domains.map(
            domain => {

                const riskClass =
                    String(
                        domain.risk_level ||
                        "LOW"
                    ).toLowerCase();

                const dns =
                    domain.dns_active

                        ? `
                            <span class="online">
                                ${language === "de" ? "AKTIV" : "ACTIVE"}
                            </span>
                          `

                        : `
                            <span class="offline">
                                OFFLINE
                            </span>
                          `;

                const website =
                    domain.website_active

                        ? `
                            <span class="online">
                                ${language === "de" ? "ONLINE" : "ONLINE"}
                            </span>
                          `

                        : `
                            <span class="offline">
                                OFFLINE
                            </span>
                          `;

                const login =
                    domain.website_active &&
                    domain.login_found

                        ? `
                            <span class="online">
                                ${language === "de" ? "GEFUNDEN" : "FOUND"}
                            </span>
                          `

                        : `
                            <span class="offline">
                                ${language === "de" ? "KEINE" : "NONE"}
                            </span>
                          `;

                let company;

                if (
                    domain.website_active &&
                    domain.company_name_header
                ) {

                    company = `
                        <span class="online">
                            ${language === "de" ? "HEADER" : "HEADER"}
                        </span>
                    `;

                } else if (
                    domain.website_active &&
                    domain.company_name_found
                ) {

                    company = `
                        <span class="online">
                            ${language === "de" ? "GEFUNDEN" : "FOUND"}
                        </span>
                    `;

                } else {

                    company = `
                        <span class="offline">
                            ${language === "de" ? "KEINE" : "NONE"}
                        </span>
                    `;
                }

                const forSale =
                    domain.website_active &&
                    Boolean(
                        domain.domain_for_sale
                    )

                        ? `
                            <span class="for-sale-badge">
                                ${language === "de" ? "ZU VERKAUFEN?" : "FOR SALE?"}
                            </span>
                          `

                        : `
                            <span class="offline">
                                ${language === "de" ? "NEIN" : "NO"}
                            </span>
                          `;

                                const threatSources = Array.isArray(domain.threat_sources) ? domain.threat_sources : [];
                                const reportedSources = threatSources.filter(source => source.status === "REPORTED");
                                const threatStatus = reportedSources.length > 0
                                    ? "REPORTED"
                                    : String(domain.threat_status || "NOT_CHECKED").toUpperCase();
                                const threatLabel = threatStatus === "REPORTED"
                                        ? (language === "de" ? "GEMELDET" : "REPORTED")
                                        : threatStatus === "CLEAN"
                                                ? (language === "de" ? "NICHT GEMELDET" : "NOT REPORTED")
                                                : (language === "de" ? "UNBEKANNT" : "UNKNOWN");

                return `

                    <tr
                        class="domain-table-row"
                        data-domain-id="${Number(
                            domain.id
                        )}"
                    >

                        <td>

                            <div class="domain-cell">

                                <span class="domain-link">

                                    ${escapeHtml(
                                        domain.domain
                                    )}

                                </span>

                                ${domain.change_type === "new"
                                    ? `<span class="domain-change-badge is-new">${language === "de" ? "NEU" : "NEW"}</span>`
                                    : domain.change_type === "website_changed"
                                        ? `<span class="domain-change-badge is-changed">${language === "de" ? "WEBSITE GEÄNDERT" : "WEBSITE CHANGED"}</span>`
                                    : domain.change_type === "ip_changed"
                                        ? `<span class="domain-change-badge is-changed">${language === "de" ? "IP GEÄNDERT" : "IP CHANGED"}</span>`
                                    : domain.change_type === "changed"
                                        ? `<span class="domain-change-badge is-changed">${language === "de" ? "GEÄNDERT" : "CHANGED"}</span>`
                                        : ""}

                                <button
                                    class="copy-domain-button"
                                    type="button"
                                    data-copy-domain="${escapeHtml(
                                        domain.domain
                                    )}"
                                    title="Copy domain"
                                >
                                    Copy
                                </button>

                            </div>

                        </td>

                        <td>

                            <span
                                class="
                                    risk-badge
                                    risk-${riskClass}
                                "
                            >

                                ${escapeHtml(
                                    domain.risk_level
                                )}

                            </span>

                        </td>

                        <td>

                            <strong>
                                ${escapeHtml(
                                    domain.risk_score
                                )}
                            </strong>

                            / 100

                        </td>

                        <td>
                            <span class="threat-status threat-${threatStatus.toLowerCase()}" title="${escapeHtml(domain.threat_source || "-")}">
                                ${threatLabel} (${threatSources.length} Quellen)
                            </span>
                        </td>

                        <td>
                            ${dns}
                        </td>

                        <td>
                            ${website}
                        </td>

                        <td>
                            ${login}
                        </td>

                        <td>
                            ${company}
                        </td>

                        <td>
                            ${forSale}
                        </td>

                        <td>

                            ${escapeHtml(
                                domain.http_status ??
                                "-"
                            )}

                        </td>

                        <td>

                            ${formatDate(
                                domain.last_seen
                            )}

                        </td>

                        <td class="domain-row-actions">
                            <button
                                type="button"
                                class="monitor-domain-button"
                                data-monitor-domain-id="${Number(domain.id)}"
                            >
                                ${language === "de" ? "Ausblenden & prüfen" : "Hide & monitor"}
                            </button>
                            <button
                                type="button"
                                class="exclude-domain-button"
                                data-exclude-domain="${escapeHtml(domain.domain)}"
                            >
                                ${language === "de" ? "Ausschließen" : "Exclude"}
                            </button>
                        </td>

                    </tr>

                `;
            }
        ).join("");
}

function setupDomainTableEvents() {

    const table =
        document.getElementById(
            "domains-table"
        );

    if (
        !table
    ) {

        return;
    }

    table.addEventListener(
        "click",
        event => {

            const copyButton =
                event.target.closest(
                    ".copy-domain-button"
                );

            if (
                copyButton
            ) {

                event.stopPropagation();

                const domain =
                    copyButton.getAttribute(
                        "data-copy-domain"
                    );

                copyDomain(
                    domain
                );

                return;
            }

            const excludeButton = event.target.closest(
                ".exclude-domain-button"
            );

            if (excludeButton) {
                event.stopPropagation();
                excludeDiscoveredDomain(
                    excludeButton.getAttribute("data-exclude-domain")
                );
                return;
            }

            const monitorButton = event.target.closest(
                ".monitor-domain-button"
            );

            if (monitorButton) {
                event.stopPropagation();
                monitorDiscoveredDomain(
                    Number(monitorButton.getAttribute("data-monitor-domain-id"))
                );
                return;
            }

            const row =
                event.target.closest(
                    ".domain-table-row"
                );

            if (
                !row
            ) {

                return;
            }

            const domainId =
                row.getAttribute(
                    "data-domain-id"
                );

            if (
                !domainId
            ) {

                return;
            }

            openDomainDetails(
                Number(
                    domainId
                )
            );
        }
    );
}

async function monitorDiscoveredDomain(domainId) {
    if (!domainId) return;

    try {
        const response = await fetch("api/muted_domains.php", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain_id: domainId })
        });
        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Could not start monitoring");
        }

        renderedDomainsSignature = "";
        await loadDomains();
    } catch (error) {
        alert(
            language === "de"
                ? `Stille Überwachung konnte nicht aktiviert werden:\n\n${error.message}`
                : `Could not start silent monitoring:\n\n${error.message}`
        );
    }
}

document.getElementById("new-domain")?.addEventListener("keydown", event => {
    if (event.key === "Enter") {
        event.preventDefault();
        addProtectedDomain();
    }
});

function filterDomains() {

    const search =
        document.getElementById(
            "search"
        ).value.toLowerCase();

    const risk =
        document.getElementById(
            "risk-filter"
        ).value;

    const filtered =
        allDomains.filter(
            domain => {

                const matchesSearch =
                    String(
                        domain.domain ||
                        ""
                    )
                    .toLowerCase()
                    .includes(
                        search
                    );

                const matchesRisk =
                    risk === "ALL" ||
                    domain.risk_level ===
                        risk;

                return (
                    matchesSearch &&
                    matchesRisk
                );
            }
        );

    renderDomains(
        filtered
    );
}

function openDomainDetails(
    domainId
) {

    const domain =
        allDomains.find(
            item =>
                Number(
                    item.id
                ) ===
                Number(
                    domainId
                )
        );

    if (
        !domain
    ) {

        console.error(
            "Domain not found:",
            domainId,
            allDomains
        );

        return;
    }

    currentDetailDomain =
        domain.domain ||
        "";

    const modal =
        document.getElementById(
            "domain-modal"
        );

    if (
        !modal
    ) {

        console.error(
            "domain-modal not found"
        );

        return;
    }

    const riskLevel =
        String(
            domain.risk_level ||
            "LOW"
        );

    const riskBadge =
        document.getElementById(
            "detail-risk"
        );

    document.getElementById(
        "detail-domain"
    ).textContent =
        domain.domain ||
        "-";

    const changeElement = document.getElementById("detail-change");
    if (changeElement) {
        if (domain.change_type === "new") {
            changeElement.textContent = language === "de" ? "Neu seit dem letzten Scan" : "New since the last scan";
            changeElement.className = "domain-change-note is-new";
        } else if (["changed", "website_changed", "ip_changed"].includes(domain.change_type)) {
            const changes = (domain.changes || []).map(change => {
                const before = change.before === null ? "-" : change.before;
                const after = change.after === null ? "-" : change.after;
                const labels = language === "de"
                    ? { risk_score: "Risikoscore", dns_active: "DNS-Status", website_active: "Website-Status", http_status: "HTTP-Status", ips_snapshot: "IP-Adressen" }
                    : { risk_score: "Risk score", dns_active: "DNS status", website_active: "Website status", http_status: "HTTP status", ips_snapshot: "IP addresses" };
                const formatValue = value => {
                    if (change.field === "dns_active" || change.field === "website_active") return value === 1 ? "ONLINE" : "OFFLINE";
                    if (change.field === "ips_snapshot") return Array.isArray(value) ? (value.length ? value.join(", ") : "-") : value;
                    return value;
                };
                return `${labels[change.field] || change.label}: ${formatValue(before)} → ${formatValue(after)}`;
            });
            changeElement.textContent = changes.join(" | ");
            changeElement.className = "domain-change-note is-changed";
        } else {
            changeElement.textContent = "";
            changeElement.className = "domain-change-note";
        }
    }

    riskBadge.textContent =
        riskLevel;

    riskBadge.className =
        "risk-badge risk-" +
        riskLevel.toLowerCase();

    document.getElementById(
        "detail-risk-score"
    ).textContent =
        `${domain.risk_score ?? 0} / 100`;

    document.getElementById(
        "detail-risk-level"
    ).textContent =
        riskLevel;

    const registrationElement =
        document.getElementById(
            "detail-registration-date"
        );

    const ageElement =
        document.getElementById(
            "detail-domain-age"
        );

    if (
        domain.registration_date
    ) {

        const registrationDate =
            parseDateValue(
                domain.registration_date
            );

        if (
            registrationDate
        ) {

            registrationElement.textContent =
                formatFullDate(
                    registrationDate
                );

            if (
                ageElement
            ) {

                ageElement.textContent =
                    calculateDomainAge(
                        registrationDate
                    );
            }

        } else {

            registrationElement.textContent =
                "Not available";

            if (
                ageElement
            ) {

                ageElement.textContent =
                    "Not available";
            }
        }

    } else {

        registrationElement.textContent =
            "Not available";

        if (
            ageElement
        ) {

            ageElement.textContent =
                "Not available";
        }
    }

    document.getElementById(
        "detail-registrar"
    ).textContent =
        domain.registrar ||
        "Not available";

    const detailDns =
        document.getElementById(
            "detail-dns"
        );

    detailDns.textContent =
        domain.dns_active
            ? "ACTIVE"
            : "OFFLINE";

    detailDns.className =
        domain.dns_active
            ? "online"
            : "offline";

    const ips =
        Array.isArray(
            domain.ips
        )
            ? domain.ips
            : [];

    document.getElementById(
        "detail-ips"
    ).textContent =
        ips.length
            ? ips.join(", ")
            : "None";

    const detailWebsite =
        document.getElementById(
            "detail-website"
        );

    detailWebsite.textContent =
        domain.website_active
            ? "ONLINE"
            : "OFFLINE";

    detailWebsite.className =
        domain.website_active
            ? "online"
            : "offline";

    document.getElementById(
        "detail-http"
    ).textContent =
        domain.http_status ??
        "-";

    document.getElementById(
        "detail-url"
    ).textContent =
        domain.final_url ||
        "-";

    document.getElementById(
        "detail-redirect"
    ).textContent =
        domain.redirected_to_protected
            ? "Protected domain"
            : "No";

    document.getElementById(
        "detail-login"
    ).textContent =
        domain.login_found
            ? "FOUND"
            : "NOT FOUND";

    document.getElementById(
        "detail-company"
    ).textContent =
        domain.company_name_found
            ? "FOUND"
            : "NOT FOUND";

    document.getElementById(
        "detail-header"
    ).textContent =
        domain.company_name_header
            ? "FOUND"
            : "NOT FOUND";

    const detailForSale =
        document.getElementById(
            "detail-for-sale"
        );

    if (
        detailForSale
    ) {

        if (
            domain.website_active &&
            Boolean(
                domain.domain_for_sale
            )
        ) {

            detailForSale.textContent =
                "PROBABLY FOR SALE";

            detailForSale.className =
                "for-sale-text";

        } else {

            detailForSale.textContent =
                "NOT DETECTED";

            detailForSale.className =
                "offline";
        }
    }

    document.getElementById(
        "detail-title"
    ).textContent =
        domain.title ||
        "No title";

    document.getElementById(
        "detail-first-seen"
    ).textContent =
        formatDate(
            domain.first_seen
        );

    document.getElementById(
        "detail-last-seen"
    ).textContent =
        formatDate(
            domain.last_seen
        );

    const threatStatusElement = document.getElementById("detail-threat-status");
    const threatSourceElement = document.getElementById("detail-threat-source");
    const threatDetectionsElement = document.getElementById("detail-threat-detections");
    const threatCheckedElement = document.getElementById("detail-threat-checked");
    const threatStatus = String(domain.threat_status || "NOT_CHECKED").toUpperCase();

    if (threatStatusElement) {
        threatStatusElement.textContent = threatStatus === "REPORTED"
            ? "REPORTED"
            : threatStatus === "CLEAN"
                ? "NOT REPORTED"
                : "UNKNOWN";
        threatStatusElement.className = threatStatus === "REPORTED" ? "online" : "offline";
    }
    if (threatSourceElement) threatSourceElement.textContent = domain.threat_source || "-";
    if (threatDetectionsElement) threatDetectionsElement.textContent = domain.threat_detections ?? "-";
    if (threatCheckedElement) threatCheckedElement.textContent = formatDate(domain.threat_checked_at);
    modal.classList.add(
        "open"
    );

    document.body.classList.add(
        "modal-open"
    );
}

function parseDateValue(
    value
) {

    if (
        !value
    ) {

        return null;
    }

    let stringValue =
        String(
            value
        ).trim();

    if (
        !stringValue
    ) {

        return null;
    }

    if (
        !stringValue.includes(
            "T"
        )
    ) {

        stringValue =
            stringValue.replace(
                " ",
                "T"
            );
    }

    const parsed =
        new Date(
            stringValue
        );

    if (
        Number.isNaN(
            parsed.getTime()
        )
    ) {

        return null;
    }

    return parsed;
}

function formatFullDate(
    date
) {

    if (
        !date
    ) {

        return "-";
    }

    return date.toLocaleString(
        language === "de" ? "de-AT" : "en-GB",
        {

            day:
                "2-digit",

            month:
                "2-digit",

            year:
                "numeric",

            hour:
                "2-digit",

            minute:
                "2-digit"

        }
    ).replace(
        ",",
        " ·"
    );
}

function calculateDomainAge(
    registrationDate
) {

    if (
        !registrationDate
    ) {

        return "Not available";
    }

    const now =
        new Date();

    if (
        registrationDate >
        now
    ) {

        return "Invalid registration date";
    }

    let years =
        now.getFullYear() -
        registrationDate.getFullYear();

    let months =
        now.getMonth() -
        registrationDate.getMonth();

    let days =
        now.getDate() -
        registrationDate.getDate();

    if (
        days <
        0
    ) {

        months--;
    }

    if (
        months <
        0
    ) {

        years--;

        months +=
            12;
    }

    const parts =
        [];

    if (
        years >
        0
    ) {

        parts.push(
            years +
            (
                years ===
                1
                    ? " year"
                    : " years"
            )
        );
    }

    if (
        months >
        0
    ) {

        parts.push(
            months +
            (
                months ===
                1
                    ? " month"
                    : " months"
            )
        );
    }

    if (
        parts.length ===
        0
    ) {

        return "Less than 1 month";
    }

    return parts.join(
        ", "
    );
}

function closeDomainDetails() {

    const modal =
        document.getElementById(
            "domain-modal"
        );

    if (
        !modal
    ) {

        return;
    }

    modal.classList.remove(
        "open"
    );

    document.body.classList.remove(
        "modal-open"
    );
}

async function copyDomain(
    domain
) {

    if (
        !domain
    ) {

        return;
    }

    try {

        if (
            navigator.clipboard &&
            navigator.clipboard.writeText
        ) {

            await navigator.clipboard.writeText(
                domain
            );

        } else {

            const textarea =
                document.createElement(
                    "textarea"
                );

            textarea.value =
                domain;

            textarea.style.position =
                "fixed";

            textarea.style.opacity =
                "0";

            document.body.appendChild(
                textarea
            );

            textarea.select();

            document.execCommand(
                "copy"
            );

            textarea.remove();
        }

        console.log(
            "Copied:",
            domain
        );

    } catch (
        error
    ) {

        console.error(
            "Copy error:",
            error
        );
    }
}

function copyCurrentDetailDomain() {

    copyDomain(
        currentDetailDomain
    );
}

async function loadScans() {

    try {

        const response =
            await fetch(
                "api/scans.php?t=" +
                Date.now(),
                {
                    cache:
                        "no-store"
                }
            );

        const data =
            await response.json();

        if (
            !data.success
        ) {

            throw new Error(
                data.error ||
                "API error"
            );
        }

        const table =
            document.getElementById(
                "scans-table"
            );

        if (
            !data.scans ||
            data.scans.length ===
            0
        ) {

            table.innerHTML = `

                <tr>

                    <td colspan="6" class="loading">${language === "de" ? "Noch keine Scans vorhanden." : "No scans yet."}</td>

                </tr>

            `;

            return;
        }

        table.innerHTML =
            data.scans.map(
                scan => `

                    <tr>

                        <td>

                            #${escapeHtml(
                                scan.id
                            )}

                        </td>

                        <td>

                            ${formatDate(
                                scan.started_at
                            )}

                        </td>

                        <td>

                            ${formatDate(
                                scan.finished_at
                            )}

                        </td>

                        <td>

                            ${escapeHtml(
                                scan.candidates_count
                            )}

                        </td>

                        <td>

                            ${escapeHtml(
                                scan.registered_count
                            )}

                        </td>

                        <td>

                            ${escapeHtml(
                                scan.active_count
                            )}

                        </td>

                    </tr>

                `
            ).join("");

    } catch (
        error
    ) {

        console.error(
            "Scan API error:",
            error
        );
    }
}

async function deleteAllData() {

    if (
        !confirm(
            "Alle Scan-Daten wirklich löschen?"
        )
    ) {

        return;
    }

    try {

        const response =
            await fetch(
                "api/delete_all.php",
                {
                    method:
                        "POST"
                }
            );

        const text =
            await response.text();

        let data;

        try {

            data =
                JSON.parse(
                    text
                );

        } catch {

            throw new Error(
                text
            );
        }

        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Delete failed"
            );
        }

        await loadDashboard();

        await loadDomains();

        await loadScans();

        await loadProtectedDomains();

        showDashboardNotice("Alle Scan-Daten wurden gelöscht.");

    } catch (
        error
    ) {

        alert(
            "Löschen fehlgeschlagen:\n\n" +
            error.message
        );
    }
}

async function startScan() {

    const button =
        document.getElementById(
            "start-scan-button"
        );

    const hasProtectedDomain = allProtectedDomains.some(domain => domain.active);
    if (!hasProtectedDomain) {
        showDashboardNotice(translations[language].noProtectedDomains, "warning");
        const protectedSection = document.getElementById("protected-domains");
        protectedSection?.scrollIntoView({ behavior: "smooth", block: "start" });
        document.getElementById("new-domain")?.focus({ preventScroll: true });
        return;
    }

    setScanStartRequested(
        true
    );

    updateScanButton(
        true
    );

    try {

        const response =
            await fetch(
                "api/start_scan.php",
                {
                    method:
                        "POST"
                }
            );

        const data =
            await response.json();

        if (
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Scan could not be started"
            );
        }

        displayedProgress =
            0;

        dashboardScanRunning =
            true;

        lastProgressStatus =
            "starting";

        const progressPanel = document.getElementById(
            "scan-progress-panel"
        );

        const progressFill = document.getElementById(
            "scan-progress-fill"
        );

        const progressPercent = document.getElementById(
            "scan-progress-percent"
        );

        const progressTitle = document.getElementById(
            "scan-progress-title"
        );

        const progressDomain = document.getElementById(
            "scan-progress-domain"
        );

        const progressCount = document.getElementById(
            "scan-progress-count"
        );

        const progressMessage = document.getElementById(
            "scan-progress-message"
        );

        if (progressPanel) {
            progressPanel.classList.add("visible");
        }

        if (progressFill) {
            progressFill.style.width = "0%";
        }

        if (progressPercent) {
            progressPercent.textContent = "0%";
        }

        if (progressTitle) {
            progressTitle.textContent = translations[language].scanStarting;
        }

        if (progressDomain) {
            progressDomain.textContent = translations[language].preparingScanner;
        }

        if (progressCount) {
            progressCount.textContent = "0 / 0";
        }

        if (progressMessage) {
            progressMessage.textContent = translations[language].starting;
        }

        updateScanButton(
            true
        );

        await loadDashboard();

        await loadScans();

        await loadScanProgress();

    } catch (
        error
    ) {

        console.error(
            "Start scan error:",
            error
        );

        alert(
            "Scan konnte nicht gestartet werden:\n\n" +
            error.message
        );

        setScanStartRequested(
            false
        );

        updateScanButton(
            false
        );
    }
}

async function stopScan() {

    if (
        !confirm(
            "Möchtest du den laufenden Scan wirklich stoppen?"
        )
    ) {

        return;
    }

    const button =
        document.getElementById(
            "stop-scan-button"
        );

    button.disabled =
        true;

    button.textContent =
        "Stopping...";

    try {

        const response =
            await fetch(
                "api/stop_scan.php",
                {
                    method:
                        "POST"
                }
            );

        const data =
            await response.json();

        if (
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Scan could not be stopped"
            );
        }

        setScanStartRequested(
            false
        );

        updateScanButton(
            false
        );

        await loadDashboard();

        await loadScans();

        await loadScanProgress();

        const stoppedProgressPanel = document.getElementById("scan-progress-panel");
        if (stoppedProgressPanel) stoppedProgressPanel.classList.remove("visible");

    } catch (
        error
    ) {

        console.error(
            "Stop scan error:",
            error
        );

        alert(
            "Scan konnte nicht gestoppt werden:\n\n" +
            error.message
        );

        button.disabled =
            false;

        button.textContent =
            "■ Stop Scan";
    }
}

async function loadScanProgress() {

    try {

        const response =
            await fetch(
                "api/progress.php?t=" +
                Date.now(),
                {
                    cache:
                        "no-store"
                }
            );

        const data =
            await response.json();

        if (
            !data.success
        ) {

            return;
        }

        const progress =
            data.progress;

        const fill =
            document.getElementById(
                "scan-progress-fill"
            );

        const percent =
            document.getElementById(
                "scan-progress-percent"
            );

        const count =
            document.getElementById(
                "scan-progress-count"
            );

        const domain =
            document.getElementById(
                "scan-progress-domain"
            );

        const title =
            document.getElementById(
                "scan-progress-title"
            );

        const message =
            document.getElementById(
                "scan-progress-message"
            );

        const progressPanel =
            document.getElementById(
                "scan-progress-panel"
            );

        const runningStatuses = [
            "starting",
            "running",
            "generating",
            "dns",
            "website",
            "rdap",
            "email_alert"
        ];

        const scanIsRunning =
            runningStatuses.includes(
                progress.status
            ) &&
            (
                dashboardScanRunning === true
                ||
                scanStartRequested
            );

        const scanHasError = progress.status === "error";

        const scanIsFinished =
            progress.status === "finished" ||
            progress.status === "cancelled" ||
            (dashboardScanRunning === false && !scanHasError);

        if (progressPanel) {

            progressPanel.classList.toggle(
                "visible",
                scanIsRunning || scanHasError
            );
        }

        if (scanIsFinished) {

            displayedProgress =
                100;
        }

        if (!scanIsRunning) {

            displayedProgress =
                scanIsFinished
                    ? 100
                    : 0;
        }

        let value =
            Number(
                progress.percentage ||
                0
            );

        if (scanIsRunning) {

            value = Math.min(
                99,
                Math.max(
                    0,
                    value
                )
            );
        }

        if (scanIsRunning) {

            displayedProgress =
                value;
        }

        const previousProgressStatus = lastProgressStatus;
        lastProgressStatus =
            progress.status ||
            "";

        fill.style.width =
            displayedProgress +
            "%";

        percent.textContent =
            displayedProgress +
            "%";

        count.textContent =
            `${progress.current || 0} / ${progress.total || 0}`;

        domain.textContent =
            progress.domain ||
            translations[language].noScanRunning;

        message.textContent = translateProgressMessage(
            progress.message || translations[language].ready
        );

        switch (
            progress.status
        ) {

            case "starting":

                title.textContent =
                    translations[language].scanStarting;

                break;

            case "running":

                title.textContent =
                    translations[language].scanStarting;

                break;

            case "generating":

                title.textContent =
                    translations[language].generatingCandidates;

                break;

            case "dns":

                    title.textContent =
                    translations[language].dnsChecks;

                break;

            case "website":

                    title.textContent =
                    translations[language].websiteChecks;

                break;

            case "rdap":

                    title.textContent =
                    translations[language].rdapChecks;

                break;

            case "finished":

                title.textContent =
                    translations[language].scanFinished;

                if (progress.message === "No protected domains configured.") {
                    message.textContent = translations[language].noProtectedDomains;
                }

                setScanStartRequested(
                    false
                );

                updateScanButton(
                    false
                );

                break;

            case "cancelled":

                title.textContent =
                    translations[language].scanCancelled;

                setScanStartRequested(
                    false
                );

                updateScanButton(
                    false
                );

                break;

            case "error":

                title.textContent =
                    translations[language].scanError;

                setScanStartRequested(
                    false
                );

                updateScanButton(
                    false
                );

                break;

            default:

                title.textContent =
                    translations[language].scannerReady;
        }

        if (
            ["finished", "cancelled", "error"].includes(progress.status) &&
            previousProgressStatus !== progress.status
        ) {
            await Promise.all([
                loadDashboard(),
                loadDomains(),
                loadScans(),
                loadProtectedDomains()
            ]);
            applyLanguage();
        }

    } catch (
        error
    ) {

        console.error(
            "Progress error:",
            error
        );
    }
}

function translateProgressMessage(message) {
    const value = String(message || "");
    if (language === "en") return value;
    const knownMessages = {
        "No protected domains configured.": "Keine geschützten Domains konfiguriert.",
        "No candidates generated.": "Keine Kandidaten erzeugt.",
        "All scans finished.": "Alle Scans abgeschlossen.",
        "Scan cancelled by user.": "Scan vom Benutzer abgebrochen."
    };
    if (knownMessages[value]) return knownMessages[value];
    if (value.startsWith("DNS: ")) return `DNS-Prüfung: ${value.slice(5)}`;
    if (value.startsWith("Website: ")) return `Website-Prüfung: ${value.slice(9)}`;
    if (value.startsWith("Generating candidates for ")) return `Kandidaten werden erzeugt für ${value.slice(27)}`;
    return value;
}

async function checkAutomaticScan() {

    try {

        if (dashboardScanRunning || scanStartRequested) return;

        const response = await fetch(
            "api/settings.php?t=" + Date.now(),
            { cache: "no-store" }
        );

        const data =
            await response.json();

        if (
            !data.success
        ) {

            console.error(
                "Automatic scan error:",
                data.error
            );

            return;
        }

        const nextScan = data.settings?.next_scan;
        updateNextScan(nextScan);

    } catch (
        error
    ) {

        console.error(
            "Automatic scan check failed:",
            error
        );
    }
}

function updateScanButton(
    running
) {

    const startButton =
        document.getElementById(
            "start-scan-button"
        );

    const stopButton =
        document.getElementById(
            "stop-scan-button"
        );

    if (
        !startButton ||
        !stopButton
    ) {

        return;
    }

    if (
        !running &&
        scanStartRequested
    ) {

        return;
    }

    if (
        running
    ) {

        startButton.disabled =
            true;

        startButton.classList.remove(
            "is-loading"
        );

        startButton.classList.add(
            "scanning-active"
        );

        startButton.textContent =
            language === "de" ? "Scan läuft" : "Scanning";

        stopButton.disabled =
            false;

        stopButton.textContent =
            language === "de" ? "■ Scan stoppen" : "■ Stop Scan";

    } else {

        startButton.disabled =
            false;

        startButton.classList.remove(
            "is-loading"
        );

        startButton.classList.remove(
            "scanning-active"
        );

        startButton.textContent =
            language === "de" ? "↻ Scan starten" : "↻ Start Scan";

        stopButton.disabled =
            true;

        stopButton.textContent =
            language === "de" ? "■ Scan stoppen" : "■ Stop Scan";
    }
}

function formatDate(
    date
) {

    if (
        !date
    ) {

        return "-";
    }

    const parsed =
        new Date(
            String(
                date
            ).replace(
                " ",
                "T"
            )
        );

    if (
        Number.isNaN(
            parsed.getTime()
        )
    ) {

        return date;
    }

    return parsed.toLocaleString(
        "de-AT",
        {

            dateStyle:
                "short",

            timeStyle:
                "short"

        }
    );
}

function escapeHtml(
    value
) {

    return String(
        value ?? ""
    )

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}

async function initDashboard() {

    loadTheme();

    if (scanStartRequested) {

        updateScanButton(
            true
        );
    }

    await Promise.all([
        loadDashboard(),
        loadProtectedDomains(),
        loadDomains(),
        loadScans(),
        loadScanProgress(),
        loadSettings()
    ]);
    applyLanguage();

    setupDomainTableEvents();
    setupPageNavigation();
    showPage("dashboard");

}

document.getElementById("login-form")?.addEventListener(
    "submit",
    login
);

function updateAdminNavigation(isAdmin) {
    const navigation = document.querySelector("#main-sidebar nav");
    if (!navigation) return;
    navigation.querySelectorAll(".admin-nav").forEach(element => element.remove());
    if (isAdmin) {
        const link = document.createElement("a");
        link.href = "admin.php";
        link.className = "nav-item admin-nav";
        link.dataset.i18n = "adminPanel";
        link.textContent = translations[language].adminPanel;
        navigation.append(link);
    }
}
document.getElementById("registration-toggle")?.addEventListener("click", event => {
    event.preventDefault();
    const fields = document.getElementById("registration-fields");
    const registering = fields.hidden;
    fields.hidden = !registering;
    document.getElementById("register-password-confirm").hidden = !registering;
    document.getElementById("register-email").required = registering;
    document.getElementById("register-password-confirm").required = registering;
    document.querySelector("#login-form button[type=submit]").textContent = registering ? translations[language].register : translations[language].loginButton;
    document.getElementById("registration-toggle").textContent = registering ? translations[language].loginButton : translations[language].register;
    document.getElementById("auth-mode-title").textContent = registering ? translations[language].registerMode : translations[language].loginMode;
    document.getElementById("auth-mode-description").textContent = registering ? translations[language].registerModeDescription : translations[language].loginModeDescription;
    document.getElementById("auth-mode").classList.toggle("is-registering", registering);
    if (registering) updateAuthPlanSelection(document.getElementById("register-plan").value || "pro");
});

document.querySelectorAll("[data-plan-choice]").forEach(button => {
    button.addEventListener("click", () => updateAuthPlanSelection(button.dataset.planChoice));
});

(async function boot() {
    if (await initAuth()) {
        await initDashboard();
    }
})();

let dashboardRefreshInProgress = false;
setInterval(async () => {
    if (!currentUser || dashboardRefreshInProgress || dashboardScanRunning || scanStartRequested) return;
    dashboardRefreshInProgress = true;
    try {
        await Promise.all([loadDashboard(), loadScans()]);
        applyLanguage();
    } finally {
        dashboardRefreshInProgress = false;
    }
}, 60000);

setInterval(async () => {
    if (!currentUser) return;
    await loadScanProgress();
}, 1000);

document.addEventListener(
    "keydown",
    event => {

        if (
            event.key ===
            "Escape"
        ) {

            closeDomainDetails();
        }

    }
);
