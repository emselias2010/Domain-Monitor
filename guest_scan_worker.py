import json
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

WORDS = ["login", "secure", "account", "support", "service", "online", "verify", "portal", "mail", "admin", "help", "auth", "billing", "alert", "update", "official", "team", "cloud", "app", "check", "access"]
LIMIT = 15000
TRUSTED_REDIRECT_RISK_REDUCTION = 60


def is_domain_or_subdomain(hostname, domain):
    hostname = (hostname or "").lower().rstrip(".")
    domain = (domain or "").lower().rstrip(".")
    return hostname == domain or hostname.endswith("." + domain)


def guest_risk_score(domain, protected_domain, website_data):
    score = 15
    if website_data["website_active"] and not website_data["redirected_to_protected"]:
        score += 20
    if website_data["login_found"]:
        score += 20
    if website_data["company_name_found"]:
        score += 15
    if website_data["company_name_header"]:
        score += 15

    brand = protected_domain.split(".")[0].lower().replace("-", "")
    if brand and brand in domain.lower().replace("-", ""):
        score += 15

    if website_data["website_active"] and website_data["redirected_to_protected"]:
        score = max(0, score - 20)
    final_host = website_data.get("final_host", "")
    if website_data["website_active"] and is_domain_or_subdomain(final_host, protected_domain):
        score = max(0, score - TRUSTED_REDIRECT_RISK_REDUCTION)
    return min(100, score)


def candidates(domain):
    name, suffix = domain.split(".", 1)
    words = ["login", "secure", "account", "support", "service", "online", "verify", "portal", "mail", "admin", "help", "auth", "billing", "alert", "update", "official", "team", "cloud", "app", "check", "access", "web", "customer", "center", "connect", "security", "company", "my", "work", "info", "client", "members", "portal", "shop", "store", "pay", "signin", "confirm", "career", "jobs"]
    values = []
    seen = set()
    for word in words:
        for value in (f"{name}-{word}.{suffix}", f"{word}-{name}.{suffix}", f"{name}.{word}.{suffix}", f"{name}{word}.{suffix}"):
            if value not in seen:
                seen.add(value)
                values.append(value)
    for first in words:
        for second in words:
            for value in (f"{name}-{first}-{second}.{suffix}", f"{first}-{name}-{second}.{suffix}"):
                if value not in seen:
                    seen.add(value)
                    values.append(value)
                if len(values) >= LIMIT:
                    return values
    substitutions = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}
    for position, character in enumerate(name):
        replacement = substitutions.get(character)
        if replacement:
            variant = name[:position] + replacement + name[position + 1:]
            for value in (f"{variant}.{suffix}", f"{variant}-login.{suffix}", f"{variant}-secure.{suffix}"):
                if value not in seen:
                    seen.add(value)
                    values.append(value)
    index = 0
    while len(values) < LIMIT:
        value = f"{name}-variant-{index}.{suffix}"
        if value not in seen:
            seen.add(value)
            values.append(value)
        index += 1
    return values


def check_dns(domain):
    try:
        socket.setdefaulttimeout(1.0)
        socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        return domain
    except (socket.timeout, socket.gaierror, OSError):
        return None


def website(domain, protected_domain):
    for scheme in ("https", "http"):
        try:
            response = requests.get(f"{scheme}://{domain}", timeout=4, allow_redirects=True, headers={"User-Agent": "Domain-Monitor/1.0"})
            html = response.text or ""
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
            final_host = urlparse(response.url).hostname or ""
            lower_html = html.lower()
            return {"website_active": True, "http_status": response.status_code, "title": title, "final_url": response.url, "final_host": final_host, "redirected_to_protected": is_domain_or_subdomain(final_host, protected_domain) and final_host.lower() != domain.lower(), "login_found": any(word in lower_html for word in ("login", "sign in", "passwort", "password")), "company_name_found": protected_domain.split(".")[0].lower() in lower_html, "company_name_header": protected_domain.split(".")[0].lower() in (response.headers.get("server", "") + response.headers.get("location", "")).lower()}
        except Exception:
            continue
    return {"website_active": False, "http_status": None, "title": "", "final_url": "", "final_host": "", "redirected_to_protected": False, "login_found": False, "company_name_found": False, "company_name_header": False}


def emit(payload):
    print(json.dumps(payload, separators=(",", ":")), flush=True)


def main():
    domain = sys.argv[1]
    values = candidates(domain)
    emit({"type": "phase", "phase": "candidates", "current": len(values), "total": len(values)})
    dns_domains = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(check_dns, value) for value in values]
        for index, future in enumerate(as_completed(futures), 1):
            try:
                value = future.result()
            except Exception:
                value = None
            if value:
                dns_domains.append(value)
            if index == 1 or index % 250 == 0 or index == len(values):
                emit({"type": "phase", "phase": "dns", "current": index, "total": len(values), "registered": len(dns_domains)})

    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(website, value, domain): value for value in dns_domains}
        for index, future in enumerate(as_completed(futures), 1):
            value = futures[future]
            try:
                web = future.result()
            except Exception:
                web = {"website_active": False, "http_status": None, "title": "", "final_url": "", "final_host": "", "redirected_to_protected": False, "login_found": False, "company_name_found": False, "company_name_header": False}
            risk_score = guest_risk_score(value, domain, web)
            risk_level = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 30 else "low"
            result = {"domain": value, "dns_active": True, "ips": [], "risk_score": risk_score, "risk_level": risk_level, **web}
            results.append(result)
            emit({"type": "result", "result": result, "current": index, "total": len(dns_domains)})
            if index == 1 or index % 25 == 0 or index == len(dns_domains):
                emit({"type": "phase", "phase": "websites", "current": index, "total": len(dns_domains)})

    emit({"type": "phase", "phase": "report", "current": 1, "total": 1})
    emit({"type": "complete", "candidates": len(values), "registered": len(dns_domains), "results": results})


if __name__ == "__main__":
    main()
