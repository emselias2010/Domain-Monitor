import json
import argparse
import hashlib
import os
import re
import socket
import smtplib
import subprocess
import sys
import time
from email.message import EmailMessage
from urllib.parse import urlparse

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

import mysql.connector
import requests

from config import (
    DB_HOST,
    DB_PORT,
    DB_USER,
    DB_PASSWORD,
    DB_NAME
)


# ============================================================
# WINDOWS CONSOLE / OUTPUT ENCODING
# ============================================================

try:
    sys.stdout.reconfigure(
        encoding="utf-8",
        errors="replace"
    )

    sys.stderr.reconfigure(
        encoding="utf-8",
        errors="replace"
    )

except AttributeError:
    pass


# ============================================================
# SETTINGS
# ============================================================

REQUEST_TIMEOUT = 6
WEBSITE_TIMEOUT = 12
WEBSITE_ATTEMPTS = 2
RDAP_TIMEOUT = 3

DNS_WORKERS = 30
WEBSITE_WORKERS = 8
RDAP_WORKERS = 20

DICTIONARY_VARIANT_LIMIT = 1053
MAX_GENERATED_CANDIDATES = 1_000_000
THREAT_INTELLIGENCE_ENABLED = False
OPENPHISH_DOMAINS = None

# Amount subtracted from the risk score when the website
# clearly appears to be a domain-for-sale / parking page.
FOR_SALE_RISK_REDUCTION = 25
TRUSTED_REDIRECT_RISK_REDUCTION = 60

USER_AGENT = (
    "Domain-Monitor/1.0 "
    "(authorized security monitoring)"
)

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

PROGRESS_FILE = os.path.join(
    BASE_DIR,
    "scan_progress.json"
)

PROGRESS_TEMP_FILE = os.path.join(
    BASE_DIR,
    "scan_progress.tmp"
)

TLD_FILE = os.path.join(
    BASE_DIR,
    "tlds.txt"
)

DICTIONARY_FILE = os.path.join(
    BASE_DIR,
    "dictionary.txt"
)

DNSTWIST_FUZZERS = (
    "*original,addition,bitsquatting,cyrillic,"
    "homoglyph,hyphenation,insertion,omission,plural,"
    "repetition,replacement,subdomain,transposition,"
    "vowel-swap,dictionary,tld-swap"
)

PID_FILE = os.path.join(
    BASE_DIR,
    "scanner.pid"
)

RDAP_BOOTSTRAP_URL = (
    "https://data.iana.org/rdap/dns.json"
)

rdap_bootstrap = None
SCAN_USER_ID = 0
SCAN_JOB_ID = 0


def configure_scan_runtime():

    global SCAN_USER_ID
    global SCAN_JOB_ID
    global PROGRESS_FILE
    global PROGRESS_TEMP_FILE
    global PID_FILE

    parser = argparse.ArgumentParser()
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--job-id", type=int, required=True)
    parser.add_argument("--progress-file", required=True)
    parser.add_argument("--pid-file", required=True)
    parser.add_argument("--log-file", required=False)

    args = parser.parse_args()

    SCAN_USER_ID = args.user_id
    SCAN_JOB_ID = args.job_id
    PROGRESS_FILE = os.path.abspath(args.progress_file)
    PROGRESS_TEMP_FILE = PROGRESS_FILE + ".tmp"
    PID_FILE = os.path.abspath(args.pid_file)


# ============================================================
# DATABASE
# ============================================================

def get_connection():

    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=False
    )


def ensure_connection(connection):

    try:

        connection.ping(
            reconnect=True,
            attempts=3,
            delay=1
        )

    except mysql.connector.Error:

        connection.reconnect(
            attempts=3,
            delay=1
        )


# ============================================================
# PID FILE
# ============================================================

def create_pid_file():

    try:

        with open(
            PID_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                str(os.getpid())
            )

    except OSError as error:

        print(
            f"[!] Could not create PID file: {error}"
        )


def remove_pid_file():

    try:

        if os.path.exists(
            PID_FILE
        ):

            os.remove(
                PID_FILE
            )

    except OSError:

        pass


# ============================================================
# NEXT AUTOMATIC SCAN
# ============================================================

def schedule_next_scan(
    connection
):

    ensure_connection(
        connection
    )

    cursor = connection.cursor(
        dictionary=True
    )

    cursor.execute(
        """
        SELECT
            id,
            enabled,
            interval_hours
        FROM scan_settings
        WHERE user_id = %s
        ORDER BY id ASC
        LIMIT 1
        """,
        (SCAN_USER_ID,)
    )

    settings = cursor.fetchone()

    cursor.close()

    if not settings:
        return

    if not settings["enabled"]:
        return

    interval_hours = int(
        settings["interval_hours"]
    )

    next_scan = (
        datetime.now()
        +
        timedelta(
            hours=interval_hours
        )
    )

    ensure_connection(
        connection
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE scan_settings
        SET
            next_scan = %s,
            updated_at = NOW()
        WHERE id = %s
        """,
        (
            next_scan.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            settings["id"]
        )
    )

    connection.commit()

    cursor.close()

    print(
        "[+] Next automatic scan: "
        +
        next_scan.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )


def load_scan_limit(connection):

    global MAX_GENERATED_CANDIDATES
    global THREAT_INTELLIGENCE_ENABLED

    cursor = connection.cursor(dictionary=True)
    cursor.execute(
        "SELECT role, plan, pro_until FROM users WHERE id = %s LIMIT 1",
        (SCAN_USER_ID,)
    )
    user = cursor.fetchone() or {}
    trial_active = False
    if user.get("pro_until"):
        trial_until = user["pro_until"]
        if isinstance(trial_until, str):
            trial_until = datetime.strptime(trial_until, "%Y-%m-%d %H:%M:%S")
        trial_active = trial_until >= datetime.now()
    permanent_pro = user.get("role") == "admin" or (user.get("plan") == "pro" and not user.get("pro_until"))
    plan_limit = 1_000_000 if permanent_pro or (user.get("plan") == "pro" and trial_active) else 50_000
    cursor.execute(
        "SELECT max_domains, threat_intelligence_enabled FROM scan_settings "
        "WHERE user_id = %s ORDER BY id ASC LIMIT 1",
        (SCAN_USER_ID,)
    )
    settings = cursor.fetchone() or {}
    cursor.close()

    MAX_GENERATED_CANDIDATES = max(
        1000,
        min(plan_limit, int(settings.get("max_domains") or plan_limit))
    )

    has_pro_access = permanent_pro or (user.get("plan") == "pro" and trial_active)
    THREAT_INTELLIGENCE_ENABLED = bool(settings.get("threat_intelligence_enabled", 0)) and has_pro_access


# ============================================================
# PROGRESS
# ============================================================

def update_progress(
    status,
    current=0,
    total=0,
    domain="",
    message="",
    protected_current=0,
    protected_total=0
):

    percentage = 0

    if total > 0:

        phase_ranges = {
            "generating": (0, 5),
            "dns": (5, 50),
            "website": (50, 80),
            "rdap": (80, 100)
        }

        phase_start, phase_end = phase_ranges.get(
            status,
            (0, 100)
        )

        phase_progress = min(
            1,
            max(
                0,
                current / total
            )
        )

        percentage = int(
            phase_start
            +
            (
                (phase_end - phase_start)
                * phase_progress
            )
        )

        if status != "finished":

            percentage = min(
                99,
                percentage
            )

    elif status == "finished":

        percentage = 100


    data = {
        "status":
            status,

        "current":
            current,

        "total":
            total,

        "percentage":
            percentage,

        "domain":
            domain,

        "message":
            message,

        "protected_current":
            protected_current,

        "protected_total":
            protected_total,

        "updated_at":
            datetime.now().isoformat()
    }


    try:

        with open(
            PROGRESS_TEMP_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4
            )

            file.flush()

            os.fsync(
                file.fileno()
            )


        for attempt in range(5):

            try:

                os.replace(
                    PROGRESS_TEMP_FILE,
                    PROGRESS_FILE
                )

                return

            except PermissionError:

                if attempt == 4:
                    raise

                time.sleep(0.05)


    except OSError as error:

        try:

            with open(
                PROGRESS_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    data,
                    file,
                    indent=4
                )

        except OSError as fallback_error:

            print(
                f"[!] Could not update progress: {error}; "
                f"fallback failed: {fallback_error}"
            )


# ============================================================
# PROTECTED DOMAINS
# ============================================================

def get_protected_domains(
    connection
):

    ensure_connection(
        connection
    )

    cursor = connection.cursor(
        dictionary=True
    )

    cursor.execute(
        """
        SELECT
            id,
            domain
        FROM protected_domains
        WHERE active = 1
        AND user_id = %s
        ORDER BY id ASC
        """,
        (SCAN_USER_ID,)
    )

    domains = cursor.fetchall()

    cursor.close()

    return domains


def get_excluded_domains(
    connection
):

    ensure_connection(
        connection
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS excluded_domains (
            id INT AUTO_INCREMENT PRIMARY KEY,
            domain VARCHAR(253) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    connection.commit()

    cursor.execute(
        """
        SELECT domain
        FROM excluded_domains
        WHERE user_id = %s
        ORDER BY id ASC
        """,
        (SCAN_USER_ID,)
    )

    domains = [
        row[0].strip().lower()
        for row in cursor.fetchall()
        if row[0]
    ]

    cursor.close()

    return domains


def is_excluded_domain(
    candidate,
    excluded_domains
):

    candidate = candidate.strip().lower().rstrip(".")

    return any(
        candidate == excluded
        or candidate.endswith("." + excluded)
        for excluded in excluded_domains
    )


def is_domain_or_subdomain(
    hostname,
    domain
):

    hostname = hostname.strip().lower().rstrip(".")
    domain = domain.strip().lower().rstrip(".")

    return (
        hostname == domain
        or hostname.endswith("." + domain)
    )


def check_urlhaus_domain(domain):

    checked_at = datetime.now()
    normalized_domain = domain.strip().lower().rstrip(".")
    reference_url = "https://urlhaus.abuse.ch/host/" + normalized_domain + "/"

    if not THREAT_INTELLIGENCE_ENABLED:
        return {
            "source": "URLhaus",
            "status": "NOT_CHECKED",
            "category": "disabled",
            "detections": 0,
            "reference_url": reference_url,
            "checked_at": checked_at
        }

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": normalized_domain},
            timeout=5
        )
        response.raise_for_status()
        payload = response.json()
        urls = payload.get("urls") or []

        if urls:
            return {
                "source": "URLhaus",
                "status": "REPORTED",
                "category": "malware",
                "detections": len(urls),
                "reference_url": reference_url,
                "checked_at": checked_at
            }

        if payload.get("query_status") in ("no_results", "no_urls"):
            return {
                "source": "URLhaus",
                "status": "CLEAN",
                "category": "not_reported",
                "detections": 0,
                "reference_url": reference_url,
                "checked_at": checked_at
            }

        return {
            "source": "URLhaus",
            "status": "UNKNOWN",
            "category": "unknown",
            "detections": 0,
            "reference_url": reference_url,
            "checked_at": checked_at
        }

    except (requests.RequestException, ValueError) as error:
        print(f"[!] URLhaus check failed for {domain}: {error}")
        return {
            "source": "URLhaus",
            "status": "UNKNOWN",
            "category": "error",
            "detections": 0,
            "reference_url": reference_url,
            "checked_at": checked_at
        }


def load_openphish_domains():

    global OPENPHISH_DOMAINS

    if OPENPHISH_DOMAINS is not None:
        return OPENPHISH_DOMAINS

    try:
        response = requests.get(
            "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt",
            timeout=15
        )
        response.raise_for_status()
        domains = set()
        for line in response.text.splitlines():
            hostname = urlparse(line.strip()).hostname
            if hostname:
                domains.add(hostname.lower().rstrip("."))
        OPENPHISH_DOMAINS = domains
    except (requests.RequestException, ValueError) as error:
        print(f"[!] OpenPhish feed unavailable: {error}")
        OPENPHISH_DOMAINS = set()

    return OPENPHISH_DOMAINS


def check_openphish_domain(domain):

    checked_at = datetime.now()
    normalized_domain = domain.strip().lower().rstrip(".")
    reference_url = "https://openphish.com/"

    if not THREAT_INTELLIGENCE_ENABLED:
        return {
            "source": "OpenPhish",
            "status": "NOT_CHECKED",
            "category": "disabled",
            "detections": 0,
            "reference_url": reference_url,
            "checked_at": checked_at
        }

    domains = load_openphish_domains()
    reported = normalized_domain in domains or any(
        normalized_domain.endswith("." + reported_domain)
        for reported_domain in domains
    )

    return {
        "source": "OpenPhish",
        "status": "REPORTED" if reported else "CLEAN",
        "category": "phishing" if reported else "not_reported",
        "detections": 1 if reported else 0,
        "reference_url": reference_url,
        "checked_at": checked_at
    }


def check_threatfox_domain(domain):

    checked_at = datetime.now()
    normalized_domain = domain.strip().lower().rstrip(".")
    reference_url = "https://threatfox.abuse.ch/"

    if not THREAT_INTELLIGENCE_ENABLED:
        return {
            "source": "ThreatFox",
            "status": "NOT_CHECKED",
            "category": "disabled",
            "detections": 0,
            "reference_url": reference_url,
            "checked_at": checked_at
        }

    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": normalized_domain},
            timeout=8
        )
        response.raise_for_status()
        payload = response.json()
        indicators = payload.get("data") or []
        matching_indicators = [
            indicator
            for indicator in indicators
            if normalized_domain in str(indicator.get("ioc", "")).lower()
            or normalized_domain in str(indicator.get("host", "")).lower()
        ]

        return {
            "source": "ThreatFox",
            "status": "REPORTED" if matching_indicators else "CLEAN",
            "category": "malware" if matching_indicators else "not_reported",
            "detections": len(matching_indicators),
            "reference_url": reference_url,
            "checked_at": checked_at
        }
    except (requests.RequestException, ValueError) as error:
        print(f"[!] ThreatFox check failed for {domain}: {error}")
        return {
            "source": "ThreatFox",
            "status": "UNKNOWN",
            "category": "error",
            "detections": 0,
            "reference_url": reference_url,
            "checked_at": checked_at
        }
def save_threat_intelligence(connection, domain_id, result):

    ensure_connection(connection)
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO threat_intelligence
            (domain_id, source, status, category, detections, reference_url, checked_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            status = VALUES(status),
            category = VALUES(category),
            detections = VALUES(detections),
            reference_url = VALUES(reference_url),
            checked_at = VALUES(checked_at)
        """,
        (
            domain_id,
            result["source"],
            result["status"],
            result["category"],
            result["detections"],
            result["reference_url"],
            result["checked_at"]
        )
    )
    connection.commit()
    cursor.close()


# ============================================================
# DNSTWIST
# ============================================================

def generate_candidates(
    protected_domain
):

    print()

    print(
        f"[+] Generating candidates for "
        f"{protected_domain}..."
    )

    command = [
        sys.executable,
        "-m",
        "dnstwist",
        "--format",
        "list",
        "--fuzzers",
        DNSTWIST_FUZZERS,
        "--dictionary",
        DICTIONARY_FILE,
        "--tld",
        TLD_FILE,
        protected_domain
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

    except subprocess.TimeoutExpired:

        print(
            f"[!] Candidate generation timed out "
            f"for {protected_domain}"
        )

        return []

    except OSError as error:

        print(
            f"[!] Could not start dnstwist: "
            f"{error}"
        )

        return []


    if result.returncode != 0:

        print(
            f"[!] dnstwist failed for "
            f"{protected_domain}"
        )

        if result.stderr:

            print(
                result.stderr
            )

        return []


    candidates = []
    candidate_set = set()

    protected_lower = (
        protected_domain
        .strip()
        .lower()
    )


    for line in result.stdout.splitlines():

        candidate = (
            line
            .strip()
            .lower()
        )


        if not candidate:
            continue


        if candidate == protected_lower:
            continue


        add_candidate(candidate, protected_lower, candidates, candidate_set)


    certificate_candidates = (
        generate_certificate_candidates(
            protected_domain
        )
    )


    for candidate in certificate_candidates:

        add_candidate(candidate, protected_lower, candidates, candidate_set)

    for candidate in generate_extended_candidates(
        protected_domain,
        candidates
    ):
        add_candidate(candidate, protected_lower, candidates, candidate_set)


    print(
        f"[+] Certificate Transparency: "
        f"{len(certificate_candidates)} additional candidates"
    )


    return candidates


def is_punycode_candidate(candidate):

    return any(
        label.startswith("xn--")
        for label in candidate.lower().split(".")
    )


def add_candidate(
    candidate,
    protected_domain,
    candidates,
    candidate_set
):

    candidate = candidate.strip().lower().rstrip(".")

    if (
        not candidate
        or candidate == protected_domain
        or is_punycode_candidate(candidate)
        or len(candidate) > 253
        or candidate in candidate_set
        or len(candidates) >= MAX_GENERATED_CANDIDATES
    ):
        return

    labels = candidate.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return

    candidate_set.add(candidate)
    candidates.append(candidate)


def generate_extended_candidates(
    protected_domain,
    dnstwist_candidates
):

    protected_domain = protected_domain.strip().lower().rstrip(".")
    labels = protected_domain.split(".")
    if len(labels) < 2:
        return []

    name = labels[0]
    suffix = ".".join(labels[1:])
    seeds = [name]

    for candidate in dnstwist_candidates:
        candidate_labels = candidate.split(".")
        if (
            len(candidate_labels) == len(labels)
            and candidate_labels[1:] == labels[1:]
            and not is_punycode_candidate(candidate)
        ):
            seeds.append(candidate_labels[0])

    seeds = list(dict.fromkeys(seeds))[:250]
    variants = []

    for seed in seeds:
        for position in range(1, len(seed)):
            for separator in ("-", "."):
                split_name = seed[:position] + separator + seed[position:]
                variants.append(f"{split_name}.{suffix}")

        for replacement, lookalikes in LOOKALIKE_REPLACEMENTS.items():
            for lookalike in lookalikes:
                if replacement in seed:
                    variants.append(
                        f"{seed.replace(replacement, lookalike, 1)}.{suffix}"
                    )

    words = load_dictionary_words()
    for word in words:
        for seed in seeds:
            for separator in ("-", "."):
                variants.extend((
                    f"{word}{separator}{seed}.{suffix}",
                    f"{seed}{separator}{word}.{suffix}"
                ))

    return variants


def load_dictionary_words():

    try:
        with open(DICTIONARY_FILE, "r", encoding="utf-8") as dictionary:
            words = dictionary.read().splitlines()
    except OSError as error:
        print(f"[!] Could not read dictionary variants: {error}")
        return []

    return [
        word.strip().lower()
        for word in words
        if re.fullmatch(r"[a-z0-9]+", word.strip().lower())
    ][:DICTIONARY_VARIANT_LIMIT]


LOOKALIKE_REPLACEMENTS = {
    "a": ("4",),
    "b": ("8",),
    "e": ("3",),
    "g": ("9",),
    "i": ("1", "l"),
    "o": ("0",),
    "s": ("5",),
}


def generate_hyphen_prefix_candidates(
    protected_domain
):

    protected_domain = protected_domain.strip().lower().rstrip(".")
    candidates = []

    try:
        with open(DICTIONARY_FILE, "r", encoding="utf-8") as dictionary:
            words = dictionary.read().splitlines()
    except OSError as error:
        print(f"[!] Could not read dictionary for hyphen prefixes: {error}")
        return candidates

    for word in words:
        prefix = word.strip().lower()
        if not prefix or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", prefix):
            continue

        candidate = f"{prefix}-{protected_domain}"
        if len(candidate) <= 253 and candidate != protected_domain:
            candidates.append(candidate)

    return candidates


def generate_certificate_candidates(
    protected_domain
):

    try:

        response = requests.get(
            "https://crt.sh/",
            params={
                "q":
                    "%." + protected_domain,
                "output":
                    "json"
            },
            headers={
                "User-Agent":
                    USER_AGENT
            },
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        records = response.json()

    except (
        requests.RequestException,
        ValueError
    ) as error:

        print(
            f"[!] Certificate Transparency lookup failed "
            f"for {protected_domain}: {error}"
        )

        return []


    protected_lower = (
        protected_domain
        .strip()
        .lower()
    )

    suffix = (
        "." +
        protected_lower
    )

    candidates = []


    for record in records:

        names = (
            record.get(
                "name_value",
                ""
            )
            if isinstance(
                record,
                dict
            )
            else ""
        )


        for name in names.splitlines():

            candidate = (
                name
                .strip()
                .lower()
                .lstrip("*.")
                .rstrip(".")
            )


            if (
                not candidate or
                candidate == protected_lower or
                not candidate.endswith(suffix)
            ):

                continue


            if candidate not in candidates:

                candidates.append(
                    candidate
                )


    return candidates


# ============================================================
# DNS
# ============================================================

def check_dns(
    domain
):

    try:

        addresses = (
            socket
            .gethostbyname_ex(
                domain
            )[2]
        )


        if addresses:

            return True, addresses


    except (
        socket.gaierror,
        OSError
    ):

        pass


    return False, []


def dns_worker(
    domain
):

    active, ips = check_dns(
        domain
    )

    return {
        "domain":
            domain,

        "dns_active":
            active,

        "ips":
            ips
    }


# ============================================================
# HOSTNAME
# ============================================================

def get_hostname(
    url
):

    try:

        hostname = (
            url
            .split(
                "://",
                1
            )[-1]
            .split(
                "/",
                1
            )[0]
            .split(
                ":",
                1
            )[0]
            .lower()
            .strip(".")
        )

        return hostname

    except Exception:

        return ""


# ============================================================
# WEBSITE CHECK
# ============================================================

def check_website(
    domain,
    protected_domain
):

    headers = {
        "User-Agent":
            USER_AGENT
    }


    urls = [
        f"https://{domain}",
        f"http://{domain}"
    ]


    for url in urls:

        for attempt in range(
            WEBSITE_ATTEMPTS
        ):

            try:

                response = requests.get(
                    url,
                    headers=headers,
                    timeout=WEBSITE_TIMEOUT,
                    allow_redirects=True
                )


                html = (
                    response.text
                    or ""
                )

                if response.status_code == 429:
                    return {
                        "active": True,
                        "status": 429,
                        "title": "",
                        "url": response.url,
                        "redirected_to_protected": False,
                        "login_found": False,
                        "company_name_found": False,
                        "company_name_header": False,
                        "domain_for_sale": False
                    }


                final_url = (
                    response.url
                )


                final_hostname = (
                    get_hostname(
                        final_url
                    )
                )


                protected_hostname = (
                    protected_domain
                    .lower()
                    .strip()
                    .rstrip(".")
                )


                current_domain = (
                    domain
                    .lower()
                    .strip()
                    .rstrip(".")
                )


                redirected_to_protected = (
                    final_hostname ==
                    protected_hostname
                    and
                    final_hostname !=
                    current_domain
                )


                # ------------------------------------------------
                # WEBSITE CONTENT ANALYSIS
                # ------------------------------------------------

                login_found = detect_login(
                    html
                )


                company_name_found = detect_brand(
                    html,
                    protected_domain
                )


                company_name_header = (
                    detect_brand_in_header(
                        html,
                        protected_domain
                    )
                )


                domain_for_sale = (
                    detect_domain_for_sale(
                        html
                    )
                )


                title = extract_title(
                    html
                )


                return {

                "active":
                    True,

                "status":
                    response.status_code,

                "title":
                    title,

                "url":
                    final_url,

                "redirected_to_protected":
                    redirected_to_protected,

                "login_found":
                    login_found,

                "company_name_found":
                    company_name_found,

                "company_name_header":
                    company_name_header,

                "domain_for_sale":
                    domain_for_sale
                }


            except requests.RequestException:

                if attempt + 1 < WEBSITE_ATTEMPTS:
                    continue

                break


    return {

        "active":
            False,

        "status":
            None,

        "title":
            "",

        "url":
            "",

        "redirected_to_protected":
            False,

        "login_found":
            False,

        "company_name_found":
            False,

        "company_name_header":
            False,

        "domain_for_sale":
            False
    }


def website_worker(
    domain,
    protected_domain
):

    website = check_website(
        domain,
        protected_domain
    )


    return {

        "domain":
            domain,

        "website":
            website
    }


# ============================================================
# RDAP BOOTSTRAP
# ============================================================

def load_rdap_bootstrap():

    global rdap_bootstrap


    if rdap_bootstrap is not None:

        return rdap_bootstrap


    try:

        response = requests.get(

            RDAP_BOOTSTRAP_URL,

            headers={

                "User-Agent":
                    USER_AGENT,

                "Accept":
                    "application/json"

            },

            timeout=RDAP_TIMEOUT
        )


        response.raise_for_status()


        rdap_bootstrap = (
            response.json()
        )


        return rdap_bootstrap


    except (
        requests.RequestException,
        ValueError
    ) as error:

        print(
            f"[!] Could not load RDAP bootstrap: "
            f"{error}"
        )


        rdap_bootstrap = {}

        return rdap_bootstrap


# ============================================================
# RDAP SERVER
# ============================================================

def get_rdap_server(
    domain
):

    bootstrap = (
        load_rdap_bootstrap()
    )


    if not bootstrap:

        return None


    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )


    if "." not in domain:

        return None


    tld = (
        domain
        .split(".")[-1]
    )


    services = bootstrap.get(
        "services",
        []
    )


    for service in services:

        if (
            not isinstance(
                service,
                list
            )
            or
            len(service) < 2
        ):

            continue


        tlds = service[0]

        urls = service[1]


        if not isinstance(
            tlds,
            list
        ):

            continue


        if not isinstance(
            urls,
            list
        ):

            continue


        if (
            tld in tlds
            and
            urls
        ):

            return urls[0]


    return None


# ============================================================
# RDAP REGISTRAR
# ============================================================

def extract_registrar(
    data
):

    entities = data.get(
        "entities",
        []
    )


    if not isinstance(
        entities,
        list
    ):

        return None


    for entity in entities:

        if not isinstance(
            entity,
            dict
        ):

            continue


        roles = entity.get(
            "roles",
            []
        )


        if (
            "registrar"
            not in
            roles
        ):

            continue


        vcard_array = entity.get(
            "vcardArray",
            []
        )


        if (
            isinstance(
                vcard_array,
                list
            )
            and
            len(vcard_array) >= 2
            and
            isinstance(
                vcard_array[1],
                list
            )
        ):

            for item in vcard_array[1]:

                if (
                    isinstance(
                        item,
                        list
                    )
                    and
                    len(item) >= 4
                    and
                    item[0] == "fn"
                ):

                    value = item[3]


                    if value:

                        return str(
                            value
                        )[:255]


        handle = entity.get(
            "handle"
        )


        if handle:

            return str(
                handle
            )[:255]


    return None


# ============================================================
# RDAP REGISTRATION
# ============================================================

def get_registration_data(
    domain
):

    result = {

        "registration_date":
            None,

        "registrar":
            None

    }


    rdap_server = (
        get_rdap_server(
            domain
        )
    )


    if not rdap_server:

        return result


    url = (
        rdap_server.rstrip("/")
        +
        "/domain/"
        +
        domain
    )


    try:

        response = requests.get(

            url,

            headers={

                "User-Agent":
                    USER_AGENT,

                "Accept":
                    "application/rdap+json, "
                    "application/json"

            },

            timeout=RDAP_TIMEOUT
        )


        if response.status_code != 200:

            return result


        data = response.json()


        if (
            data.get(
                "objectClassName"
            )
            !=
            "domain"
        ):

            return result


        events = data.get(
            "events",
            []
        )


        if isinstance(
            events,
            list
        ):

            for event in events:

                if not isinstance(
                    event,
                    dict
                ):

                    continue


                if (
                    event.get(
                        "eventAction"
                    )
                    !=
                    "registration"
                ):

                    continue


                event_date = event.get(
                    "eventDate"
                )


                if not event_date:

                    continue


                try:

                    parsed_date = (
                        datetime.fromisoformat(
                            event_date.replace(
                                "Z",
                                "+00:00"
                            )
                        )
                    )


                    result[
                        "registration_date"
                    ] = (
                        parsed_date
                        .replace(
                            tzinfo=None
                        )
                        .strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )


                except ValueError:

                    result[
                        "registration_date"
                    ] = str(
                        event_date
                    )[:19]


                break


        result["registrar"] = (
            extract_registrar(
                data
            )
        )


    except (
        requests.RequestException,
        ValueError,
        TypeError
    ):

        pass


    return result


def rdap_worker(
    domain
):

    registration_data = (
        get_registration_data(
            domain
        )
    )

    return {

        "domain":
            domain,

        "registration_data":
            registration_data

    }


def bounded_futures(items, worker, max_workers):
    item_iterator = iter(items)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        pending = {}
        for _ in range(max_workers * 2):
            try:
                item = next(item_iterator)
            except StopIteration:
                break
            pending[executor.submit(worker, item)] = item
        while pending:
            completed = next(as_completed(pending))
            item = pending.pop(completed)
            yield item, completed
            try:
                next_item = next(item_iterator)
            except StopIteration:
                continue
            pending[executor.submit(worker, next_item)] = next_item


# ============================================================
# LOGIN DETECTION
# ============================================================

def detect_login(
    html
):

    text = html.lower()


    if re.search(
        r'<input[^>]+type\s*=\s*["\']?password',
        text,
        re.IGNORECASE
    ):

        return True


    login_keywords = [

        "login",
        "log in",
        "sign in",
        "signin",
        "anmelden",
        "einloggen",
        "username",
        "user name",
        "password",
        "passwort"

    ]


    for keyword in login_keywords:

        if keyword in text:

            return True


    return False


# ============================================================
# BRAND NAME
# ============================================================

def get_brand_name(
    protected_domain
):

    return (
        protected_domain
        .split(".")[0]
        .replace(
            "-",
            " "
        )
        .replace(
            "_",
            " "
        )
        .strip()
        .lower()
    )


# ============================================================
# BRAND IN HTML
# ============================================================

def detect_brand(
    html,
    protected_domain
):

    brand = (
        get_brand_name(
            protected_domain
        )
    )


    if not brand:

        return False


    text = re.sub(
        r"\s+",
        " ",
        html.lower()
    )


    return (
        brand
        in
        text
    )


# ============================================================
# BRAND IN HEADER
# ============================================================

def detect_brand_in_header(
    html,
    protected_domain
):

    match = re.search(

        r"<header\b[^>]*>(.*?)</header>",

        html,

        re.IGNORECASE |
        re.DOTALL
    )


    if not match:

        return False


    header_content = (
        match.group(1)
        .lower()
    )


    brand = (
        get_brand_name(
            protected_domain
        )
    )


    if not brand:

        return False


    return (
        brand
        in
        header_content
    )


# ============================================================
# DOMAIN FOR SALE DETECTION
# ============================================================

def detect_domain_for_sale(
    html
):

    if not html:

        return False


    # --------------------------------------------------------
    # Remove scripts and styles
    # --------------------------------------------------------

    text = re.sub(
        r"<script\b[^>]*>.*?</script>",
        " ",
        html,
        flags=
            re.IGNORECASE |
            re.DOTALL
    )


    text = re.sub(
        r"<style\b[^>]*>.*?</style>",
        " ",
        text,
        flags=
            re.IGNORECASE |
            re.DOTALL
    )


    # --------------------------------------------------------
    # Remove remaining HTML
    # --------------------------------------------------------

    text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )


    # --------------------------------------------------------
    # Normalize whitespace
    # --------------------------------------------------------

    text = re.sub(
        r"\s+",
        " ",
        text.lower()
    ).strip()


    # --------------------------------------------------------
    # Explicit phrases
    # --------------------------------------------------------

    explicit_phrases = [

        "this domain is for sale",

        "this domain is for sale!",

        "domain is for sale",

        "domain is available for purchase",

        "domain available for purchase",

        "buy this domain",

        "buy the domain",

        "purchase this domain",

        "purchase the domain",

        "domain for sale",

        "domain for purchase",

        "domain for rent",

        "domain kaufen",

        "diese domain kaufen",

        "diese domain steht zum verkauf",

        "diese domain ist zu verkaufen",

        "domain zu verkaufen",

        "domain steht zum verkauf",

        "domain zum verkauf",

        "diese domain ist käuflich",

        "domain erwerben"

    ]


    for phrase in explicit_phrases:

        if phrase in text:

            return True


    # --------------------------------------------------------
    # More general patterns
    # --------------------------------------------------------

    sale_patterns = [

        r"\bfor\s+sale\b",

        r"\bfor\s+purchase\b",

        r"\bavailable\s+for\s+purchase\b",

        r"\bavailable\s+to\s+buy\b",

        r"\bmake\s+an\s+offer\b",

        r"\bmake\s+offer\b",

        r"\binquire\s+about\s+this\s+domain\b",

        r"\binquire\s+for\s+this\s+domain\b"

    ]


    for pattern in sale_patterns:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):

            return True


    return False


# ============================================================
# TITLE
# ============================================================

def extract_title(
    html
):

    match = re.search(

        r"<title[^>]*>(.*?)</title>",

        html,

        re.IGNORECASE |
        re.DOTALL
    )


    if not match:

        return ""


    title = (
        match.group(1)
    )


    title = re.sub(
        r"<[^>]+>",
        "",
        title
    )


    return " ".join(
        title.split()
    )[:500]


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk(

    protected_domain,

    domain,

    dns_active,

    website_active,

    website,

    excluded_domains=None,

    threat_status="NOT_CHECKED"

):

    score = 0

    indicators = []


    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    if dns_active:

        score += 15

        indicators.append(
            "DNS active"
        )


    # --------------------------------------------------------
    # WEBSITE
    # --------------------------------------------------------

    if website_active:

        if website[
            "redirected_to_protected"
        ]:

            indicators.append(
                "Redirects to protected domain"
            )

        else:

            score += 20

            indicators.append(
                "Website online"
            )


        # ----------------------------------------------------
        # LOGIN
        # ----------------------------------------------------

        if website[
            "login_found"
        ]:

            score += 20

            indicators.append(
                "Login form / login keywords detected"
            )


        # ----------------------------------------------------
        # COMPANY HTML
        # ----------------------------------------------------

        if website[
            "company_name_found"
        ]:

            score += 15

            indicators.append(
                "Company name found in HTML"
            )


        # ----------------------------------------------------
        # COMPANY HEADER
        # ----------------------------------------------------

        if website[
            "company_name_header"
        ]:

            score += 15

            indicators.append(
                "Company name found in HTML header"
            )


        # ----------------------------------------------------
        # DOMAIN FOR SALE
        # ----------------------------------------------------

        if website[
            "domain_for_sale"
        ]:

            score -= (
                FOR_SALE_RISK_REDUCTION
            )

            indicators.append(
                "Domain appears to be for sale"
            )


    # --------------------------------------------------------
    # COMPANY IN DOMAIN
    # --------------------------------------------------------

    brand = get_brand_name(
        protected_domain
    )


    domain_clean = (
        domain
        .lower()
        .replace(
            "-",
            ""
        )
        .replace(
            "_",
            ""
        )
    )


    brand_clean = (
        brand.replace(
            " ",
            ""
        )
    )


    if (
        brand_clean
        and
        brand_clean in domain_clean
    ):

        score += 15

        indicators.append(
            "Company name detected in domain"
        )


    # --------------------------------------------------------
    # REDIRECT
    # --------------------------------------------------------

    final_hostname = get_hostname(
        website.get(
            "url",
            ""
        )
    )


    trusted_target = (
        is_domain_or_subdomain(
            final_hostname,
            protected_domain
        )
        or
        any(
            is_domain_or_subdomain(
                final_hostname,
                excluded_domain
            )
            for excluded_domain in (
                excluded_domains or []
            )
        )
    )

    if (
        website_active
        and
        website[
            "redirected_to_protected"
        ]
    ):

        score = max(
            0,
            score - 20
        )


    if (
        website_active
        and
        trusted_target
    ):

        score = max(
            0,
            score - TRUSTED_REDIRECT_RISK_REDUCTION
        )

        indicators.append(
            "Final URL points to a trusted company domain"
        )


    if threat_status == "REPORTED":

        score += 50

        indicators.append(
            "Domain reported by threat intelligence"
        )

    elif threat_status == "CLEAN":

        indicators.append(
            "Domain not reported by threat intelligence sources"
        )


    # --------------------------------------------------------
    # LIMIT SCORE
    # --------------------------------------------------------

    score = max(
        0,
        score
    )


    score = min(
        score,
        100
    )


    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if score >= 80:

        level = "CRITICAL"

    elif score >= 60:

        level = "HIGH"

    elif score >= 30:

        level = "MEDIUM"

    else:

        level = "LOW"


    return (
        score,
        level,
        indicators
    )


# ============================================================
# SAVE DOMAIN
# ============================================================

def save_domain(

    connection,

    protected_domain_id,

    domain,

    dns_active,

    website_active,

    http_status,

    title,

    ips,

    risk_score,

    website,

    registration_date,

    registrar

):

    ensure_connection(
        connection
    )


    cursor = connection.cursor()

    now = datetime.now()


    cursor.execute(
        """
        SELECT id
        FROM domains
        WHERE domain = %s
        AND user_id = %s
        """,
        (
            domain,
            SCAN_USER_ID,
        )
    )


    result = cursor.fetchone()


    # --------------------------------------------------------
    # UPDATE
    # --------------------------------------------------------

    if result:

        domain_id = result[0]


        cursor.execute(
            """
            UPDATE domains
            SET

                protected_domain_id = %s,

                last_seen = %s,

                dns_active = %s,

                website_active = %s,

                http_status = %s,

                title = %s,

                risk_score = %s,

                final_url = %s,

                redirected_to_protected = %s,

                login_found = %s,

                company_name_found = %s,

                company_name_header = %s,

                domain_for_sale = %s,

                registration_date = %s,

                registrar = %s

            WHERE id = %s
            """,
            (

                protected_domain_id,

                now,

                int(
                    dns_active
                ),

                int(
                    website_active
                ),

                http_status,

                title,

                risk_score,

                website["url"],

                int(
                    website[
                        "redirected_to_protected"
                    ]
                ),

                int(
                    website[
                        "login_found"
                    ]
                ),

                int(
                    website[
                        "company_name_found"
                    ]
                ),

                int(
                    website[
                        "company_name_header"
                    ]
                ),

                int(
                    website[
                        "domain_for_sale"
                    ]
                ),

                registration_date,

                registrar,

                domain_id

            )
        )


    # --------------------------------------------------------
    # INSERT
    # --------------------------------------------------------

    else:

        cursor.execute(
            """
            INSERT INTO domains (

                user_id,

                protected_domain_id,

                domain,

                first_seen,

                last_seen,

                dns_active,

                website_active,

                http_status,

                title,

                risk_score,

                final_url,

                redirected_to_protected,

                login_found,

                company_name_found,

                company_name_header,

                domain_for_sale,

                registration_date,

                registrar

            )

            VALUES (

                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s

            )
            """,
            (

                SCAN_USER_ID,

                protected_domain_id,

                domain,

                now,

                now,

                int(
                    dns_active
                ),

                int(
                    website_active
                ),

                http_status,

                title,

                risk_score,

                website["url"],

                int(
                    website[
                        "redirected_to_protected"
                    ]
                ),

                int(
                    website[
                        "login_found"
                    ]
                ),

                int(
                    website[
                        "company_name_found"
                    ]
                ),

                int(
                    website[
                        "company_name_header"
                    ]
                ),

                int(
                    website[
                        "domain_for_sale"
                    ]
                ),

                registration_date,

                registrar

            )
        )


        domain_id = (
            cursor.lastrowid
        )


    # --------------------------------------------------------
    # IP ADDRESSES
    # --------------------------------------------------------

    for ip in ips:

        cursor.execute(
            """
            INSERT IGNORE INTO domain_ips (

                domain_id,

                ip_address

            )

            VALUES (

                %s,
                %s

            )
            """,
            (
                domain_id,
                ip
            )
        )


    connection.commit()

    cursor.close()


    return domain_id


# ============================================================
# SAVE SCAN RESULT
# ============================================================

def save_scan_result(

    connection,

    scan_id,

    domain_id,

    dns_active,

    website_active,

    http_status,

    risk_score,

    ips

):

    ensure_connection(
        connection
    )


    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM scans WHERE id = %s AND user_id = %s LIMIT 1",
        (scan_id, SCAN_USER_ID)
    )
    if cursor.fetchone() is None:
        cursor.close()
        print(f"[!] Scan {scan_id} no longer exists; skipping scan result.")
        return

    cursor.execute(
        """
        SELECT domain, risk_score, dns_active, website_active, http_status,
               final_url, redirected_to_protected, login_found,
               company_name_found, company_name_header, domain_for_sale,
               registration_date, registrar
        FROM domains WHERE id = %s AND user_id = %s
        """,
        (domain_id, SCAN_USER_ID)
    )
    finding = cursor.fetchone()
    fingerprint = hashlib.sha256(
        json.dumps(finding, default=str, sort_keys=True).encode("utf-8")
    ).hexdigest() if finding else None


    cursor.execute(
        """
        INSERT INTO scan_results (

            scan_id,

            domain_id,

            dns_active,

            website_active,

            http_status,

            risk_score,
            finding_fingerprint,

            ips_snapshot

        )

        VALUES (

            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s

        )
        """,
        (

            scan_id,

            domain_id,

            int(
                dns_active
            ),

            int(
                website_active
            ),

            http_status,

            risk_score,
            fingerprint,

            json.dumps(sorted(set(ips or [])))

        )
    )


    connection.commit()

    cursor.close()


def restore_changed_muted_domains(connection, scan_id):

    ensure_connection(connection)

    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT muted.domain_id, current_result.finding_fingerprint,
               (
                   SELECT previous_result.finding_fingerprint
                   FROM scan_results previous_result
                   JOIN scans previous_scan ON previous_scan.id = previous_result.scan_id
                   WHERE previous_result.domain_id = muted.domain_id
                     AND previous_result.scan_id <> current_result.scan_id
                     AND previous_scan.finished_at IS NOT NULL
                   ORDER BY previous_result.id DESC
                   LIMIT 1
               ) AS previous_fingerprint
        FROM muted_domains muted
        JOIN scan_results current_result ON current_result.domain_id = muted.domain_id
        WHERE current_result.scan_id = %s
          AND muted.user_id = %s
        """,
        (scan_id, SCAN_USER_ID)
    )
    changed_domain_ids = [
        domain_id
        for domain_id, current_fingerprint, previous_fingerprint in cursor.fetchall()
        if previous_fingerprint
        and current_fingerprint
        and current_fingerprint != previous_fingerprint
    ]
    for domain_id in changed_domain_ids:
        cursor.execute(
            "DELETE FROM muted_domains WHERE domain_id = %s AND user_id = %s",
            (domain_id, SCAN_USER_ID)
        )
    connection.commit()
    cursor.close()


# ============================================================
# CREATE SCAN
# ============================================================

def create_scan(

    connection,

    protected_domain_id

):

    ensure_connection(
        connection
    )


    cursor = connection.cursor()


    cursor.execute(
        """
        INSERT INTO scans (

            user_id,

            protected_domain_id,

            started_at

        )

        VALUES (

            %s,
            %s,
            %s

        )
        """,
        (

            SCAN_USER_ID,

            protected_domain_id,

            datetime.now()

        )
    )


    scan_id = (
        cursor.lastrowid
    )


    connection.commit()

    cursor.close()


    return scan_id


# ============================================================
# FINISH SCAN
# ============================================================

def finish_scan(

    connection,

    scan_id,

    candidates_count,

    registered_count,

    active_count

):

    ensure_connection(
        connection
    )


    cursor = connection.cursor()

    cursor.execute(
        """
         SELECT d.domain, d.risk_score, d.user_id, u.email,
             d.dns_active, d.website_active, d.http_status, d.final_url,
             d.title, d.redirected_to_protected, d.login_found,
             d.company_name_found, d.company_name_header,
             d.domain_for_sale, d.registration_date, d.registrar,
               r.finding_fingerprint,
               (SELECT r2.finding_fingerprint
                FROM scan_results r2 JOIN scans s2 ON s2.id = r2.scan_id
                WHERE r2.domain_id = r.domain_id AND s2.user_id = d.user_id
                  AND s2.id <> r.scan_id AND s2.finished_at IS NOT NULL
                ORDER BY s2.finished_at DESC LIMIT 1) AS previous_fingerprint
        FROM scan_results r
        JOIN domains d ON d.id = r.domain_id
        JOIN users u ON u.id = d.user_id
        WHERE r.scan_id = %s AND d.risk_score >= 80
          AND u.notifications_enabled = 1
          AND (u.role = 'admin' OR u.plan = 'pro' OR (u.pro_until IS NOT NULL AND u.pro_until >= NOW()))
                    AND EXISTS (
                            SELECT 1 FROM app_settings
                            WHERE setting_key = 'notifications_enabled'
                                AND setting_value = '1'
                    )
        """,
        (scan_id,)
    )
    alerts = [row for row in cursor.fetchall()
              if not row[17] or row[16] != row[17]]

    cursor.execute(
        "SELECT setting_key, setting_value FROM app_settings WHERE setting_key IN ('smtp_host', 'smtp_port', 'smtp_user', 'smtp_password', 'smtp_from', 'smtp_tls')"
    )
    smtp_settings = {row[0]: row[1] for row in cursor.fetchall()}
    smtp_host = smtp_settings.get("smtp_host", "")
    smtp_port = int(smtp_settings.get("smtp_port", "587"))
    smtp_user = smtp_settings.get("smtp_user", "")
    smtp_password = smtp_settings.get("smtp_password", "")
    smtp_from = smtp_settings.get("smtp_from", "")
    smtp_tls = smtp_settings.get("smtp_tls", "1") == "1"


    cursor.execute(
        """
        UPDATE scans

        SET

            finished_at = %s,

            candidates_count = %s,

            registered_count = %s,

            active_count = %s

        WHERE id = %s
        """,
        (

            datetime.now(),

            candidates_count,

            registered_count,

            active_count,

            scan_id

        )
    )


    connection.commit()

    if smtp_host and smtp_from:
        for alert in alerts:
            (
                domain, risk_score, user_id, recipient,
                dns_active, website_active, http_status, final_url,
                title, redirected_to_protected, login_found,
                company_name_found, company_name_header, domain_for_sale,
                registration_date, registrar, _, _
            ) = alert

            if not recipient:
                continue
            message = EmailMessage()
            message["Subject"] = f"Domain Monitor: neue hohe Gefahr bei {domain}"
            message["From"] = smtp_from
            message["To"] = recipient
            website_link = final_url or f"https://{domain}"
            message.set_content(
                f"Für {domain} wurde ein neuer oder veränderter Befund mit "
                f"Risikoscore {risk_score}/100 erkannt.\n\n"
                f"Direkt zur Webseite:\n{website_link}\n\n"
                f"Details\n"
                f"- Domain: {domain}\n"
                f"- Risikoscore: {risk_score}/100\n"
                f"- DNS aktiv: {'Ja' if dns_active else 'Nein'}\n"
                f"- Webseite online: {'Ja' if website_active else 'Nein'}\n"
                f"- HTTP-Status: {http_status or 'Nicht verfügbar'}\n"
                f"- Seitentitel: {title or 'Nicht verfügbar'}\n"
                f"- Endgültige URL: {final_url or 'Nicht verfügbar'}\n"
                f"- Weiterleitung zur geschützten Domain: {'Ja' if redirected_to_protected else 'Nein'}\n"
                f"- Login erkannt: {'Ja' if login_found else 'Nein'}\n"
                f"- Firmenname im HTML: {'Ja' if company_name_found else 'Nein'}\n"
                f"- Firmenname im Header: {'Ja' if company_name_header else 'Nein'}\n"
                f"- Domain zum Verkauf: {'Ja' if domain_for_sale else 'Nein'}\n"
                f"- Registriert seit: {registration_date or 'Nicht verfügbar'}\n"
                f"- Registrar: {registrar or 'Nicht verfügbar'}\n\n"
                f"Diese Warnung wurde vom Domain Monitor erzeugt."
            )
            update_progress(
                "email_alert",
                domain=domain,
                message=f"Warn-E-Mail wird an {recipient} gesendet."
            )
            try:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                    if smtp_tls:
                        server.starttls()
                    if smtp_user:
                        server.login(smtp_user, smtp_password)
                    server.send_message(message)
            except (OSError, smtplib.SMTPException) as error:
                print(f"[!] Alert email failed for user {user_id}: {error}")

    cursor.close()


# ============================================================
# PRINT RESULT
# ============================================================

def print_domain_result(

    protected_domain,

    domain,

    dns_active,

    ips,

    website,

    registration_data,

    risk,

    risk_level,

    indicators

):

    print()

    print(
        "=" * 70
    )


    if risk_level == "CRITICAL":

        print(
            "[CRITICAL] CRITICAL DOMAIN"
        )

    elif risk_level == "HIGH":

        print(
            "[HIGH] HIGH RISK DOMAIN"
        )

    elif risk_level == "MEDIUM":

        print(
            "[MEDIUM] MEDIUM RISK DOMAIN"
        )

    else:

        print(
            "[LOW] LOW RISK DOMAIN"
        )


    print(
        "=" * 70
    )

    print()


    print(
        f"Protected:    {protected_domain}"
    )


    print(
        f"Domain:       {domain}"
    )


    print(
        f"Risk Score:   {risk}/100"
    )


    print(
        f"Risk Level:   {risk_level}"
    )


    print()

    print(
        "DNS:"
    )


    if dns_active:

        print(
            "  Status:     ACTIVE"
        )


        if ips:

            print(
                "  IP:         "
                +
                ", ".join(
                    ips
                )
            )

    else:

        print(
            "  Status:     INACTIVE"
        )


    print()

    print(
        "WEBSITE:"
    )


    if website["active"]:

        print(
            "  Status:     ONLINE"
        )


        print(
            f"  HTTP:       {website['status']}"
        )


        print(
            f"  URL:        {website['url']}"
        )


        if website[
            "redirected_to_protected"
        ]:

            print(
                "  Redirect:   PROTECTED DOMAIN"
            )


        print(
            "  Login:      "
            +
            (
                "FOUND"
                if website["login_found"]
                else "NOT FOUND"
            )
        )


        print(
            "  Company:    "
            +
            (
                "FOUND"
                if website["company_name_found"]
                else "NOT FOUND"
            )
        )


        print(
            "  Header:     "
            +
            (
                "FOUND"
                if website["company_name_header"]
                else "NOT FOUND"
            )
        )


        print(
            "  For Sale:   "
            +
            (
                "YES"
                if website["domain_for_sale"]
                else "NO"
            )
        )


        if website["title"]:

            print(
                f"  Title:      {website['title']}"
            )


    else:

        print(
            "  Status:     OFFLINE"
        )


    print()

    print(
        "REGISTRATION:"
    )


    registration_date = (
        registration_data[
            "registration_date"
        ]
    )


    registrar = (
        registration_data[
            "registrar"
        ]
    )


    if registration_date:

        print(
            f"  Registered: {registration_date}"
        )

    else:

        print(
            "  Registered: NOT AVAILABLE"
        )


    if registrar:

        print(
            f"  Registrar:  {registrar}"
        )

    else:

        print(
            "  Registrar:  NOT AVAILABLE"
        )


    print()

    print(
        "RISK INDICATORS:"
    )


    if indicators:

        for indicator in indicators:

            print(
                f"  - {indicator}"
            )

    else:

        print(
            "  None"
        )


    print()

    print(
        "=" * 70
    )


# ============================================================
# RUN SCAN
# ============================================================

def run_scan():

    create_pid_file()


    print()

    print(
        "=" * 70
    )


    print(
        " DOMAIN MONITOR"
    )


    print(
        "=" * 70
    )


    print()


    update_progress(

        "starting",

        message=
            "Loading protected domains..."

    )


    connection = get_connection()


    try:

        load_scan_limit(connection)

        protected_domains = (
            get_protected_domains(
                connection
            )
        )


        excluded_domains = (
            get_excluded_domains(
                connection
            )
        )


        if not protected_domains:

            print(
                "[!] No active protected "
                "domains found."
            )


            update_progress(

                "finished",

                current=1,

                total=1,

                message=
                    "No protected domains configured."

            )


            schedule_next_scan(
                connection
            )


            return


        protected_total = (
            len(
                protected_domains
            )
        )


        print(
            f"[+] Active protected domains: "
            f"{protected_total}"
        )


        # ====================================================
        # RDAP BOOTSTRAP
        # ====================================================

        print(
            "[+] Preparing RDAP..."
        )


        load_rdap_bootstrap()


        print(
            "[+] RDAP bootstrap loaded."
        )


        # ====================================================
        # GENERATE ALL CANDIDATES
        # ====================================================

        all_scan_targets = []

        total_candidates = 0


        for protected_index, protected in enumerate(

            protected_domains,

            start=1

        ):

            protected_domain = (
                protected["domain"]
            )


            update_progress(

                "generating",

                current=
                    protected_index - 1,

                total=
                    protected_total,

                domain=
                    protected_domain,

                message=
                    f"Generating candidates for {protected_domain}",

                protected_current=
                    protected_index,

                protected_total=
                    protected_total

            )


            candidates = (
                generate_candidates(
                    protected_domain
                )
            )


            original_candidate_count = (
                len(candidates)
            )


            candidates = [
                candidate
                for candidate in candidates
                if not is_excluded_domain(
                    candidate,
                    excluded_domains
                )
            ]


            excluded_candidate_count = (
                original_candidate_count
                -
                len(candidates)
            )


            if excluded_candidate_count > 0:

                print(
                    f"[+] Excluded company domains: "
                    f"{excluded_candidate_count}"
                )


            print(
                f"[+] {protected_domain}: "
                f"{len(candidates)} candidates"
            )


            all_scan_targets.append({

                "protected_id":
                    protected["id"],

                "protected_domain":
                    protected_domain,

                "candidates":
                    candidates,

                "scan_id":
                    None

            })


            total_candidates += (
                len(
                    candidates
                )
            )


        print()


        print(
            f"[+] Total candidates: "
            f"{total_candidates}"
        )


        print()


        if total_candidates == 0:

            update_progress(

                "finished",

                current=1,

                total=1,

                message=
                    "No candidates generated."

            )


            schedule_next_scan(
                connection
            )


            return


        # ====================================================
        # CREATE SCAN RECORDS
        # ====================================================

        for target in all_scan_targets:

            target["scan_id"] = (
                create_scan(
                    connection,
                    target[
                        "protected_id"
                    ]
                )
            )


        # ====================================================
        # GLOBAL COUNTERS
        # ====================================================

        total_registered = 0

        total_websites = 0

        global_dns_current = 0

        global_website_current = 0

        global_rdap_current = 0


        # ====================================================
        # PROCESS PROTECTED DOMAINS
        # ====================================================

        for target in all_scan_targets:

            protected_id = (
                target[
                    "protected_id"
                ]
            )


            protected_domain = (
                target[
                    "protected_domain"
                ]
            )


            scan_id = (
                target[
                    "scan_id"
                ]
            )


            candidates = (
                target[
                    "candidates"
                ]
            )


            print()

            print(
                "#" * 70
            )


            print(
                f" SCANNING: {protected_domain}"
            )


            print(
                "#" * 70
            )


            print()


            # =================================================
            # PHASE 1/3 - DNS
            # =================================================

            print(
                "[+] PHASE 1/3 - DNS CHECKS"
            )


            print()


            dns_results = []


            for domain, future in bounded_futures(
                candidates,
                dns_worker,
                DNS_WORKERS
            ):


                    try:

                        result = (
                            future.result()
                        )


                    except Exception as error:

                        print(

                            f"\n[!] DNS error for "
                            f"{domain}: {error}"

                        )


                        result = {

                            "domain":
                                domain,

                            "dns_active":
                                False,

                            "ips":
                                []

                        }


                    dns_results.append(
                        result
                    )


                    global_dns_current += 1


                    update_progress(

                        "dns",

                        current=
                            global_dns_current,

                        total=
                            total_candidates,

                        domain=
                            domain,

                        message=
                            f"DNS: {domain}"

                    )


                    print(

                        f"\rDNS "
                        f"[{global_dns_current}/"
                        f"{total_candidates}] "
                        f"{domain:<45}",

                        end="",

                        flush=True

                    )


            print()

            print()


            active_dns_domains = [

                result

                for result in dns_results

                if result[
                    "dns_active"
                ]

            ]


            registered_count = (
                len(
                    active_dns_domains
                )
            )


            total_registered += (
                registered_count
            )


            print(
                f"[+] DNS active: "
                f"{registered_count}"
            )


            print(
                f"[+] DNS inactive: "
                f"{len(candidates) - registered_count}"
            )


            # =================================================
            # PHASE 2/3 - WEBSITE
            # =================================================

            print()

            print(
                "[+] PHASE 2/3 - WEBSITE CHECKS"
            )

            print()


            website_results = []


            website_items = [
                (result, protected_domain)
                for result in active_dns_domains
            ]
            def run_website(item):
                dns_result, target_domain = item
                return website_worker(dns_result["domain"], target_domain)
            for (dns_result, _), future in bounded_futures(
                website_items,
                run_website,
                WEBSITE_WORKERS
            ):


                    domain = (
                        dns_result[
                            "domain"
                        ]
                    )


                    try:

                        website_result = (
                            future.result()
                        )


                    except Exception as error:

                        print(

                            f"\n[!] Website error "
                            f"for {domain}: "
                            f"{error}"

                        )


                        website_result = {

                            "domain":
                                domain,

                            "website": {

                                "active":
                                    False,

                                "status":
                                    None,

                                "title":
                                    "",

                                "url":
                                    "",

                                "redirected_to_protected":
                                    False,

                                "login_found":
                                    False,

                                "company_name_found":
                                    False,

                                "company_name_header":
                                    False,

                                "domain_for_sale":
                                    False

                            }

                        }


                    website_result[
                        "ips"
                    ] = dns_result[
                        "ips"
                    ]


                    website_results.append(
                        website_result
                    )


                    global_website_current += 1


                    update_progress(

                        "website",

                        current=
                            global_website_current,

                        total=
                            max(
                                1,
                                total_registered
                            ),

                        domain=
                            domain,

                        message=
                            f"Website: {domain}"

                    )


                    print(

                        f"\rWebsite "
                        f"[{global_website_current}/"
                        f"{total_registered}] "
                        f"{domain:<40}",

                        end="",

                        flush=True

                    )


            print()

            print()


            online_websites = [

                result

                for result in website_results

                if result[
                    "website"
                ][
                    "active"
                ]

            ]


            active_count = (
                len(
                    online_websites
                )
            )


            total_websites += (
                active_count
            )


            print(
                f"[+] Websites online: "
                f"{active_count}"
            )


            print(
                f"[+] Websites offline: "
                f"{len(website_results) - active_count}"
            )


            # =================================================
            # PHASE 3/3 - RDAP
            #
            # ONLY ONLINE WEBSITES
            # =================================================

            print()

            print(
                "[+] PHASE 3/3 - RDAP"
            )

            print()


            rdap_results = {}


            for website_result, future in bounded_futures(
                online_websites,
                lambda result: rdap_worker(result["domain"]),
                RDAP_WORKERS
            ):


                    domain = (
                        website_result[
                            "domain"
                        ]
                    )


                    try:

                        rdap_result = (
                            future.result()
                        )


                    except Exception as error:

                        print(

                            f"\n[!] RDAP error "
                            f"for {domain}: "
                            f"{error}"

                        )


                        rdap_result = {

                            "domain":
                                domain,

                            "registration_data": {

                                "registration_date":
                                    None,

                                "registrar":
                                    None

                            }

                        }


                    rdap_results[
                        domain
                    ] = rdap_result[
                        "registration_data"
                    ]


                    global_rdap_current += 1


                    update_progress(

                        "rdap",

                        current=
                            global_rdap_current,

                        total=
                            max(
                                1,
                                total_websites
                            ),

                        domain=
                            domain,

                        message=
                            f"RDAP: {domain}"

                    )


                    print(

                        f"\rRDAP "
                        f"[{global_rdap_current}/"
                        f"{total_websites}] "
                        f"{domain:<40}",

                        end="",

                        flush=True

                    )


            print()

            print()


            # =================================================
            # SAVE RESULTS
            # =================================================

            print(
                "[+] Saving scan results..."
            )


            website_map = {

                result[
                    "domain"
                ]:
                    result

                for result in website_results

            }


            for dns_result in active_dns_domains:

                domain = (
                    dns_result[
                        "domain"
                    ]
                )


                ips = (
                    dns_result[
                        "ips"
                    ]
                )


                website_result = (
                    website_map.get(
                        domain
                    )
                )


                if website_result:

                    website = (
                        website_result[
                            "website"
                        ]
                    )

                else:

                    website = {

                        "active":
                            False,

                        "status":
                            None,

                        "title":
                            "",

                        "url":
                            "",

                        "redirected_to_protected":
                            False,

                        "login_found":
                            False,

                        "company_name_found":
                            False,

                        "company_name_header":
                            False,

                        "domain_for_sale":
                            False

                    }


                registration_data = {

                    "registration_date":
                        None,

                    "registrar":
                        None

                }


                # RDAP only for online websites.

                if website["active"]:

                    registration_data = (
                        rdap_results.get(
                            domain,
                            registration_data
                        )
                    )


                # ------------------------------------------------
                # RISK
                # ------------------------------------------------

                threat_results = [
                    check_urlhaus_domain(domain),
                    check_openphish_domain(domain),
                    check_threatfox_domain(domain)
                ]
                threat_result = next(
                    (
                        result
                        for result in threat_results
                        if result["status"] == "REPORTED"
                    ),
                    threat_results[0]
                )

                (
                    risk,
                    risk_level,
                    indicators
                ) = calculate_risk(

                    protected_domain,

                    domain,

                    True,

                    website["active"],

                    website,

                    excluded_domains,

                    threat_result["status"]

                )


                # ------------------------------------------------
                # SAVE DOMAIN
                # ------------------------------------------------

                domain_id = (
                    save_domain(

                        connection,

                        protected_id,

                        domain,

                        True,

                        website["active"],

                        website["status"],

                        website["title"],

                        ips,

                        risk,

                        website,

                        registration_data[
                            "registration_date"
                        ],

                        registration_data[
                            "registrar"
                        ]

                    )
                )

                for threat_result_item in threat_results:
                    save_threat_intelligence(
                        connection,
                        domain_id,
                        threat_result_item
                    )


                # ------------------------------------------------
                # SAVE RESULT
                # ------------------------------------------------

                save_scan_result(

                    connection,

                    scan_id,

                    domain_id,

                    True,

                    website["active"],

                    website["status"],

                    risk,

                    ips

                )


                # ------------------------------------------------
                # PRINT
                # ------------------------------------------------

                print_domain_result(

                    protected_domain,

                    domain,

                    True,

                    ips,

                    website,

                    registration_data,

                    risk,

                    risk_level,

                    indicators

                )


            restore_changed_muted_domains(
                connection,
                scan_id
            )


            # =================================================
            # FINISH PROTECTED DOMAIN
            # =================================================

            finish_scan(

                connection,

                scan_id,

                len(candidates),

                registered_count,

                active_count

            )


            print()

            print(

                f"[+] Finished "
                f"{protected_domain}"

            )


            print(

                f"    Candidates:       "
                f"{len(candidates)}"

            )


            print(

                f"    DNS active:       "
                f"{registered_count}"

            )


            print(

                f"    Websites online:  "
                f"{active_count}"

            )


        # ====================================================
        # COMPLETE
        # ====================================================

        update_progress(

            "finished",

            current=
                total_candidates,

            total=
                total_candidates,

            message=
                "All scans finished."

        )


        # ====================================================
        # SCHEDULE NEXT SCAN
        # ====================================================

        schedule_next_scan(
            connection
        )


        print()

        print(
            "=" * 70
        )


        print(
            " ALL SCANS FINISHED"
        )


        print(
            "=" * 70
        )


        print()


        print(
            f"Candidates:        "
            f"{total_candidates}"
        )


        print(
            f"DNS active:        "
            f"{total_registered}"
        )


        print(
            f"Websites online:   "
            f"{total_websites}"
        )


        print()


        print(
            "=" * 70
        )


    finally:

        connection.close()

        remove_pid_file()


# ============================================================
# MAIN
# ============================================================

def mark_job_status(status):

    if SCAN_JOB_ID <= 0 or SCAN_USER_ID <= 0:
        return

    connection = None

    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE user_scan_jobs
            SET status = %s, finished_at = NOW()
            WHERE id = %s AND user_id = %s AND status <> 'cancelled'
            """,
            (status, SCAN_JOB_ID, SCAN_USER_ID)
        )
        connection.commit()
        cursor.close()
    except mysql.connector.Error as error:
        print(f"[!] Could not update scan job status: {error}")
    finally:
        if connection is not None:
            connection.close()

if __name__ == "__main__":

    try:

        configure_scan_runtime()

        run_scan()
        mark_job_status("finished")


    except KeyboardInterrupt:

        update_progress(

            "cancelled",

            message=
                "Scan cancelled by user."

        )

        mark_job_status("cancelled")


        remove_pid_file()


        print()


        print(
            "[!] Scan cancelled by user."
        )


    except Exception as error:

        update_progress(

            "error",

            message=
                str(error)

        )

        mark_job_status("error")


        remove_pid_file()


        print()


        print(
            "=" * 70
        )


        print(
            "[!] SCANNER ERROR"
        )


        print(
            "=" * 70
        )


        print()


        print(
            error
        )


        print()