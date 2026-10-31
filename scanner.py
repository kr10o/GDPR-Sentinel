#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDPR Sentinel - Napredni višeslojni web crawler i skener usklađenosti domena.
100% kompatibilan s postojećim modulima (app.py, models.py, risk_analyzer.py, generator.py)
uz dubinsku forenziku podstranica, kolačića, trackera, obrazaca i međunarodnih prijenosa.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
import urllib.parse
import urllib.robotparser
import uuid
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import httpx
from bs4 import BeautifulSoup

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("gdpr_sentinel.scanner")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ============================================================================
# BAZA ZNANJA: TRACKERI, CMP SUSTAVI, KOLAČIĆI I PRAVNE KLJUČNE RIJEČI
# ============================================================================

TRACKER_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "google_analytics_4": {
        "name": "Google Analytics 4 (GA4)",
        "provider": "Google Ireland Ltd. / Google LLC",
        "country": "SAD (EU-US DPF)",
        "category": "Analitika",
        "risk_level": "HIGH",
        "gdpr_article": "Čl. 6(1)(a), Čl. 44-49 GDPR",
        "patterns": [
            r"googletagmanager\.com/gtag/js",
            r"google-analytics\.com/g/collect",
            r"gtag\s*\(\s*['\"]config['\"]\s*,\s*['\"]G-[A-Z0-9]+['\"]",
            r"_ga_[A-Z0-9]+",
        ],
        "dpa_required": True,
    },
    "google_tag_manager": {
        "name": "Google Tag Manager (GTM)",
        "provider": "Google Ireland Ltd. / Google LLC",
        "country": "SAD (EU-US DPF)",
        "category": "Upravljanje skriptama / Tag Manager",
        "risk_level": "MEDIUM",
        "gdpr_article": "Čl. 28, Čl. 44 GDPR",
        "patterns": [
            r"googletagmanager\.com/gtm\.js",
            r"googletagmanager\.com/ns\.html",
            r"GTM-[A-Z0-9]{5,}",
        ],
        "dpa_required": True,
    },
    "google_fonts_external": {
        "name": "Google Fonts (Vanjski CDN)",
        "provider": "Google LLC",
        "country": "SAD",
        "category": "Vanjski resursi / Fontovi",
        "risk_level": "HIGH",
        "gdpr_article": "Čl. 6(1)(f) / Presuda LG München (prijenos IP adrese bez privole)",
        "patterns": [
            r"fonts\.googleapis\.com",
            r"fonts\.gstatic\.com",
        ],
        "dpa_required": False,
    },
    "meta_pixel": {
        "name": "Meta (Facebook) Pixel",
        "provider": "Meta Platforms Ireland Ltd. / Meta Platforms Inc.",
        "country": "SAD (EU-US DPF)",
        "category": "Marketing i Remarketing",
        "risk_level": "CRITICAL",
        "gdpr_article": "Čl. 6(1)(a), Čl. 44-49 GDPR",
        "patterns": [
            r"connect\.facebook\.net/.*/fbevents\.js",
            r"facebook\.com/tr\?",
            r"fbq\s*\(\s*['\"]init['\"]",
            r"_fbp",
        ],
        "dpa_required": True,
    },
    "tiktok_pixel": {
        "name": "TikTok Pixel",
        "provider": "TikTok Technology Limited / ByteDance",
        "country": "Irska / Kina / Singapur",
        "category": "Marketing i Remarketing",
        "risk_level": "CRITICAL",
        "gdpr_article": "Čl. 6(1)(a), Čl. 44-49 GDPR",
        "patterns": [
            r"analytics\.tiktok\.com/i18n/pixel/events\.js",
            r"ttq\.load\s*\(",
            r"_ttp",
        ],
        "dpa_required": True,
    },
    "hotjar": {
        "name": "Hotjar Session Recording & Heatmaps",
        "provider": "Hotjar Ltd. (Contentsquare)",
        "country": "Malta (EU)",
        "category": "Bihevioralna analitika / Snimanje sesija",
        "risk_level": "HIGH",
        "gdpr_article": "Čl. 6(1)(a), Čl. 32 GDPR",
        "patterns": [
            r"static\.hotjar\.com",
            r"vars\.hotjar\.com",
            r"_hjSession",
            r"hjid",
        ],
        "dpa_required": True,
    },
    "microsoft_clarity": {
        "name": "Microsoft Clarity",
        "provider": "Microsoft Corporation",
        "country": "SAD (EU-US DPF)",
        "category": "Bihevioralna analitika / Snimanje sesija",
        "risk_level": "HIGH",
        "gdpr_article": "Čl. 6(1)(a), Čl. 44 GDPR",
        "patterns": [
            r"clarity\.ms/tag/",
            r"_clck",
            r"_clsk",
        ],
        "dpa_required": True,
    },
    "linkedin_insight": {
        "name": "LinkedIn Insight Tag",
        "provider": "LinkedIn Ireland Unlimited Company",
        "country": "SAD / Irska",
        "category": "Marketing i B2B praćenje",
        "risk_level": "HIGH",
        "gdpr_article": "Čl. 6(1)(a), Čl. 44 GDPR",
        "patterns": [
            r"snap\.licdn\.com/li\.lms-analytics/insight\.min\.js",
            r"_linkedin_partner_id",
            r"li_fat_id",
        ],
        "dpa_required": True,
    },
    "hubspot": {
        "name": "HubSpot Marketing & CRM Tracker",
        "provider": "HubSpot Inc.",
        "country": "SAD (EU-US DPF)",
        "category": "CRM i Marketing automatizacija",
        "risk_level": "HIGH",
        "gdpr_article": "Čl. 6(1)(a), Čl. 28 GDPR",
        "patterns": [
            r"js\.hs-scripts\.com",
            r"js\.hs-analytics\.net",
            r"__hstc",
            r"hubspotutk",
        ],
        "dpa_required": True,
    },
    "youtube_embed_standard": {
        "name": "YouTube Iframe (Standardni bez nocookie načina)",
        "provider": "Google LLC",
        "country": "SAD",
        "category": "Ugrađeni multimedijski sadržaj",
        "risk_level": "HIGH",
        "gdpr_article": "Čl. 6(1)(a) GDPR",
        "patterns": [
            r"youtube\.com/embed/",
        ],
        "dpa_required": False,
    },
    "stripe_js": {
        "name": "Stripe Payment SDK",
        "provider": "Stripe Payments Europe Ltd. / Stripe Inc.",
        "country": "Irska / SAD",
        "category": "Procesor plaćanja (Nužno / Legitimni interes)",
        "risk_level": "LOW",
        "gdpr_article": "Čl. 6(1)(b), Čl. 28 GDPR",
        "patterns": [
            r"js\.stripe\.com",
            r"__stripe_mid",
            r"__stripe_sid",
        ],
        "dpa_required": True,
    },
    "intercom": {
        "name": "Intercom Live Chat",
        "provider": "Intercom Inc.",
        "country": "SAD (EU-US DPF)",
        "category": "Korisnička podrška i komunikacija",
        "risk_level": "MEDIUM",
        "gdpr_article": "Čl. 6(1)(a/f), Čl. 28 GDPR",
        "patterns": [
            r"widget\.intercom\.io",
            r"intercomSettings",
            r"intercom-id-",
        ],
        "dpa_required": True,
    },
    "cloudflare_insights": {
        "name": "Cloudflare Web Analytics / Turnstile / CDN",
        "provider": "Cloudflare Inc.",
        "country": "SAD (EU-US DPF)",
        "category": "Sigurnost, CDN i Analitika",
        "risk_level": "LOW",
        "gdpr_article": "Čl. 6(1)(f), Čl. 28 GDPR",
        "patterns": [
            r"static\.cloudflareinsights\.com/beacon\.min\.js",
            r"challenges\.cloudflare\.com/turnstile",
            r"__cf_bm",
            r"cf_clearance",
        ],
        "dpa_required": True,
    },
}

CMP_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "cookiebot": {
        "name": "Cookiebot (Usercentrics)",
        "patterns": [r"consent\.cookiebot\.com", r"Cookiebot", r"CybotCookiebotDialog"],
    },
    "onetrust": {
        "name": "OneTrust CMP",
        "patterns": [r"cdn\.cookielaw\.org", r"OneTrust", r"onetrust-banner-sdk", r"OptanonConsent"],
    },
    "usercentrics": {
        "name": "Usercentrics CMP",
        "patterns": [r"app\.usercentrics\.eu", r"usercentrics-root", r"UC_UI"],
    },
    "cookieyes": {
        "name": "CookieYes CMP",
        "patterns": [r"cdn-cookieyes\.com", r"cky-consent-container", r"cookieyes-consent"],
    },
    "complianz": {
        "name": "Complianz GDPR/CCPA",
        "patterns": [r"complianz-gdpr", r"cmplz-cookiebanner", r"cmplz_banner-status"],
    },
    "iubenda": {
        "name": "iubenda Cookie Solution",
        "patterns": [r"cdn\.iubenda\.com/cs/", r"_iub_cs-"],
    },
    "didomi": {
        "name": "Didomi CMP",
        "patterns": [r"sdk\.privacy-center\.org", r"didomi-host", r"didomi_token"],
    },
    "osano": {
        "name": "Osano Consent Manager",
        "patterns": [r"cmp\.osano\.com", r"osano-cm-window"],
    },
    "borlabs": {
        "name": "Borlabs Cookie",
        "patterns": [r"borlabs-cookie", r"BorlabsCookie"],
    },
    "klaro": {
        "name": "Klaro! Consent Manager",
        "patterns": [r"klaro\.js", r"klaro-cookie-notice"],
    },
    "quantcast": {
        "name": "Quantcast Choice (InMobi)",
        "patterns": [r"quantcast\.mgr\.consensu\.org", r"qc-cmp2-container"],
    },
    "custom_banner": {
        "name": "Prilagođeni (Custom) Cookie Banner",
        "patterns": [
            r"id=['\"][^'\"]*cookie[-_]?banner[^'\"]*['\"]",
            r"class=['\"][^'\"]*cookie[-_]?consent[^'\"]*['\"]",
            r"class=['\"][^'\"]*gdpr[-_]?banner[^'\"]*['\"]",
            r"id=['\"][^'\"]*gdpr[-_]?consent[^'\"]*['\"]",
        ],
    },
}

COOKIE_CLASSIFICATION_RULES: List[Tuple[str, str, str, bool]] = [
    # (Regex uzorak imena kolačića, Kategorija, Opis, Pre-consent dozvoljen?)
    (r"^(_ga|_gid|_gat|__utma|__utmb|__utmc|__utmz|_ga_.*)$", "Analitički", "Google Analytics identifikator praćenja sesije i korisnika", False),
    (r"^(_fbp|_fbc|fr)$", "Marketinški", "Meta/Facebook Pixel identifikator za oglašavanje i remarketing", False),
    (r"^(_ttp|_tt_enable_cookie|tt_.*)$", "Marketinški", "TikTok Pixel oglašivački identifikator", False),
    (r"^(_hj.*|hjid)$", "Analitički", "Hotjar snimanje sesije i bihevioralna analitika", False),
    (r"^(_clck|_clsk|CLID)$", "Analitički", "Microsoft Clarity analitički identifikator", False),
    (r"^(__hstc|hubspotutk|__hssc|__hssrc)$", "Marketinški", "HubSpot praćenje posjetitelja i marketing automatizacija", False),
    (r"^(bcookie|li_gc|lidc|UserMatchHistory|AnalyticsSyncHistory)$", "Marketinški", "LinkedIn Insight Tag praćenje i B2B atribucija", False),
    (r"^(IDE|test_cookie|DSID|NID|1P_JAR)$", "Marketinški", "Google DoubleClick / Ads profiliranje korisnika", False),
    (r"^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session|sessionid|connect\.sid|laravel_session)$", "Nužni", "Standardni identifikator korisničke sesije poslužitelja", True),
    (r"^(csrftoken|XSRF-TOKEN|_csrf|__Host-.*|__Secure-.*)$", "Nužni", "Sigurnosni token za zaštitu od CSRF napada", True),
    (r"^(__cf_bm|cf_clearance|__cfduid)$", "Nužni", "Cloudflare zaštita od botova i sigurnosna provjera", True),
    (r"^(__stripe_mid|__stripe_sid)$", "Nužni", "Stripe sprječavanje prijevara pri plaćanju", True),
    (r"^(CookieConsent|OptanonConsent|euconsent-v2|cmplz_.*|cookieyes-consent|borlabs-cookie)$", "Nužni", "Pohrana statusa korisničke privole za kolačiće (CMP)", True),
    (r"^(lang|locale|pll_language|wp-wpml_current_language|theme|currency)$", "Funkcionalni", "Korisničke postavke jezika, valute ili prikaza sučelja", True),
]

PRIORITY_LEGAL_KEYWORDS: Dict[str, List[str]] = {
    "privacy_policy": [
        "privatnost", "pravila-privatnosti", "politika-privatnosti", "zaštita-podataka",
        "zastita-podataka", "osobni-podaci", "privacy", "privacy-policy", "datenschutz",
        "gdpr", "opća-uredba", "opca-uredba",
    ],
    "cookie_policy": [
        "kolačići", "kolacici", "politika-kolacica", "pravila-kolacica",
        "cookie", "cookies", "cookie-policy", "cookie-richtlinie",
    ],
    "terms_of_service": [
        "uvjeti", "uvjeti-koristenja", "uvjeti-poslovanja", "opci-uvjeti",
        "terms", "terms-of-service", "tos", "agb",
    ],
    "dpa_imprint_contact": [
        "dpa", "data-processing", "impressum", "impresum", "kontakt", "contact", "o-nama", "about",
    ],
}

REJECT_BUTTON_PATTERNS: List[str] = [
    r"odbij\s*sve", r"samo\s*nužni", r"samo\s*nuzni", r"ne\s*prihvaćam", r"ne\s*prihvacam",
    r"odbaci\s*sve", r"reject\s*all", r"decline\s*all", r"only\s*necessary",
    r"essential\s*only", r"alle\s*ablehnen", r"nur\s*notwendige",
]

ACCEPT_BUTTON_PATTERNS: List[str] = [
    r"prihvati\s*sve", r"slažem\s*se", r"slazem\s*se", r"dopusti\s*sve",
    r"accept\s*all", r"allow\s*all", r"i\s*agree", r"alle\s*akzeptieren",
]


# ============================================================================
# STRUKTURE PODATAKA (KOMPATIBILNE S models.py I data/scans/*.json)
# ============================================================================

@dataclass
class CookieFinding:
    name: str
    domain: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str = "None/Unset"
    expires: Optional[str] = None
    category: str = "Neklasificirani"
    description: str = "Nije pronađen u bazi poznatih kolačića"
    allowed_pre_consent: bool = False
    set_before_consent: bool = True
    gdpr_compliant: bool = False
    found_on_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TrackerFinding:
    id: str
    name: str
    provider: str
    country: str
    category: str
    risk_level: str
    gdpr_article: str
    dpa_required: bool
    matched_evidence: List[str] = field(default_factory=list)
    found_on_pages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FormFinding:
    page_url: str
    action: str
    method: str
    is_secure_action: bool
    fields_detected: List[str]
    collects_pii: bool
    has_prechecked_consent: bool
    has_consent_checkbox: bool
    has_privacy_link_nearby: bool
    risk_level: str
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# GLAVNI ASINKRONI I SINKRONI CRAWLER / SKENER DOMENA
# ============================================================================

class GDPRScanner:
    """
    Napredni više-stranični GDPR skener i web crawler.
    Može se koristiti asinkrono (`await scanner.scan_domain_async(url)`)
    ili sinkrono (`scanner.scan(url)` / `scanner.scan_domain(url)`).
    """

    def __init__(
        self,
        max_pages: int = 12,
        max_depth: int = 2,
        concurrency: int = 4,
        timeout: float = 15.0,
        respect_robots: bool = True,
        use_headless_fallback: bool = True,
        scans_dir: Union[str, Path] = "data/scans",
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36 GDPR-Sentinel-Audit/2.0"
        ),
    ) -> None:
        self.max_pages = max(1, max_pages)
        self.max_depth = max(0, max_depth)
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.respect_robots = respect_robots
        self.use_headless_fallback = use_headless_fallback and PLAYWRIGHT_AVAILABLE
        self.scans_dir = Path(scans_dir)
        self.user_agent = user_agent

    # ------------------------------------------------------------------------
    # POMOĆNE METODE ZA NORMALIZACIJU URL-OVA I DOMENA
    # ------------------------------------------------------------------------

    @staticmethod
    def normalize_target_url(raw_input: str) -> Tuple[str, str]:
        """Normalizira ulaznu domenu ili URL u kanonski (https://domena, čista_domena)."""
        cleaned = (raw_input or "").strip()
        if not cleaned:
            raise ValueError("Domena ili URL ne smije biti prazan.")
        if not re.match(r"^https?://", cleaned, re.IGNORECASE):
            cleaned = f"https://{cleaned}"
        parsed = urllib.parse.urlparse(cleaned)
        domain = (parsed.netloc or parsed.path).lower().strip()
        if ":" in domain:
            domain = domain.split(":")[0]
        if not domain:
            raise ValueError(f"Neispravna domena: {raw_input}")
        base_url = f"{parsed.scheme.lower()}://{domain}"
        path = parsed.path if parsed.path else "/"
        return urllib.parse.urljoin(base_url, path), domain

    @staticmethod
    def _is_same_domain(url: str, root_domain: str) -> bool:
        try:
            netloc = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
            root_clean = root_domain.lower().lstrip("www.")
            netloc_clean = netloc.lstrip("www.")
            return netloc_clean == root_clean
        except Exception:
            return False

    @staticmethod
    def _Canonicalize_url(base_url: str, href: str) -> Optional[str]:
        if not href:
            return None
        href = href.strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "whatsapp:", "viber:", "#", "data:")):
            return None
        joined = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(joined)
        if parsed.scheme not in ("http", "https"):
            return None
        # Ignoriraj binarne datoteke i statičke medije pri HTML crawliranju
        skip_ext = (
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".mp4",
            ".mp3", ".avi", ".mov", ".zip", ".rar", ".tar", ".gz", ".7z",
            ".woff", ".woff2", ".ttf", ".eot", ".css", ".js", ".xml", ".json",
        )
        if parsed.path.lower().endswith(skip_ext):
            return None
        clean_path = parsed.path or "/"
        if len(clean_path) > 1 and clean_path.endswith("/"):
            clean_path = clean_path.rstrip("/")
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc.lower(), clean_path, "", "", ""))

    @staticmethod
    def _score_url_priority(url: str, link_text: str = "") -> int:
        """
        Dodjeljuje prioritet URL-u (niži broj = viši prioritet u redu čekanja).
        Pravne stranice (Pravila privatnosti, Kolačići, Uvjeti, Kontakt) dobivaju prioritet 0.
        """
        combined = f"{url.lower()} {link_text.lower()}"
        for group_keywords in PRIORITY_LEGAL_KEYWORDS.values():
            for kw in group_keywords:
                if kw in combined:
                    return 0
        if any(k in combined for k in ("login", "register", "registracija", "prijava", "checkout", "kosarica", "newsletter")):
            return 1
        return 2

    # ------------------------------------------------------------------------
    # MREŽNA, DNS I SSL/TLS FORENZIKA (ČLANAK 32. GDPR)
    # ------------------------------------------------------------------------

    def _inspect_network_and_tls(self, domain: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "domain": domain,
            "ip_address": None,
            "reverse_dns": None,
            "is_eu_ip_heuristic": True,
            "ssl_valid": False,
            "ssl_issuer": None,
            "ssl_subject": None,
            "ssl_version": None,
            "ssl_cipher": None,
            "ssl_expires": None,
            "ssl_days_remaining": None,
            "errors": [],
        }

        try:
            ip_addr = socket.gethostbyname(domain)
            info["ip_address"] = ip_addr
            try:
                rev_host, _, _ = socket.gethostbyaddr(ip_addr)
                info["reverse_dns"] = rev_host
                if any(us_Cloud in rev_host.lower() for us_Cloud in (".amazonaws.com", ".bc.googleusercontent.com", ".cloudflare.com", ".hwcdn.net")):
                    if not any(eu_zone in rev_host.lower() for eu_zone in ("eu-", "europe-", "fra", "ams", "dub", "vie", "zag")):
                        info["is_eu_ip_heuristic"] = False
            except Exception:
                pass
        except Exception as exc:
            info["errors"].append(f"DNS pogreška: {exc}")
            return info

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    info["ssl_valid"] = True
                    info["ssl_version"] = ssock.version()
                    cipher_info = ssock.cipher()
                    info["ssl_cipher"] = cipher_info[0] if cipher_info else None

                    if cert:
                        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                        subject_dict = dict(x[0] for x in cert.get("subject", []))
                        info["ssl_issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
                        info["ssl_subject"] = subject_dict.get("commonName")
                        not_after = cert.get("notAfter")
                        if not_after:
                            exp_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                                tzinfo=datetime.timezone.utc
                            )
                            info["ssl_expires"] = exp_dt.isoformat()
                            now_utc = datetime.datetime.now(datetime.timezone.utc)
                            info["ssl_days_remaining"] = (exp_dt - now_utc).days
        except Exception as exc:
            info["ssl_valid"] = False
            info["errors"].append(f"TLS/SSL pogreška: {exc}")

        return info

    # ------------------------------------------------------------------------
    # ANALIZA KOLAČIĆA, ZAGLAVLJA, SKRIPTI I OBRAZACA
    # ------------------------------------------------------------------------

    @staticmethod
    def _classify_cookie(name: str) -> Tuple[str, str, bool]:
        for pattern, category, desc, allowed_pre in COOKIE_CLASSIFICATION_RULES:
            if re.search(pattern, name, re.IGNORECASE):
                return category, desc, allowed_pre
        return "Neklasificirani", "Kolačić zahtijeva ručnu deklaraciju u Politici kolačića", False

    def _extract_cookies_from_response(
        self, response: httpx.Response, page_url: str
    ) -> List[CookieFinding]:
        findings: List[CookieFinding] = []
        raw_headers = response.headers.get_list("set-cookie")

        for raw_cookie in raw_headers:
            parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
            if not parts or "=" not in parts[0]:
                continue
            name, _ = parts[0].split("=", 1)
            name = name.strip()

            secure = False
            http_only = False
            same_site = "None/Unset"
            domain = urllib.parse.urlparse(page_url).netloc
            path = "/"
            expires = None

            for attr in parts[1:]:
                attr_lower = attr.lower()
                if attr_lower == "secure":
                    secure = True
                elif attr_lower == "httponly":
                    http_only = True
                elif attr_lower.startswith("samesite="):
                    same_site = attr.split("=", 1)[1].strip()
                elif attr_lower.startswith("domain="):
                    domain = attr.split("=", 1)[1].strip()
                elif attr_lower.startswith("path="):
                    path = attr.split("=", 1)[1].strip()
                elif attr_lower.startswith("expires="):
                    expires = attr.split("=", 1)[1].strip()
                elif attr_lower.startswith("max-age="):
                    expires = f"Max-Age: {attr.split('=', 1)[1].strip()}s"

            category, desc, allowed_pre = self._classify_cookie(name)
            gdpr_ok = allowed_pre and secure

            findings.append(
                CookieFinding(
                    name=name,
                    domain=domain,
                    path=path,
                    secure=secure,
                    http_only=http_only,
                    same_site=same_site,
                    expires=expires,
                    category=category,
                    description=desc,
                    allowed_pre_consent=allowed_pre,
                    set_before_consent=True,
                    gdpr_compliant=gdpr_ok,
                    found_on_url=page_url,
                )
            )

        return findings

    @staticmethod
    def _analyze_security_headers(headers: httpx.Headers) -> Dict[str, Any]:
        h_map = {k.lower(): v for k, v in headers.items()}
        checks = {
            "strict-transport-security": {
                "present": "strict-transport-security" in h_map,
                "value": h_map.get("strict-transport-security"),
                "gdpr_relevance": "Čl. 32 GDPR - Enkripcija u prijenosu (HSTS)",
            },
            "content-security-policy": {
                "present": "content-security-policy" in h_map,
                "value": h_map.get("content-security-policy"),
                "gdpr_relevance": "Čl. 32 GDPR - Sprječavanje neovlaštenog ubacivanja skripti i curenja podataka (CSP)",
            },
            "x-content-type-options": {
                "present": "x-content-type-options" in h_map,
                "value": h_map.get("x-content-type-options"),
                "gdpr_relevance": "Zaštita od MIME-sniffing napada",
            },
            "x-frame-options": {
                "present": "x-frame-options" in h_map,
                "value": h_map.get("x-frame-options"),
                "gdpr_relevance": "Zaštita od Clickjacking prijevara pri davanju privole",
            },
            "referrer-policy": {
                "present": "referrer-policy" in h_map,
                "value": h_map.get("referrer-policy"),
                "gdpr_relevance": "Sprječavanje curenja URL parametara trećim stranama",
            },
            "permissions-policy": {
                "present": "permissions-policy" in h_map,
                "value": h_map.get("permissions-policy"),
                "gdpr_relevance": "Ograničavanje pristupa kameri, mikrofonu i geolokaciji",
            },
        }
        present_count = sum(1 for item in checks.values() if item["present"])
        return {
            "headers": checks,
            "present_count": present_count,
            "total_checked": len(checks),
            "score_pct": round((present_count / len(checks)) * 100, 1),
        }

    @staticmethod
    def _detect_trackers_in_html(
        html: str, page_url: str, tracker_registry: Dict[str, TrackerFinding]
    ) -> None:
        for tracker_id, meta in TRACKER_SIGNATURES.items():
            matched_snippets: List[str] = []
            for pattern in meta["patterns"]:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    snippet = match.group(0)[:80]
                    matched_snippets.append(snippet)

            # Posebna provjera za YouTube nocookie izuzeće
            if tracker_id == "youtube_embed_standard" and matched_snippets:
                if "youtube-nocookie.com/embed/" in html.lower() and "youtube.com/embed/" not in html.lower():
                    continue

            if matched_snippets:
                if tracker_id not in tracker_registry:
                    tracker_registry[tracker_id] = TrackerFinding(
                        id=tracker_id,
                        name=meta["name"],
                        provider=meta["provider"],
                        country=meta["country"],
                        category=meta["category"],
                        risk_level=meta["risk_level"],
                        gdpr_article=meta["gdpr_article"],
                        dpa_required=meta["dpa_required"],
                        matched_evidence=matched_snippets,
                        found_on_pages=[page_url],
                    )
                else:
                    existing = tracker_registry[tracker_id]
                    if page_url not in existing.found_on_pages:
                        existing.found_on_pages.append(page_url)
                    for s in matched_snippets:
                        if s not in existing.matched_evidence:
                            existing.matched_evidence.append(s)

    @staticmethod
    def _detect_cmp_and_consent(html: str, soup: BeautifulSoup) -> Dict[str, Any]:
        detected_cmps: List[str] = []
        for cmp_id, meta in CMP_SIGNATURES.items():
            for pattern in meta["patterns"]:
                if re.search(pattern, html, re.IGNORECASE):
                    if meta["name"] not in detected_cmps:
                        detected_cmps.append(meta["name"])
                    break

        google_consent_mode_v2 = bool(
            re.search(r"gtag\s*\(\s*['\"]consent['\"]\s*,\s*['\"]default['\"]", html, re.IGNORECASE)
            and re.search(r"ad_user_data|ad_personalization", html, re.IGNORECASE)
        )
        iab_tcf_v2 = bool(re.search(r"__tcfapi|__tcfapiLocator", html, re.IGNORECASE))

        # Provjera gumba "Prihvati sve" i "Odbij sve" u tekstu elemenata
        interactive_texts = " ".join(
            el.get_text(" ", strip=True)
            for el in soup.find_all(["button", "a", "input", "span", "div"], limit=400)
        )
        has_accept_btn = any(re.search(p, interactive_texts, re.IGNORECASE) for p in ACCEPT_BUTTON_PATTERNS)
        has_reject_btn = any(re.search(p, interactive_texts, re.IGNORECASE) for p in REJECT_BUTTON_PATTERNS)

        return {
            "has_cookie_banner": bool(detected_cmps or has_accept_btn or has_reject_btn),
            "detected_cmp_platforms": detected_cmps,
            "google_consent_mode_v2": google_consent_mode_v2,
            "iab_tcf_v2_detected": iab_tcf_v2,
            "has_accept_button": has_accept_btn,
            "has_equal_reject_button": has_reject_btn,
            "dark_pattern_suspected": bool((detected_cmps or has_accept_btn) and not has_reject_btn),
        }

    @staticmethod
    def _analyze_forms_on_page(soup: BeautifulSoup, page_url: str) -> List[FormFinding]:
        findings: List[FormFinding] = []
        pii_field_keywords = (
            "email", "e-mail", "mail", "phone", "tel", "mobitel", "telefon",
            "name", "ime", "prezime", "fullname", "adresa", "address", "oib",
            "jmbg", "iban", "card", "password", "lozinka", "datum_rodjenja", "birth",
        )

        for form in soup.find_all("form"):
            action = (form.get("action") or page_url).strip()
            full_action = urllib.parse.urljoin(page_url, action)
            method = (form.get("method") or "GET").upper().strip()
            is_secure_action = full_action.lower().startswith("https://")

            fields_detected: List[str] = []
            collects_pii = False
            has_prechecked_consent = False
            has_consent_checkbox = False

            for inp in form.find_all(["input", "textarea", "select"]):
                inp_type = (inp.get("type") or "text").lower()
                if inp_type in ("hidden", "submit", "button", "reset", "image"):
                    continue
                inp_name = (
                    inp.get("name")
                    or inp.get("id")
                    or inp.get("placeholder")
                    or inp.get("aria-label")
                    or inp_type
                )
                inp_name_str = str(inp_name).strip()
                fields_detected.append(f"{inp_name_str} ({inp_type})")

                if inp_type in ("email", "tel", "password") or any(
                    kw in inp_name_str.lower() for kw in pii_field_keywords
                ):
                    collects_pii = True

                if inp_type == "checkbox":
                    label_text = form.get_text(" ", strip=True).lower()
                    if any(
                        w in label_text
                        for w in ("privol", "slažem", "slazem", "privatnost", "uvjet", "newsletter", "marketing", "consent", "privacy", "agree")
                    ):
                        has_consent_checkbox = True
                        if inp.has_attr("checked"):
                            has_prechecked_consent = True

            form_html_lower = str(form).lower()
            has_privacy_link = any(
                kw in form_html_lower
                for kw in ("privatnost", "privacy", "gdpr", "uvjeti", "zaštita podataka", "zastita-podataka")
            )

            issues: List[str] = []
            risk_level = "LOW"

            if collects_pii:
                if not is_secure_action:
                    issues.append("Obrazac šalje osobne podatke preko nezaštićenog HTTP protokola (Čl. 32 GDPR).")
                    risk_level = "CRITICAL"
                if method == "GET":
                    issues.append("Obrazac s osobnim podacima koristi HTTP GET metodu čime PII podaci ostaju u URL zapisima (Čl. 32 GDPR).")
                    risk_level = "HIGH" if risk_level != "CRITICAL" else "CRITICAL"
                if has_prechecked_consent:
                    issues.append("Detektirana unaprijed označena (pre-checked) kućica za privolu — izravno kršenje Čl. 7. i uvodne izjave 32. GDPR-a (presuda Planet49).")
                    risk_level = "CRITICAL"
                if not has_privacy_link and not has_consent_checkbox:
                    issues.append("Obrazac prikuplja osobne podatke bez vidljive obavijesti ili poveznice na Pravila privatnosti (Čl. 13 GDPR).")
                    if risk_level == "LOW":
                        risk_level = "MEDIUM"

            if fields_detected:
                findings.append(
                    FormFinding(
                        page_url=page_url,
                        action=full_action,
                        method=method,
                        is_secure_action=is_secure_action,
                        fields_detected=fields_detected,
                        collects_pii=collects_pii,
                        has_prechecked_consent=has_prechecked_consent,
                        has_consent_checkbox=has_consent_checkbox,
                        has_privacy_link_nearby=has_privacy_link,
                        risk_level=risk_level,
                        issues=issues,
                    )
                )

        return findings

    @staticmethod
    def _extract_contact_and_dpo_info(text: str, html: str) -> Dict[str, Any]:
        emails = sorted(
            set(
                re.findall(
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                    html,
                )
            )
        )
        valid_emails = [
            e for e in emails
            if not e.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".js", ".css"))
        ]
        dpo_emails = [
            e for e in valid_emails
            if any(k in e.lower() for k in ("dpo", "gdpr", "privacy", "privatnost", "zastita", "szop", "legal"))
        ]
        oib_matches = sorted(set(re.findall(r"\b(?:OIB\s*[:\-]?\s*)?(\d{11})\b", text)))
        has_azop_mention = bool(
            re.search(r"\bAZOP\b|Agencij[ae]\s+za\s+zaštitu\s+osobnih\s+podataka", text, re.IGNORECASE)
        )
        has_data_subject_rights = bool(
            re.search(
                r"pravo\s+na\s+pristup|pravo\s+na\s+brisanje|pravo\s+na\s+ispravak|right\s+to\s+erasure|right\s+of\s+access",
                text,
                re.IGNORECASE,
            )
        )
        return {
            "emails_found": valid_emails[:25],
            "dpo_Contact_detected": bool(dpo_emails or re.search(r"službenik\s+za\s+zaštitu|dpo|data\s+protection\s+officer", text, re.IGNORECASE)),
            "dpo_emails": dpo_emails,
            "oib_candidates": oib_matches[:10],
            "mentions_azop_supervisory_authority": has_azop_mention,
            "mentions_data_subject_rights": has_data_subject_rights,
        }

    # ------------------------------------------------------------------------
    # OTKRIVANJE SITEMAP.XML I ROBOTS.TXT RUTA
    # ------------------------------------------------------------------------

    async def _discover_robots_and_sitemap(
        self, client: httpx.AsyncClient, base_url: str
    ) -> Tuple[Optional[urllib.robotparser.RobotFileParser], List[str]]:
        rp = urllib.robotparser.RobotFileParser()
        sitemap_urls: List[str] = []
        discovered_pages: List[str] = []

        robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
        try:
            resp = await client.get(robots_url, timeout=6.0)
            if resp.status_code == 200 and "text" in resp.headers.get("content-type", "").lower():
                lines = resp.text.splitlines()
                rp.parse(lines)
                for line in lines:
                    if line.lower().startswith("sitemap:"):
                        sm_url = line.split(":", 1)[1].strip()
                        if sm_url:
                            sitemap_urls.append(sm_url)
        except Exception:
            rp = None

        if not sitemap_urls:
            sitemap_urls.append(urllib.parse.urljoin(base_url, "/sitemap.xml"))

        for sm_url in sitemap_urls[:2]:
            try:
                sm_resp = await client.get(sm_url, timeout=6.0)
                if sm_resp.status_code == 200 and "xml" in sm_resp.headers.get("content-type", "").lower():
                    root = ET.fromstring(sm_resp.text)
                    for elem in root.iter():
                        if elem.tag.endswith("loc") and elem.text:
                            loc_url = elem.text.strip()
                            if self._score_url_priority(loc_url) == 0:
                                discovered_pages.insert(0, loc_url)
                            elif len(discovered_pages) < self.max_pages * 2:
                                discovered_pages.append(loc_url)
            except Exception:
                continue

        return rp, discovered_pages

    # ------------------------------------------------------------------------
    # HEADLESS PLAYWRIGHT FALLBACK ZA DINAMIČKE / SPA DOMENE
    # ------------------------------------------------------------------------

    async def _run_headless_probe(self, url: str) -> Dict[str, Any]:
        """Pokreće pravi preglednik ako je Playwright instaliran kako bi uhvatio JS kolačiće i localStorage."""
        result: Dict[str, Any] = {
            "executed": False,
            "js_cookies": [],
            "local_storage_keys": [],
            "session_storage_keys": [],
            "third_party_requests": [],
            "rendered_html": "",
        }
        if not self.use_headless_fallback or not PLAYWRIGHT_AVAILABLE:
            return result

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(user_agent=self.user_agent)
                page = await context.new_page()

                third_party_hosts: Set[str] = set()
                root_domain = urllib.parse.urlparse(url).netloc.lower().lstrip("www.")

                def _on_request(req: Any) -> None:
                    try:
                        host = urllib.parse.urlparse(req.url).netloc.lower().split(":")[0].lstrip("www.")
                        if host and host != root_domain and not host.endswith(f".{root_domain}"):
                            third_party_hosts.add(host)
                    except Exception:
                        pass

                page.on("request", _on_request)
                await page.goto(url, wait_until="networkidle", timeout=int(self.timeout * 1000))
                await page.wait_for_timeout(1200)

                result["executed"] = True
                result["rendered_html"] = await page.content()
                result["js_cookies"] = await context.cookies()
                result["local_storage_keys"] = await page.evaluate("() => Object.keys(window.localStorage || {})")
                result["session_storage_keys"] = await page.evaluate("() => Object.keys(window.sessionStorage || {})")
                result["third_party_requests"] = sorted(third_party_hosts)
                await browser.close()
        except Exception as exc:
            logger.debug("Playwright fallback preskočen za %s: %s", url, exc)

        return result

    # ------------------------------------------------------------------------
    # GLAVNA ASINKRONA METODA PRETRAŽIVANJA DOMENE (MULTI-PAGE BFS CRAWLER)
    # ------------------------------------------------------------------------

    async def scan_domain_async(
        self,
        target: str,
        save_to_disk: bool = True,
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        start_time = time.perf_counter()
        start_url, domain = self.normalize_target_url(target)
        scan_id = scan_id or uuid.uuid4().hex[:8]
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        logger.info("Pokrećem dubinsko GDPR skeniranje domene: %s (ID: %s)", domain, scan_id)

        # 1. Mrežna i TLS provjera u pozadinskoj dretvi
        net_tls_info = await asyncio.to_thread(self._inspect_network_and_tls, domain)

        visited_urls: Set[str] = set()
        crawled_pages: List[Dict[str, Any]] = []
        all_cookies: Dict[str, CookieFinding] = {}
        tracker_registry: Dict[str, TrackerFinding] = {}
        all_forms: List[FormFinding] = []
        external_resources: Set[str] = set()
        legal_pages_found: Dict[str, Optional[str]] = {
            "privacy_policy": None,
            "cookie_policy": None,
            "terms_of_service": None,
            "dpa_imprint_contact": None,
        }
        aggregated_text_chunks: List[str] = []
        aggregated_html_chunks: List[str] = []
        root_security_headers: Dict[str, Any] = {}
        cmp_summary: Dict[str, Any] = {
            "has_cookie_banner": False,
            "detected_cmp_platforms": [],
            "google_consent_mode_v2": False,
            "iab_tcf_v2_detected": False,
            "has_accept_button": False,
            "has_equal_reject_button": False,
            "dark_pattern_suspected": False,
        }
        http_to_https_redirect = False

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "hr-HR,hr;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        async with httpx.AsyncClient(
            headers=headers,
            follow_redirects=True,
            timeout=self.timeout,
            verify=False,
        ) as client:
            # Provjera automatskog HTTP -> HTTPS preusmjeravanja
            try:
                http_test_url = f"http://{domain}/"
                http_resp = await client.get(http_test_url, timeout=6.0)
                if str(http_resp.url).lower().startswith("https://"):
                    http_to_https_redirect = True
            except Exception:
                pass

            # Otkrivanje robots.txt i sitemap.xml
            rp, sitemap_candidates = await self._discover_robots_and_sitemap(client, start_url)

            # Red čekanja: (prioritet, dubina, url)
            queue: List[Tuple[int, int, str]] = [(0, 0, start_url)]
            for sm_url in sitemap_candidates:
                if self._is_same_domain(sm_url, domain):
                    prio = self._score_url_priority(sm_url)
                    queue.append((prio, 1, sm_url))

            # Dodaj tipične hrvatske i engleske pravne rute kao kandidate ako nisu u sitemapu
            common_legal_paths = [
                "/politika-privatnosti", "/pravila-privatnosti", "/privatnost",
                "/privacy-policy", "/privacy", "/politika-kolacica", "/kolacici",
                "/cookie-policy", "/uvjeti-koristenja", "/kontakt",
            ]
            for lpath in common_legal_paths:
                candidate_url = urllib.parse.urljoin(start_url, lpath)
                queue.append((1, 1, candidate_url))

            semaphore = asyncio.Semaphore(self.concurrency)

            async def _fetch_and_process(prio: int, depth: int, current_url: str) -> List[Tuple[int, int, str]]:
                if current_url in visited_urls or len(visited_urls) >= self.max_pages:
                    return []
                if self.respect_robots and rp is not None:
                    try:
                        if not rp.can_fetch(self.user_agent, current_url):
                            return []
                    except Exception:
                        pass

                visited_urls.add(current_url)
                new_links: List[Tuple[int, int, str]] = []

                async with semaphore:
                    try:
                        resp = await client.get(current_url)
                    except Exception as exc:
                        logger.debug("Neuspješno dohvaćanje %s: %s", current_url, exc)
                        return []

                # Ignoriraj nepostojeće (404) kandidatske podstranice osim ako je riječ o početnoj stranici
                if resp.status_code >= 400 and current_url != start_url:
                    return []

                content_type = resp.headers.get("content-type", "").lower()
                if "html" not in content_type and current_url != start_url:
                    return []

                final_url = str(resp.url)
                html = resp.text or ""
                soup = BeautifulSoup(html, "html.parser")

                # Sigurnosna zaglavlja na korijenskoj stranici
                nonlocal root_security_headers
                if not root_security_headers or current_url == start_url:
                    root_security_headers = self._analyze_security_headers(resp.headers)

                # Ekstrakcija kolačića iz HTTP odgovora
                page_cookies = self._extract_cookies_from_response(resp, final_url)
                for c in page_cookies:
                    if c.name not in all_cookies:
                        all_cookies[c.name] = c

                # Detekcija trackera i trećih strana
                self._detect_trackers_in_html(html, final_url, tracker_registry)

                # Provjera vanjskih skripti, iframeova i stilova
                for tag, attr in [("script", "src"), ("iframe", "src"), ("link", "href")]:
                    for el in soup.find_all(tag):
                        src_val = el.get(attr)
                        if not src_val:
                            continue
                        full_src = urllib.parse.urljoin(final_url, src_val)
                        parsed_src = urllib.parse.urlparse(full_src)
                        if parsed_src.scheme in ("http", "https") and not self._is_same_domain(full_src, domain):
                            external_resources.add(parsed_src.netloc.lower())

                # Detekcija CMP sustava i Cookie Bannera
                page_cmp = self._detect_cmp_and_consent(html, soup)
                if page_cmp["has_cookie_banner"]:
                    cmp_summary["has_cookie_banner"] = True
                for p_name in page_cmp["detected_cmp_platforms"]:
                    if p_name not in cmp_summary["detected_cmp_platforms"]:
                        cmp_summary["detected_cmp_platforms"].append(p_name)
                cmp_summary["google_consent_mode_v2"] = (
                    cmp_summary["google_consent_mode_v2"] or page_cmp["google_consent_mode_v2"]
                )
                cmp_summary["iab_tcf_v2_detected"] = (
                    cmp_summary["iab_tcf_v2_detected"] or page_cmp["iab_tcf_v2_detected"]
                )
                cmp_summary["has_accept_button"] = (
                    cmp_summary["has_accept_button"] or page_cmp["has_accept_button"]
                )
                cmp_summary["has_equal_reject_button"] = (
                    cmp_summary["has_equal_reject_button"] or page_cmp["has_equal_reject_button"]
                )
                cmp_summary["dark_pattern_suspected"] = bool(
                    cmp_summary["has_cookie_banner"] and not cmp_summary["has_equal_reject_button"]
                )

                # Analiza obrazaca (<form>)
                page_forms = self._analyze_forms_on_page(soup, final_url)
                all_forms.extend(page_forms)

                # Klasifikacija pravnih stranica
                page_title = (soup.title.string.strip() if soup.title and soup.title.string else "")
                url_and_title = f"{final_url.lower()} {page_title.lower()}"
                for legal_key, kw_list in PRIORITY_LEGAL_KEYWORDS.items():
                    if any(kw in url_and_title for kw in kw_list):
                        if not legal_pages_found[legal_key]:
                            legal_pages_found[legal_key] = final_url

                page_text = soup.get_text(" ", strip=True)
                aggregated_text_chunks.append(page_text[:15000])
                aggregated_html_chunks.append(html[:25000])

                crawled_pages.append(
                    {
                        "url": final_url,
                        "status_code": resp.status_code,
                        "title": page_title,
                        "cookies_set": len(page_cookies),
                        "forms_count": len(page_forms),
                        "depth": depth,
                    }
                )

                # Pronalaženje novih internih poveznica
                if depth < self.max_depth:
                    for a_tag in soup.find_all("a", href=True):
                        canon = self._Canonicalize_url(final_url, a_tag["href"])
                        if not canon or not self._is_same_domain(canon, domain):
                            continue
                        link_text = a_tag.get_text(" ", strip=True)
                        for legal_key, kw_list in PRIORITY_LEGAL_KEYWORDS.items():
                            if any(kw in f"{canon.lower()} {link_text.lower()}" for kw in kw_list):
                                if not legal_pages_found[legal_key]:
                                    legal_pages_found[legal_key] = canon
                        if canon not in visited_urls:
                            link_prio = self._score_url_priority(canon, link_text)
                            new_links.append((link_prio, depth + 1, canon))

                return new_links

            # BFS petlja s prioritetnim sortiranjem
            while queue and len(visited_urls) < self.max_pages:
                queue.sort(key=lambda item: (item[0], item[1]))
                batch: List[Tuple[int, int, str]] = []
                seen_in_batch: Set[str] = set()

                while queue and len(batch) < self.concurrency and (len(visited_urls) + len(batch)) < self.max_pages:
                    item = queue.pop(0)
                    if item[2] not in visited_urls and item[2] not in seen_in_batch:
                        batch.append(item)
                        seen_in_batch.add(item[2])

                if not batch:
                    break

                results = await asyncio.gather(
                    *(_fetch_and_process(p, d, u) for p, d, u in batch),
                    return_exceptions=True,
                )
                for res in results:
                    if isinstance(res, list):
                        for candidate in res:
                            if candidate[2] not in visited_urls:
                                queue.append(candidate)

        # Opcijski Playwright Headless fallback na početnoj stranici
        headless_data = await self._run_headless_probe(start_url)
        if headless_data["executed"]:
            if headless_data["rendered_html"]:
                self._detect_trackers_in_html(headless_data["rendered_html"], start_url, tracker_registry)
            for js_c in headless_data["js_cookies"]:
                c_name = js_c.get("name", "")
                if c_name and c_name not in all_cookies:
                    cat, desc, allowed_pre = self._classify_cookie(c_name)
                    all_cookies[c_name] = CookieFinding(
                        name=c_name,
                        domain=js_c.get("domain", domain),
                        path=js_c.get("path", "/"),
                        secure=bool(js_c.get("secure", False)),
                        http_only=bool(js_c.get("httpOnly", False)),
                        same_site=str(js_c.get("sameSite", "None/Unset")),
                        expires=str(js_c.get("expires", "")),
                        category=cat,
                        description=f"{desc} (Postavljen putem JavaScripta)",
                        allowed_pre_consent=allowed_pre,
                        set_before_consent=True,
                        gdpr_compliant=allowed_pre and bool(js_c.get("secure", False)),
                        found_on_url=start_url,
                    )
            for host in headless_data["third_party_requests"]:
                external_resources.add(host)

        # Sinteza rezultata i izračun GDPR bodova i rizika
        full_text = "\n".join(aggregated_text_chunks)
        full_html = "\n".join(aggregated_html_chunks)
        contact_dpo_info = self._extract_contact_and_dpo_info(full_text, full_html)

        cookie_list = [c.to_dict() for c in all_cookies.values()]
        tracker_list = [t.to_dict() for t in tracker_registry.values()]
        form_list = [f.to_dict() for f in all_forms]

        compliance_eval = self._evaluate_gdpr_compliance(
            net_tls_info=net_tls_info,
            http_to_https_redirect=http_to_https_redirect,
            security_headers=root_security_headers,
            cookies=cookie_list,
            trackers=tracker_list,
            cmp_summary=cmp_summary,
            legal_pages=legal_pages_found,
            forms=form_list,
            contact_dpo=contact_dpo_info,
        )

        duration_sec = round(time.perf_counter() - start_time, 2)

        # Konačni JSON rječnik (100% kompatibilan s postojećim poljima + prošireni detalji)
        scan_report: Dict[str, Any] = {
            "id": scan_id,
            "scan_id": scan_id,
            "domain": domain,
            "url": start_url,
            "timestamp": timestamp_iso,
            "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": duration_sec,
            "status": "completed" if crawled_pages else "failed",
            "pages_scanned_count": len(crawled_pages),
            "crawled_pages": crawled_pages,
            # Ključni indikatori za postojeći app.py, risk_analyzer.py i generator.py
            "score": compliance_eval["score"],
            "compliance_score": compliance_eval["score"],
            "risk_level": compliance_eval["risk_level"],
            "https": bool(net_tls_info.get("ssl_valid")),
            "ssl_valid": bool(net_tls_info.get("ssl_valid")),
            "http_to_https_redirect": http_to_https_redirect,
            "has_cookie_banner": cmp_summary["has_cookie_banner"],
            "has_privacy_policy": bool(legal_pages_found["privacy_policy"]),
            "has_cookie_policy": bool(legal_pages_found["cookie_policy"]),
            "has_terms_of_service": bool(legal_pages_found["terms_of_service"]),
            "has_dpo_contact": contact_dpo_info["dpo_Contact_detected"],
            "legal_pages": legal_pages_found,
            "cmp_details": cmp_summary,
            "network_and_tls": net_tls_info,
            "security_headers": root_security_headers,
            "cookies": cookie_list,
            "cookies_count": len(cookie_list),
            "non_essential_preconsent_cookies": [
                c["name"] for c in cookie_list if not c["allowed_pre_consent"]
            ],
            "trackers": tracker_list,
            "trackers_detected": [t["name"] for t in tracker_list],
            "third_party_domains": sorted(external_resources),
            "us_data_transfer_detected": any("SAD" in t["country"] for t in tracker_list),
            "dpa_processors_required": [
                {"name": t["name"], "provider": t["provider"], "country": t["country"]}
                for t in tracker_list
                if t["dpa_required"]
            ],
            "forms": form_list,
            "forms_count": len(form_list),
            "contact_and_dpo": contact_dpo_info,
            "headless_browser_used": headless_data["executed"],
            "local_storage_keys": headless_data["local_storage_keys"],
            "issues": compliance_eval["issues"],
            "findings": compliance_eval["issues"],
            "recommendations": compliance_eval["recommendations"],
        }

        if save_to_disk:
            self.save_scan_report(scan_report)

        return scan_report

    # ------------------------------------------------------------------------
    # SUSTAV BODOVANJA I PROCJENE GDPR RIZIKA (ČLANCI 5, 6, 7, 13, 25, 28, 32, 44)
    # ------------------------------------------------------------------------

    @staticmethod
    def _evaluate_gdpr_compliance(
        net_tls_info: Dict[str, Any],
        http_to_https_redirect: bool,
        security_headers: Dict[str, Any],
        cookies: List[Dict[str, Any]],
        trackers: List[Dict[str, Any]],
        cmp_summary: Dict[str, Any],
        legal_pages: Dict[str, Optional[str]],
        forms: List[Dict[str, Any]],
        contact_dpo: Dict[str, Any],
    ) -> Dict[str, Any]:
        score = 100
        issues: List[Dict[str, str]] = []
        recommendations: List[str] = []

        def add_issue(severity: str, title: str, description: str, article: str, penalty: int, rec: str) -> None:
            nonlocal score
            score = max(0, score - penalty)
            issues.append(
                {
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "gdpr_article": article,
                    "penalty_points": str(penalty),
                }
            )
            if rec not in recommendations:
                recommendations.append(rec)

        # 1. SSL / TLS provjera
        if not net_tls_info.get("ssl_valid"):
            add_issue(
                "CRITICAL",
                "Neispravan ili nedostupan SSL/TLS certifikat",
                "Domena nema valjanu HTTPS enkripciju za zaštitu osobnih podataka u prijenosu.",
                "Članak 32. st. 1. (a) GDPR",
                25,
                "Odmah instalirajte valjani TLS 1.3 certifikat i prisilite HTTPS preusmjeravanje.",
            )
        elif not http_to_https_redirect:
            add_issue(
                "MEDIUM",
                "Nedostaje automatsko HTTP -> HTTPS preusmjeravanje",
                "Posjetitelji koji pristupe putem http:// protokola nisu automatski preusmjereni na zaštićeni HTTPS.",
                "Članak 32. GDPR",
                5,
                "Konfigurirajte 301 preusmjeravanje sa svih HTTP ruta na HTTPS na razini poslužitelja ili Cloudflare Edgea.",
            )

        # 2. Pravila privatnosti i Politika kolačića
        if not legal_pages.get("privacy_policy"):
            add_issue(
                "CRITICAL",
                "Nedostaju Pravila privatnosti (Privacy Policy)",
                "Crawler nije pronašao javno dostupnu poveznicu na Pravila privatnosti na skeniranim stranicama.",
                "Članak 12., 13. i 14. GDPR",
                22,
                "Generirajte i objavite Pravila privatnosti putem GDPR Sentinel generatora te postavite poveznicu u podnožje (footer).",
            )
        if not legal_pages.get("cookie_policy") and (cookies or trackers):
            add_issue(
                "HIGH",
                "Nedostaje Politika kolačića (Cookie Policy)",
                "Domena koristi kolačiće i/ili skripte za praćenje, ali nema zasebnu ili jasno označenu Politiku kolačića.",
                "Članak 13. GDPR i ePrivacy direktiva",
                12,
                "Objavite detaljnu Politiku kolačića s tablicom svih aktivnih kolačića, njihovom svrhom i rokom trajanja.",
            )

        # 3. Kolačići prije privole (Pre-Consent Violations) i zastavice
        non_essential_pre = [c for c in cookies if not c["allowed_pre_consent"]]
        if non_essential_pre:
            names_str = ", ".join(c["name"] for c in non_essential_pre[:8])
            add_issue(
                "CRITICAL",
                f"Postavljanje analitičkih/marketinških kolačića prije privole ({len(non_essential_pre)})",
                f"Kolačići ({names_str}) postavljeni su odmah pri učitavanju stranice bez prethodne privole korisnika.",
                "Članak 6. st. 1. (a) i Članak 7. GDPR",
                20,
                "Blokirajte sve nenužne kolačiće i skripte do trenutka kada korisnik aktivno klikne 'Prihvati' u CMP banneru.",
            )

        insecure_cookies = [c for c in cookies if not c["secure"]]
        if insecure_cookies:
            add_issue(
                "MEDIUM",
                f"Kolačići bez 'Secure' zastavice ({len(insecure_cookies)})",
                "Detektirani su kolačići koji se mogu prenositi preko nezaštićenog HTTP prijenosa.",
                "Članak 32. GDPR",
                6,
                "Postavite zastavice 'Secure', 'HttpOnly' i 'SameSite=Lax/Strict' na sve kolačiće sesije.",
            )

        # 4. Trackeri i Cookie Banner / CMP
        high_risk_trackers = [t for t in trackers if t["risk_level"] in ("HIGH", "CRITICAL")]
        if high_risk_trackers and not cmp_summary.get("has_cookie_banner"):
            t_names = ", ".join(t["name"] for t in high_risk_trackers)
            add_issue(
                "CRITICAL",
                "Aktivni sustavi praćenja bez ikakvog Cookie Bannera (CMP)",
                f"Detektirani su alati za praćenje ({t_names}), a stranica uopće nema mehanizam za prikupljanje privole.",
                "Članak 6. i Članak 7. GDPR",
                22,
                "Implementirajte certificirani Consent Management Platform (CMP) s prioritetnim blokiranjem skripti.",
            )
        elif cmp_summary.get("dark_pattern_suspected"):
            add_issue(
                "HIGH",
                "Sumnja na neusklađen Cookie Banner (nedostaje gumb 'Odbij sve')",
                "Detektiran je banner za kolačiće, ali u prvom sloju nije pronađena jednako dostupna opcija za odbijanje ('Odbij sve' / 'Samo nužni').",
                "Članak 7. st. 3. GDPR i smjernice EDPB-a o Dark Patterns",
                12,
                "Osigurajte da gumb 'Odbij sve' bude na istoj razini i istog vizualnog prioriteta kao i gumb 'Prihvati sve'.",
            )

        # 5. Google Fonts vanjski CDN (Presuda LG München)
        if any(t["id"] == "google_fonts_external" for t in trackers):
            add_issue(
                "MEDIUM",
                "Učitavanje Google Fonts s vanjskog poslužitelja (SAD)",
                "Stranica povlači fontove s fonts.googleapis.com / fonts.gstatic.com čime se IP adresa posjetitelja automatski šalje Googleu u SAD.",
                "Članak 6. i Članak 44. GDPR (Presuda LG München Az. 3 O 17493/20)",
                8,
                "Preuzmite fontove lokalno na vlastiti poslužitelj (self-hosting) i uklonite pozive prema fonts.googleapis.com.",
            )

        # 6. Međunarodni prijenos podataka i DPA ugovori (Članak 28. i 44.)
        dpa_needed = [t for t in trackers if t["dpa_required"]]
        if dpa_needed:
            providers = ", ".join(sorted(set(t["provider"] for t in dpa_needed)))
            add_issue(
                "MEDIUM",
                f"Potrebni Ugovori o obradi podataka (DPA) za {len(dpa_needed)} izvršitelja",
                f"Detektirani su vanjski izvršitelji obrade ({providers}) koji zahtijevaju sklopljen DPA ugovor i unos u ROPA evidenciju.",
                "Članak 28. i Članak 30. GDPR",
                5,
                "Generirajte DPA ugovore i ažurirajte Evidenciju aktivnosti obrade (ROPA) u GDPR Sentinelu.",
            )

        # 7. Obrasci (Forms)
        for f in forms:
            for f_issue in f.get("issues", []):
                add_issue(
                    f["risk_level"],
                    f"Neusklađen web obrazac na {f['page_url']}",
                    f_issue,
                    "Članak 7., 13., 25. i 32. GDPR",
                    10 if f["risk_level"] == "CRITICAL" else 6,
                    "Uklonite unaprijed označene privole, koristite HTTPS POST metodu i dodajte poveznicu na Pravila privatnosti ispod obrasca.",
                )

        # 8. Sigurnosna HTTP zaglavlja
        if security_headers.get("score_pct", 0) < 50:
            add_issue(
                "LOW",
                f"Nedostaju sigurnosna HTTP zaglavlja ({security_headers.get('present_count', 0)}/{security_headers.get('total_checked', 6)})",
                "Poslužitelj ne šalje preporučena zaglavlja (CSP, HSTS, X-Frame-Options, Referrer-Policy).",
                "Članak 32. GDPR (Tehničke i organizacijske mjere)",
                5,
                "Postavite Content-Security-Policy, Strict-Transport-Security i Referrer-Policy: strict-origin-when-cross-origin.",
            )

        # 9. Prava ispitanika i AZOP kontakt
        if legal_pages.get("privacy_policy") and not contact_dpo.get("mentions_azop_supervisory_authority"):
            add_issue(
                "LOW",
                "Nije detektirana uputa o pravu na pritužbu AZOP-u",
                "Na skeniranim stranicama nije pronađena referenca na Agenciju za zaštitu osobnih podataka (AZOP).",
                "Članak 13. st. 2. (d) GDPR",
                4,
                "U Pravila privatnosti uvrstite kontakt podatke AZOP-a (Selska cesta 136, Zagreb, azop.hr) i opis prava ispitanika.",
            )

        if score >= 85:
            risk_level = "LOW"
        elif score >= 60:
            risk_level = "MEDIUM"
        elif score >= 35:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return {
            "score": score,
            "risk_level": risk_level,
            "issues": issues,
            "recommendations": recommendations,
        }

    # ------------------------------------------------------------------------
    # SPREMANJE I UČITAVANJE SKENOVA IZ data/scans/*.json
    # ------------------------------------------------------------------------

    def save_scan_report(self, report: Dict[str, Any]) -> Path:
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        scan_id = report.get("id") or report.get("scan_id") or uuid.uuid4().hex[:8]
        out_path = self.scans_dir / f"{scan_id}.json"
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        logger.info("Izvještaj skeniranja spremljen u: %s (Bodovi: %s/100)", out_path, report.get("score"))
        return out_path

    def load_existing_domains(self) -> List[Dict[str, str]]:
        """
        Učitava sve jedinstvene domene iz postojećih `data/scans/*.json` datoteka.
        Vraća listu rječnika: [{'scan_id': 'a8ffde08', 'domain': 'beat-battle-royale.com', 'url': '...'}, ...]
        """
        if not self.scans_dir.exists():
            return []

        seen_domains: Dict[str, Dict[str, str]] = {}
        for json_file in sorted(self.scans_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                with json_file.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
                raw_target = data.get("url") or data.get("domain") or ""
                if not raw_target:
                    continue
                norm_url, norm_domain = self.normalize_target_url(raw_target)
                if norm_domain not in seen_domains:
                    seen_domains[norm_domain] = {
                        "scan_id": data.get("id") or data.get("scan_id") or json_file.stem,
                        "domain": norm_domain,
                        "url": norm_url,
                        "source_file": str(json_file),
                    }
            except Exception as exc:
                logger.warning("Preskačem nečitljivu datoteku skena %s: %s", json_file, exc)

        return list(seen_domains.values())

    async def rescan_loaded_domains_async(
        self, overwrite_existing_ids: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Automatski učitava sve domene iz `data/scans/*.json` i izvršava dubinsko
        ponovno skeniranje svake domene.
        """
        loaded = self.load_existing_domains()
        if not loaded:
            logger.warning("Nema pronađenih domena u direktoriju %s.", self.scans_dir)
            return []

        logger.info("Učitano %d domena iz %s za dubinsko skeniranje.", len(loaded), self.scans_dir)
        results: List[Dict[str, Any]] = []
        for entry in loaded:
            sid = entry["scan_id"] if overwrite_existing_ids else None
            report = await self.scan_domain_async(entry["url"], save_to_disk=True, scan_id=sid)
            results.append(report)
        return results

    # ------------------------------------------------------------------------
    # SINKRONI OMOTAČI ZA KOMPATIBILNOST S FLASK / SYNCHRONOUS POZIVIMA
    # ------------------------------------------------------------------------

    @staticmethod
    def _run_coro_sync(coro: Any) -> Any:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        return asyncio.run(coro)

    def scan(self, target: str, save_to_disk: bool = True, scan_id: Optional[str] = None) -> Dict[str, Any]:
        return self._run_coro_sync(self.scan_domain_async(target, save_to_disk=save_to_disk, scan_id=scan_id))

    def scan_domain(self, target: str, save_to_disk: bool = True, scan_id: Optional[str] = None) -> Dict[str, Any]:
        return self.scan(target, save_to_disk=save_to_disk, scan_id=scan_id)

    def scan_url(self, target: str, save_to_disk: bool = True, scan_id: Optional[str] = None) -> Dict[str, Any]:
        return self.scan(target, save_to_disk=save_to_disk, scan_id=scan_id)

    def rescan_loaded_domains(self, overwrite_existing_ids: bool = True) -> List[Dict[str, Any]]:
        return self._run_coro_sync(self.rescan_loaded_domains_async(overwrite_existing_ids=overwrite_existing_ids))


# ============================================================================
# ALIASI KLASA I FUNKCIJA ZA 100% KOMPATIBILNOST S app.py I TESTOVIMA
# ============================================================================

DomainScanner = GDPRScanner
WebsiteScanner = GDPRScanner
Scanner = GDPRScanner


def scan_domain(target: str, save_to_disk: bool = True, **kwargs: Any) -> Dict[str, Any]:
    scanner = GDPRScanner(**kwargs)
    return scanner.scan(target, save_to_disk=save_to_disk)


def scan_url(target: str, save_to_disk: bool = True, **kwargs: Any) -> Dict[str, Any]:
    scanner = GDPRScanner(**kwargs)
    return scanner.scan(target, save_to_disk=save_to_disk)


def run_scan(target: str, save_to_disk: bool = True, **kwargs: Any) -> Dict[str, Any]:
    scanner = GDPRScanner(**kwargs)
    return scanner.scan(target, save_to_disk=save_to_disk)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GDPR Sentinel - Napredni Python Crawler za domene")
    parser.add_argument("domains", nargs="*", help="Domene ili URL-ovi za skeniranje (npr. beat-battle-royale.com)")
    parser.add_argument("--rescan-all", action="store_true", help="Učitaj i ponovno skeniraj sve domene iz data/scans/*.json")
    parser.add_argument("--max-pages", type=int, default=12, help="Maksimalni broj podstranica po domeni (zadano: 12)")
    parser.add_argument("--depth", type=int, default=2, help="Maksimalna dubina pretraživanja (zadano: 2)")
    parser.add_argument("--scans-dir", type=str, default="data/scans", help="Putanja do direktorija sa skenovima")
    args = parser.parse_args()

    crawler = GDPRScanner(
        max_pages=args.max_pages,
        max_depth=args.depth,
        scans_dir=args.scans_dir,
    )

    if args.rescan_all or not args.domains:
        reports = crawler.rescan_loaded_domains(overwrite_existing_ids=True)
        print(f"\n[OK] Završeno ponovno skeniranje {len(reports)} učitanih domena iz '{args.scans_dir}'.")
        for r in reports:
            print(f" - {r['domain']} (ID: {r['id']}): Bodovi={r['score']}/100 | Rizik={r['risk_level']} | Podstranica={r['pages_scanned_count']}")
    else:
        for dom in args.domains:
            rep = crawler.scan(dom, save_to_disk=True)
            print(f"\n[OK] Domena: {rep['domain']} (ID: {rep['id']})")
            print(f"     Bodovi usklađenosti: {rep['score']}/100 ({rep['risk_level']})")
            print(f"     Skenirano podstranica: {rep['pages_scanned_count']}")
            print(f"     Detektirani kolačići: {rep['cookies_count']} | Trackeri: {len(rep['trackers'])}")
