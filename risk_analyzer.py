#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDPR Sentinel - Napredni analizator rizika (risk_analyzer.py).
Obrađuje rezultate iz scanner.py, generira forenzičku matricu pre-consent kolačića,
analizira otkrivene podstranice i gradi ROPA evidenciju aktivnosti obrade (Čl. 30. GDPR).
"""

from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("gdpr_sentinel.risk_analyzer")


class RiskAnalyzer:
    """
    Analizira JSON izvještaj skeniranja domene i priprema strukturirane tablice
    za izravan ispis u PDF izvještajima (pregled.pdf, kolacici.pdf, ropa.pdf, dpa.pdf).
    """

    SEVERITY_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
    }

    SEVERITY_LABELS_HR: Dict[str, str] = {
        "CRITICAL": "KRITIČAN RIZIK",
        "HIGH": "VISOK RIZIK",
        "MEDIUM": "UMJEREN RIZIK",
        "LOW": "NIZAK RIZIK",
    }

    def __init__(self, company_profile_path: Union[str, Path] = "data/company_profile.json") -> None:
        self.company_profile_path = Path(company_profile_path)

    def load_company_profile(self) -> Dict[str, Any]:
        default_profile = {
            "company_name": "Web Labirint d.o.o. / Korisnik GDPR Sentinela",
            "address": "Koprivnica, Republika Hrvatska",
            "oib": "00000000000",
            "email": "dpo@domena.hr",
            "dpo_name": "Službenik za zaštitu podataka",
            "phone": "+385 95 000 0000",
        }
        if self.company_profile_path.is_file():
            try:
                with self.company_profile_path.open("r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict):
                    default_profile.update({k: v for k, v in loaded.items() if v})
            except Exception as exc:
                logger.warning("Neuspješno čitanje company_profile.json: %s", exc)
        return default_profile

    # ------------------------------------------------------------------------
    # 1. FORENZIKA PRE-CONSENT KOLAČIĆA
    # ------------------------------------------------------------------------

    @staticmethod
    def extract_cookie_audit_tables(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Vraća strukturirane liste svih kolačića i kolačića postavljenih prije privole
        (pre-consent) spremne za tablični prikaz u PDF-u.
        """
        raw_cookies: List[Dict[str, Any]] = scan_data.get("cookies", []) or []
        domain = scan_data.get("domain", "nepoznata-domena.hr")

        all_cookies_rows: List[Dict[str, Any]] = []
        preconsent_violations: List[Dict[str, Any]] = []
        category_counts: Dict[str, int] = {
            "Nužni": 0,
            "Analitički": 0,
            "Marketinški": 0,
            "Funkcionalni": 0,
            "Neklasificirani": 0,
        }

        for c in raw_cookies:
            if isinstance(c, str):
                c = {"name": c, "domain": domain, "category": "Neklasificirani", "allowed_pre_consent": False}

            name = str(c.get("name") or "Nepoznat")
            c_domain = str(c.get("domain") or domain)
            category = str(c.get("category") or "Neklasificirani")
            secure = bool(c.get("secure", False))
            http_only = bool(c.get("http_only", c.get("httpOnly", False)))
            same_site = str(c.get("same_site") or c.get("sameSite") or "None/Unset")
            expires = str(c.get("expires") or "Sesija (Session)")
            allowed_pre = bool(c.get("allowed_pre_consent", category == "Nužni"))
            set_before = bool(c.get("set_before_consent", True))
            found_on = str(c.get("found_on_url") or scan_data.get("url") or f"https://{domain}/")
            description = str(c.get("description") or "Kolačić detektiran tijekom automatskog skeniranja")

            category_counts[category] = category_counts.get(category, 0) + 1

            flags_list = []
            flags_list.append("Secure:DA" if secure else "Secure:NE")
            flags_list.append("HttpOnly:DA" if http_only else "HttpOnly:NE")
            flags_list.append(f"SameSite:{same_site}")
            flags_str = " | ".join(flags_list)

            is_preconsent_violation = set_before and not allowed_pre
            status_label = (
                "PREKRŠAJ (Prije privole)"
                if is_preconsent_violation
                else ("DOZVOLJEN (Nužni)" if allowed_pre else "ZAHTIJEVA PRIVOLU")
            )

            row = {
                "name": name,
                "category": category,
                "domain": c_domain,
                "expires": expires,
                "flags": flags_str,
                "secure": secure,
                "http_only": http_only,
                "same_site": same_site,
                "found_on_url": found_on,
                "status_label": status_label,
                "is_violation": is_preconsent_violation,
                "description": description,
            }
            all_cookies_rows.append(row)
            if is_preconsent_violation:
                preconsent_violations.append(row)

        return {
            "total_cookies": len(all_cookies_rows),
            "preconsent_violations_count": len(preconsent_violations),
            "all_cookies_table": all_cookies_rows,
            "preconsent_table": preconsent_violations,
            "category_counts": category_counts,
        }

    # ------------------------------------------------------------------------
    # 2. TOPOLOGIJA I POPIS OTKRIVENIH PODSTRANICA
    # ------------------------------------------------------------------------

    @staticmethod
    def extract_crawled_pages_table(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gradi obogaćenu tablicu svih otkrivenih i skeniranih podstranica
        s oznakom njihove pravne uloge (Pravila privatnosti, Kolačići, Uvjeti, Kontakt).
        """
        raw_pages: List[Dict[str, Any]] = scan_data.get("crawled_pages", []) or []
        legal_map: Dict[str, Optional[str]] = scan_data.get("legal_pages", {}) or {}
        base_url = scan_data.get("url") or f"https://{scan_data.get('domain', 'domena.hr')}/"

        # Ako je sken iz starije verzije koja nije imala crawled_pages, rekonstruiraj korijensku stranicu
        if not raw_pages:
            raw_pages = [
                {
                    "url": base_url,
                    "status_code": 200,
                    "title": scan_data.get("domain", "Početna stranica"),
                    "cookies_set": len(scan_data.get("cookies", []) or []),
                    "forms_count": scan_data.get("forms_count", len(scan_data.get("forms", []) or [])),
                    "depth": 0,
                }
            ]

        reverse_legal_role: Dict[str, str] = {}
        role_labels = {
            "privacy_policy": "Pravila privatnosti",
            "cookie_policy": "Politika kolačića",
            "terms_of_service": "Uvjeti korištenja",
            "dpa_imprint_contact": "Kontakt / Impressum / DPA",
        }
        for role_key, role_url in legal_map.items():
            if role_url:
                reverse_legal_role[role_url.rstrip("/").lower()] = role_labels.get(role_key, role_key)

        rows: List[Dict[str, Any]] = []
        for idx, page in enumerate(raw_pages, start=1):
            p_url = str(page.get("url") or base_url)
            norm_p_url = p_url.rstrip("/").lower()
            role = reverse_legal_role.get(norm_p_url)

            if not role:
                lower_u = p_url.lower()
                if any(k in lower_u for k in ("privatnost", "privacy", "gdpr", "zastita-podataka")):
                    role = "Pravila privatnosti"
                elif any(k in lower_u for k in ("kolacic", "cookie")):
                    role = "Politika kolačića"
                elif any(k in lower_u for k in ("uvjeti", "terms", "tos")):
                    role = "Uvjeti korištenja"
                elif any(k in lower_u for k in ("kontakt", "contact", "impressum", "o-nama")):
                    role = "Kontakt / Informacije"
                elif idx == 1 or int(page.get("depth", 0)) == 0:
                    role = "Početna stranica (Root)"
                else:
                    role = "Javna podstranica"

            rows.append(
                {
                    "index": idx,
                    "url": p_url,
                    "status_code": int(page.get("status_code", 200)),
                    "depth": int(page.get("depth", 0)),
                    "cookies_set": int(page.get("cookies_set", 0)),
                    "forms_count": int(page.get("forms_count", 0)),
                    "title": str(page.get("title") or "Bez naslova")[:65],
                    "legal_role": role,
                }
            )

        return {
            "total_pages_crawled": len(rows),
            "pages_table": rows,
            "legal_pages_coverage": {
                "Pravila privatnosti": legal_map.get("privacy_policy") or "NIJE PRONAĐENO",
                "Politika kolačića": legal_map.get("cookie_policy") or "NIJE PRONAĐENO",
                "Uvjeti korištenja": legal_map.get("terms_of_service") or "NIJE PRONAĐENO",
                "Kontakt / DPA / Impressum": legal_map.get("dpa_imprint_contact") or "NIJE PRONAĐENO",
            },
        }

    # ------------------------------------------------------------------------
    # 3. ROPA GENERATOR (EVIDENCIJA AKTIVNOSTI OBRADE - ČL. 30. GDPR)
    # ------------------------------------------------------------------------

    def build_ropa_entries(
        self, scan_data: Dict[str, Any], company_profile: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, str]]:
        """
        Generira stavke Evidencije aktivnosti obrade (ROPA) izravno iz rezultata
        skeniranja domene (poslužiteljski zapisi, obrasci na podstranicama, kolačići, trackeri).
        """
        domain = scan_data.get("domain", "domena.hr")
        https_ok = bool(scan_data.get("https") or scan_data.get("ssl_valid"))
        tls_measure = "TLS 1.3 enkripcija u prijenosu" if https_ok else "UPOZORENJE: Nedostaje valjani TLS"
        entries: List[Dict[str, str]] = []

        # 1. Osnovno posluživanje web stranice i sigurnosni zapisi
        entries.append(
            {
                "activity_id": "ROPA-01",
                "name": f"Posluživanje web sjedišta ({domain}) i sigurnosni nadzor",
                "purpose": "Osiguravanje dostupnosti, mrežna sigurnost i obrana od DDoS/bot napada",
                "legal_basis": "Čl. 6(1)(f) GDPR - Legitimni interes voditelja obrade",
                "data_subjects": "Svi posjetitelji web sjedišta",
                "data_categories": "IP adresa, User-Agent, zaglavlja HTTP zahtjeva, vremenska oznaka",
                "recipients": "Hosting poslužitelj / CDN infrastruktura",
                "third_country_transfer": "EU/EGP (ili SAD uz DPF ako se koristi Cloudflare/AWS)",
                "retention_period": "Do 30 dana u rotirajućim sigurnosnim zapisima (access/error logs)",
                "security_measures": f"{tls_measure}, vatrozid, ograničenje pristupa poslužitelju",
                "source_pages": f"Sve otkrivene podstranice ({scan_data.get('pages_scanned_count', 1)})",
            }
        )

        # 2. Obrasci (Forms) pronađeni na podstranicama
        forms: List[Dict[str, Any]] = scan_data.get("forms", []) or []
        if forms:
            form_urls = ", ".join(sorted(set(str(f.get("page_url", domain)) for f in forms)))
            detected_fields = ", ".join(
                sorted(set(field_item for f in forms for field_item in (f.get("fields_detected") or [])))
            )[:140]
            entries.append(
                {
                    "activity_id": "ROPA-02",
                    "name": "Obrada upita, registracija i komunikacija putem web obrazaca",
                    "purpose": "Odgovaranje na upite korisnika, realizacija usluge ili prijava na novosti",
                    "legal_basis": "Čl. 6(1)(b) predugovorne radnje / Čl. 6(1)(a) privola ispitanika",
                    "data_subjects": "Korisnici koji ispunjavaju web obrasce na podstranicama",
                    "data_categories": detected_fields or "Ime, e-mail adresa, telefon, sadržaj poruke",
                    "recipients": "Interni odjel podrške / prodaje i pružatelj e-mail hostinga",
                    "third_country_transfer": "Nema prijenosa izvan EU/EGP (osim uz SCC/DPF za cloud mail)",
                    "retention_period": "12 mjeseci za opće upite ili do opoziva privole",
                    "security_measures": f"{tls_measure}, validacija unosa, kontrola pristupa",
                    "source_pages": form_urls[:120],
                }
            )

        # 3. Kolačići (Pre-consent i funkcionalni/analitički)
        cookie_audit = self.extract_cookie_audit_tables(scan_data)
        if cookie_audit["total_cookies"] > 0:
            cookie_names = ", ".join(c["name"] for c in cookie_audit["all_cookies_table"][:12])
            pre_count = cookie_audit["preconsent_violations_count"]
            measure_note = (
                f"UPOZORENJE: {pre_count} kolačića postavljeno prije privole! Potrebna blokada u CMP-u."
                if pre_count > 0
                else "Kolačići ograničeni na nužne prije privole uz Secure/SameSite zastavice."
            )
            entries.append(
                {
                    "activity_id": "ROPA-03",
                    "name": "Upravljanje kolačićima (Cookies) i identifikatorima sesije",
                    "purpose": "Održavanje sesije, spremanje postavki privatnosti, analitika i marketing",
                    "legal_basis": "Čl. 6(1)(f) za nužne kolačiće; Čl. 6(1)(a) privola za analitičke/marketinške",
                    "data_subjects": "Posjetitelji web sjedišta",
                    "data_categories": f"Identifikatori kolačića ({cookie_names}), IP adresa",
                    "recipients": "Voditelj obrade i treće strane deklarirane u Politici kolačića",
                    "third_country_transfer": "Ovisno o vanjskim skriptama (vidi stavke izvršitelja obrade)",
                    "retention_period": "Od trajanja sesije do maksimalno 13 mjeseci",
                    "security_measures": measure_note,
                    "source_pages": ", ".join(
                        sorted(set(c["found_on_url"] for c in cookie_audit["all_cookies_table"]))
                    )[:120],
                }
            )

        # 4. Pojedinačni detektirani sustavi praćenja i izvršitelji obrade (Trackers)
        trackers: List[Dict[str, Any]] = scan_data.get("trackers", []) or []
        for idx, tr in enumerate(trackers, start=4):
            tr_pages = ", ".join(tr.get("found_on_pages") or [f"https://{domain}/"])[:120]
            entries.append(
                {
                    "activity_id": f"ROPA-{idx:02d}",
                    "name": f"Vanjska integracija: {tr.get('name', 'Vanjski servis')}",
                    "purpose": f"{tr.get('category', 'Analitika i vanjski resursi')}",
                    "legal_basis": f"Čl. 6(1)(a) izričita privola ({tr.get('gdpr_article', 'Čl. 6 GDPR')})",
                    "data_subjects": "Posjetitelji web sjedišta",
                    "data_categories": "IP adresa, online identifikatori, podaci o interakciji s DOM-om",
                    "recipients": str(tr.get("provider", "Vanjski izvršitelj obrade")),
                    "third_country_transfer": str(tr.get("country", "EU / SAD")),
                    "retention_period": "Prema politici zadržavanja izvršitelja (tipično 2 do 14 mjeseci)",
                    "security_measures": (
                        "Potreban sklopljen DPA ugovor (Čl. 28.) i aktivacija tek nakon CMP privole"
                        if tr.get("dpa_required")
                        else "Preporučena lokalna pohrana resursa (self-hosting) radi izbjegavanja prijenosa IP-a"
                    ),
                    "source_pages": tr_pages,
                }
            )

        return entries

    # ------------------------------------------------------------------------
    # GLAVNA METODA ANALIZE SKENA (KOMPATIBILNA S app.py)
    # ------------------------------------------------------------------------

    def analyze_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        company_profile = self.load_company_profile()
        cookie_audit = self.extract_cookie_audit_tables(scan_data)
        pages_audit = self.extract_crawled_pages_table(scan_data)
        ropa_entries = self.build_ropa_entries(scan_data, company_profile)

        score = int(scan_data.get("score", scan_data.get("compliance_score", 50)))
        risk_level = str(scan_data.get("risk_level", "MEDIUM")).upper()
        if risk_level not in self.SEVERITY_LABELS_HR:
            risk_level = "LOW" if score >= 85 else ("MEDIUM" if score >= 60 else ("HIGH" if score >= 35 else "CRITICAL"))

        issues: List[Dict[str, Any]] = scan_data.get("issues") or scan_data.get("findings") or []
        recommendations: List[str] = scan_data.get("recommendations") or []

        # Ako je sken učitan iz starije JSON datoteke koja nije imala pre-consent izračun
        if cookie_audit["preconsent_violations_count"] > 0 and not any(
            "prije privole" in str(i.get("title", "")).lower() for i in issues
        ):
            viol_names = ", ".join(c["name"] for c in cookie_audit["preconsent_table"][:8])
            issues.insert(
                0,
                {
                    "severity": "CRITICAL",
                    "title": f"Kolačići postavljeni prije privole ({cookie_audit['preconsent_violations_count']})",
                    "description": f"Detektirani su nenužni kolačići ({viol_names}) aktivni prije privole korisnika.",
                    "gdpr_article": "Članak 6. st. 1. (a) i Članak 7. GDPR",
                },
            )

        return {
            "scan_id": scan_data.get("id") or scan_data.get("scan_id") or "audit",
            "domain": scan_data.get("domain", "domena.hr"),
            "url": scan_data.get("url", ""),
            "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": score,
            "compliance_score": score,
            "risk_level": risk_level,
            "risk_label_hr": self.SEVERITY_LABELS_HR.get(risk_level, "UMJEREN RIZIK"),
            "cookie_audit": cookie_audit,
            "pages_audit": pages_audit,
            "ropa_entries": ropa_entries,
            "issues": issues,
            "recommendations": recommendations,
            "company_profile": company_profile,
        }

    def analyze(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return self.analyze_scan(scan_data)

    def evaluate(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return self.analyze_scan(scan_data)


# Aliasi za potpunu povratnu kompatibilnost
GDPRRiskAnalyzer = RiskAnalyzer


def analyze_scan(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    return RiskAnalyzer().analyze_scan(scan_data)


def analyze_risk(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    return RiskAnalyzer().analyze_scan(scan_data)


def calculate_risk_score(scan_data: Dict[str, Any]) -> int:
    return int(RiskAnalyzer().analyze_scan(scan_data)["score"])
