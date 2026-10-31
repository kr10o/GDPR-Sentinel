#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDPR Sentinel - Napredni PDF i Markdown generator dokumenata (generator.py).
Generira izravno u output/pdf/ (pregled.pdf, kolacici.pdf, ropa.pdf, privatnost.pdf, dpa.pdf)
i u generated_docs/ strukturirane PDF izvještaje s tablicama pre-consent kolačića
i popisom svih otkrivenih podstranica.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from fpdf import FPDF

from risk_analyzer import RiskAnalyzer

logger = logging.getLogger("gdpr_sentinel.generator")


# ============================================================================
# POMOĆNA KLASA ZA STILIZIRANE VIŠESTRANIČNE PDF DOKUMENTE (FPDF2)
# ============================================================================

class SentinelPDF(FPDF):
    """
    Prilagođeni FPDF2 engine s podrškom za hrvatske dijakritičke znakove
    putem static/fonts/regular.ttf i static/fonts/bold.ttf te automatskim prijelomom tablica.
    """

    def __init__(
        self,
        doc_title: str = "GDPR Sentinel Izvještaj",
        domain_subtitle: str = "",
        regular_font_path: Union[str, Path] = "static/fonts/regular.ttf",
        bold_font_path: Union[str, Path] = "static/fonts/bold.ttf",
    ) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.doc_title = doc_title
        self.domain_subtitle = domain_subtitle
        self.font_family_name = "Helvetica"
        self.unicode_ready = False

        self.set_margins(left=14, top=18, right=14)
        self.set_auto_page_break(auto=True, margin=18)
        self._register_unicode_fonts(Path(regular_font_path), Path(bold_font_path))

    def _register_unicode_fonts(self, reg_path: Path, bold_path: Path) -> None:
        candidates_reg = [
            reg_path,
            Path(__file__).resolve().parent / "static" / "fonts" / "regular.ttf",
            Path("C:/Windows/Fonts/arial.ttf"),
            Path("C:/Windows/Fonts/segoeui.ttf"),
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        ]
        candidates_bold = [
            bold_path,
            Path(__file__).resolve().parent / "static" / "fonts" / "bold.ttf",
            Path("C:/Windows/Fonts/arialbd.ttf"),
            Path("C:/Windows/Fonts/segoeuib.ttf"),
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ]

        chosen_reg = next((p for p in candidates_reg if p.is_file()), None)
        chosen_bold = next((p for p in candidates_bold if p.is_file()), None)

        if chosen_reg and chosen_bold:
            try:
                self.add_font("SentinelSans", style="", fname=str(chosen_reg))
                self.add_font("SentinelSans", style="B", fname=str(chosen_bold))
                self.font_family_name = "SentinelSans"
                self.unicode_ready = True
            except Exception as exc:
                logger.warning("Greška pri učitavanju TTF fonta, koristim fallback: %s", exc)

    def safe_text(self, text: Any) -> str:
        raw = str(text if text is not None else "")
        if self.unicode_ready:
            return raw
        replacements = {
            "č": "c", "ć": "c", "ž": "z", "š": "s", "đ": "d",
            "Č": "C", "Ć": "C", "Ž": "Z", "Š": "S", "Đ": "D",
            "—": "-", "–": "-", "•": "*", "„": '"', "”": '"', "“": '"',
        }
        for k, v in replacements.items():
            raw = raw.replace(k, v)
        return raw.encode("latin-1", "replace").decode("latin-1")

    def header(self) -> None:
        self.set_fill_color(15, 23, 42)  # Dark slate (#0f172a)
        self.rect(0, 0, 210, 14, style="F")
        self.set_y(4)
        self.set_x(14)
        self.set_font(self.font_family_name, "B", 9)
        self.set_text_color(56, 189, 248)  # Cyan accent (#38bdf8)
        self.cell(95, 6, self.safe_text(f"GDPR SENTINEL // {self.doc_title.upper()}"), align="L")
        self.set_font(self.font_family_name, "", 8)
        self.set_text_color(203, 213, 225)
        self.cell(87, 6, self.safe_text(self.domain_subtitle), align="R")
        self.ln(12)
        self.set_text_color(30, 41, 59)

    def footer(self) -> None:
        self.set_y(-13)
        self.set_draw_color(203, 213, 225)
        self.line(14, self.get_y(), 196, self.get_y())
        self.ln(2)
        self.set_font(self.font_family_name, "", 7.5)
        self.set_text_color(100, 116, 139)
        now_str = datetime.datetime.now().strftime("%d.%m.%Y. %H:%M")
        self.cell(
            120,
            5,
            self.safe_text(f"Automatski revizijski dokument | Generirano: {now_str} | Sukladno Uredbi (EU) 2016/679 (GDPR)"),
            align="L",
        )
        self.cell(62, 5, self.safe_text(f"Stranica {self.page_no()}/{{nb}}"), align="R")

    def section_heading(self, title: str, subtitle: str = "") -> None:
        if self.get_y() > 245:
            self.add_page()
        self.ln(3)
        self.set_fill_color(241, 245, 249)
        self.set_draw_color(14, 165, 233)
        self.set_line_width(0.6)
        y_start = self.get_y()
        self.rect(14, y_start, 182, 8.5, style="F")
        self.line(14, y_start, 14, y_start + 8.5)
        self.set_xy(17, y_start + 1.5)
        self.set_font(self.font_family_name, "B", 10.5)
        self.set_text_color(15, 23, 42)
        self.cell(176, 5.5, self.safe_text(title))
        self.ln(8.5)
        if subtitle:
            self.set_font(self.font_family_name, "", 8.5)
            self.set_text_color(71, 85, 105)
            self.multi_cell(182, 4.5, self.safe_text(subtitle))
            self.ln(1.5)
        self.set_line_width(0.2)

    def key_value_grid(self, pairs: List[Tuple[str, str]]) -> None:
        self.set_draw_color(226, 232, 240)
        for idx, (label, val) in enumerate(pairs):
            if self.get_y() > 265:
                self.add_page()
            if idx % 2 == 0:
                self.set_fill_color(248, 250, 252)
            else:
                self.set_fill_color(255, 255, 255)
            self.set_font(self.font_family_name, "B", 8.5)
            self.set_text_color(51, 65, 85)
            self.cell(58, 6.5, self.safe_text(f" {label}"), border=1, fill=True)
            self.set_font(self.font_family_name, "", 8.5)
            self.set_text_color(15, 23, 42)
            self.cell(124, 6.5, self.safe_text(f" {val}"[:95]), border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

    def render_structured_table(
        self,
        headers: List[str],
        col_widths: List[float],
        rows: List[List[str]],
        highlight_col_idx: Optional[int] = None,
    ) -> None:
        """
        Iscrtava profesionalnu tablicu s automatskim ponavljanjem zaglavlja pri prijelomu stranice
        i dinamičkim izračunom visine retka.
        """
        def _draw_header() -> None:
            self.set_fill_color(30, 41, 59)
            self.set_text_color(255, 255, 255)
            self.set_draw_color(71, 85, 105)
            self.set_font(self.font_family_name, "B", 8)
            for h_text, w in zip(headers, col_widths):
                self.cell(w, 7, self.safe_text(f" {h_text}"), border=1, fill=True)
            self.ln(7)

        if self.get_y() > 245:
            self.add_page()
        _draw_header()

        self.set_font(self.font_family_name, "", 7.5)
        self.set_draw_color(203, 213, 225)

        for r_idx, row in enumerate(rows):
            # Procijeni broj linija za najdužu ćeliju u retku
            max_lines = 1
            wrapped_cells: List[List[str]] = []
            for cell_val, w in zip(row, col_widths):
                clean_val = self.safe_text(cell_val)
                chars_per_line = max(8, int((w - 2) * 0.62))
                words = clean_val.split(" ")
                lines: List[str] = []
                current_line = ""
                for word in words:
                    # Ako je pojedinačna riječ (npr. dugi URL) duža od širine stupca, razlomi je
                    while len(word) > chars_per_line:
                        if current_line:
                            lines.append(current_line)
                            current_line = ""
                        lines.append(word[:chars_per_line])
                        word = word[chars_per_line:]
                    if not current_line:
                        current_line = word
                    elif len(current_line) + 1 + len(word) <= chars_per_line:
                        current_line += " " + word
                    else:
                        lines.append(current_line)
                        current_line = word
                if current_line:
                    lines.append(current_line)
                if not lines:
                    lines = ["-"]
                lines = lines[:5]  # Maksimalno 5 linija po ćeliji radi preglednosti
                wrapped_cells.append(lines)
                if len(lines) > max_lines:
                    max_lines = len(lines)

            row_height = max_lines * 4.3 + 1.8
            if self.get_y() + row_height > 274:
                self.add_page()
                _draw_header()
                self.set_font(self.font_family_name, "", 7.5)

            y_top = self.get_y()
            x_cur = 14.0

            is_violation_row = False
            if highlight_col_idx is not None and highlight_col_idx < len(row):
                cell_upper = str(row[highlight_col_idx]).upper()
                if any(k in cell_upper for k in ("PREKRŠAJ", "KRITIČ", "CRITICAL", "VISOK", "HIGH", "NEUSKLAĐEN")):
                    is_violation_row = True

            for c_idx, (lines, w) in enumerate(zip(wrapped_cells, col_widths)):
                if is_violation_row and c_idx == highlight_col_idx:
                    self.set_fill_color(254, 226, 226)  # Svijetlo crvena za prekršaj
                    self.set_text_color(153, 27, 27)
                    self.set_font(self.font_family_name, "B", 7.5)
                else:
                    if r_idx % 2 == 0:
                        self.set_fill_color(255, 255, 255)
                    else:
                        self.set_fill_color(248, 250, 252)
                    self.set_text_color(30, 41, 59)
                    self.set_font(self.font_family_name, "", 7.5)

                self.rect(x_cur, y_top, w, row_height, style="DF")
                for l_idx, line_str in enumerate(lines):
                    self.set_xy(x_cur + 1.2, y_top + 1.0 + l_idx * 4.3)
                    self.cell(w - 2.4, 4.0, line_str)
                x_cur += w

            self.set_xy(14, y_top + row_height)

        self.ln(3)


# ============================================================================
# GLAVNI GENERATOR DOKUMENATA (PDF + MARKDOWN)
# ============================================================================

class DocumentGenerator:
    """
    Upravlja generiranjem svih revizijskih PDF i Markdown izvještaja:
    - output/pdf/pregled.pdf (+ generated_docs/GDPR_Izvjestaj_<domena>_<id>.pdf)
    - output/pdf/kolacici.pdf (+ generated_docs/Politika_Kolacica_<ts>.pdf/.md)
    - output/pdf/ropa.pdf
    - output/pdf/privatnost.pdf (+ generated_docs/Pravila_Privatnosti_<ts>.pdf/.md)
    - output/pdf/dpa.pdf (+ generated_docs/Ugovor_DPA_<ts>.pdf/.md)
    """

    def __init__(
        self,
        output_pdf_dir: Union[str, Path] = "output/pdf",
        generated_docs_dir: Union[str, Path] = "generated_docs",
        company_profile_path: Union[str, Path] = "data/company_profile.json",
    ) -> None:
        self.output_pdf_dir = Path(output_pdf_dir)
        self.generated_docs_dir = Path(generated_docs_dir)
        self.analyzer = RiskAnalyzer(company_profile_path=company_profile_path)
        self.output_pdf_dir.mkdir(parents=True, exist_ok=True)
        self.generated_docs_dir.mkdir(parents=True, exist_ok=True)

    def _prepare_context(
        self,
        scan_data: Dict[str, Any],
        risk_data: Optional[Dict[str, Any]] = None,
        company_profile: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        analyzed = risk_data if (risk_data and "cookie_audit" in risk_data) else self.analyzer.analyze_scan(scan_data)
        profile = company_profile or analyzed.get("company_profile") or self.analyzer.load_company_profile()
        return analyzed, profile

    # ------------------------------------------------------------------------
    # SEC-A: ZAJEDNIČKE POMOĆNE METODE ZA ISCRTAVANJE TABLICA U PDF-U
    # ------------------------------------------------------------------------

    @staticmethod
    def _draw_preconsent_cookies_table_on_pdf(pdf: SentinelPDF, cookie_audit: Dict[str, Any]) -> None:
        pre_rows_data = cookie_audit.get("preconsent_table", [])
        pdf.section_heading(
            f"Tablica pronađenih Pre-Consent kolačića ({len(pre_rows_data)} prekršaja)",
            "Kolačići u nastavku postavljeni su u preglednik posjetitelja odmah pri učitavanju domene, "
            "prije nego što je korisnik dao privolu putem CMP bannera (kršenje Čl. 6. st. 1. (a) GDPR-a i ePrivacy direktive).",
        )

        if not pre_rows_data:
            pdf.set_font(pdf.font_family_name, "B", 8.5)
            pdf.set_text_color(22, 101, 52)
            pdf.multi_cell(
                182,
                5.5,
                pdf.safe_text(
                    "[USKLAĐENO] Na skeniranim podstranicama nisu pronađeni analitički ili marketinški kolačići "
                    "postavljeni prije privole korisnika."
                ),
            )
            pdf.set_text_color(30, 41, 59)
            pdf.ln(2)
            return

        headers = ["Naziv kolačića", "Kategorija", "Status privole", "Sigurnosne zastavice", "Otkriven na podstranici"]
        col_widths = [32.0, 24.0, 34.0, 44.0, 48.0]
        rows = [
            [
                c["name"],
                c["category"],
                c["status_label"],
                c["flags"],
                c["found_on_url"],
            ]
            for c in pre_rows_data
        ]
        pdf.render_structured_table(headers, col_widths, rows, highlight_col_idx=2)

    @staticmethod
    def _draw_all_cookies_table_on_pdf(pdf: SentinelPDF, cookie_audit: Dict[str, Any]) -> None:
        all_rows_data = cookie_audit.get("all_cookies_table", [])
        pdf.section_heading(
            f"Cjelovita tablica svih detektiranih kolačića ({len(all_rows_data)})",
            "Pregled svih HTTP i JavaScript kolačića pronađenih tijekom dubinskog pretraživanja domene.",
        )

        if not all_rows_data:
            pdf.set_font(pdf.font_family_name, "", 8.5)
            pdf.multi_cell(182, 5, pdf.safe_text("Tijekom skeniranja nisu detektirani aktivni kolačići."))
            pdf.ln(2)
            return

        headers = ["Naziv", "Kategorija", "Pre-Consent Status", "Trajanje / Zastavice", "Podstranica izvora"]
        col_widths = [30.0, 23.0, 34.0, 47.0, 48.0]
        rows = [
            [
                c["name"],
                c["category"],
                c["status_label"],
                f"{c['expires']} | {c['flags']}",
                c["found_on_url"],
            ]
            for c in all_rows_data
        ]
        pdf.render_structured_table(headers, col_widths, rows, highlight_col_idx=2)

    @staticmethod
    def _draw_crawled_pages_table_on_pdf(pdf: SentinelPDF, pages_audit: Dict[str, Any]) -> None:
        pages_data = pages_audit.get("pages_table", [])
        pdf.section_heading(
            f"Popis otkrivenih i skeniranih podstranica ({len(pages_data)})",
            "Rezultat višestraničnog BFS pretraživanja domene, sitemap.xml indeksa i prioritetnih pravnih ruta.",
        )

        headers = ["#", "URL otkrivene podstranice", "HTTP", "Dubina", "Kolačići", "Obrasci", "Detektirana uloga / Naslov"]
        col_widths = [8.0, 68.0, 13.0, 13.0, 15.0, 15.0, 50.0]
        rows = [
            [
                str(p["index"]),
                p["url"],
                str(p["status_code"]),
                str(p["depth"]),
                str(p["cookies_set"]),
                str(p["forms_count"]),
                f"{p['legal_role']} ({p['title']})",
            ]
            for p in pages_data
        ]
        pdf.render_structured_table(headers, col_widths, rows)

    # ------------------------------------------------------------------------
    # 1. GLAVNI REVIZIJSKI IZVJEŠTAJ: output/pdf/pregled.pdf
    # ------------------------------------------------------------------------

    def generate_audit_pdf(
        self,
        scan_data: Dict[str, Any],
        risk_data: Optional[Dict[str, Any]] = None,
        company_profile: Optional[Dict[str, Any]] = None,
        output_path: Optional[Union[str, Path]] = None,
    ) -> Path:
        analyzed, profile = self._prepare_context(scan_data, risk_data, company_profile)
        domain = analyzed["domain"]
        scan_id = analyzed["scan_id"]

        pdf = SentinelPDF(
            doc_title="Revizijski GDPR Izvještaj",
            domain_subtitle=f"Domena: {domain} | ID: {scan_id}",
        )
        pdf.alias_nb_pages()
        pdf.add_page()

        # 1. Sažetak skeniranja i ocjena
        pdf.section_heading(
            "1. Izvršni sažetak GDPR usklađenosti domene",
            f"Izvještaj dubinskog tehničkog i pravnog pregleda web sjedišta {domain}.",
        )
        cmp_info = scan_data.get("cmp_details", {}) or {}
        cmp_platforms = ", ".join(cmp_info.get("detected_cmp_platforms") or []) or (
            "Detektiran osnovni banner" if scan_data.get("has_cookie_banner") else "NIJE PRONAĐEN"
        )
        pdf.key_value_grid(
            [
                ("Skenirana domena / URL", f"{domain} ({scan_data.get('url', f'https://{domain}')})"),
                ("Ocjena usklađenosti i razina rizika", f"{analyzed['score']}/100 — {analyzed['risk_label_hr']}"),
                ("Broj otkrivenih podstranica", str(analyzed["pages_audit"]["total_pages_crawled"])),
                ("Ukupno kolačića / Pre-Consent prekršaja", f"{analyzed['cookie_audit']['total_cookies']} ukupno / {analyzed['cookie_audit']['preconsent_violations_count']} prije privole"),
                ("Cookie Banner (CMP) sustav", cmp_platforms),
                ("Gumb 'Odbij sve' u prvom sloju", "DA (Usklađeno)" if cmp_info.get("has_equal_reject_button") else "NE (Sumnja na Dark Pattern)"),
                ("SSL/TLS certifikat i HTTPS redirect", f"TLS Valjan: {'DA' if scan_data.get('https') else 'NE'} | HTTP->HTTPS: {'DA' if scan_data.get('http_to_https_redirect') else 'NE'}"),
                ("Pravila privatnosti / Politika kolačića", f"Privatnost: {analyzed['pages_audit']['legal_pages_coverage']['Pravila privatnosti']} | Kolačići: {analyzed['pages_audit']['legal_pages_coverage']['Politika kolačića']}"),
            ]
        )

        # 2. Tablica pronađenih Pre-Consent kolačića
        self._draw_preconsent_cookies_table_on_pdf(pdf, analyzed["cookie_audit"])

        # 3. Tablica svih otkrivenih podstranica
        self._draw_crawled_pages_table_on_pdf(pdf, analyzed["pages_audit"])

        # 4. Detektirani sustavi praćenja (Trackers) i prijenos u treće zemlje
        trackers = scan_data.get("trackers", []) or []
        pdf.section_heading(
            f"4. Detektirani sustavi praćenja i vanjski izvršitelji ({len(trackers)})",
            "Analiza vanjskih skripti, piksela i prijenosa osobnih podataka izvan EU/EGP (Čl. 28. i Čl. 44.-49. GDPR).",
        )
        if trackers:
            t_headers = ["Sustav / Skripta", "Izvršitelj obrade", "Država", "Rizik", "Pravna osnova / Članak", "Otkriveno na podstranicama"]
            t_widths = [32.0, 36.0, 22.0, 18.0, 32.0, 42.0]
            t_rows = [
                [
                    t.get("name", ""),
                    t.get("provider", ""),
                    t.get("country", ""),
                    t.get("risk_level", "MEDIUM"),
                    t.get("gdpr_article", "Čl. 6 GDPR"),
                    ", ".join(t.get("found_on_pages") or [domain]),
                ]
                for t in trackers
            ]
            pdf.render_structured_table(t_headers, t_widths, t_rows, highlight_col_idx=3)
        else:
            pdf.set_font(pdf.font_family_name, "", 8.5)
            pdf.multi_cell(182, 5, pdf.safe_text("Nisu pronađene poznate skripte trećih strana za praćenje."))
            pdf.ln(2)

        # 5. Utvrđene nesukladnosti i preporuke za sanaciju
        issues = analyzed.get("issues", [])
        pdf.section_heading(
            f"5. Utvrđene nesukladnosti i korektivne mjere ({len(issues)})",
            "Prioritetni popis pravnih i tehničkih nedostataka s referencama na članke GDPR uredbe.",
        )
        if issues:
            i_headers = ["Ozbiljnost", "Naziv utvrđene nesukladnosti", "Opis nalaza i tehnički dokaz", "Članak GDPR-a"]
            i_widths = [24.0, 48.0, 78.0, 32.0]
            i_rows = [
                [
                    i.get("severity", "MEDIUM"),
                    i.get("title", ""),
                    i.get("description", ""),
                    i.get("gdpr_article", "Čl. 5. i 32. GDPR"),
                ]
                for i in issues
            ]
            pdf.render_structured_table(i_headers, i_widths, i_rows, highlight_col_idx=0)

        primary_path = Path(output_path) if output_path else (self.output_pdf_dir / "pregled.pdf")
        primary_path.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(primary_path))

        # Spremi i imenovanu kopiju u generated_docs/ kao u izvornom repozitoriju
        safe_dom = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
        archive_path = self.generated_docs_dir / f"GDPR_Izvjestaj_{safe_dom}_{scan_id}.pdf"
        if archive_path.resolve() != primary_path.resolve():
            pdf.output(str(archive_path))

        logger.info("Generiran glavni GDPR izvještaj: %s i %s", primary_path, archive_path)
        return primary_path

    # ------------------------------------------------------------------------
    # 2. POLITIKA KOLAČIĆA I PRE-CONSENT AUDIT: output/pdf/kolacici.pdf
    # ------------------------------------------------------------------------

    def generate_cookie_policy_pdf(
        self,
        scan_data: Dict[str, Any],
        company_profile: Optional[Dict[str, Any]] = None,
        output_path: Optional[Union[str, Path]] = None,
    ) -> Path:
        analyzed, profile = self._prepare_context(scan_data, company_profile=company_profile)
        domain = analyzed["domain"]
        cookie_audit = analyzed["cookie_audit"]
        pages_audit = analyzed["pages_audit"]

        pdf = SentinelPDF(
            doc_title="Politika Kolačića i Pre-Consent Revizija",
            domain_subtitle=f"Domena: {domain} | Kolačića: {cookie_audit['total_cookies']}",
        )
        pdf.alias_nb_pages()
        pdf.add_page()

        pdf.section_heading(
            "1. Opće informacije o Politici kolačića i voditelju obrade",
            "Ovaj dokument objedinjuje javnu Politiku kolačića prema ePrivacy direktivi i Članku 13. GDPR-a "
            "te tehničku reviziju kolačića postavljenih prije privole (Pre-Consent Audit).",
        )
        pdf.key_value_grid(
            [
                ("Voditelj obrade", profile.get("company_name", "")),
                ("Sjedište i OIB", f"{profile.get('address', '')} | OIB: {profile.get('oib', '')}"),
                ("Kontakt za zaštitu podataka (DPO)", profile.get("email", "")),
                ("Predmetna web domena", f"{domain} ({scan_data.get('url', '')})"),
                ("Ukupno detektiranih kolačića", str(cookie_audit["total_cookies"])),
                ("Kolačići postavljeni prije privole (Pre-Consent)", f"{cookie_audit['preconsent_violations_count']} (Zahtijevaju blokadu prije privole)"),
                ("Raspodjela po kategorijama", ", ".join(f"{k}: {v}" for k, v in cookie_audit["category_counts"].items())),
            ]
        )

        # Tablica 1: Pre-consent kolačići (izravni zahtjev)
        self._draw_preconsent_cookies_table_on_pdf(pdf, cookie_audit)

        # Tablica 2: Svi kolačići na domeni
        self._draw_all_cookies_table_on_pdf(pdf, cookie_audit)

        # Tablica 3: Popis otkrivenih podstranica na kojima su skenirani kolačići
        self._draw_crawled_pages_table_on_pdf(pdf, pages_audit)

        primary_path = Path(output_path) if output_path else (self.output_pdf_dir / "kolacici.pdf")
        primary_path.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(primary_path))

        ts_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        arch_pdf = self.generated_docs_dir / f"Politika_Kolacica_{ts_str}.pdf"
        arch_md = self.generated_docs_dir / f"Politika_Kolacica_{ts_str}.md"
        if arch_pdf.resolve() != primary_path.resolve():
            pdf.output(str(arch_pdf))

        # Spremi i Markdown verziju u generated_docs/
        md_lines = [
            f"# Politika Kolačića i Pre-Consent Izvještaj — {domain}\n",
            f"- **Voditelj obrade:** {profile.get('company_name')}",
            f"- **Datum izrade:** {datetime.datetime.now().strftime('%d.%m.%Y. %H:%M')}",
            f"- **Ukupno kolačića:** {cookie_audit['total_cookies']} (Pre-consent prekršaja: {cookie_audit['preconsent_violations_count']})\n",
            "## 1. Tablica pronađenih Pre-Consent kolačića\n",
            "| Naziv kolačića | Kategorija | Status | Zastavice | Podstranica izvora |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        if cookie_audit["preconsent_table"]:
            for c in cookie_audit["preconsent_table"]:
                md_lines.append(
                    f"| `{c['name']}` | {c['category']} | **{c['status_label']}** | {c['flags']} | {c['found_on_url']} |"
                )
        else:
            md_lines.append("| *Nema pre-consent prekršaja* | - | Usklađeno | - | - |")

        md_lines.extend(
            [
                "\n## 2. Popis otkrivenih podstranica\n",
                "| # | URL podstranice | HTTP | Dubina | Kolačići | Obrasci | Pravna uloga |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for p in pages_audit["pages_table"]:
            md_lines.append(
                f"| {p['index']} | {p['url']} | {p['status_code']} | {p['depth']} | {p['cookies_set']} | {p['forms_count']} | {p['legal_role']} |"
            )
        arch_md.write_text("\n".join(md_lines), encoding="utf-8")

        return primary_path

    # ------------------------------------------------------------------------
    # 3. EVIDENCIJA AKTIVNOSTI OBRADE (ROPA): output/pdf/ropa.pdf
    # ------------------------------------------------------------------------

    def generate_ropa_pdf(
        self,
        scan_data: Dict[str, Any],
        company_profile: Optional[Dict[str, Any]] = None,
        output_path: Optional[Union[str, Path]] = None,
    ) -> Path:
        analyzed, profile = self._prepare_context(scan_data, company_profile=company_profile)
        domain = analyzed["domain"]
        ropa_entries = analyzed["ropa_entries"]
        cookie_audit = analyzed["cookie_audit"]
        pages_audit = analyzed["pages_audit"]

        pdf = SentinelPDF(
            doc_title="ROPA - Evidencija Aktivnosti Obrade (Čl. 30. GDPR)",
            domain_subtitle=f"Domena: {domain} | Aktivnosti: {len(ropa_entries)}",
        )
        pdf.alias_nb_pages()
        pdf.add_page()

        pdf.section_heading(
            "1. Podaci o voditelju obrade i opsegu ROPA evidencije (Članak 30. GDPR)",
            "Evidencija aktivnosti obrade generirana temeljem automatizirane forenzike podstranica, "
            "kolačića, web obrazaca i vanjskih izvršitelja obrade.",
        )
        pdf.key_value_grid(
            [
                ("Naziv voditelja obrade", profile.get("company_name", "")),
                ("Adresa i OIB", f"{profile.get('address', '')} | OIB: {profile.get('oib', '')}"),
                ("Službenik za zaštitu podataka (DPO)", f"{profile.get('dpo_name', '')} ({profile.get('email', '')})"),
                ("Obuhvaćena digitalna imovina", f"{domain} ({pages_audit['total_pages_crawled']} skeniranih podstranica)"),
                ("Međunarodni prijenos u SAD / treće zemlje", "DA (Detektirani vanjski servisi)" if scan_data.get("us_data_transfer_detected") else "NE (Samo EU/EGP)"),
            ]
        )

        # Tablica 1: ROPA stavke
        pdf.section_heading(
            f"2. Registar aktivnosti obrade osobnih podataka ({len(ropa_entries)} stavki)",
            "Svaka aktivnost obrade mapirana je na pravnu osnovu, kategorije podataka, rokove čuvanja i podstranice izvora.",
        )
        r_headers = ["ID", "Aktivnost i svrha obrade", "Pravna osnova", "Kategorije podataka", "Primatelj / Prijenos", "Tehničke mjere i podstranice"]
        r_widths = [14.0, 38.0, 30.0, 32.0, 30.0, 38.0]
        r_rows = [
            [
                e["activity_id"],
                f"{e['name']} - {e['purpose']}",
                e["legal_basis"],
                e["data_categories"],
                f"{e['recipients']} ({e['third_country_transfer']})",
                f"{e['security_measures']} | Izvor: {e['source_pages']}",
            ]
            for e in ropa_entries
        ]
        pdf.render_structured_table(r_headers, r_widths, r_rows)

        # Tablica 2: Pre-Consent kolačići evidentirani u ROPA-i
        self._draw_preconsent_cookies_table_on_pdf(pdf, cookie_audit)

        # Tablica 3: Popis otkrivenih podstranica uključenih u ROPA reviziju
        self._draw_crawled_pages_table_on_pdf(pdf, pages_audit)

        primary_path = Path(output_path) if output_path else (self.output_pdf_dir / "ropa.pdf")
        primary_path.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(primary_path))
        return primary_path

    # ------------------------------------------------------------------------
    # 4. PRAVILA PRIVATNOSTI: output/pdf/privatnost.pdf
    # ------------------------------------------------------------------------

    def generate_privacy_policy_pdf(
        self,
        scan_data: Dict[str, Any],
        company_profile: Optional[Dict[str, Any]] = None,
        output_path: Optional[Union[str, Path]] = None,
    ) -> Path:
        analyzed, profile = self._prepare_context(scan_data, company_profile=company_profile)
        domain = analyzed["domain"]
        cookie_audit = analyzed["cookie_audit"]
        pages_audit = analyzed["pages_audit"]

        pdf = SentinelPDF(
            doc_title="Pravila Privatnosti (Čl. 13. i 14. GDPR)",
            domain_subtitle=f"Domena: {domain}",
        )
        pdf.alias_nb_pages()
        pdf.add_page()

        pdf.section_heading(
            f"1. Pravila privatnosti i zaštite osobnih podataka — {domain}",
            "Dokument izrađen sukladno Članku 12., 13. i 14. Opće uredbe o zaštiti podataka (EU) 2016/679.",
        )
        pdf.key_value_grid(
            [
                ("Voditelj obrade", profile.get("company_name", "")),
                ("Sjedište i OIB", f"{profile.get('address', '')} | OIB: {profile.get('oib', '')}"),
                ("Kontakt službenika za zaštitu podataka", profile.get("email", "")),
                ("Nadzorno tijelo (Čl. 13. st. 2. d)", "Agencija za zaštitu osobnih podataka (AZOP), Selska cesta 136, Zagreb (azop.hr)"),
                ("Prava ispitanika (Čl. 15. - 22. GDPR)", "Pravo na pristup, ispravak, brisanje ('pravo na zaborav'), ograničenje, prenosivost i prigovor"),
            ]
        )

        self._draw_crawled_pages_table_on_pdf(pdf, pages_audit)
        self._draw_preconsent_cookies_table_on_pdf(pdf, cookie_audit)

        primary_path = Path(output_path) if output_path else (self.output_pdf_dir / "privatnost.pdf")
        primary_path.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(primary_path))

        ts_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        arch_pdf = self.generated_docs_dir / f"Pravila_Privatnosti_{ts_str}.pdf"
        arch_md = self.generated_docs_dir / f"Pravila_Privatnosti_{ts_str}.md"
        if arch_pdf.resolve() != primary_path.resolve():
            pdf.output(str(arch_pdf))
        arch_md.write_text(
            f"# Pravila Privatnosti — {domain}\n\nVoditelj obrade: {profile.get('company_name')}\nKontakt: {profile.get('email')}\n",
            encoding="utf-8",
        )
        return primary_path

    # ------------------------------------------------------------------------
    # 5. UGOVOR O OBRADI PODATAKA (DPA - ČL. 28. GDPR): output/pdf/dpa.pdf
    # ------------------------------------------------------------------------

    def generate_dpa_pdf(
        self,
        scan_data: Dict[str, Any],
        company_profile: Optional[Dict[str, Any]] = None,
        output_path: Optional[Union[str, Path]] = None,
    ) -> Path:
        analyzed, profile = self._prepare_context(scan_data, company_profile=company_profile)
        domain = analyzed["domain"]
        processors = scan_data.get("dpa_processors_required", []) or []

        pdf = SentinelPDF(
            doc_title="Ugovor o Obradi Osobnih Podataka (DPA - Čl. 28. GDPR)",
            domain_subtitle=f"Domena: {domain}",
        )
        pdf.alias_nb_pages()
        pdf.add_page()

        pdf.section_heading(
            "1. Predmet Ugovora o obradi osobnih podataka (Data Processing Agreement)",
            "Standardni ugovorni predložak prema Članku 28. GDPR-a s prilogom detektiranih podizvršitelja i podstranica.",
        )
        pdf.key_value_grid(
            [
                ("Voditelj obrade", f"{profile.get('company_name', '')}, {profile.get('address', '')}"),
                ("Predmetna web domena", domain),
                ("Detektirani vanjski izvršitelji (Čl. 28.)", str(len(processors))),
                ("Tehničke mjere sigurnosti (Čl. 32.)", f"HTTPS/TLS: {'DA' if scan_data.get('https') else 'NE'} | Sigurnosna zaglavlja: {scan_data.get('security_headers', {}).get('score_pct', 0)}%"),
            ]
        )

        if processors:
            pdf.section_heading("2. Popis detektiranih podizvršitelja obrade na domeni")
            p_headers = ["Naziv usluge / alata", "Naziv izvršitelja obrade", "Država / Mehanizam prijenosa"]
            p_widths = [55.0, 75.0, 52.0]
            p_rows = [[p.get("name", ""), p.get("provider", ""), p.get("country", "")] for p in processors]
            pdf.render_structured_table(p_headers, p_widths, p_rows)

        self._draw_crawled_pages_table_on_pdf(pdf, analyzed["pages_audit"])

        primary_path = Path(output_path) if output_path else (self.output_pdf_dir / "dpa.pdf")
        primary_path.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(primary_path))

        ts_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        arch_pdf = self.generated_docs_dir / f"Ugovor_DPA_{ts_str}.pdf"
        arch_md = self.generated_docs_dir / f"Ugovor_DPA_{ts_str}.md"
        if arch_pdf.resolve() != primary_path.resolve():
            pdf.output(str(arch_pdf))
        arch_md.write_text(
            f"# Ugovor o obradi osobnih podataka (DPA) — {domain}\n\nVoditelj obrade: {profile.get('company_name')}\n",
            encoding="utf-8",
        )
        return primary_path

    # ------------------------------------------------------------------------
    # MASOVNO GENERIRANJE SVIH PDF DOKUMENATA ZA DOMENU
    # ------------------------------------------------------------------------

    def generate_all_reports(
        self,
        scan_data: Dict[str, Any],
        company_profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        analyzed, profile = self._prepare_context(scan_data, company_profile=company_profile)
        return {
            "pregled_pdf": str(self.generate_audit_pdf(scan_data, analyzed, profile)),
            "kolacici_pdf": str(self.generate_cookie_policy_pdf(scan_data, profile)),
            "ropa_pdf": str(self.generate_ropa_pdf(scan_data, profile)),
            "privatnost_pdf": str(self.generate_privacy_policy_pdf(scan_data, profile)),
            "dpa_pdf": str(self.generate_dpa_pdf(scan_data, profile)),
        }

    # Metode za kompatibilnost s mogućim pozivima iz app.py
    def generate_document(self, doc_type: str, scan_data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> str:
        scan_payload = scan_data or kwargs.get("scan") or {"domain": kwargs.get("domain", "domena.hr")}
        dtype = (doc_type or "").lower()
        if "kolacic" in dtype or "cookie" in dtype:
            return str(self.generate_cookie_policy_pdf(scan_payload))
        if "ropa" in dtype or "evidencij" in dtype:
            return str(self.generate_ropa_pdf(scan_payload))
        if "dpa" in dtype or "ugovor" in dtype:
            return str(self.generate_dpa_pdf(scan_payload))
        if "privatnost" in dtype or "privacy" in dtype:
            return str(self.generate_privacy_policy_pdf(scan_payload))
        return str(self.generate_audit_pdf(scan_payload))


# Aliasi za potpunu kompatibilnost s postojećim modulima u repozitoriju
GDPRDocumentGenerator = DocumentGenerator
PDFGenerator = DocumentGenerator
ReportGenerator = DocumentGenerator


def generate_all_pdfs_from_latest_scan(scans_dir: Union[str, Path] = "data/scans") -> Dict[str, str]:
    scans_path = Path(scans_dir)
    json_files = sorted(scans_path.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not json_files:
        raise FileNotFoundError(f"Nema pronađenih JSON skenova u {scans_path}")
    with json_files[0].open("r", encoding="utf-8") as fh:
        latest_scan = json.load(fh)
    gen = DocumentGenerator()
    return gen.generate_all_reports(latest_scan)


if __name__ == "__main__":
    import sys

    scans_folder = Path("data/scans")
    gen = DocumentGenerator()

    if len(sys.argv) > 1 and Path(sys.argv[1]).is_file():
        with Path(sys.argv[1]).open("r", encoding="utf-8") as fh:
            scan_obj = json.load(fh)
        paths = gen.generate_all_reports(scan_obj)
        print(f"[OK] Generirani PDF izvještaji za {scan_obj.get('domain')}:")
        for k, v in paths.items():
            print(f"  - {k}: {v}")
    else:
        scan_files = sorted(scans_folder.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for sf in scan_files:
            try:
                with sf.open("r", encoding="utf-8") as fh:
                    s_data = json.load(fh)
                paths = gen.generate_all_reports(s_data)
                print(f"[OK] Domena {s_data.get('domain')} ({sf.name}) -> PDF izvještaji ažurirani.")
            except Exception as exc:
                print(f"[GREŠKA] Preskačem {sf.name}: {exc}")
