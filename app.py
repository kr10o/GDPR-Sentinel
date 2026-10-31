#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDPR Sentinel - FastAPI SaaS Backend (app.py)
Fully compatible with uvicorn, FastAPI, Jinja2, APScheduler (monitor.py),
scanner.py, risk_analyzer.py, and generator.py.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from generator import DocumentGenerator
from risk_analyzer import RiskAnalyzer
from scanner import GDPRScanner

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("gdpr_sentinel.app")

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SCANS_DIR = DATA_DIR / "scans"
OUTPUT_PDF_DIR = BASE_DIR / "output" / "pdf"
GENERATED_DOCS_DIR = BASE_DIR / "generated_docs"
COMPANY_PROFILE_PATH = DATA_DIR / "company_profile.json"
REGULATORY_UPDATES_PATH = DATA_DIR / "regulatory_updates.json"
REGULATORY_SETTINGS_PATH = DATA_DIR / "regulatory_settings.json"

for folder in (DATA_DIR, SCANS_DIR, OUTPUT_PDF_DIR, GENERATED_DOCS_DIR):
    folder.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="GDPR Sentinel SaaS",
    description="Forenzički GDPR Crawler, Analizator Rizika i Generator Dokumenata",
    version="2.0.0",
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

risk_analyzer = RiskAnalyzer(company_profile_path=COMPANY_PROFILE_PATH)
doc_generator = DocumentGenerator(
    output_pdf_dir=OUTPUT_PDF_DIR,
    generated_docs_dir=GENERATED_DOCS_DIR,
    company_profile_path=COMPANY_PROFILE_PATH,
)


# ============================================================================
# HELPER FUNCTIONS FOR LOADING & ENRICHING SCANS FROM data/scans/*.json
# ============================================================================

def _load_raw_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    clean_id = Path(scan_id).stem
    target_file = SCANS_DIR / f"{clean_id}.json"
    if not target_file.is_file():
        return None
    try:
        with target_file.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        logger.error("Failed reading scan %s: %s", target_file, exc)
        return None


def _enrich_scan_payload(raw_scan: Dict[str, Any]) -> Dict[str, Any]:
    analysis = risk_analyzer.analyze_scan(raw_scan)
    enriched = dict(raw_scan)
    enriched["id"] = raw_scan.get("id") or raw_scan.get("scan_id") or analysis["scan_id"]
    enriched["scan_id"] = enriched["id"]
    enriched["domain"] = analysis["domain"]
    enriched["score"] = analysis["score"]
    enriched["compliance_score"] = analysis["score"]
    enriched["risk_level"] = analysis["risk_level"]
    enriched["risk_label_hr"] = analysis["risk_label_hr"]
    enriched["cookie_audit"] = analysis["cookie_audit"]
    enriched["pages_audit"] = analysis["pages_audit"]
    enriched["ropa_entries"] = analysis["ropa_entries"]
    enriched["issues"] = analysis["issues"]
    enriched["recommendations"] = analysis["recommendations"]
    enriched["pdf_links"] = {
        "pregled": "/output/pdf/pregled.pdf",
        "kolacici": "/output/pdf/kolacici.pdf",
        "ropa": "/output/pdf/ropa.pdf",
        "privatnost": "/output/pdf/privatnost.pdf",
        "dpa": "/output/pdf/dpa.pdf",
    }
    return enriched


def _load_all_enriched_scans() -> List[Dict[str, Any]]:
    scans: List[Dict[str, Any]] = []
    if not SCANS_DIR.exists():
        return scans

    json_files = sorted(
        SCANS_DIR.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for jf in json_files:
        try:
            with jf.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if not isinstance(raw, dict):
                continue
            if "id" not in raw and "scan_id" not in raw:
                raw["id"] = jf.stem
            scans.append(_enrich_scan_payload(raw))
        except Exception as exc:
            logger.warning("Skipping invalid scan file %s: %s", jf, exc)

    return scans


def _load_json_file(path: Path, default: Any) -> Any:
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    return default


# ============================================================================
# WEB & REST API ROUTES
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    scans = _load_all_enriched_scans()
    company = risk_analyzer.load_company_profile()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "initial_scans": scans,
            "company_profile": company,
        },
    )


@app.get("/api/scans")
async def api_list_scans():
    scans = _load_all_enriched_scans()
    return {"status": "ok", "count": len(scans), "scans": scans}


@app.get("/api/scans/{scan_id}")
async def api_get_scan(scan_id: str):
    raw = _load_raw_scan(scan_id)
    if not raw:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "message": f"Sken '{scan_id}' nije pronađen."},
        )
    return {"status": "ok", "scan": _enrich_scan_payload(raw)}


@app.post("/api/scan")
async def api_run_scan(payload: Dict[str, Any] = Body(default={})):
    target_domain = str(payload.get("domain") or payload.get("url") or "").strip()
    if not target_domain:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Unesite domenu ili URL za skeniranje."},
        )

    max_pages = int(payload.get("max_pages", 12))
    max_depth = int(payload.get("max_depth", 2))
    scan_id = payload.get("scan_id") or None

    try:
        scanner = GDPRScanner(
            max_pages=max_pages,
            max_depth=max_depth,
            scans_dir=SCANS_DIR,
        )
        raw_report = await scanner.scan_domain_async(
            target_domain, save_to_disk=True, scan_id=scan_id
        )
        enriched = _enrich_scan_payload(raw_report)
        pdf_paths = doc_generator.generate_all_reports(raw_report)
        enriched["generated_files"] = pdf_paths
        return {
            "status": "ok",
            "message": f"Domena {enriched['domain']} uspješno skenirana ({enriched['pages_audit']['total_pages_crawled']} podstranica).",
            "scan": enriched,
        }
    except Exception as exc:
        logger.exception("Error scanning domain %s", target_domain)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Greška pri skeniranju: {exc}"},
        )


@app.post("/api/rescan-all")
async def api_rescan_all_loaded_domains(payload: Dict[str, Any] = Body(default={})):
    max_pages = int(payload.get("max_pages", 12))
    max_depth = int(payload.get("max_depth", 2))

    try:
        scanner = GDPRScanner(
            max_pages=max_pages,
            max_depth=max_depth,
            scans_dir=SCANS_DIR,
        )
        updated_reports = await scanner.rescan_loaded_domains_async(overwrite_existing_ids=True)
        enriched_list = [_enrich_scan_payload(r) for r in updated_reports]
        if updated_reports:
            doc_generator.generate_all_reports(updated_reports[0])

        return {
            "status": "ok",
            "message": f"Uspješno ponovno skenirano {len(enriched_list)} učitanih domena.",
            "count": len(enriched_list),
            "scans": enriched_list,
        }
    except Exception as exc:
        logger.exception("Error during batch rescan")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Greška pri batch skeniranju: {exc}"},
        )


@app.post("/api/generate-pdf")
@app.post("/api/generate")
async def api_generate_pdfs(payload: Dict[str, Any] = Body(default={})):
    scan_id = str(payload.get("scan_id") or payload.get("id") or "").strip()
    doc_type = str(payload.get("doc_type") or payload.get("type") or "all").strip().lower()

    raw_scan: Optional[Dict[str, Any]] = None
    if scan_id:
        raw_scan = _load_raw_scan(scan_id)
    if not raw_scan:
        all_scans = _load_all_enriched_scans()
        if all_scans:
            raw_scan = all_scans[0]

    if not raw_scan:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "message": "Nema dostupnog skena za generiranje PDF-a."},
        )

    try:
        paths = doc_generator.generate_all_reports(raw_scan)
        ts = int(datetime.datetime.now().timestamp())
        urls = {
            "pregled": f"/output/pdf/pregled.pdf?t={ts}",
            "kolacici": f"/output/pdf/kolacici.pdf?t={ts}",
            "ropa": f"/output/pdf/ropa.pdf?t={ts}",
            "privatnost": f"/output/pdf/privatnost.pdf?t={ts}",
            "dpa": f"/output/pdf/dpa.pdf?t={ts}",
        }
        selected_url = urls.get(doc_type, urls["pregled"])
        return {
            "status": "ok",
            "message": f"PDF izvještaji za domenu {raw_scan.get('domain')} su uspješno generirani.",
            "scan_id": raw_scan.get("id") or raw_scan.get("scan_id"),
            "domain": raw_scan.get("domain"),
            "pdf_url": selected_url,
            "urls": urls,
            "files": paths,
        }
    except Exception as exc:
        logger.exception("Error generating PDF reports")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Greška pri generiranju PDF-a: {exc}"},
        )


@app.get("/api/company-profile")
@app.get("/api/company")
async def api_get_company_profile():
    return {"status": "ok", "profile": risk_analyzer.load_company_profile()}


@app.post("/api/company-profile")
@app.post("/api/company")
async def api_save_company_profile(payload: Dict[str, Any] = Body(default={})):
    current = risk_analyzer.load_company_profile()
    for key in ("company_name", "address", "oib", "email", "dpo_name", "phone"):
        if key in payload:
            current[key] = str(payload[key]).strip()
    COMPANY_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with COMPANY_PROFILE_PATH.open("w", encoding="utf-8") as fh:
        json.dump(current, fh, ensure_ascii=False, indent=2)
    return {
        "status": "ok",
        "message": "Profil tvrtke uspješno spremljen.",
        "profile": current,
    }


@app.get("/api/regulatory-updates")
async def api_regulatory_updates():
    updates = _load_json_file(REGULATORY_UPDATES_PATH, [])
    settings = _load_json_file(REGULATORY_SETTINGS_PATH, {})
    return {"status": "ok", "updates": updates, "settings": settings}


@app.get("/output/pdf/{filename}")
async def serve_output_pdf(filename: str, download: Optional[str] = Query(default=None)):
    file_path = OUTPUT_PDF_DIR / Path(filename).name
    if not file_path.is_file():
        scans = _load_all_enriched_scans()
        if scans:
            doc_generator.generate_all_reports(scans[0])
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="PDF dokument nije pronađen.")

    disposition = "attachment" if download == "1" else "inline"
    return FileResponse(
        path=str(file_path),
        media_type="application/pdf",
        filename=file_path.name if download == "1" else None,
        headers={"Content-Disposition": f'{disposition}; filename="{file_path.name}"'},
    )


@app.get("/generated_docs/{filename}")
async def serve_generated_docs(filename: str, download: Optional[str] = Query(default=None)):
    file_path = GENERATED_DOCS_DIR / Path(filename).name
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Dokument nije pronađen.")

    media_type = "application/pdf" if file_path.suffix.lower() == ".pdf" else "text/markdown; charset=utf-8"
    disposition = "attachment" if download == "1" else "inline"
    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=file_path.name if download == "1" else None,
        headers={"Content-Disposition": f'{disposition}; filename="{file_path.name}"'},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="127.0.0.1", port=port, reload=True)
