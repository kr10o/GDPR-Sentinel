import os
import json
import uuid
import re
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, Request, Form, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from apscheduler.schedulers.background import BackgroundScheduler
import uvicorn

from models import CompanyProfile, RegulatorySettings, ScanResult
from scanner import scan_domain
from risk_analyzer import analyze_gdpr_risks
from generator import generate_pdf_report, generate_document_pdf
from templates_library import get_privacy_policy_markdown, get_cookie_policy_markdown, get_dpa_markdown, get_ropa_markdown
from monitor import load_regulatory_updates, check_for_gdpr_updates, mark_update_read, SETTINGS_FILE

@asynccontextmanager
async def lifespan(app):
    configure_schedule(load_regulatory_settings())
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)

app = FastAPI(title="GDPR Sentinel", lifespan=lifespan)

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

PROFILE_FILE = str(Path(__file__).parent / "data/company_profile.json")
SCANS_DIR = str(Path(__file__).parent / "data/scans")
GENERATED_DIR = str(Path(__file__).parent / "generated_docs")

os.makedirs("data", exist_ok=True)
os.makedirs(SCANS_DIR, exist_ok=True)
os.makedirs(GENERATED_DIR, exist_ok=True)

# Helper functions for persistence
def load_company_profile() -> CompanyProfile:
    if os.path.exists(PROFILE_FILE):
        try:
            with open(PROFILE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return CompanyProfile(**data)
        except Exception:
            pass
    profile = CompanyProfile()
    save_company_profile(profile)
    return profile

def save_company_profile(profile: CompanyProfile):
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump(profile.model_dump(), f, ensure_ascii=False, indent=2)

def load_regulatory_settings() -> RegulatorySettings:
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return RegulatorySettings(**data)
        except Exception:
            pass
    settings = RegulatorySettings()
    save_regulatory_settings(settings)
    return settings

def save_regulatory_settings(settings: RegulatorySettings):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings.model_dump(), f, ensure_ascii=False, indent=2)

# Scheduler for periodic checking
scheduler = BackgroundScheduler()

def scheduled_regulatory_check():
    settings = load_regulatory_settings()
    if settings.is_active:
        print(f"[{datetime.now()}] Pokrecem periodicku provjeru ažuriranja GDPR propisa...")
        check_for_gdpr_updates()

def configure_schedule(settings):
    hours = {"hourly": 1, "daily": 24, "weekly": 168, "monthly": 720}[settings.check_frequency]
    scheduler.add_job(scheduled_regulatory_check, 'interval', hours=hours, id='gdpr_monitor', replace_existing=True)

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    profile = load_company_profile()
    settings = load_regulatory_settings()
    updates = load_regulatory_updates()
    unread_count = sum(1 for u in updates if not u.get("read", False))
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "profile": profile,
            "settings": settings,
            "updates": updates,
            "unread_count": unread_count
        }
    )

@app.post("/api/scan")
def run_scan(target_url: str = Form(...)):
    if not target_url.strip():
        raise HTTPException(status_code=400, detail="Molimo unesite domenu ili URL.")
    
    # Run scan
    try:
        raw_scan = scan_domain(target_url.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if raw_scan.get("error"):
        raise HTTPException(status_code=502, detail=raw_scan["error"])
    # Run advanced risk analysis
    risk_analysis = analyze_gdpr_risks(raw_scan)
    
    scan_id = str(uuid.uuid4())[:8]
    full_result = {
        **raw_scan,
        **risk_analysis,
        "scan_id": scan_id
    }
    
    # Save scan result
    scan_file = os.path.join(SCANS_DIR, f"{scan_id}.json")
    with open(scan_file, "w", encoding="utf-8") as f:
        json.dump(full_result, f, ensure_ascii=False, indent=2)
        
    # Generate audit PDF report immediately
    pdf_filename = f"GDPR_Izvjestaj_{full_result.get('domain', 'audit')}_{scan_id}.pdf"
    pdf_path = os.path.join(GENERATED_DIR, pdf_filename)
    generate_pdf_report(full_result, pdf_path)
    
    full_result["pdf_download_url"] = f"/download/{pdf_filename}"
    return JSONResponse(full_result)

@app.get("/api/profile")
def get_profile():
    return load_company_profile()

@app.post("/api/profile")
def update_profile(profile_data: CompanyProfile):
    save_company_profile(profile_data)
    return {"status": "success", "message": "Podaci o kompaniji uspješno spremljeni."}

@app.get("/api/regulatory/updates")
def get_updates():
    return load_regulatory_updates()

@app.post("/api/regulatory/check-now")
def trigger_check():
    updates = check_for_gdpr_updates()
    return {"status": "success", "updates": updates}

@app.post("/api/regulatory/mark-read/{update_id}")
def mark_read(update_id: str):
    mark_update_read(update_id)
    return {"status": "success"}

@app.post("/api/regulatory/settings")
def update_regulatory_settings(settings: RegulatorySettings):
    save_regulatory_settings(settings)
    configure_schedule(settings)
    return {"status": "success", "message": "Postavke pracenja i obavijesti ažurirane."}

@app.post("/api/generate-doc")
def generate_document(doc_type: str = Form(...), scan_id: str = Form(None)):
    profile = load_company_profile()
    
    detected_cookies = []
    if scan_id:
        if not re.fullmatch(r"[a-f0-9]{8}", scan_id):
            raise HTTPException(status_code=400, detail="Neispravan ID skeniranja.")
        scan_file = os.path.join(SCANS_DIR, f"{scan_id}.json")
        if os.path.exists(scan_file):
            with open(scan_file, "r", encoding="utf-8") as f:
                scan_data = json.load(f)
                detected_cookies = scan_data.get("cookies_detected", [])
    
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    
    if doc_type == "privacy_policy":
        md_content = get_privacy_policy_markdown(profile)
        base_name = f"Pravila_Privatnosti_{now_str}"
        title = "Pravila Privatnosti"
    elif doc_type == "cookie_policy":
        md_content = get_cookie_policy_markdown(profile, detected_cookies)
        base_name = f"Politika_Kolacica_{now_str}"
        title = "Politika Kolacica"
    elif doc_type == "dpa":
        md_content = get_dpa_markdown(profile)
        base_name = f"Ugovor_DPA_{now_str}"
        title = "Ugovor o Obradi Podataka (DPA)"
    elif doc_type == "ropa":
        md_content = get_ropa_markdown(profile)
        base_name = f"Evidencija_ROPA_{now_str}"
        title = "Evidencija Aktivnosti Obrade (ROPA)"
    else:
        raise HTTPException(status_code=400, detail="Nepoznat tip dokumenta.")

    # Save Markdown file
    md_filename = f"{base_name}.md"
    md_path = os.path.join(GENERATED_DIR, md_filename)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    # Save PDF file
    pdf_filename = f"{base_name}.pdf"
    pdf_path = os.path.join(GENERATED_DIR, pdf_filename)
    generate_document_pdf(md_content, pdf_path, title=title)

    return {
        "status": "success",
        "doc_type": doc_type,
        "title": title,
        "md_url": f"/download/{md_filename}",
        "pdf_url": f"/download/{pdf_filename}",
        "markdown_content": md_content
    }

@app.get("/download/{filename}")
def download_file(filename: str):
    file_path = os.path.join(GENERATED_DIR, filename)
    if Path(filename).name != filename or "\\" in filename or Path(file_path).resolve().parent != Path(GENERATED_DIR).resolve():
        raise HTTPException(status_code=400, detail="Neispravan naziv datoteke.")
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Datoteka nije pronadena.")
    return FileResponse(file_path, filename=filename)

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
