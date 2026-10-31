import json
import os
import hashlib
from urllib.parse import urljoin
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import requests
from bs4 import BeautifulSoup

NOTIFICATIONS_FILE = str(Path(__file__).parent / "data/regulatory_updates.json")
SETTINGS_FILE = str(Path(__file__).parent / "data/regulatory_settings.json")

DEFAULT_UPDATES = []
def load_regulatory_updates() -> List[Dict[str, Any]]:
    if not os.path.exists(NOTIFICATIONS_FILE):
        os.makedirs(os.path.dirname(NOTIFICATIONS_FILE), exist_ok=True)
        with open(NOTIFICATIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_UPDATES, f, ensure_ascii=False, indent=2)
        return DEFAULT_UPDATES
    
    try:
        with open(NOTIFICATIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_UPDATES

def save_regulatory_updates(updates: List[Dict[str, Any]]):
    os.makedirs(os.path.dirname(NOTIFICATIONS_FILE), exist_ok=True)
    with open(NOTIFICATIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(updates, f, ensure_ascii=False, indent=2)

def check_for_gdpr_updates() -> List[Dict[str, Any]]:
    """
    Provjerava službene izvore i dodaje eventualne nove regulative.
    Ukljucuje provjeru i simulaciju novih objava sa službenih izvora (EDPB / EUR-Lex).
    """
    current_updates = load_regulatory_updates()
    new_found = []

    # Provjera web izvora (EDPB news / press releases)
    try:
        res = requests.get("https://edpb.europa.eu/news/news_en", timeout=8)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, "html.parser")
            # Traženje najnovijih vijesti
            items = soup.find_all("div", class_="views-row")[:3]
            for item in items:
                title_tag = item.find("h3") or item.find("h2") or item.find("a")
                if title_tag:
                    title_text = title_tag.get_text(strip=True)
                    # Provjeri postoji li vec
                    if not any(u["title"] == title_text for u in current_updates):
                        item_id = "EDPB-" + hashlib.sha256(title_text.encode()).hexdigest()[:12]
                        new_item = {
                            "id": item_id,
                            "date": datetime.now().strftime("%Y-%m-%d"),
                            "source": "EDPB Službeni Izvor",
                            "title": title_text,
                            "summary": "Identificirano novo službeno priopcenje / smjernica Europskog odbora za zaštitu podataka.",
                            "impact_level": "Srednji",
                            "url": urljoin("https://edpb.europa.eu", (item.find("a", href=True) or {}).get("href", "/news/news_en")),
                            "read": False
                        }
                        current_updates.insert(0, new_item)
                        new_found.append(new_item)
    except Exception as e:
        print(f"Napomena kod dohvacanja online izvora: {e}")

    if new_found:
        save_regulatory_updates(current_updates)
    
    return current_updates

def mark_update_read(update_id: str):
    updates = load_regulatory_updates()
    for u in updates:
        if u["id"] == update_id:
            u["read"] = True
            break
    save_regulatory_updates(updates)
