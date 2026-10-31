from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal

class CompanyProfile(BaseModel):
    name: str = "Primjer d.o.o."
    id_number: str = "HR12345678901" # OIB / PDV ID
    address: str = "Ilica 100, 10000 Zagreb, Hrvatska"
    email: str = "kontakt@primjer.hr"
    phone: str = "+385 1 2345 678"
    website: str = "https://primjer.hr"
    dpo_name: Optional[str] = "Marko Horvat"
    dpo_email: Optional[str] = "dpo@primjer.hr"
    data_purposes: List[str] = [
        "Pružanje usluga i ispunjenje ugovornih obveza",
        "Korisnicka podrška i komunikacija",
        "Izdavanje racuna i zakonsko knjigovodstvo",
        "Poboljšanje funkcionalnosti web stranice i statistika"
    ]
    data_retention_period: str = "5 godina sukladno važecim racunovodstvenim propisima"
    third_parties: List[str] = [
        "Hosting pružatelji (EU serveri)",
        "Racunovodstveni servis",
        "Analiticki servisi uz privolu korisnika"
    ]
    security_measures: List[str] = [
        "TLS/SSL enkripcija u prijenosu podataka",
        "Redovite sigurnosne kopije (backup)",
        "Kontrola pristupa i autentifikacija s više faktora"
    ]

class RegulatorySettings(BaseModel):
    check_frequency: Literal["hourly", "daily", "weekly", "monthly"] = "weekly"  # hourly, daily, weekly, monthly
    notification_type: Literal["in_app", "email", "both"] = "in_app"  # in_app, email, both
    notification_email: str = "compliance@primjer.hr"
    is_active: bool = True

class RiskItem(BaseModel):
    id: str
    category: str
    title: str
    description: str
    risk_level: str  # 'Visok', 'Srednji', 'Nizak'
    impact: str      # 'Visok', 'Srednji', 'Nizak'
    probability: str # 'Visoka', 'Srednja', 'Niska'
    gdpr_article: str
    recommendation: str

class ScanResult(BaseModel):
    url: str
    domain: str
    scan_timestamp: str
    compliance_score: int
    ssl_valid: bool
    ssl_details: str
    privacy_policy_found: bool
    privacy_policy_url: Optional[str] = None
    cookie_banner_found: bool
    cookies_detected: List[Dict[str, Any]] = []
    trackers_detected: List[str] = []
    forms_detected: List[Dict[str, Any]] = []
    security_headers: Dict[str, Any] = {}
    risks: List[RiskItem] = []
    summary: Dict[str, int] = {"high": 0, "medium": 0, "low": 0, "total": 0}
