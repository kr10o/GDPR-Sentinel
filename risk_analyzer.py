from typing import Dict, Any, List
from models import RiskItem

def analyze_gdpr_risks(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    risks: List[Dict[str, Any]] = []
    
    # 1. SSL / TLS Enkripcija (Clanak 32 GDPR - Sigurnost obrade)
    if not scan_data.get("ssl_valid", False):
        risks.append({
            "id": "RISK_SSL_01",
            "category": "Sigurnost i Enkripcija",
            "title": "Nepostojeci ili nevaljan SSL/TLS certifikat",
            "description": "Podaci koji se prenose izmedu korisnika i poslužitelja nisu kriptirani, što omogucuje presretanje osobnih podataka (Man-in-the-Middle napadi).",
            "risk_level": "Visok",
            "impact": "Visok",
            "probability": "Visoka",
            "gdpr_article": "Clanak 32. (Sigurnost obrade osobnih podataka)",
            "recommendation": "Instalirajte i ispravno konfigurirajte TLS certifikat (npr. Let's Encrypt) te prisilno preusmjerite sav promet na HTTPS."
        })

    # 2. Pravila privatnosti (Clanak 12., 13. i 14. GDPR - Nacelo transparentnosti)
    if not scan_data.get("privacy_policy_found", False):
        risks.append({
            "id": "RISK_PRIVACY_01",
            "category": "Transparentnost i Informiranje",
            "title": "Nisu pronadena Pravila privatnosti (Privacy Policy)",
            "description": "Na web stranici nije pronadena lako dostupna poveznica na dokument o privatnosti kojim se posjetitelji informiraju o prikupljanju podataka.",
            "risk_level": "Visok",
            "impact": "Visok",
            "probability": "Visoka",
            "gdpr_article": "Clanci 12., 13. i 14. (Transparentne informacije i komunikacija)",
            "recommendation": "Objavite detaljna Pravila privatnosti na vidljivom mjestu (npr. u podnožju stranice) s navedenim svrhama obrade, pravnim temeljima i pravima ispitanika."
        })

    # 3. Cookie Banner i privola (Clanak 7. GDPR i Direktiva o e-privatnosti)
    cookies = scan_data.get("cookies_detected", [])
    cookie_banner = scan_data.get("cookie_banner_found", False)
    
    if cookies and not cookie_banner:
        risks.append({
            "id": "RISK_COOKIE_01",
            "category": "Kolacici i Pracenje",
            "title": "Kolacici se postavljaju bez prethodne privole (Consent)",
            "description": f"Detektirano je {len(cookies)} kolacica pri prvom posjetu bez prikazanog bannera za privolu. Ne-esencijalni kolacici zahtijevaju eksplicitan pristanak.",
            "risk_level": "Visok",
            "impact": "Visok",
            "probability": "Srednja",
            "gdpr_article": "Clanak 7. (Uvjeti privole) i Direktiva 2002/58/EZ (ePrivacy)",
            "recommendation": "Implementirajte CMP (Consent Management Platform) koji blokira sve kolacice osim nužnih dok korisnik ne klikne 'Prihvati'."
        })
    elif not cookie_banner and scan_data.get("trackers_detected"):
        risks.append({
            "id": "RISK_COOKIE_02",
            "category": "Kolacici i Pracenje",
            "title": "Vanjski trackeri su aktivni bez mehanizma privole",
            "description": "Stranica ucitava skripte za pracenje prije nego što posjetitelj uopce ima priliku dati izricitu privolu.",
            "risk_level": "Visok",
            "impact": "Visok",
            "probability": "Visoka",
            "gdpr_article": "Clanak 6. st. 1. t. (a) i Clanak 7. GDPR",
            "recommendation": "Sprijecite automatsko ucitavanje Google Analyticsa, Meta Pixela ili slicnih skripti dok korisnik ne potvrdi privolu."
        })

    # 4. Third-party trackers i prijenos u trece zemlje (Clanci 44.-49. GDPR)
    trackers = scan_data.get("trackers_detected", [])
    if trackers:
        us_trackers = [t for t in trackers if any(w in t.lower() for w in ["google", "meta", "facebook", "hubspot", "linkedin"])]
        if us_trackers:
            risks.append({
                "id": "RISK_TRANSFER_01",
                "category": "Prijenos u Trece Zemlje",
                "title": f"Moguci prijenos podataka pružateljima u SAD ({', '.join(us_trackers)})",
                "description": "Korištenje servisa poput Google Analytics ili Meta Pixel može ukljucivati slanje IP adresa i identifikatora izvan EGP-a.",
                "risk_level": "Srednji",
                "impact": "Srednji",
                "probability": "Srednja",
                "gdpr_article": "Poglavlje V (Clanci 44.-49. - Prijenos osobnih podataka trecim zemljama)",
                "recommendation": "Osigurajte sklopljen DPA (Data Processing Addendum) s ugovornim klauzulama (SCCs) i provjerite uskladenost s EU-US Data Privacy Frameworkom."
            })

    # 5. Forme bez eksplicitnog pristanka (Clanak 6. i 7. GDPR)
    forms = scan_data.get("forms_detected", [])
    unprotected_forms = [f for f in forms if f.get("has_email_or_user_data") and not f.get("has_consent_checkbox")]
    if unprotected_forms:
        risks.append({
            "id": "RISK_FORM_01",
            "category": "Obrasci i Prikupljanje Podataka",
            "title": "Obrasci za unos podataka nemaju jasnu poveznicu na privolu/pravila",
            "description": f"Pronadeno je {len(unprotected_forms)} obrazaca koji prikupljaju osobne podatke (npr. e-mail) bez jasne izjave o privoli ili linka na Pravila privatnosti.",
            "risk_level": "Srednji",
            "impact": "Srednji",
            "probability": "Srednja",
            "gdpr_article": "Clanak 6. (Zakonitost obrade) i Clanak 13.",
            "recommendation": "Dodajte kratku napomenu ispod obrasca s poveznicom na Pravila privatnosti i po potrebi checkbox za specificne privole (npr. newsletter)."
        })

    # 6. Nedostatak sigurnosnih zaglavlja (Security Headers - HSTS, CSP)
    sec_headers = scan_data.get("security_headers", {})
    if not sec_headers.get("Strict-Transport-Security"):
        risks.append({
            "id": "RISK_HEADER_01",
            "category": "Sigurnost i Enkripcija",
            "title": "Nedostaje HSTS zaglavlje (Strict-Transport-Security)",
            "description": "Preglednici nisu prisiljeni uvijek koristiti HTTPS vezu, što otvara mogucnost SSL stripping napada.",
            "risk_level": "Nizak",
            "impact": "Srednji",
            "probability": "Niska",
            "gdpr_article": "Clanak 32. (Tehnicke i organizacijske mjere zaštite)",
            "recommendation": "Omogucite HTTP Strict Transport Security (HSTS) na web poslužitelju s minimalnim trajanjem od 6 mjeseci."
        })

    if not sec_headers.get("Content-Security-Policy"):
        risks.append({
            "id": "RISK_HEADER_02",
            "category": "Sigurnost i Enkripcija",
            "title": "Nedostaje Content-Security-Policy (CSP) zaglavlje",
            "description": "Nedostatak CSP zaglavlja povecava ranjivost stranice na Cross-Site Scripting (XSS) napade koji mogu kompromitirati podatke korisnika.",
            "risk_level": "Nizak",
            "impact": "Srednji",
            "probability": "Niska",
            "gdpr_article": "Clanak 32. st. 1. t. (b) (Sposobnost osiguravanja povjerljivosti)",
            "recommendation": "Definirajte restriktivno Content-Security-Policy zaglavlje koje dozvoljava ucitavanje skripti samo s provjerenih domena."
        })

    # Izracun bodova uskladenosti (Compliance Score)
    total_deduction = 0
    high_count = sum(1 for r in risks if r["risk_level"] == "Visok")
    med_count = sum(1 for r in risks if r["risk_level"] == "Srednji")
    low_count = sum(1 for r in risks if r["risk_level"] == "Nizak")

    total_deduction += high_count * 25
    total_deduction += med_count * 10
    total_deduction += low_count * 5

    compliance_score = max(0, 100 - total_deduction)

    return {
        "risks": risks,
        "compliance_score": compliance_score,
        "summary": {
            "high": high_count,
            "medium": med_count,
            "low": low_count,
            "total": len(risks)
        }
    }
