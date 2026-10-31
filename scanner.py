import re
import socket
import ssl
import urllib.parse
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List

KNOWN_TRACKERS = {
    "Google Analytics / GTM": [r"google-analytics\.com", r"googletagmanager\.com", r"gtag/js", r"ga\("],
    "Meta / Facebook Pixel": [r"connect\.facebook\.net", r"fbevents\.js", r"fbq\("],
    "Hotjar": [r"static\.hotjar\.com", r"_hjSettings"],
    "TikTok Pixel": [r"analytics\.tiktok\.com"],
    "LinkedIn Insight": [r"snap\.licdn\.com", r"_linkedin_partner_id"],
    "Yandex Metrica": [r"mc\.yandex\.ru", r"metrika/watch"],
    "Crazy Egg": [r"crazyegg\.com"],
    "HubSpot Analytics": [r"js\.hs-scripts\.com", r"js\.hs-analytics\.net"]
}

COOKIE_BANNER_SIGNATURES = [
    "cookie", "privola", "pristanak", "consent", "gdpr", "privatnost", "accept-cookies", 
    "cookie-banner", "cookie-notice", "cookieconsent", "complianz", "onetrust", "cookiebot", "klaro"
]

PRIVACY_POLICY_KEYWORDS = [
    "privacy", "privatnost", "pravila-privatnosti", "politika-privatnosti", 
    "privacy-policy", "datenschutz", "politique-de-confidentialite"
]

def check_ssl(domain: str) -> Dict[str, Any]:
    context = ssl.create_default_context()
    try:
        clean_domain = domain.split(":")[0]
        with socket.create_connection((clean_domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                # Check expiration
                not_after_str = cert.get('notAfter', '')
                return {
                    "valid": True,
                    "details": f"Valjan SSL certifikat (Istjece: {not_after_str})",
                    "cert": cert
                }
    except Exception as e:
        return {
            "valid": False,
            "details": f"Neuspješna SSL/TLS verifikacija: {str(e)}",
            "cert": None
        }

def scan_domain(target_url: str) -> Dict[str, Any]:
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Unesite valjanu HTTP ili HTTPS adresu bez pristupnih podataka.')
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('Neispravan port u adresi.') from exc
    domain = parsed.hostname

    ssl_status = check_ssl(domain)

    # HTTP requests with session to inspect cookies
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GDPR-Compliance-Auditor/1.0"
    })

    cookies_found = []
    trackers_found = []
    forms_found = []
    security_headers = {}
    privacy_policy_found = False
    privacy_policy_url = None
    cookie_banner_found = False
    html_content = ""

    try:
        response = session.get(target_url, timeout=10, allow_redirects=True)
        response.raise_for_status()
        final_url = response.url
        html_content = response.text
        headers = response.headers

        # Check security headers
        for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"]:
            security_headers[h] = headers.get(h, None)

        # Inspect initial cookies set without prior consent
        for c in session.cookies:
            cookies_found.append({
                "name": c.name,
                "domain": c.domain,
                "path": c.path,
                "secure": c.secure,
                "httponly": any(key.lower() == 'httponly' for key in c._rest),
                "samesite": c._rest.get('samesite', 'Not specified'),
                "value_sample": (c.value[:10] + '...') if len(c.value) > 10 else c.value
            })

        soup = BeautifulSoup(html_content, "html.parser")

        # 1. Search for Privacy Policy link
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].lower()
            text = a_tag.get_text().lower()
            for kw in PRIVACY_POLICY_KEYWORDS:
                if kw in href or kw in text:
                    privacy_policy_found = True
                    privacy_policy_url = urllib.parse.urljoin(final_url, a_tag["href"])
                    break
            if privacy_policy_found:
                break

        # 2. Search for Cookie Banner / Consent elements
        # Search HTML ids and classes
        for tag in soup.find_all(["div", "section", "aside", "dialog", "footer", "span"]):
            tag_id = (tag.get("id") or "").lower()
            tag_classes = " ".join(tag.get("class") or []).lower()
            for sig in COOKIE_BANNER_SIGNATURES:
                if sig in tag_id or sig in tag_classes:
                    cookie_banner_found = True
                    break
            if cookie_banner_found:
                break

        # Also search in scripts
        if not cookie_banner_found:
            for s in soup.find_all("script"):
                src = (s.get("src") or "").lower()
                inline = (s.string or "").lower()
                for sig in ["cookiebot", "onetrust", "klaro", "complianz", "cookieconsent", "iubenda", "didomi"]:
                    if sig in src or sig in inline:
                        cookie_banner_found = True
                        break
                if cookie_banner_found:
                    break

        # 3. Search for third party trackers
        for tracker_name, patterns in KNOWN_TRACKERS.items():
            found = False
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    found = True
                    break
            if found:
                trackers_found.append(tracker_name)

        # 4. Search for Forms & Consent checkboxes
        for form in soup.find_all("form"):
            action = form.get("action", "")
            inputs = form.find_all("input")
            has_email = any(i.get("type") == "email" or "email" in (i.get("name") or "").lower() for i in inputs)
            has_consent_checkbox = False
            for i in inputs:
                if i.get("type") == "checkbox":
                    parent_text = form.get_text().lower()
                    if any(w in parent_text for w in ["slažem", "privola", "uvjeti", "politika", "pristanak", "agree", "consent", "terms"]):
                        has_consent_checkbox = True
                        break

            forms_found.append({
                "action": action,
                "has_email_or_user_data": has_email,
                "has_consent_checkbox": has_consent_checkbox,
                "input_count": len(inputs)
            })

    except Exception as e:
        session.close()
        # Report failures without producing misleading risk scores
        return {
            "error": f"Greška prilikom povezivanja na stranicu: {str(e)}",
            "url": target_url,
            "domain": domain,
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ssl_valid": ssl_status["valid"],
            "ssl_details": ssl_status["details"],
            "privacy_policy_found": False,
            "cookie_banner_found": False,
            "cookies_detected": [],
            "trackers_detected": [],
            "forms_detected": [],
            "security_headers": {}
        }

    session.close()
    return {
        "url": target_url,
        "domain": domain,
        "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ssl_valid": ssl_status["valid"],
        "ssl_details": ssl_status["details"],
        "privacy_policy_found": privacy_policy_found,
        "privacy_policy_url": privacy_policy_url,
        "cookie_banner_found": cookie_banner_found,
        "cookies_detected": cookies_found,
        "trackers_detected": trackers_found,
        "forms_detected": forms_found,
        "security_headers": security_headers
    }
