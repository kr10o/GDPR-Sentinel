from datetime import datetime
from models import CompanyProfile

def get_privacy_policy_markdown(profile: CompanyProfile, scan_info: dict = None) -> str:
    now_date = datetime.now().strftime("%d.%m.%Y.")
    purposes_str = "\n".join([f"- {p}" for p in profile.data_purposes])
    third_parties_str = "\n".join([f"- {tp}" for tp in profile.third_parties])
    security_str = "\n".join([f"- {sec}" for sec in profile.security_measures])
    
    dpo_info = f"**Službenik za zaštitu podataka (DPO):** {profile.dpo_name} ({profile.dpo_email})" if profile.dpo_name else "Službenik za zaštitu podataka nije obvezno imenovan, no za sva pitanja dostupan je naš kontakt tim."

    return f"""# Pravila privatnosti (Privacy Policy)

**Voditelj obrade:** {profile.name}  
**Identifikacijski broj / OIB:** {profile.id_number}  
**Sjedište i adresa:** {profile.address}  
**E-pošta:** {profile.email} | **Telefon:** {profile.phone}  
**Web stranica:** {profile.website}  
**Datum posljednjeg ažuriranja:** {now_date}  

---

## 1. Uvod i Temeljna Nacela
Tvrtka **{profile.name}** posvecena je zaštiti Vaših osobnih podataka u skladu s Uredbom (EU) 2016/679 Europskog parlamenta i Vijeca (Opca uredba o zaštiti podataka - GDPR) i važecim nacionalnim zakonodavstvom. Ova Pravila privatnosti opisuju koje podatke prikupljamo, u koje svrhe, na kojim pravnim osnovama te koja su Vaša prava kao ispitanika.

{dpo_info}

## 2. Svrhe Obrade i Pravni Temelji
Osobne podatke obradujemo zakonito, pošteno i transparentno, iskljucivo u sljedece svrhe:
{purposes_str}

**Pravni temelji za obradu (Clanak 6. GDPR):**
- **Izvršavanje ugovora:** Obrada je nužna radi pružanja zatraženih usluga ili isporuke proizvoda.
- **Pravna obveza:** Obrada radi uskladenosti s poreznim, racunovodstvenim i pravnim propisima.
- **Privola (Pristanak):** Za primanje marketinških obavijesti ili postavljanje ne-nužnih analitickih kolacica.
- **Legitimni interes:** Zaštita integriteta naših IT sustava, sprjecavanje prijevara i optimizacija poslovanja.

## 3. Primatelji Podataka i Trece Strane
Vaši se podaci ne prodaju niti neovlašteno ustupaju trecim stranama. Pristup podacima omogucen je samo pouzdanim izvršiteljima obrade pod strogim ugovornim obvezama:
{third_parties_str}

Svi pružatelji usluga izvan Europskog gospodarskog prostora (EGP) obvezni su primjenjivati Standardne ugovorne klauzule (SCC) ili poslovati pod priznatim okvirima (npr. Data Privacy Framework).

## 4. Razdoblje Cuvanja Podataka
Osobni podaci pohranjuju se samo onoliko dugo koliko je nužno za ostvarenje svrhe za koju su prikupljeni:
- {profile.data_retention_period}.
- Podaci prikupljeni temeljem privole cuvaju se do trenutka povlacenja privole.

## 5. Tehnicke i Organizacijske Mjere Sigurnosti (Clanak 32. GDPR)
Kako bismo sprijecili slucajan ili nezakonit gubitak, izmjenu ili neovlašten pristup, primjenjujemo visoke sigurnosne standarde:
{security_str}

## 6. Prava Ispitanika
Sukladno GDPR-u, u svakom trenutku imate sljedeca prava:
1. **Pravo na pristup:** Pravo dobiti potvrdu o tome obraduju li se Vaši podaci te kopiju tih podataka.
2. **Pravo na ispravak:** Ispravak netocnih ili dopunu nepotpunih podataka.
3. **Pravo na brisanje ("pravo na zaborav"):** Brisanje ako podaci više nisu nužni ili povucete privolu.
4. **Pravo na ogranicenje obrade:** Privremeno zaustavljanje obrade u spornim slucajevima.
5. **Pravo na prenosivost podataka:** Prijenos podataka u strukturiranom, uobicajenom formatu drugom voditelju obrade.
6. **Pravo na prigovor:** Prigovor na obradu temeljenu na legitimnom interesu ili izravnom marketingu.
7. **Pravo na povlacenje privole:** U bilo kojem trenutku, bez utjecaja na zakonitost obrade prije povlacenja.

Za ostvarivanje bilo kojeg od navedenih prava, kontaktirajte nas putem e-pošte: {profile.email}. Takoder imate pravo podnijeti pritužbu nadležnom nadzornom tijelu za zaštitu podataka (Agencija za zaštitu osobnih podataka - AZOP).
"""

def get_cookie_policy_markdown(profile: CompanyProfile, detected_cookies: list = None) -> str:
    now_date = datetime.now().strftime("%d.%m.%Y.")
    cookies_rows = ""
    if detected_cookies:
        for c in detected_cookies:
            sec_badge = "Da (Siguran)" if c.get('secure') else "Ne"
            cookies_rows += f"| {c.get('name')} | {c.get('domain')} | {c.get('path')} | {sec_badge} | Neophodan / Analiticki |\n"
    else:
        cookies_rows = "| session_id | {profile.website} | / | Da | Neophodan za rad sesije |\n| cookie_consent | {profile.website} | / | Da | Pohrana odabira privole posjetitelja |\n"

    return f"""# Politika Kolacica (Cookie Policy)

**Web stranica:** {profile.website}  
**Voditelj obrade:** {profile.name}  
**Datum stupanja na snagu:** {now_date}  

---

## 1. Što su kolacici (Cookies)?
Kolacic je mala tekstualna datoteka koju web poslužitelj pohranjuje na Vaše racunalo ili mobilni uredaj prilikom posjeta stranici. Kolacici omogucuju web stranici da zapamti Vaše postavke, sesije i nacin korištenja stranice kroz odredeno razdoblje.

## 2. Vrste kolacica koje koristimo

### a) Nužni (Tehnicki) kolacici
Ovi kolacici neophodni su za osnovno funkcioniranje web stranice, sigurnost i navigaciju. Za njihovo postavljanje nije potrebna prethodna privola (sukladno ePrivacy direktivi).

### b) Funkcionalni i preferencijalni kolacici
Omogucuju pamcenje odabira poput jezika ili regije.

### c) Analiticki i statisticki kolacici
Pomažu nam razumjeti kako posjetitelji stupaju u interakciju sa stranicom kako bismo poboljšali korisnicko iskustvo. Ovi se kolacici postavljaju iskljucivo uz Vašu izricitu privolu.

### d) Marketinški kolacici
Koriste se za pracenje korisnika kroz web stranice u svrhu prikazivanja relevantnih oglasa. Postavljaju se iskljucivo uz Vašu prethodnu privolu.

---

## 3. Popis kolacica na domeni {profile.website}

| Naziv kolacica | Domena | Putanja | Siguran (Secure) | Svrha / Tip |
| :--- | :--- | :--- | :--- | :--- |
{cookies_rows}

---

## 4. Kako upravljati kolacicima i povuci privolu?
U svakom trenutku možete promijeniti ili povuci svoju privolu za kolacice putem postavki na našem Cookie banneru ili unutar postavki Vašeg internetskog preglednika (Google Chrome, Mozilla Firefox, Safari, Edge). 

Brisanje ili blokiranje svih kolacica može utjecati na funkcionalnost i prikaz pojedinih dijelova naše web stranice.

Za sva pitanja obratite se na: {profile.email}.
"""

def get_dpa_markdown(profile: CompanyProfile) -> str:
    now_date = datetime.now().strftime("%d.%m.%Y.")
    return f"""# Ugovor o Obradi Podataka (Data Processing Agreement - DPA)
**U skladu s Clankom 28. Opce uredbe o zaštiti podataka (GDPR)**

**Sklopljen dana:** {now_date}  

**Izmedu ugovornih strana:**

1. **Voditelj obrade (Controller):**  
   **Naziv:** {profile.name}  
   **OIB/ID:** {profile.id_number}  
   **Adresa:** {profile.address}  
   **Predstavnik:** {profile.dpo_name if profile.dpo_name else profile.name}  
   *(u daljnjem tekstu: Voditelj obrade)*  

i  

2. **Izvršitelj obrade (Processor):**  
   **Naziv:** [Naziv Izvršitelja / Pružatelja usluge]  
   **Sjedište:** [Adresa Izvršitelja]  
   *(u daljnjem tekstu: Izvršitelj obrade)*  

---

### Clanak 1. Predmet i Trajanje Ugovora
Izvršitelj obrade obvezuje se u ime i za racun Voditelja obrade obradivati osobne podatke iskljucivo u svrhu pružanja ugovorenih usluga definiranih Glavnim ugovorom.

### Clanak 2. Obveze Izvršitelja obrade (Clanak 28. st. 3. GDPR)
Izvršitelj obrade se obvezuje:
1. Obradivati osobne podatke iskljucivo prema dokumentiranim uputama Voditelja obrade;
2. Osigurati da su se sve osobe ovlaštene za obradu osobnih podataka obvezale na povjerljivost;
3. Poduzeti sve mjere propisane Clankom 32. GDPR-a (sigurnost obrade);
4. Ne angažirati drugog izvršitelja obrade (podizvršitelja) bez prethodnog posebnog ili opceg pisanog odobrenja Voditelja obrade;
5. Pomagati Voditelju obrade pri ispunjavanju obveza odgovora na zahtjeve za ostvarivanje prava ispitanika;
6. Odmah obavijestiti Voditelja obrade o svakoj povredi osobnih podataka bez nepotrebnog odgadanja;
7. Po završetku pružanja usluga, po izboru Voditelja obrade, izbrisati ili vratiti sve osobne podatke;
8. Omoguciti Voditelju obrade revizije i inspekcije radi utvrdivanja uskladenosti.

### Clanak 3. Završne Odredbe
Ovaj Ugovor stupa na snagu danom potpisa obiju strana i važi sve dok Izvršitelj obraduje podatke u ime Voditelja.
"""


def get_ropa_markdown(profile: CompanyProfile) -> str:
    now_date = datetime.now().strftime("%d.%m.%Y.")
    purposes_rows = ""
    for idx, p in enumerate(profile.data_purposes, 1):
        purposes_rows += f"| {idx} | {p} | Klijenti / Korisnici | Ime, E-mail, Telefon, IP adresa | Izvrsenje ugovora / Zakonska obveza | {profile.data_retention_period} | Sigurnosne kopije, TLS enkripcija |\n"

    return f"""# Evidencija Aktivnosti Obrade (ROPA)
**Prema Clanku 30. Opce uredbe o zastiti podataka (GDPR)**

**Datum evidencije:** {now_date}  
**Voditelj obrade:** {profile.name}  
**OIB / Identifikator:** {profile.id_number}  
**Sjediste:** {profile.address}  
**Kontakt:** {profile.email}  
**Sluzbenik za zastitu podataka (DPO):** {profile.dpo_name if profile.dpo_name else 'Nije obvezno imenovan'} ({profile.dpo_email if profile.dpo_email else 'N/A'})  

---

## 1. Registar Evidencije Obrada (Clanak 30. st. 1. GDPR)

| R.br. | Svrha Obrade | Kategorija Ispitanika | Kategorija Osobnih Podataka | Pravni Temelj | Rok Cuvanja | Tehnicke Mjere Zastite |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
{purposes_rows}

---

## 2. Prijenos Podataka u Trece Zemlje (Clanak 30. st. 1. t. (e))
Prijenos podataka izvan EU/EGP provodi se iskljucivo uz primjenu odgovarajucih zastitnih mjera:
- Standardne ugovorne klauzule Europske komisije (SCC)
- EU-U.S. Data Privacy Framework

## 3. Opci Opis Tehnickih i Organizacijskih Mjera Sigurnosti (Clanak 30. st. 1. t. (g))
- Kriptografska zastita u prijenosu (TLS/SSL) i pohrani.
- Redovito testiranje, ocjenjivanje i procjena ucinkovitosti tehnickih mjera.
- Segmentacija pristupa podacima na temelju nacela "need-to-know".
"""

