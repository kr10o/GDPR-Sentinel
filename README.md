# GDPR Sentinel

Lokalna FastAPI aplikacija za tehnički pregled web stranica i pripremu GDPR predložaka.

## Pokretanje

    .venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000

Ovisnosti: `pip install -r requirements.txt`.

## Struktura

- `templates/index.html`: hrvatsko sučelje, Hero, CTA, skener, dokumenti, profil i objave.
- `static/app.css`: bijeli glassmorphism s mint, lavanda i breskva naglascima.
- `static/app.js`: navigacija, API zahtjevi i prikaz nalaza.
- `generator.py`: zajednički PDF stil, Unicode fontovi, sigurno formatiranje i tablice.
- `tests/test_regressions.py`: provjere pogrešaka skeniranja, putanja, PDF teksta i rasporeda.

Pokretanje provjera: `.venv\Scripts\python.exe -m unittest discover -s tests -v`.

## Opseg

Skener čita javni HTML i HTTP kolačiće; ne izvršava JavaScript i ne testira stvarno ponašanje privole. Ocjena nije pravna potvrda. Dokumenti su predlošci za pregled i prilagodbu. E-pošta nije konfigurirana; obavijesti su dostupne u aplikaciji. Postojeći ugrađeni demo zapisi označeni su u sučelju. Mjesečni interval znači 30 dana.

Novi PDF-ovi koriste novi dizajn. Ranije spremljene datoteke ostaju neizmijenjene. Primjeri novog izgleda nalaze se u `output/pdf`.

Implementacija slijedi službene upute:
- https://fastapi.tiangolo.com/async/
- https://fastapi.tiangolo.com/advanced/events/
- https://docs.reportlab.com/reportlab/userguide/ch3_fonts/

Za zajedničku ili javnu instalaciju potrebna je zasebna dorada autentifikacije, pohrane po korisniku i ograničavanja odredišta mrežnih provjera. Sučelje trenutačno učitava Tailwind i Font Awesome preko CDN-a.
