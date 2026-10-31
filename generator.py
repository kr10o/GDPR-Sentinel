"""Shared, print-friendly Sentinel design for reports and document templates."""
import re
from html import escape
from pathlib import Path
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

FONT_DIR = Path(__file__).parent / 'static' / 'fonts'
for name, filename in [('Sentinel', 'regular.ttf'), ('Sentinel-Bold', 'bold.ttf')]:
    pdfmetrics.registerFont(TTFont(name, str(FONT_DIR / filename)))
pdfmetrics.registerFontFamily('Sentinel', normal='Sentinel', bold='Sentinel-Bold', italic='Sentinel', boldItalic='Sentinel-Bold')
INK = colors.HexColor('#172b36')
MUTED = colors.HexColor('#60717c')
TEAL = colors.HexColor('#087e79')
LINE = colors.HexColor('#e0e9ec')
WIDTH = A4[0] - 88
STYLES = {
    'body': ParagraphStyle('Body', fontName='Sentinel', fontSize=9, leading=14, textColor=INK, spaceAfter=6, splitLongWords=True),
    'title': ParagraphStyle('Title', fontName='Sentinel-Bold', fontSize=25, leading=32, textColor=INK, spaceAfter=16),
    'h2': ParagraphStyle('Heading', fontName='Sentinel-Bold', fontSize=13, leading=19, textColor=TEAL, spaceBefore=16, spaceAfter=9, keepWithNext=True),
    'h3': ParagraphStyle('Subheading', fontName='Sentinel-Bold', fontSize=10, leading=15, textColor=INK, spaceBefore=10, spaceAfter=6, keepWithNext=True),
    'small': ParagraphStyle('Small', fontName='Sentinel', fontSize=8, leading=12, textColor=MUTED, spaceAfter=6),
}

def inline(text):
    text = escape(str(text), quote=False)
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    return text

def para(text, style='body'):
    return Paragraph(inline(text), STYLES[style])

def page_design(canvas, doc):
    canvas.saveState()
    w, h = A4
    # Pale mint-to-lavender accent translates glass surfaces into a clean print layout.
    for n in range(100):
        t = n / 99
        canvas.setFillColor(colors.Color((224+8*t)/255, (244-12*t)/255, (237+12*t)/255))
        canvas.rect(44+n*WIDTH/100, h-35, WIDTH/100+1, 4, fill=1, stroke=0)
    canvas.setFont('Sentinel-Bold', 8)
    canvas.setFillColor(TEAL)
    canvas.drawString(44, h-53, 'GDPR SENTINEL')
    canvas.setFont('Sentinel', 7)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(w-44, h-53, 'PREGLED · PRIVATNOST · DOKUMENTACIJA')
    canvas.setStrokeColor(LINE)
    canvas.line(44, 43, w-44, 43)
    canvas.drawString(44, 29, 'GDPR Sentinel  /  '+datetime.now().strftime('%d.%m.%Y.'))
    canvas.drawRightString(w-44, 29, f'Stranica {doc.page}')
    canvas.restoreState()

def build(story, path, title):
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=44, rightMargin=44,
                            topMargin=78, bottomMargin=60, title=title, author='GDPR Sentinel')
    doc.build(story, onFirstPage=page_design, onLaterPages=page_design)

def table(rows, widths=None, header=True):
    count = max(len(row) for row in rows)
    data = [[para(cell, 'small') for cell in list(row)+['']*(count-len(row))] for row in rows]
    result = Table(data, colWidths=widths or [WIDTH/count]*count, repeatRows=1 if header else 0, hAlign='LEFT')
    commands = [('VALIGN',(0,0),(-1,-1),'TOP'),('ROWBACKGROUNDS',(0,0),(-1,-1),[colors.white,colors.HexColor('#f7faf9')]),('LINEBELOW',(0,0),(-1,-1),.4,LINE)]
    if header: commands.append(('BACKGROUND',(0,0),(-1,0),colors.HexColor('#eaf4f0')))
    for direction in ['LEFT','RIGHT','TOP','BOTTOM']: commands.append((direction+'PADDING',(0,0),(-1,-1),9))
    result.setStyle(TableStyle(commands))
    return result

def generate_pdf_report(scan, output_filepath):
    story = [para('Pregled privatnosti\ni procjena rizika'.replace('\n',' '),'title'),
             para(scan.get('domain','Web stranica'),'h2'), para(scan.get('url',''),'small'),
             para('Vrijeme provjere: '+str(scan.get('scan_timestamp','')),'small')]
    summary=scan.get('summary',{})
    story += [Spacer(1,12), table([['TEHNIČKA OCJENA','VISOKI RIZICI','SREDNJI RIZICI','NISKI RIZICI'],
              [f"{scan.get('compliance_score',0)} / 100",summary.get('high',0),summary.get('medium',0),summary.get('low',0)]]),
              Spacer(1,12),para('Automatizirani pregled javno dostupnog HTML-a. Ne izvršava JavaScript i nije potvrda pravne usklađenosti. Nalaze i preporuke potrebno je provjeriti u kontekstu stvarne obrade podataka.','small'),
              para('01 / Tehnički nalazi','h2')]
    story.append(table([
        ['KOMPONENTA','NALAZ'],
        ['SSL / TLS',scan.get('ssl_details','Nema podataka')],
        ['Pravila privatnosti',scan.get('privacy_policy_url') or 'Poveznica nije pronađena'],
        ['Cookie banner','Prepoznata oznaka u HTML-u' if scan.get('cookie_banner_found') else 'Nije prepoznat u HTML-u'],
        ['HTTP kolačići',', '.join(c.get('name','') for c in scan.get('cookies_detected',[])) or 'Nisu zabilježeni'],
        ['Poznati trackeri',', '.join(scan.get('trackers_detected',[])) or 'Nisu prepoznati']
    ], [140,WIDTH-140]))
    story.append(para('02 / Rizici i sljedeći koraci','h2'))
    for risk in scan.get('risks',[]):
        story.append(para(risk.get('title','Nalaz'),'h3'))
        story.append(para(f"{risk.get('risk_level','')} rizik · {risk.get('category','')} · {risk.get('gdpr_article','')}",'small'))
        story.append(para(risk.get('description','')))
        story.append(para('**Preporuka:** '+risk.get('recommendation','')))
        story.append(HRFlowable(width='100%', thickness=.5, color=LINE, spaceAfter=8))
    if not scan.get('risks'): story.append(para('Nisu prepoznati rizici u okviru ove tehničke provjere.'))
    build(story, output_filepath, 'GDPR pregled - '+scan.get('domain',''))

def generate_document_pdf(markdown_text, output_filepath, title='Pravni dokument'):
    story=[]; rows=[]
    def flush():
        if rows:
            story.append(table(rows)); story.append(Spacer(1,10)); rows.clear()
    if not markdown_text.lstrip().startswith('# '): story.append(para(title,'title'))
    for line in markdown_text.splitlines():
        line=line.strip()
        if line.startswith('|') and line.endswith('|'):
            cells=[cell.strip() for cell in line[1:-1].split('|')]
            if not all(re.fullmatch(r'[:\-\s]*',cell) for cell in cells): rows.append(cells)
            continue
        flush()
        if not line: continue
        if re.fullmatch(r'-{3,}',line):
            story.append(HRFlowable(width='100%',thickness=.5,color=LINE,spaceBefore=8,spaceAfter=8)); continue
        match=re.match(r'^(#{1,3})\s+(.*)',line)
        if match: story.append(para(match[2],{1:'title',2:'h2',3:'h3'}[len(match[1])]))
        else: story.append(para(line))
    flush()
    build(story or [para(title,'title')],output_filepath,title)
