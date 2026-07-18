"""
FORENSISCH MITMPROXY ADDON
==========================
Installatieq (eenmalig):
    pip install mitmproxy

Starten:
    mitmproxy --scripts forensic_mitm.py          # met interactieve TUI
    mitmdump  --scripts forensic_mitm.py          # alleen terminal output
    mitmweb   --scripts forensic_mitm.py          # browser-dashboard op http://127.0.0.1:8081

iPhone instellen:
    1. Start mitmproxy op je laptop
    2. iPhone: Instellingen → Wi-Fi → jouw netwerk → (i) → Proxy → Handmatig
       Host: <laptop IP>   Poort: 8080
    3. Ga op iPhone naar http://mitm.it en installeer het certificaat
    4. iPhone: Instellingen → Algemeen → Info → Certificaatvertrouwen → zet mitm.it AAN
    5. Klaar — al het verkeer loopt nu door dit script

Wat het doet:
    - Verwijdert ALLE blokkerende headers (CSP, X-Frame-Options, HSTS, CORS, ...)
    - Opent CORS volledig op elk response
    - Verwijdert CSS verberging uit HTML/CSS (display:none, opacity:0, font-size:0, ...)
    - Injecteert forensisch banner + ontsluiter-script in HTML pagina's
    - Scant elk request/response op 60+ bekende forensische patronen (NB-01 t/m NB-179)
    - Decodeert base64 blokken en scant ook de gedecodeerde inhoud
    - Analyseert cookies op ontbrekende Secure/HttpOnly/SameSite vlaggen
    - Logt alles met kleurcodering naar terminal + forensic_mitm.log
    - Blokkeert NOOIT iets — bij fout altijd origineel doorsturen
"""

import re
import base64
import datetime
import os
import sys
from mitmproxy import http, ctx

# ── Logbestand ───────────────────────────────────────────────
LOG_BESTAND = os.path.join(os.path.dirname(__file__), 'forensic_mitm.log')

# ── Kleurcodes terminal ───────────────────────────────────────
RESET  = '\033[0m'
ROOD   = '\033[91m'
GEEL   = '\033[93m'
BLAUW  = '\033[94m'
GRIJS  = '\033[90m'
WIT    = '\033[97m'
GROEN  = '\033[92m'

ERNST_KLEUR = {
    'KRITIEK': ROOD,
    'HOOG':    GEEL,
    'MEDIUM':  BLAUW,
    'INFO':    GRIJS,
}

# ── Forensische patronen (NB-register) ───────────────────────
PATRONEN = [
    # Diagnoses / medische codes
    ('KRITIEK', 'NB-01',  r'F19\.1',                         'F19.1 psychoactieve stof'),
    ('KRITIEK', 'NB-01',  r'neusdruppelmisbruik',             'Term neusdruppelmisbruik (gefabriceerd)'),
    ('KRITIEK', 'NB-03',  r'361055000',                       'SNOMED 361055000 alcoholmisbruik'),
    ('KRITIEK', 'NB-23',  r'228273003',                       'SNOMED 228273003 drugsgebruik'),
    ('KRITIEK', 'NB-23b', r'228366006',                       'SNOMED 228366006 stimulant misuse'),
    ('KRITIEK', 'NB-23c', r'266927001',                       'SNOMED 266927001 afhankelijkheid'),
    ('KRITIEK', 'NB-xx',  r'F60\.31|borderline\s*persoon',   'F60.31 borderline persoonlijkheidsstoornis'),
    ('KRITIEK', 'NB-23',  r'transactie.{0,10}77832',         'Transactie-ID 77832 SNOMED SUCCESS'),

    # Anonieme / vervalste auteurs
    ('KRITIEK', 'NB-18',  r'nullFlavor\s*=\s*["\']?UNK',    'CDA nullFlavor=UNK anonieme auteur'),
    ('KRITIEK', 'NB-18',  r'extension\s*=\s*["\']?999999',  'Epic extension=999999 anonymous auteur'),
    ('KRITIEK', 'NB-05',  r'extension\s*=\s*["\']?373282512','A. al-Mousawi extensie code'),
    ('KRITIEK', 'NB-04',  r'extension\s*=\s*["\']?51504662','N.M. Nota extensie code A'),
    ('KRITIEK', 'NB-04',  r'extension\s*=\s*["\']?84107660','N.M. Nota extensie code B'),
    ('KRITIEK', 'NB-05',  r'Epic@spaarnegasthuis\.nl',       'Epic admin e-mail account'),

    # Feature flags die data verbergen
    ('KRITIEK', 'NB-11',  r'DISABLEMYCONDITIONS',            'Feature flag DISABLEMYCONDITIONS'),
    ('KRITIEK', 'NB-11',  r'DISABLEPLANOFCARE',              'Feature flag DISABLEPLANOFCARE'),
    ('KRITIEK', 'NB-108', r'SUBSTANCEHXQNR',                 'SUBSTANCEHXQNR verslavingsmodule'),
    ('KRITIEK', 'NB-82',  r'AUTOGENERATESIGNATURE',          'AUTOGENERATESIGNATURE'),
    ('KRITIEK', 'NB-163', r'USERAUDITTRAIL|MYCHARTAUDITTRAIL','Audit trail feature flag'),
    ('KRITIEK', 'NB-99',  r'noView\s*:\s*true',              'noView:true data verborgen'),
    ('HOOG',    'NB-56',  r'\bGUARD\b',                      'GUARD blok CDA'),
    ('KRITIEK', 'NB-13',  r'HANDMATIGE_EDIT_BOM',            'Bytemanipulatie vlag'),

    # CSS verberging klassen
    ('KRITIEK', 'NB-12',  r'hiddenProvider',                 'CSS klasse hiddenProvider'),
    ('KRITIEK', 'NB-12',  r'CEDataExternal',                 'CSS klasse CEDataExternal'),
    ('HOOG',    'NB-12',  r'WoundListSection',               'CSS WoundListSection'),
    ('KRITIEK', 'NB-89',  r'override\.css',                  'override.css stylesheet referentie'),
    ('KRITIEK', 'NB-71',  r'lucy\.css|lucy_colors',          'lucy.css custom renderingslaag'),
    ('HOOG',    'NB-84',  r'printBlackText',                 'printBlackText alarmkleur override'),

    # Trackers
    ('KRITIEK', 'NB-53',  r'recording_capture_keystrokes\s*=\s*true', 'Hotjar keystroke capture ACTIEF'),
    ('KRITIEK', 'NB-79',  r'hjid\s*=|hotjar\.com',          'Hotjar tracker'),
    ('HOOG',    'NB-69',  r'sentry\.io',                     'Sentry.io telemetrie'),
    ('HOOG',    'NB-69',  r'DE36B70A',                       'Sentry device ID DE36B70A'),
    ('HOOG',    'NB-114', r'hoppinger\.com',                 'Hoppinger supply chain'),
    ('KRITIEK', 'NB-114', r'spaarne-rebuild\.productie\.hoppinger', 'Hoppinger productie-injectie'),
    ('KRITIEK', 'NB-178', r'account_id\s*[:=]\s*763232',    'VWO tracker account_id=763232'),
    ('KRITIEK', 'NB-178', r'vwo_uuid',                       'VWO UUID tracking na cookie-weigering'),
    ('KRITIEK', 'NB-178', r'body\s*\{[^}]*opacity\s*:\s*0', 'VWO body opacity:0 rendering-aanval'),
    ('HOOG',    'NB-69',  r'datadog.*browser-intake|browser-intake.*datadoghq', 'Datadog RUM telemetrie'),
    ('KRITIEK', 'NB-91',  r'FocusZorgTeam.*test\.authorization', 'FocusZorgTeam test-server in productie'),

    # Timestamps / identifiers
    ('KRITIEK', 'NB-166', r'20260110033455',                 'NACHT-TIMESTAMP 10-01-2026 03:34:55 AVG-dag'),
    ('KRITIEK', 'NB-166', r'215672185',                      'BSN Grothe in response'),
    ('KRITIEK', 'NB-166', r'0133033170',                     'MDN Grothe in response'),

    # ChipSoft HiX API (NB-177)
    ('KRITIEK', 'NB-177', r'ChipSoft\.PlatformServices',     'ChipSoft HiX API blootgesteld'),
    ('KRITIEK', 'NB-177', r'GetCurrentPatientAndUserObject', 'ChipSoft patientobject gelekt'),
    ('KRITIEK', 'NB-177', r'2001702222',                     'ChipSoft patient-ID Grothe'),
    ('HOOG',    'NB-177', r'DYN_CURRENT_USER',               'ChipSoft HiX sessietoken'),
    ('HOOG',    'NB-177', r'PATIENT_PATIENT',                'ChipSoft HiX patientklasse'),
    ('HOOG',    'NB-177', r'GetPatientDocuments',            'ChipSoft GetPatientDocuments'),
    ('HOOG',    'NB-177', r'GetPathologyResults',            'ChipSoft GetPathologyResults'),
    ('HOOG',    'NB-177', r'GetDcrRegistrations',            'ChipSoft GetDcrRegistrations toestemmingen'),
    ('HOOG',    'NB-177', r'DigiDClusterHybrid',             'ChipSoft DigiD authenticatiestroom'),

    # Overige
    ('HOOG',    'NB-179', r'centramed\.nl',                  'Centramed aansprakelijkheidsverzekeraar'),
    ('KRITIEK', 'NB-113', r'Brijder|Parnassia.*Indigo|Indigo.*Parnassia', 'Parnassia/Brijder (nooit in behandeling)'),
    ('HOOG',    'NB-109', r'\$lastn',                        'FHIR $lastn replay'),
    ('HOOG',    'MEDMIJ', r'quliRedirect',                   'MedMij quliRedirect cookie'),
    ('HOOG',    'MEDMIJ', r'mfn=',                           'MedMij provider token mfn='),
]

# Gecompileerde regex patronen (eenmalig bij laden)
PATRONEN_COMPILED = [
    (ernst, nb, re.compile(patroon, re.IGNORECASE | re.DOTALL), label)
    for ernst, nb, patroon, label in PATRONEN
]

# Headers die data verbergen of toegang blokkeren
BLOKKEER_HEADERS = [
    'content-security-policy',
    'content-security-policy-report-only',
    'x-frame-options',
    'x-xss-protection',
    'x-content-type-options',
    'strict-transport-security',
    'feature-policy',
    'permissions-policy',
    'cross-origin-embedder-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'expect-ct',
    'nel',
    'report-to',
]

# Audit trail endpoints
AUDIT_ENDPOINTS = [
    'GetClinicianAccessLogSettings', 'GetClinicianAccessLogEntries',
    'GetThirdPartyAccessLogEntries', 'access-logs', 'AccessLog',
    'AuditTrail', 'auditlog', 'audit-log', 'audit_log',
]

# ── Logging ───────────────────────────────────────────────────

_log_fh = open(LOG_BESTAND, 'a', encoding='utf-8')


def _log(ernst: str, bron: str, label: str, detail: str = ''):
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    kleur = ERNST_KLEUR.get(ernst, WIT)
    prefix = {'KRITIEK': '[!!]', 'HOOG': '[! ]', 'MEDIUM': '[~ ]', 'INFO': '[i ]'}.get(ernst, '[  ]')
    regel = f"{ts} {prefix} [{ernst}] {bron} | {label}"
    if detail:
        detail_kort = detail[:300].replace('\n', ' ')
        regel += f"\n          → {detail_kort}"
    print(f"{kleur}{regel}{RESET}")
    _log_fh.write(regel + '\n')
    _log_fh.flush()


def _log_scheidslijn(tekst: str):
    lijn = f"{'─' * 60}"
    print(f"{GRIJS}{lijn}\n  {tekst}\n{lijn}{RESET}")
    _log_fh.write(lijn + '\n  ' + tekst + '\n' + lijn + '\n')
    _log_fh.flush()


# ── Hulpfuncties ─────────────────────────────────────────────

def _is_audit(url: str) -> bool:
    return any(ep in url for ep in AUDIT_ENDPOINTS)


def _is_html(flow: http.HTTPFlow) -> bool:
    ct = flow.response.headers.get('content-type', '').lower()
    body_start = flow.response.content[:200].decode('utf-8', errors='ignore').lower()
    return 'text/html' in ct or '<html' in body_start


def _is_css(flow: http.HTTPFlow) -> bool:
    ct = flow.response.headers.get('content-type', '').lower()
    return 'text/css' in ct or flow.request.path.endswith('.css')


def _scan_tekst(tekst: str, url: str, context: str):
    """Scan tekst op alle forensische patronen. Logt elke treffer met context."""
    for ernst, nb, regex, label in PATRONEN_COMPILED:
        for m in regex.finditer(tekst):
            start = max(0, m.start() - 80)
            eind  = min(len(tekst), m.end() + 120)
            ctx_fragment = tekst[start:eind].replace('\n', ' ').replace('\r', '')
            _log(ernst, f"{nb} [{context}]", label, f"{url} | ...{ctx_fragment}...")


def _decode_base64_blokken(tekst: str) -> list[str]:
    """Zoek base64 blokken, decodeer ze, retourneer leesbare fragmenten."""
    resultaten = []
    regex = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    for m in regex.finditer(tekst):
        try:
            decoded = base64.b64decode(m.group()).decode('utf-8', errors='ignore')
            # Alleen doorsturen als het leesbare ASCII tekst bevat
            if sum(1 for c in decoded if 32 <= ord(c) <= 126) > len(decoded) * 0.6:
                resultaten.append(decoded)
        except Exception:
            pass
    return resultaten


def _analyseer_cookie(naam_waarde: str, url: str):
    """Analyseer Set-Cookie header op ontbrekende beveiligingsvlaggen."""
    heeft_secure   = bool(re.search(r';\s*Secure', naam_waarde, re.I))
    heeft_httponly = bool(re.search(r';\s*HttpOnly', naam_waarde, re.I))
    heeft_samesite = bool(re.search(r';\s*SameSite', naam_waarde, re.I))
    naam = naam_waarde.split(';')[0].split('=')[0].strip()

    ontbrekend = []
    if not heeft_secure:   ontbrekend.append('GEEN-Secure')
    if not heeft_httponly: ontbrekend.append('GEEN-HttpOnly')
    if not heeft_samesite: ontbrekend.append('GEEN-SameSite')

    ernst = 'HOOG' if ontbrekend else 'INFO'
    _log(ernst, 'COOKIE', f"Cookie: {naam}", ' '.join(ontbrekend) or 'OK' + f' | {url}')


def _strip_css_verberging(body: str) -> tuple[str, int]:
    """Verwijder alle CSS-verberging uit HTML/CSS tekst. Retourneert (nieuw_body, aantal_wijzigingen)."""
    origineel_len = len(body)
    wijzigingen = 0

    vervangingen = [
        # display:none in CSS regels
        (r'(\{[^}]*)\bdisplay\s*:\s*none(\s*!important)?([^}]*\})',
         r'\1display:block\3', 'display:none→block'),
        # visibility:hidden
        (r'\bvisibility\s*:\s*hidden(\s*!important)?',
         'visibility:visible', 'visibility:hidden→visible'),
        # opacity:0
        (r'\bopacity\s*:\s*0(\s*!important)?',
         'opacity:1', 'opacity:0→1'),
        # font-size:0
        (r'\bfont-size\s*:\s*0(px|em|rem|pt)?(\s*!important)?',
         'font-size:inherit', 'font-size:0→inherit'),
        # height:0 / width:0
        (r'\bheight\s*:\s*0(px)?(\s*!important)?',
         'height:auto', 'height:0→auto'),
        (r'\bwidth\s*:\s*0(px)?(\s*!important)?',
         'width:auto', 'width:0→auto'),
        # max-height:0
        (r'\bmax-height\s*:\s*0(px)?(\s*!important)?',
         'max-height:none', 'max-height:0→none'),
        # clip:rect(0,0,0,0)
        (r'\bclip\s*:\s*rect\s*\([^)]*\)',
         'clip:auto', 'clip:rect→auto'),
        # clip-path verberging
        (r'\bclip-path\s*:\s*inset\s*\(100%[^)]*\)',
         'clip-path:none', 'clip-path:inset(100%)→none'),
        # off-screen positie
        (r'\b(left|top)\s*:\s*-\d{3,}(px|em|rem)(\s*!important)?',
         r'\1:auto', 'off-screen→auto'),
        # overflow:hidden op bekende verberg-combinaties
        (r'(hiddenProvider|CEDataExternal|SRonly)[^{]*\{[^}]*overflow\s*:\s*hidden',
         lambda m: m.group().replace('overflow:hidden', 'overflow:visible'), 'overflow:hidden→visible'),
    ]

    for patroon, vervanging, naam in vervangingen:
        nieuw = re.sub(patroon, vervanging, body, flags=re.IGNORECASE | re.DOTALL)
        if nieuw != body:
            wijzigingen += 1
            body = nieuw

    # Inline style="display:none" op HTML elementen
    def ontsluit_inline(m):
        return m.group().replace('display:none', 'display:block').replace(
            'display: none', 'display:block') + ' data-fo-was-hidden="1"'

    nieuw = re.sub(
        r'(<[^>]+style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*["\'])',
        ontsluit_inline, body, flags=re.IGNORECASE
    )
    if nieuw != body:
        wijzigingen += 1
        body = nieuw

    # [hidden] attribuut
    nieuw = re.sub(r'\bhidden\b(?=\s*[/>]|\s+\w)', 'data-was-hidden', body, flags=re.IGNORECASE)
    if nieuw != body:
        wijzigingen += 1
        body = nieuw

    return body, wijzigingen


# ── Forensisch banner + ontsluiter JS (geinjecteerd in HTML) ─

INJECT_JS = """
<script id="__fo_inject">
(function(){
var n=0,r=[];
document.querySelectorAll('*').forEach(function(e){
  if(['SCRIPT','STYLE','META','HEAD'].includes(e.tagName))return;
  var s=window.getComputedStyle(e),c=[];
  if(s.display==='none'){e.style.setProperty('display','block','important');c.push('display:none');}
  if(s.visibility==='hidden'){e.style.setProperty('visibility','visible','important');c.push('visibility:hidden');}
  if(parseFloat(s.opacity)<0.05){e.style.setProperty('opacity','1','important');c.push('opacity:0');}
  if(parseFloat(s.fontSize)<1&&e.textContent.trim()){e.style.setProperty('font-size','14px','important');c.push('font-size:0');}
  if(e.hasAttribute('hidden')){e.removeAttribute('hidden');c.push('[hidden]');}
  if(e.getAttribute('aria-hidden')==='true'&&e.textContent.trim()){e.setAttribute('aria-hidden','false');c.push('aria-hidden');}
  var l=parseFloat(s.left),t=parseFloat(s.top);
  if((s.position==='absolute'||s.position==='fixed')&&(l<-200||t<-200)){
    e.style.setProperty('position','relative','important');
    e.style.setProperty('left','auto','important');
    e.style.setProperty('top','auto','important');
    c.push('off-screen');
  }
  if(c.length){
    e.style.setProperty('outline','3px solid #e00','important');
    e.setAttribute('title','🔴 VERBORGEN: '+c.join(' | '));
    n++;r.push(e.tagName+(e.id?'#'+e.id:'')+'→'+c.join(','));
  }
});
var b=document.createElement('div');
b.id='__fo_b';
b.style.cssText='position:fixed;top:0;left:0;right:0;background:#c00;color:#fff;font:bold 12px monospace;padding:5px 10px;z-index:2147483647;display:flex;justify-content:space-between;align-items:center;';
b.innerHTML='<span>🔴 FORENSISCH MITM ACTIEF — '+n+' verborgen elementen ontsloten</span>'
  +'<button onclick="this.parentNode.remove()" style="background:none;border:1px solid #fff;color:#fff;padding:1px 6px;cursor:pointer;">✕</button>';
document.body&&document.body.insertBefore(b,document.body.firstChild);
if(r.length)console.log('[FO] Ontsloten:\\n  '+r.slice(0,50).join('\\n  '));
})();
</script>
"""


# ── mitmproxy hooks ───────────────────────────────────────────

class ForensischAddon:

    def __init__(self):
        _log('INFO', 'OPSTART', f'Forensisch MITM gestart — log: {LOG_BESTAND}')
        _log('INFO', 'OPSTART', f'{len(PATRONEN)} patronen geladen (NB-01 t/m NB-179)')

    def request(self, flow: http.HTTPFlow):
        try:
            url  = flow.request.pretty_url
            su   = url.split('?')[0]
            meth = flow.request.method

            _log('INFO', 'REQ', f"{meth} {su}")

            # Audit trail detectie
            if _is_audit(url):
                _log('HOOG', 'NB-163', 'Audit trail request', f"{meth} {su}")

            # PII in URL
            for pii, naam in [('215672185', 'BSN'), ('0133033170', 'MDN'), ('2001702222', 'ChipSoft-ID')]:
                if pii in url:
                    _log('KRITIEK', 'PII', f'{naam} in URL: {pii}', su)

            # Authorization header
            auth = flow.request.headers.get('authorization', '')
            if auth:
                _log('INFO', 'AUTH', 'Authorization header aanwezig', auth[:60])
                bearer = re.search(r'Bearer\s+([A-Za-z0-9._-]{20,})', auth, re.I)
                if bearer:
                    _log('INFO', 'TOKEN', 'Bearer token', bearer.group(1)[:80])

            # Cookies
            cookies = flow.request.headers.get('cookie', '')
            if cookies:
                if 'quliRedirect' in cookies:
                    _log('HOOG', 'MEDMIJ', 'quliRedirect cookie aanwezig', su)
                if 'JSESSIONID' in cookies:
                    _log('INFO', 'SESSION', 'JSESSIONID sessiecookie', su)

            # Scan request body
            body = flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else ''
            if body:
                _scan_tekst(body, su, 'REQ-BODY')
                for decoded in _decode_base64_blokken(body):
                    _scan_tekst(decoded, su, 'REQ-BASE64')

            # Scan URL querystring
            qs = url[url.index('?'):] if '?' in url else ''
            if qs:
                _scan_tekst(qs, su, 'URL-PARAMS')

        except Exception as e:
            _log('INFO', 'FOUT', f'Request handler: {e}')

    def response(self, flow: http.HTTPFlow):
        try:
            url    = flow.request.pretty_url
            su     = url.split('?')[0]
            meth   = flow.request.method
            status = flow.response.status_code

            _log_scheidslijn(f"{meth} {status} {su}")

            # Audit trail
            if _is_audit(url):
                if status in (401, 403, 0):
                    _log('KRITIEK', 'NB-163', f'Audit trail GEBLOKKEERD HTTP {status}', su)
                else:
                    _log('INFO', 'NB-163', f'Audit trail bereikbaar HTTP {status}', su)

            # HTTP 204 op API
            body_bytes = flow.response.content or b''
            if status == 204 and b'api' in url.lower().encode():
                _log('HOOG', 'DATA', 'HTTP 204 lege response — mogelijke data-filtering', su)

            # ── Headers ──────────────────────────────────────
            # Log alle headers
            for naam, waarde in flow.response.headers.items():
                _log('INFO', 'HEADER', f"{naam}: {waarde[:150]}")

            # Set-Cookie analyseren
            for sc in flow.response.headers.get_all('set-cookie'):
                _analyseer_cookie(sc, su)

            # Verwijder blokkerende headers
            for h in BLOKKEER_HEADERS:
                if h in flow.response.headers:
                    verwijderd = flow.response.headers[h][:80]
                    del flow.response.headers[h]
                    _log('INFO', 'HEADER-DEL', f"Verwijderd: {h}", verwijderd)

            # Zet CORS volledig open
            flow.response.headers['Access-Control-Allow-Origin']   = '*'
            flow.response.headers['Access-Control-Allow-Methods']  = 'GET, POST, OPTIONS, PUT, DELETE, PATCH'
            flow.response.headers['Access-Control-Allow-Headers']  = '*'
            flow.response.headers['Access-Control-Expose-Headers'] = '*'

            # ── Body ─────────────────────────────────────────
            if not body_bytes:
                return

            body = body_bytes.decode('utf-8', errors='ignore')

            # Scan response body
            _scan_tekst(body, su, 'RESP-BODY')

            # Base64 decoderen en scannen
            for decoded in _decode_base64_blokken(body):
                _scan_tekst(decoded, su, 'RESP-BASE64')

            # CSS verberging strippen uit HTML en CSS
            if _is_html(flow) or _is_css(flow) or 'display' in body:
                body, n_wijz = _strip_css_verberging(body)
                if n_wijz > 0:
                    _log('KRITIEK', 'NB-12/53', f'CSS verberging verwijderd ({n_wijz} wijzigingen)', su)

            # Forensisch banner + ontsluiter JS injecteren in HTML
            if _is_html(flow) and '</body>' in body:
                body = body.replace('</body>', INJECT_JS + '</body>', 1)
                _log('INFO', 'INJECT', 'Forensisch ontsluiter geinjecteerd', su)

            flow.response.content = body.encode('utf-8', errors='replace')

        except Exception as e:
            _log('INFO', 'FOUT', f'Response handler: {e}')
            # Originele response ongewijzigd doorsturen bij fout


# ── Addon registratie ─────────────────────────────────────────
addons = [ForensischAddon()]
