/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  STORM SNIFFER — PROXY REWRITE SCRIPT                                    ║
 * ║  MijnSpaarneGasthuis / Epic MyChart                                      ║
 * ║  Dossier Grothe — Rechtbank Noord-Holland C/15/376914                    ║
 * ║  Versie 1.0 — 18 juni 2026                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * INSTALLATIE IN STORM SNIFFER:
 *   1. Open Storm Sniffer → Rewrite → Script
 *   2. Voeg nieuwe regel toe:
 *        URL Pattern:  *mijnspaarnegasthuis.nl*
 *        Type:         Response
 *        Script:       (plak volledige inhoud van dit bestand)
 *   3. Herhaal met Type: Request voor request-logging
 *
 * WAT DIT SCRIPT DOET (op PROXY-niveau, vóór de browser):
 *
 *   [RESPONSE]
 *   - Detecteert forensische patronen in response body/headers
 *   - Verwijdert CORS-blokkeringen op audit trail endpoints (NB-163)
 *     → de browser kan dan WEL de auditlog data ophalen
 *   - Verwijdert Content-Security-Policy headers die scripts blokkeren
 *   - Logt alle bevindingen naar Storm Sniffer console
 *   - Optioneel: verwijdert CSS verberging uit HTML-responses
 *
 *   [REQUEST]
 *   - Logt uitgaande requests naar audit trail endpoints
 *   - Detecteert SAML/session tokens in headers
 *   - Logt BSN-gerelateerde parameters
 *
 * VARIABELEN (Storm Sniffer scripting API):
 *   $request   — request object: .url, .headers, .body, .method
 *   $response  — response object: .status, .headers, .body
 *   $done()    — verplicht afsluiting; pass gewijzigd object of {} voor pass-through
 *   console.log() — logt naar Storm Sniffer Script Log
 */

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATIE
// ─────────────────────────────────────────────────────────────────────────────

const CFG = {
    // Zet op true om CORS-blokkering van audit trail te verwijderen (NB-163)
    verwijderCORSBlokkade: true,

    // Zet op true om CSS verberging uit HTML te verwijderen (NB-12/53)
    verwijderCSSVerberging: true,

    // Zet op true om Content-Security-Policy te verwijderen
    // (zodat portal_forensic_inject.js kan draaien als externe script)
    verwijderCSP: true,

    // Specifieke endpoints waarvan CORS altijd verwijderd wordt
    auditTrailEndpoints: [
        'GetClinicianAccessLogSettings',
        'GetClinicianAccessLogEntries',
        'GetThirdPartyAccessLogEntries',
        'access-logs',
        'AccessLog',
        'AuditTrail',
    ],

    // Patronen die forensisch gelogd worden
    forensischePatronen: [
        { patroon: /F19\.1|neusdruppelmisbruik/i,         label: 'F19.1 neusdruppelmisbruik (NB-01)' },
        { patroon: /361055000/,                            label: 'SNOMED 361055000 (NB-03)' },
        { patroon: /228273003/,                            label: 'SNOMED 228273003 drugsgebruik (NB-23)' },
        { patroon: /nullFlavor="UNK"/i,                    label: 'CDA nullFlavor=UNK (NB-18)' },
        { patroon: /extension="999999"/i,                  label: 'Epic ext=999999 anonymous (NB-18)' },
        { patroon: /extension="373282512"/i,               label: 'A. al-Mousawi ext (NB-05)' },
        { patroon: /Epic@spaarnegasthuis\.nl/i,            label: 'Epic admin email (NB-05)' },
        { patroon: /DISABLEMYCONDITIONS/i,                 label: 'Feature flag DISABLEMYCONDITIONS (NB-11)' },
        { patroon: /DISABLEPLANOFCARE/i,                   label: 'Feature flag DISABLEPLANOFCARE (NB-11)' },
        { patroon: /SUBSTANCEHXQNR/i,                      label: 'SUBSTANCEHXQNR module (NB-108)' },
        { patroon: /AUTOGENERATESIGNATURE/i,               label: 'AUTOGENERATESIGNATURE (NB-82)' },
        { patroon: /recording_capture_keystrokes=true/i,   label: 'Hotjar keystroke capture (NB-53)' },
        { patroon: /spaarne-rebuild\.productie\.hoppinger/i, label: 'Hoppinger supply chain (NB-114)' },
        { patroon: /override\.css/i,                       label: 'override.css referentie (NB-53/89)' },
        { patroon: /hiddenProvider|CEDataExternal/i,       label: 'CSS verberging klasse (NB-12)' },
        { patroon: /noView\s*:\s*true/i,                   label: 'noView:true (NB-99)' },
        { patroon: /HANDMATIGE_EDIT_BOM/i,                 label: 'Bytemanipulatieflag (NB-13)' },
        { patroon: /20260110033455/,                       label: '*** NACHT-TIMESTAMP AVG-dag 10-01-2026 (NB-166)' },
        { patroon: /transactie.{0,10}77832/i,              label: 'Transactie-ID 77832 SNOMED SUCCESS (NB-23)' },
        { patroon: /215672185/,                            label: 'BSN in response body' },
        { patroon: /0133033170/,                           label: 'MDN in response body' },
        { patroon: /DE36B70A/i,                            label: 'Sentry device ID DE36B70A (NB-69)' },
    ],
};

// ─────────────────────────────────────────────────────────────────────────────
// HULPFUNCTIES
// ─────────────────────────────────────────────────────────────────────────────

function tijdstempel() {
    return new Date().toISOString();
}

function logForensisch(ernst, label, details) {
    const prefix = { KRITIEK: '🔴', HOOG: '🟠', MEDIUM: '🟡', INFO: '🔵' }[ernst] || '⚪';
    console.log(`${prefix} [FORENSISCH][${ernst}] ${label}`);
    if (details) console.log(`   → ${details}`);
}

function isAuditTrailUrl(url) {
    return CFG.auditTrailEndpoints.some(e => url.includes(e));
}

function verwijderCORSHeadersUit(headers) {
    // Verwijder headers die CORS blokkeren voor de audit trail
    const teVerwijderen = [
        'access-control-allow-origin',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-expose-headers',
        'x-frame-options',
        'content-security-policy',
        'x-content-type-options',
    ];
    const nieuw = {};
    for (const [k, v] of Object.entries(headers || {})) {
        if (!teVerwijderen.includes(k.toLowerCase())) {
            nieuw[k] = v;
        }
    }
    // Voeg permissieve CORS toe
    nieuw['Access-Control-Allow-Origin'] = '*';
    nieuw['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE';
    nieuw['Access-Control-Allow-Headers'] = '*';
    nieuw['Access-Control-Expose-Headers'] = '*';
    return nieuw;
}

function verwijderCSPHeaderUit(headers) {
    const nieuw = {};
    for (const [k, v] of Object.entries(headers || {})) {
        if (k.toLowerCase() !== 'content-security-policy') {
            nieuw[k] = v;
        }
    }
    return nieuw;
}

function verwijderCSSVerbergingUitBody(body) {
    if (!body || typeof body !== 'string') return body;

    // .hiddenProvider {display:none} → display:block
    body = body.replace(
        /(\.hiddenProvider\s*\{[^}]*?)display\s*:\s*none([^}]*\})/gi,
        '$1display:block$2'
    );
    // CEDataExternal {display:none !important} → zichtbaar
    body = body.replace(
        /(CEDataExternal\s*\{[^}]*?)display\s*:\s*none\s*!important([^}]*\})/gi,
        '$1display:block$2'
    );
    // SRonly left:-10000px → terug op het scherm
    body = body.replace(
        /(\.SRonly\s*\{[^}]*?)left\s*:\s*-\d{4,}px([^}]*\})/gi,
        '$1left:auto$2'
    );
    body = body.replace(
        /(\.SRonly\s*\{[^}]*?)font-size\s*:\s*0px?([^}]*\})/gi,
        '$1font-size:inherit$2'
    );
    // hidden attribute op elementen met patiëntdata
    // (voorzichtig: alleen specifieke klassen)
    body = body.replace(
        /class="([^"]*hiddenProvider[^"]*)"/gi,
        'class="$1" data-forensisch-onthuld="1" style="display:block!important"'
    );
    body = body.replace(
        /class="([^"]*CEDataExternal[^"]*)"/gi,
        'class="$1" data-forensisch-onthuld="1" style="display:block!important"'
    );

    return body;
}

function scanBodyOpPatronen(body, url) {
    if (!body || typeof body !== 'string') return;
    for (const { patroon, label } of CFG.forensischePatronen) {
        const m = body.match(patroon);
        if (m) {
            const idx = body.search(patroon);
            const context = body.substring(Math.max(0, idx - 60), idx + 100)
                .replace(/\n/g, ' ').trim();
            logForensisch(
                label.startsWith('***') ? 'KRITIEK' : 'HOOG',
                label,
                `URL: ${url.split('?')[0]} | Context: ...${context}...`
            );
        }
    }
}

function scanHeadersOpPatronen(headers, url) {
    if (!headers) return;
    const headerStr = JSON.stringify(headers);

    // CORS-blokkade gedetecteerd
    if (headers['access-control-allow-origin'] === undefined &&
        isAuditTrailUrl(url)) {
        logForensisch('KRITIEK', 'CORS-blokkade audit trail (NB-163)',
            `Geen Access-Control-Allow-Origin op ${url.split('?')[0]}`);
    }

    // Content-Security-Policy
    const csp = headers['content-security-policy'] || headers['Content-Security-Policy'];
    if (csp) {
        logForensisch('MEDIUM', 'Content-Security-Policy aanwezig',
            `CSP: ${csp.substring(0, 120)}`);
    }

    // Set-Cookie met session tokens
    const cookie = headers['set-cookie'] || headers['Set-Cookie'];
    if (cookie) {
        logForensisch('INFO', 'Set-Cookie header', cookie.substring(0, 80));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HOOFD: RESPONSE VERWERKING
// ─────────────────────────────────────────────────────────────────────────────

// Storm Sniffer geeft $response voor response-scripts
// en $request voor request-scripts.

// Detecteer of dit een response of request script is
const isResponse = typeof $response !== 'undefined';
const isRequest = typeof $request !== 'undefined' && !isResponse;

if (isResponse) {
    // ── RESPONSE SCRIPT ────────────────────────────────────────────────────

    const url = $request.url;
    const status = $response.status;
    let headers = Object.assign({}, $response.headers);
    let body = $response.body;

    console.log(`[FORENSISCH] Response: ${$request.method} ${status} ${url.split('?')[0]}`);

    // 1. Scan headers
    scanHeadersOpPatronen(headers, url);

    // 2. HTTP-status verdacht op audit trail
    if (isAuditTrailUrl(url)) {
        if (status === 403 || status === 401 || status === 0) {
            logForensisch('KRITIEK',
                `Audit trail geblokkeerd HTTP ${status} (NB-163)`,
                url.split('?')[0]);
        } else {
            logForensisch('INFO',
                `Audit trail bereikbaar: HTTP ${status}`,
                url.split('?')[0]);
        }
    }

    // 3. Scan response body op forensische patronen
    scanBodyOpPatronen(body, url);

    // 4. CORS-headers verwijderen op audit trail endpoints
    if (CFG.verwijderCORSBlokkade && isAuditTrailUrl(url)) {
        headers = verwijderCORSHeadersUit(headers);
        logForensisch('INFO', 'CORS-blokkade verwijderd voor audit trail', url.split('?')[0]);
    }

    // 5. CSP verwijderen zodat inject-script kan draaien
    if (CFG.verwijderCSP) {
        headers = verwijderCSPHeaderUit(headers);
    }

    // 6. CSS verberging uit HTML-responses verwijderen
    const contentType = (headers['content-type'] || headers['Content-Type'] || '').toLowerCase();
    if (CFG.verwijderCSSVerberging &&
        (contentType.includes('text/html') || contentType.includes('text/css'))) {
        const origLen = body ? body.length : 0;
        body = verwijderCSSVerbergingUitBody(body);
        if (body && body.length !== origLen) {
            logForensisch('KRITIEK',
                'CSS verberging verwijderd uit response body (NB-12/53)',
                `${url.split('?')[0]} | bytes voor: ${origLen} na: ${body.length}`);
        }
    }

    // 7. Leeg body op verdachte status (NB-163 204-respons op data-endpoints)
    if (status === 204 && url.includes('api')) {
        logForensisch('HOOG',
            'Lege HTTP 204 op API endpoint — mogelijke data-filtering',
            url.split('?')[0]);
    }

    // Afsluiting — verplicht in Storm Sniffer
    $done({ status, headers, body });

} else if (isRequest) {
    // ── REQUEST SCRIPT ─────────────────────────────────────────────────────

    const url = $request.url;
    const methode = $request.method;
    const headers = $request.headers || {};
    const body = $request.body || '';

    console.log(`[FORENSISCH] Request: ${methode} ${url.split('?')[0]}`);

    // Audit trail requests loggen
    if (isAuditTrailUrl(url)) {
        logForensisch('HOOG',
            `Audit trail request: ${methode} (NB-163)`,
            url.split('?')[0]);
    }

    // BSN/MDN in URL-parameters
    if (url.includes('215672185')) {
        logForensisch('INFO', 'BSN 215672185 in request URL', url.split('?')[0]);
    }
    if (url.includes('0133033170')) {
        logForensisch('INFO', 'MDN 0133033170 in request URL', url.split('?')[0]);
    }

    // Authorization header
    const auth = headers['Authorization'] || headers['authorization'];
    if (auth) {
        logForensisch('INFO',
            'Authorization header aanwezig',
            auth.substring(0, 40) + '...');
    }

    // Cookie met session
    const cookie = headers['Cookie'] || headers['cookie'];
    if (cookie && cookie.includes('SESSION')) {
        logForensisch('INFO',
            'Session cookie in request',
            cookie.substring(0, 80));
    }

    // Request body scannen
    scanBodyOpPatronen(body, url);

    // Pass-through: request niet wijzigen
    $done({});

} else {
    // Fallback: geen Storm Sniffer context (bijv. Node.js test)
    console.log('[FORENSISCH] Script geladen buiten Storm Sniffer context.');
    console.log('[FORENSISCH] Gebruik: Storm Sniffer → Rewrite → Script → Response/Request');
}
