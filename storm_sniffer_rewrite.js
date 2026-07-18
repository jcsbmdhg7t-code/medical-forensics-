(function () {
'use strict';

// ============================================================
// FORENSISCH PROXYMAN SCRIPT — alles doorlaten, alles ontsluiten
// Filosofie: geen enkel response wordt geblokkeerd of gefilterd.
//            Security-headers die data VERBERGEN worden verwijderd.
//            Alles wat interessant is wordt gelogd en zichtbaar gemaakt.
// ============================================================

var PATRONEN = [
    // Diagnoses / medische codes
    { p: /F19\.1/i,                         l: 'F19.1 psychoactieve stof (NB-01)', ernst: 'KRITIEK' },
    { p: /neusdruppelmisbruik/i,             l: 'Term "neusdruppelmisbruik" gefabriceerd (NB-01)', ernst: 'KRITIEK' },
    { p: /361055000/,                        l: 'SNOMED 361055000 alcoholmisbruik (NB-03)', ernst: 'KRITIEK' },
    { p: /228273003/,                        l: 'SNOMED 228273003 drugsgebruik (NB-23)', ernst: 'KRITIEK' },
    { p: /228366006/,                        l: 'SNOMED 228366006 stimulant misuse (NB-23b)', ernst: 'KRITIEK' },
    { p: /266927001/,                        l: 'SNOMED 266927001 afhankelijkheid (NB-23c)', ernst: 'KRITIEK' },
    { p: /F60\.31|borderline\s*persoon/i,    l: 'F60.31 borderline persoonlijkheidsstoornis (NB-xx)', ernst: 'KRITIEK' },
    { p: /transactie.{0,10}77832/i,          l: 'Transactie-ID 77832 SNOMED SUCCESS (NB-23)', ernst: 'KRITIEK' },

    // Anonieme/vervalste auteurs
    { p: /nullFlavor\s*=\s*["']?UNK/i,       l: 'CDA nullFlavor=UNK anonieme auteur (NB-18)', ernst: 'KRITIEK' },
    { p: /extension\s*=\s*["']?999999/i,     l: 'Epic extension=999999 anonymous auteur (NB-18)', ernst: 'KRITIEK' },
    { p: /extension\s*=\s*["']?373282512/i,  l: 'A. al-Mousawi extensie code (NB-05)', ernst: 'KRITIEK' },
    { p: /extension\s*=\s*["']?51504662/i,   l: 'N.M. Nota extensie code A (NB-04)', ernst: 'KRITIEK' },
    { p: /extension\s*=\s*["']?84107660/i,   l: 'N.M. Nota extensie code B (NB-04)', ernst: 'KRITIEK' },
    { p: /Epic@spaarnegasthuis\.nl/i,        l: 'Epic admin e-mail account (NB-05)', ernst: 'KRITIEK' },

    // Feature flags die data verbergen
    { p: /DISABLEMYCONDITIONS/i,             l: 'Feature flag DISABLEMYCONDITIONS (NB-11)', ernst: 'KRITIEK' },
    { p: /DISABLEPLANOFCARE/i,               l: 'Feature flag DISABLEPLANOFCARE (NB-11)', ernst: 'KRITIEK' },
    { p: /SUBSTANCEHXQNR/i,                  l: 'SUBSTANCEHXQNR verslaving module (NB-108)', ernst: 'KRITIEK' },
    { p: /AUTOGENERATESIGNATURE/i,           l: 'AUTOGENERATESIGNATURE (NB-82)', ernst: 'KRITIEK' },
    { p: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i,l: 'Audit trail feature flag (NB-163)', ernst: 'KRITIEK' },
    { p: /noView\s*:\s*true/i,               l: 'noView:true data verborgen (NB-99)', ernst: 'KRITIEK' },
    { p: /GUARD\b/,                          l: 'GUARD blok CDA (NB-56)', ernst: 'HOOG' },
    { p: /HANDMATIGE_EDIT_BOM/i,             l: 'Bytemanipulatie vlag (NB-13)', ernst: 'KRITIEK' },

    // CSS verberging
    { p: /hiddenProvider/i,                  l: 'CSS klasse hiddenProvider (NB-12)', ernst: 'KRITIEK' },
    { p: /CEDataExternal/i,                  l: 'CSS klasse CEDataExternal (NB-12)', ernst: 'KRITIEK' },
    { p: /WoundListSection/i,                l: 'CSS WoundListSection (NB-12)', ernst: 'HOOG' },
    { p: /override\.css/i,                   l: 'override.css stylesheet referentie (NB-53/89)', ernst: 'KRITIEK' },
    { p: /lucy\.css|lucy_colors/i,           l: 'lucy.css custom renderingslaag (NB-71)', ernst: 'KRITIEK' },
    { p: /printBlackText/i,                  l: 'printBlackText alarmkleur override (NB-84)', ernst: 'HOOG' },

    // Trackers / supply chain
    { p: /recording_capture_keystrokes\s*=\s*true/i, l: 'Hotjar keystroke capture ACTIEF (NB-53)', ernst: 'KRITIEK' },
    { p: /hjid\s*=|hotjar\.com/i,            l: 'Hotjar tracker (NB-79)', ernst: 'KRITIEK' },
    { p: /sentry\.io/i,                      l: 'Sentry.io telemetrie (NB-69)', ernst: 'HOOG' },
    { p: /DE36B70A/i,                        l: 'Sentry device ID DE36B70A (NB-69)', ernst: 'HOOG' },
    { p: /hoppinger\.com/i,                  l: 'Hoppinger supply chain (NB-114)', ernst: 'HOOG' },
    { p: /spaarne-rebuild\.productie\.hoppinger/i, l: 'Hoppinger productie-injectie (NB-114)', ernst: 'KRITIEK' },
    { p: /account_id\s*[:=]\s*763232/i,      l: 'VWO tracker account_id=763232 (NB-53/178)', ernst: 'KRITIEK' },
    { p: /vwo_uuid/i,                        l: 'VWO UUID tracking na cookie-weigering (NB-178)', ernst: 'KRITIEK' },
    { p: /body\s*\{[^}]*opacity\s*:\s*0/i,   l: 'VWO body opacity:0 rendering-aanval (NB-53/178)', ernst: 'KRITIEK' },
    { p: /datadog.*browser-intake|browser-intake.*datadoghq/i, l: 'Datadog RUM telemetrie (NB-69)', ernst: 'HOOG' },
    { p: /FocusZorgTeam.*test\.authorization/i, l: 'FocusZorgTeam test-server in productie (NB-91)', ernst: 'KRITIEK' },

    // Timestamps / identifiers
    { p: /20260110033455/,                   l: 'NACHT-TIMESTAMP 10-01-2026 03:34:55 AVG-dag (NB-166)', ernst: 'KRITIEK' },
    { p: /215672185/,                        l: 'BSN Grothe 215672185 in response', ernst: 'KRITIEK' },
    { p: /0133033170/,                       l: 'MDN Grothe 0133033170 in response', ernst: 'KRITIEK' },

    // ChipSoft HiX API (NB-177)
    { p: /ChipSoft\.PlatformServices/i,      l: 'ChipSoft HiX API blootgesteld (NB-177)', ernst: 'KRITIEK' },
    { p: /GetCurrentPatientAndUserObject/i,  l: 'ChipSoft patientobject gelekt (NB-177)', ernst: 'KRITIEK' },
    { p: /2001702222/,                       l: 'ChipSoft patient-ID Grothe (NB-177)', ernst: 'KRITIEK' },
    { p: /DYN_CURRENT_USER/i,               l: 'ChipSoft HiX sessietoken (NB-177)', ernst: 'HOOG' },
    { p: /PATIENT_PATIENT/i,                 l: 'ChipSoft HiX patientklasse (NB-177)', ernst: 'HOOG' },
    { p: /GetPatientDocuments/i,             l: 'ChipSoft GetPatientDocuments (NB-177)', ernst: 'HOOG' },
    { p: /GetPathologyResults/i,             l: 'ChipSoft GetPathologyResults (NB-177)', ernst: 'HOOG' },
    { p: /GetDcrRegistrations/i,             l: 'ChipSoft GetDcrRegistrations toestemmingen (NB-177)', ernst: 'HOOG' },
    { p: /DigiDClusterHybrid/i,              l: 'ChipSoft DigiD authenticatiestroom (NB-177)', ernst: 'HOOG' },

    // Overige
    { p: /centramed\.nl/i,                   l: 'Centramed aansprakelijkheidsverzekeraar (NB-179)', ernst: 'HOOG' },
    { p: /Brijder|Parnassia.*Indigo|Indigo.*Parnassia/i, l: 'Parnassia/Brijder — nooit in behandeling (NB-113)', ernst: 'KRITIEK' },
    { p: /\$lastn/i,                         l: 'FHIR $lastn replay (NB-109)', ernst: 'HOOG' },
    { p: /quliRedirect/i,                    l: 'MedMij quliRedirect cookie', ernst: 'HOOG' },
    { p: /mfn=/i,                            l: 'MedMij provider token mfn=', ernst: 'HOOG' },
];

// Headers die data verbergen of toegang blokkeren — worden uit ALLE responses verwijderd
var BLOKKEER_HEADERS = [
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
];

// Audit trail endpoints — extra logging als ze geblokkeerd zijn
var AUDIT_ENDPOINTS = [
    'GetClinicianAccessLogSettings', 'GetClinicianAccessLogEntries',
    'GetThirdPartyAccessLogEntries', 'access-logs', 'AccessLog',
    'AuditTrail', 'auditlog', 'audit-log', 'audit_log',
];

// ---- hulpfuncties ----

function log(ernst, label, detail) {
    var p = ernst === 'KRITIEK' ? '[!!]' : ernst === 'HOOG' ? '[!]' : ernst === 'MEDIUM' ? '[~]' : '[i]';
    console.log(p + ' [F][' + ernst + '] ' + label);
    if (detail) console.log('       ' + String(detail).slice(0, 400));
}

function hGet(h, n) {
    if (!h) return '';
    var lo = n.toLowerCase(), keys = Object.keys(h);
    for (var i = 0; i < keys.length; i++)
        if (keys[i].toLowerCase() === lo) return String(h[keys[i]] || '');
    return '';
}

function hDel(h, n) {
    if (!h) return;
    var lo = n.toLowerCase(), keys = Object.keys(h);
    for (var i = 0; i < keys.length; i++)
        if (keys[i].toLowerCase() === lo) { delete h[keys[i]]; return; }
}

function str(b) {
    if (!b) return '';
    if (typeof b === 'string') return b;
    try { return String(b); } catch (e) { return ''; }
}

function isAudit(url) {
    for (var i = 0; i < AUDIT_ENDPOINTS.length; i++)
        if (url.indexOf(AUDIT_ENDPOINTS[i]) !== -1) return true;
    return false;
}

// Probeer base64-blokken te decoderen en retourneer de gecombineerde tekst
function ontsluitelBase64(body) {
    var extra = '';
    var re = /[A-Za-z0-9+/]{40,}={0,2}/g;
    var m;
    var count = 0;
    while ((m = re.exec(body)) !== null && count < 30) {
        try {
            var dec = atob(m[0]);
            // Alleen loggen als het leesbare tekst bevat
            if (/[\x20-\x7E]{10,}/.test(dec)) {
                extra += ' [b64:' + dec.replace(/[^\x20-\x7E]/g, '?').slice(0, 200) + ']';
                count++;
            }
        } catch (e) {}
    }
    return extra;
}

// Log alle cookies die in Set-Cookie headers zitten
function logSetCookie(headers, su) {
    var keys = Object.keys(headers);
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].toLowerCase() === 'set-cookie') {
            var val = String(headers[keys[i]]);
            var secure = /;\s*Secure/i.test(val);
            var httpOnly = /;\s*HttpOnly/i.test(val);
            var sameSite = /SameSite=(\w+)/i.exec(val);
            var flags = (secure ? '' : 'GEEN-Secure ') + (httpOnly ? '' : 'GEEN-HttpOnly ') + (sameSite ? '' : 'GEEN-SameSite');
            if (flags.trim()) {
                log('HOOG', 'Cookie zonder beveiligingsvlaggen: ' + val.split(';')[0], su + ' | ' + flags.trim());
            } else {
                log('INFO', 'Cookie (OK): ' + val.split(';')[0], su);
            }
        }
    }
}

// Scan body voor alle bekende patronen — logt alle treffers, niet slechts de eerste
function scanBody(body, su, label) {
    if (!body || body.length < 2) return;
    for (var i = 0; i < PATRONEN.length; i++) {
        var re = new RegExp(PATRONEN[i].p.source, PATRONEN[i].p.flags || 'gi');
        var m;
        while ((m = re.exec(body)) !== null) {
            var idx = m.index;
            var ctx = body.substring(Math.max(0, idx - 80), idx + 150).replace(/[\n\r\t]+/g, ' ').trim();
            log(PATRONEN[i].ernst, PATRONEN[i].l + ' [' + label + ']', su + ' | ...' + ctx + '...');
            // voorkom eindeloze loop bij zero-width match
            if (re.lastIndex === idx) re.lastIndex++;
        }
    }
}

// Verwijder ALLE CSS-verberging — niet alleen bekende klassen
function stripAlleVerberging(body) {
    // display:none in stylesheets (zowel klasse als inline)
    body = body.replace(/(\{[^}]*)\bdisplay\s*:\s*none\s*(!important)?([^}]*\})/gi,
        '$1display:block $3');
    // visibility:hidden
    body = body.replace(/visibility\s*:\s*hidden(\s*!important)?/gi, 'visibility:visible');
    // opacity:0 (rendering aanval)
    body = body.replace(/\bopacity\s*:\s*0(\s*!important)?/gi, 'opacity:1');
    // font-size:0 (onzichtbare tekst)
    body = body.replace(/\bfont-size\s*:\s*0(px|em|rem|pt)?(\s*!important)?/gi, 'font-size:inherit');
    // height:0 / width:0 in combinatie met overflow:hidden (clip-aanval)
    body = body.replace(/\bheight\s*:\s*0(px)?(\s*!important)?/gi, 'height:auto');
    body = body.replace(/\bwidth\s*:\s*0(px)?(\s*!important)?/gi, 'width:auto');
    // clip/clip-path verberging
    body = body.replace(/\bclip\s*:\s*rect\s*\([^)]*\)/gi, 'clip:auto');
    body = body.replace(/\bclip-path\s*:\s*[^;}"]+/gi, 'clip-path:none');
    // position off-screen
    body = body.replace(/(left|top)\s*:\s*-\d{3,}(px|em|rem)(\s*!important)?/gi, '$1:auto');
    // overflow:hidden op elementen die data verbergen
    body = body.replace(/\boverflow\s*:\s*hidden(\s*!important)?/gi, 'overflow:visible');

    // Inline style="display:none" op HTML-elementen — maak zichtbaar en markeer
    body = body.replace(/(<[^>]+)\bstyle\s*=\s*["']([^"']*)display\s*:\s*none([^"']*)["']/gi,
        function (_, tag, pre, post) {
            return tag + ' style="' + pre + 'display:block' + post + '" data-forensisch-verborgen="1"';
        });

    // hidden attribuut
    body = body.replace(/(<[^>]+)\bhidden\b([^>]*>)/gi,
        function (_, tag, rest) {
            return tag + ' data-forensisch-hidden="1"' + rest;
        });

    return body;
}

// ---- context detectie ----

var isResp = false;
var isReq  = false;
try { isResp = typeof $response !== 'undefined' && $response !== null; } catch (e) {}
try { isReq  = !isResp && typeof $request !== 'undefined' && $request !== null; } catch (e) {}

// ================================================================
//  RESPONSE HANDLER
// ================================================================
if (isResp) {

    var url     = '';
    var method  = '';
    var status  = 0;
    var headers = {};
    var body    = '';

    try { url    = $request.url || ''; }    catch (e) {}
    try { method = $request.method || ''; } catch (e) {}
    try { status = $response.status || 0; } catch (e) {}
    try { headers = $response.headers ? JSON.parse(JSON.stringify($response.headers)) : {}; } catch (e) { headers = {}; }
    try { body   = str($response.body); }   catch (e) { body = ''; }

    var su = url.split('?')[0];
    var origBody    = body;
    var origHeaders = JSON.parse(JSON.stringify(headers));

    try {
        console.log('[F] >>> RESPONSE ' + method + ' HTTP/' + status + ' ' + su + ' (' + body.length + ' bytes)');

        // 1. LOG ALLE HEADERS — niets overslaan
        var hKeys = Object.keys(headers);
        for (var hi = 0; hi < hKeys.length; hi++) {
            var hv = String(headers[hKeys[hi]]).slice(0, 200);
            console.log('[F]   header: ' + hKeys[hi] + ': ' + hv);
        }

        // 2. AUDIT TRAIL DETECTIE
        if (isAudit(url)) {
            if (status === 403 || status === 401 || status === 0) {
                log('KRITIEK', 'Audit trail GEBLOKKEERD HTTP ' + status + ' (NB-163)', su);
            } else {
                log('INFO', 'Audit trail BEREIKBAAR HTTP ' + status, su);
            }
        }

        // 3. VERWIJDER ALLE BLOKKERENDE HEADERS (op elk response)
        for (var bi = 0; bi < BLOKKEER_HEADERS.length; bi++) {
            var bestaand = hGet(headers, BLOKKEER_HEADERS[bi]);
            if (bestaand) {
                log('INFO', 'Geblokkeerde header verwijderd: ' + BLOKKEER_HEADERS[bi], bestaand.slice(0, 120));
                hDel(headers, BLOKKEER_HEADERS[bi]);
            }
        }

        // 4. CORS VOLLEDIG OPENEN op elk response
        headers['Access-Control-Allow-Origin']   = '*';
        headers['Access-Control-Allow-Methods']  = 'GET, POST, OPTIONS, PUT, DELETE, PATCH';
        headers['Access-Control-Allow-Headers']  = '*';
        headers['Access-Control-Expose-Headers'] = '*';

        // 5. LOG EN ANALYSEER SET-COOKIE HEADERS
        logSetCookie(headers, su);

        // 6. HTTP 204 / lege responses op API endpoints
        if (status === 204 && body.length === 0) {
            log('HOOG', 'HTTP 204 lege response — mogelijke data-filtering', su);
        }
        if (status === 403 || status === 401) {
            log('HOOG', 'Toegang geweigerd HTTP ' + status + ' (kan data verbergen)', su);
        }

        // 7. SCAN REQUEST BODY (ook aanwezig via $request in response-context)
        var reqBody = '';
        try { reqBody = str($request.body); } catch (e) {}
        if (reqBody.length > 2) scanBody(reqBody, su, 'REQ-BODY');

        // 8. SCAN RESPONSE BODY voor alle patronen
        scanBody(body, su, 'RESP-BODY');

        // 9. BASE64 ONTSLEUTELING — scan gedecodeerde inhoud ook
        if (body.length > 0) {
            var b64extra = ontsluitelBase64(body);
            if (b64extra.length > 0) {
                scanBody(b64extra, su, 'BASE64-DECODED');
                console.log('[F] Base64 gedecodeerde fragmenten: ' + b64extra.slice(0, 500));
            }
        }

        // 10. CSS/DOM VERBERGING VERWIJDEREN — op elk HTML/CSS response
        var ct = hGet(headers, 'content-type').toLowerCase();
        var isHTML = ct.indexOf('text/html') !== -1 || body.slice(0, 100).toLowerCase().indexOf('<html') !== -1;
        var isCSS  = ct.indexOf('text/css') !== -1 || su.indexOf('.css') !== -1;

        if (isHTML || isCSS || body.indexOf('display') !== -1) {
            var lenVoor = body.length;
            body = stripAlleVerberging(body);
            var verandering = body.length - lenVoor;
            if (Math.abs(verandering) > 0) {
                log('KRITIEK', 'Verberging verwijderd (' + verandering + ' bytes gewijzigd) (NB-12/53)', su);
            }
        }

        // 11. INJECT FORENSISCH BANNER in HTML pagina's
        if (isHTML && body.indexOf('</body>') !== -1) {
            var banner = '<div id="__f_banner" style="position:fixed;bottom:0;left:0;right:0;' +
                'background:#c00;color:#fff;font:bold 12px monospace;padding:4px 8px;z-index:2147483647;">' +
                'FORENSISCH PROXY ACTIEF — ' + new Date().toISOString() + ' — ' + su +
                '</div>';
            body = body.replace('</body>', banner + '</body>');
        }

        $done({ status: status, headers: headers, body: body });

    } catch (e) {
        console.log('[F] FOUT response handler: ' + e);
        // Bij fout: originele response doorsturen — nooit blokkeren
        try { $done({ status: status, headers: origHeaders, body: origBody }); }
        catch (e2) { try { $done({}); } catch (e3) {} }
    }

// ================================================================
//  REQUEST HANDLER
// ================================================================
} else if (isReq) {

    var url     = '';
    var method  = '';
    var headers = {};
    var body    = '';

    try { url     = $request.url || ''; }    catch (e) {}
    try { method  = $request.method || ''; } catch (e) {}
    try { headers = $request.headers || {}; } catch (e) {}
    try { body    = str($request.body); }    catch (e) {}

    var su = url.split('?')[0];

    try {
        console.log('[F] <<< REQUEST ' + method + ' ' + su);

        // Log alle request headers
        var rhKeys = Object.keys(headers);
        for (var ri = 0; ri < rhKeys.length; ri++) {
            var rv = String(headers[rhKeys[ri]]).slice(0, 200);
            console.log('[F]   header: ' + rhKeys[ri] + ': ' + rv);
        }

        // Audit trail detectie
        if (isAudit(url)) log('HOOG', 'Audit trail request ' + method + ' (NB-163)', su);

        // PII in URL
        if (url.indexOf('215672185') !== -1) log('KRITIEK', 'BSN 215672185 in URL!', su);
        if (url.indexOf('0133033170') !== -1) log('KRITIEK', 'MDN 0133033170 in URL!', su);
        if (url.indexOf('2001702222') !== -1) log('KRITIEK', 'ChipSoft patient-ID in URL! (NB-177)', su);

        // Tokens en auth
        var auth = hGet(headers, 'authorization');
        if (auth) log('INFO', 'Authorization: ' + auth.slice(0, 60));
        var bearer = /Bearer\s+([A-Za-z0-9._-]{20,})/i.exec(auth);
        if (bearer) log('INFO', 'Bearer token gevonden', bearer[1].slice(0, 80));

        // Alle cookies loggen
        var ck = hGet(headers, 'cookie');
        if (ck) {
            console.log('[F]   cookies: ' + ck.slice(0, 600));
            if (ck.indexOf('quliRedirect') !== -1) log('HOOG', 'MedMij quliRedirect cookie aanwezig', su);
            if (ck.indexOf('JSESSIONID') !== -1) log('INFO', 'JSESSIONID sessiecookie', su);
            if (ck.indexOf('SESSION') !== -1) log('INFO', 'Session cookie aanwezig', su);
        }

        // CSRF tokens
        var csrf = hGet(headers, 'x-csrf-token') || hGet(headers, 'x-xsrf-token');
        if (csrf) log('INFO', 'CSRF token: ' + csrf.slice(0, 40), su);

        // Scan request body
        if (body.length > 2) {
            scanBody(body, su, 'REQ-BODY');
            var b64req = ontsluitelBase64(body);
            if (b64req.length > 0) scanBody(b64req, su, 'REQ-BASE64');
        }

        // Scan URL querystring voor patronen
        var qs = url.indexOf('?') !== -1 ? url.slice(url.indexOf('?')) : '';
        if (qs.length > 2) scanBody(qs, su, 'URL-PARAMS');

        // Request doorsturen zonder wijzigingen — we blokkeren nooit requests
        $done({});

    } catch (e) {
        console.log('[F] FOUT request handler: ' + e);
        try { $done({}); } catch (e2) {}
    }

} else {
    console.log('[F] Geen Proxyman proxy-context (gebruik als Script Rule).');
    try { $done({}); } catch (e) {}
}

})();
