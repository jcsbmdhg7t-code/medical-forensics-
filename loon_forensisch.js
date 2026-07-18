/**
 * FORENSISCH LOON SCRIPT
 * ======================
 * App: Loon (iOS) — gratis versie werkt, geen licentie nodig
 *
 * INSTALLATIE IN LOON:
 * 1. Open Loon → onderste balk → "Plug-in" tabblad
 * 2. Tik rechtsboven op + → "Script toevoegen"
 * 3. Plak dit hele bestand erin
 * 4. Script type: HTTP Request + Response
 * 5. URL-filter: *.spaarnegasthuis.nl, *.mijnspaarnegas*, *.medmij.nl
 *    (of gebruik * voor ALLES)
 * 6. Sla op
 *
 * OF via Configuratie (tekstbestand):
 *   [Script]
 *   http-request  *spaarnegasthuis*  script-path=loon_forensisch.js,timeout=60,tag=forensisch-req
 *   http-response *spaarnegasthuis*  script-path=loon_forensisch.js,requires-body=true,timeout=60,tag=forensisch-resp
 *
 * LOGS BEKIJKEN:
 *   Loon → Hulpmiddelen (Tools) → Recente verzoeken → tik op verzoek → Script Log
 *
 * iOS MELDINGEN:
 *   Loon → Instellingen → Meldingen → aanzetten
 *   Bij elke KRITIEKE treffer verschijnt een iOS melding.
 */

(function () {

var PATRONEN = [
    { p: /F19\.1/i,                          l: 'F19.1 psychoactieve stof',             nb: 'NB-01', e: 'KRITIEK' },
    { p: /neusdruppelmisbruik/i,             l: 'Term neusdruppelmisbruik',             nb: 'NB-01', e: 'KRITIEK' },
    { p: /361055000/,                        l: 'SNOMED 361055000 alcoholmisbruik',     nb: 'NB-03', e: 'KRITIEK' },
    { p: /228273003/,                        l: 'SNOMED 228273003 drugsgebruik',        nb: 'NB-23', e: 'KRITIEK' },
    { p: /228366006/,                        l: 'SNOMED 228366006 stimulant misuse',    nb: 'NB-23b',e: 'KRITIEK' },
    { p: /266927001/,                        l: 'SNOMED 266927001 afhankelijkheid',     nb: 'NB-23c',e: 'KRITIEK' },
    { p: /F60\.31/i,                         l: 'F60.31 borderline',                    nb: 'NB-xx', e: 'KRITIEK' },
    { p: /20260110033455/,                   l: 'NACHT-TIMESTAMP 10-01-2026 03:34:55',  nb: 'NB-166',e: 'KRITIEK' },
    { p: /nullFlavor\s*=\s*["']?UNK/i,      l: 'CDA nullFlavor=UNK anonieme auteur',   nb: 'NB-18', e: 'KRITIEK' },
    { p: /extension\s*=\s*["']?999999/i,    l: 'Epic extension=999999 anoniem',        nb: 'NB-18', e: 'KRITIEK' },
    { p: /extension\s*=\s*["']?51504662/i,  l: 'N.M. Nota extensie code A',            nb: 'NB-04', e: 'KRITIEK' },
    { p: /extension\s*=\s*["']?84107660/i,  l: 'N.M. Nota extensie code B',            nb: 'NB-04', e: 'KRITIEK' },
    { p: /extension\s*=\s*["']?373282512/i, l: 'A. al-Mousawi extensie code',          nb: 'NB-05', e: 'KRITIEK' },
    { p: /Epic@spaarnegasthuis\.nl/i,       l: 'Epic admin e-mail',                    nb: 'NB-05', e: 'KRITIEK' },
    { p: /DISABLEMYCONDITIONS/i,            l: 'Flag DISABLEMYCONDITIONS',             nb: 'NB-11', e: 'KRITIEK' },
    { p: /DISABLEPLANOFCARE/i,              l: 'Flag DISABLEPLANOFCARE',               nb: 'NB-11', e: 'KRITIEK' },
    { p: /SUBSTANCEHXQNR/i,                 l: 'SUBSTANCEHXQNR verslavingsmodule',     nb: 'NB-108',e: 'KRITIEK' },
    { p: /AUTOGENERATESIGNATURE/i,          l: 'AUTOGENERATESIGNATURE',                nb: 'NB-82', e: 'KRITIEK' },
    { p: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i,l:'Audit trail feature flag',             nb: 'NB-163',e: 'KRITIEK' },
    { p: /noView\s*:\s*true/i,              l: 'noView:true data verborgen',            nb: 'NB-99', e: 'KRITIEK' },
    { p: /HANDMATIGE_EDIT_BOM/i,            l: 'Bytemanipulatie vlag',                 nb: 'NB-13', e: 'KRITIEK' },
    { p: /hiddenProvider/i,                 l: 'CSS klasse hiddenProvider',             nb: 'NB-12', e: 'KRITIEK' },
    { p: /CEDataExternal/i,                 l: 'CSS klasse CEDataExternal',            nb: 'NB-12', e: 'KRITIEK' },
    { p: /override\.css/i,                  l: 'override.css referentie',              nb: 'NB-89', e: 'KRITIEK' },
    { p: /lucy\.css|lucy_colors/i,          l: 'lucy.css renderingslaag',              nb: 'NB-71', e: 'KRITIEK' },
    { p: /recording_capture_keystrokes\s*=\s*true/i, l:'Hotjar keystroke capture ACTIEF', nb:'NB-53',e:'KRITIEK' },
    { p: /hjid\s*=|hotjar\.com/i,           l: 'Hotjar tracker',                       nb: 'NB-79', e: 'KRITIEK' },
    { p: /account_id\s*[:=]\s*763232/i,     l: 'VWO account_id=763232',               nb: 'NB-178',e: 'KRITIEK' },
    { p: /vwo_uuid/i,                       l: 'VWO UUID tracking',                    nb: 'NB-178',e: 'KRITIEK' },
    { p: /body\s*\{[^}]*opacity\s*:\s*0/i,  l: 'VWO body opacity:0 aanval',           nb: 'NB-178',e: 'KRITIEK' },
    { p: /ChipSoft\.PlatformServices/i,     l: 'ChipSoft HiX API blootgesteld',        nb: 'NB-177',e: 'KRITIEK' },
    { p: /GetCurrentPatientAndUserObject/i, l: 'ChipSoft patientobject gelekt',        nb: 'NB-177',e: 'KRITIEK' },
    { p: /2001702222/,                       l: 'ChipSoft patient-ID Grothe',           nb: 'NB-177',e: 'KRITIEK' },
    { p: /215672185/,                        l: 'BSN Grothe in response',               nb: 'NB-166',e: 'KRITIEK' },
    { p: /0133033170/,                       l: 'MDN Grothe in response',               nb: 'NB-166',e: 'KRITIEK' },
    { p: /Brijder|Parnassia.*Indigo/i,      l: 'Parnassia/Brijder — nooit in beh.',   nb: 'NB-113',e: 'KRITIEK' },
    { p: /spaarne-rebuild\.productie\.hoppinger/i, l:'Hoppinger productie-injectie',   nb: 'NB-114',e: 'KRITIEK' },
    { p: /FocusZorgTeam.*test\.authorization/i, l:'FocusZorgTeam test in productie',   nb: 'NB-91', e: 'KRITIEK' },
    { p: /transactie.{0,10}77832/i,         l: 'Transactie-ID 77832 SNOMED SUCCESS',   nb: 'NB-23', e: 'KRITIEK' },
    { p: /sentry\.io/i,                     l: 'Sentry.io telemetrie',                 nb: 'NB-69', e: 'HOOG' },
    { p: /DE36B70A/i,                        l: 'Sentry device ID DE36B70A',            nb: 'NB-69', e: 'HOOG' },
    { p: /hoppinger\.com/i,                 l: 'Hoppinger supply chain',               nb: 'NB-114',e: 'HOOG' },
    { p: /datadog.*browser-intake/i,        l: 'Datadog RUM telemetrie',               nb: 'NB-69', e: 'HOOG' },
    { p: /WoundListSection/i,               l: 'CSS WoundListSection',                 nb: 'NB-12', e: 'HOOG' },
    { p: /printBlackText/i,                 l: 'printBlackText alarmkleur',            nb: 'NB-84', e: 'HOOG' },
    { p: /DYN_CURRENT_USER/i,              l: 'ChipSoft HiX sessietoken',             nb: 'NB-177',e: 'HOOG' },
    { p: /GetPatientDocuments/i,            l: 'ChipSoft GetPatientDocuments',         nb: 'NB-177',e: 'HOOG' },
    { p: /GetDcrRegistrations/i,            l: 'ChipSoft GetDcrRegistrations',         nb: 'NB-177',e: 'HOOG' },
    { p: /centramed\.nl/i,                  l: 'Centramed aansprakelijkheidsverz.',    nb: 'NB-179',e: 'HOOG' },
    { p: /quliRedirect/i,                   l: 'MedMij quliRedirect cookie',           nb: 'MEDMIJ',e: 'HOOG' },
    { p: /mfn=/i,                            l: 'MedMij provider token mfn=',           nb: 'MEDMIJ',e: 'HOOG' },
    { p: /\$lastn/i,                         l: 'FHIR $lastn replay',                   nb: 'NB-109',e: 'HOOG' },
];

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

var AUDIT_ENDPOINTS = [
    'GetClinicianAccessLogSettings', 'GetClinicianAccessLogEntries',
    'GetThirdPartyAccessLogEntries', 'access-logs', 'AccessLog', 'AuditTrail',
];

// ── hulpfuncties ──

function str(b) { return b ? String(b) : ''; }

function hGet(h, n) {
    if (!h) return '';
    var lo = n.toLowerCase(), k = Object.keys(h);
    for (var i = 0; i < k.length; i++)
        if (k[i].toLowerCase() === lo) return str(h[k[i]]);
    return '';
}

function hDel(h, n) {
    if (!h) return;
    var lo = n.toLowerCase(), k = Object.keys(h);
    for (var i = 0; i < k.length; i++)
        if (k[i].toLowerCase() === lo) { delete h[k[i]]; return; }
}

function isAudit(url) {
    return AUDIT_ENDPOINTS.some(function(e) { return url.indexOf(e) !== -1; });
}

function melding(titel, ondertitel, tekst) {
    try { $notification.post(titel, ondertitel, tekst); } catch(e) {}
}

function scan(body, url, ctx) {
    if (!body || body.length < 2) return;
    var su = url.split('?')[0];
    var kritiek = [];
    for (var i = 0; i < PATRONEN.length; i++) {
        var re = new RegExp(PATRONEN[i].p.source, 'gi');
        var m;
        while ((m = re.exec(body)) !== null) {
            var idx  = m.index;
            var frag = body.substring(Math.max(0, idx - 60), idx + 100).replace(/[\n\r\t]+/g, ' ').trim();
            var regel = '[' + PATRONEN[i].e + '] ' + PATRONEN[i].nb + ' ' + PATRONEN[i].l;
            console.log('[F][' + ctx + '] ' + regel + ' | ' + su);
            console.log('    → ...' + frag + '...');
            if (PATRONEN[i].e === 'KRITIEK') kritiek.push(PATRONEN[i].nb + ' ' + PATRONEN[i].l);
            if (re.lastIndex === idx) re.lastIndex++;
        }
    }
    if (kritiek.length > 0) {
        melding('🔴 FORENSISCH TREFFER', su.slice(-60), kritiek.slice(0, 3).join(' | '));
    }
}

function b64scan(body, url) {
    var re = /[A-Za-z0-9+\/]{40,}={0,2}/g, m;
    var count = 0;
    while ((m = re.exec(body)) !== null && count < 20) {
        try {
            var d = atob(m[0]);
            if (/[\x20-\x7E]{10,}/.test(d)) {
                scan(d, url, 'BASE64');
                count++;
            }
        } catch(e) {}
    }
}

function stripVerberging(body) {
    var v = [
        [/(\{[^}]*)\bdisplay\s*:\s*none(\s*!important)?([^}]*\})/gi, '$1display:block$3'],
        [/\bvisibility\s*:\s*hidden(\s*!important)?/gi, 'visibility:visible'],
        [/\bopacity\s*:\s*0(\s*!important)?/gi, 'opacity:1'],
        [/\bfont-size\s*:\s*0(px|em|rem)?(\s*!important)?/gi, 'font-size:inherit'],
        [/\bheight\s*:\s*0(px)?(\s*!important)?/gi, 'height:auto'],
        [/\bmax-height\s*:\s*0(px)?(\s*!important)?/gi, 'max-height:none'],
        [/\bclip\s*:\s*rect\s*\([^)]*\)/gi, 'clip:auto'],
        [/\b(left|top)\s*:\s*-\d{3,}(px|em)(\s*!important)?/gi, '$1:auto'],
        [/(<[^>]+)\bstyle\s*=\s*"([^"]*display\s*:\s*none[^"]*)"/gi,
            function(_,tag,sty){ return tag+' style="'+sty.replace(/display\s*:\s*none/,'display:block')+'" data-fo="1"'; }],
        [/\bhidden\b(?=\s*[>\/\s])/gi, 'data-was-hidden'],
    ];
    var n = 0;
    for (var i = 0; i < v.length; i++) {
        var nieuw = body.replace(v[i][0], v[i][1]);
        if (nieuw !== body) { n++; body = nieuw; }
    }
    return { body: body, n: n };
}

// ── context detectie ──

var isResp = false, isReq = false;
try { isResp = typeof $response !== 'undefined' && $response !== null; } catch(e) {}
try { isReq  = !isResp && typeof $request !== 'undefined' && $request !== null; } catch(e) {}

// ════════════════════════════════════════════════════════════
//  RESPONSE
// ════════════════════════════════════════════════════════════
if (isResp) {
    var url = '', method = '', status = 0, headers = {}, body = '';
    try { url    = $request.url || ''; }     catch(e) {}
    try { method = $request.method || ''; }  catch(e) {}
    try { status = $response.status || 0; }  catch(e) {}
    try { headers = $response.headers ? JSON.parse(JSON.stringify($response.headers)) : {}; } catch(e) { headers = {}; }
    try { body   = str($response.body); }    catch(e) {}

    var su = url.split('?')[0];
    var origBody = body, origHeaders = JSON.parse(JSON.stringify(headers));

    try {
        console.log('[F] <<< RESPONSE ' + method + ' ' + status + ' ' + su + ' (' + body.length + 'b)');

        // Audit trail
        if (isAudit(url)) {
            if (status === 401 || status === 403 || status === 0) {
                console.log('[KRITIEK] Audit trail GEBLOKKEERD HTTP ' + status);
                melding('🔴 AUDIT TRAIL GEBLOKKEERD', 'HTTP ' + status, su);
            } else {
                console.log('[INFO] Audit trail bereikbaar HTTP ' + status + ' | ' + su);
            }
        }

        // Verwijder ALLE blokkerende headers
        for (var bi = 0; bi < BLOKKEER_HEADERS.length; bi++) {
            var bv = hGet(headers, BLOKKEER_HEADERS[bi]);
            if (bv) {
                console.log('[INFO] Header verwijderd: ' + BLOKKEER_HEADERS[bi]);
                hDel(headers, BLOKKEER_HEADERS[bi]);
            }
        }

        // Open CORS volledig
        headers['Access-Control-Allow-Origin']   = '*';
        headers['Access-Control-Allow-Methods']  = 'GET, POST, OPTIONS, PUT, DELETE, PATCH';
        headers['Access-Control-Allow-Headers']  = '*';
        headers['Access-Control-Expose-Headers'] = '*';

        // HTTP 204 op API
        if (status === 204) {
            console.log('[HOOG] HTTP 204 lege response — mogelijke data-filtering: ' + su);
        }

        // Scan body
        scan(body, url, 'RESP');
        b64scan(body, url);

        // CSS verberging strippen
        var ct = hGet(headers, 'content-type').toLowerCase();
        if (ct.indexOf('text/html') !== -1 || ct.indexOf('text/css') !== -1 ||
            body.indexOf('display') !== -1 || body.indexOf('hidden') !== -1) {
            var res = stripVerberging(body);
            if (res.n > 0) {
                console.log('[KRITIEK] CSS verberging verwijderd: ' + res.n + ' aanpassingen | ' + su);
                body = res.body;
            }
        }

        $done({ status: status, headers: headers, body: body });

    } catch(e) {
        console.log('[F] FOUT response: ' + e);
        try { $done({ status: status, headers: origHeaders, body: origBody }); }
        catch(e2) { try { $done({}); } catch(e3) {} }
    }

// ════════════════════════════════════════════════════════════
//  REQUEST
// ════════════════════════════════════════════════════════════
} else if (isReq) {
    var url = '', method = '', headers = {}, body = '';
    try { url     = $request.url || ''; }    catch(e) {}
    try { method  = $request.method || ''; } catch(e) {}
    try { headers = $request.headers || {}; } catch(e) {}
    try { body    = str($request.body); }    catch(e) {}

    var su = url.split('?')[0];

    try {
        console.log('[F] >>> REQUEST ' + method + ' ' + su);

        if (isAudit(url)) {
            console.log('[HOOG] Audit trail request ' + method + ' | ' + su);
            melding('🔍 Audit trail request', method, su.slice(-60));
        }

        // PII in URL
        if (url.indexOf('215672185') !== -1) { console.log('[KRITIEK] BSN in URL!'); melding('🔴 BSN in URL', su, '215672185'); }
        if (url.indexOf('0133033170') !== -1){ console.log('[KRITIEK] MDN in URL!'); melding('🔴 MDN in URL', su, '0133033170'); }
        if (url.indexOf('2001702222') !== -1){ console.log('[KRITIEK] ChipSoft-ID in URL!'); }

        // Auth header
        var auth = hGet(headers, 'authorization');
        if (auth) console.log('[INFO] Authorization: ' + auth.slice(0, 60));

        // Cookies
        var ck = hGet(headers, 'cookie');
        if (ck) {
            if (ck.indexOf('quliRedirect') !== -1) console.log('[HOOG] MedMij quliRedirect cookie aanwezig');
            if (ck.indexOf('JSESSIONID') !== -1) console.log('[INFO] JSESSIONID sessiecookie aanwezig');
            console.log('[INFO] Cookies: ' + ck.slice(0, 200));
        }

        scan(body, url, 'REQ');
        b64scan(body, url);

        // Scan URL params
        var qs = url.indexOf('?') !== -1 ? url.slice(url.indexOf('?')) : '';
        if (qs) scan(qs, url, 'URL');

        $done({});

    } catch(e) {
        console.log('[F] FOUT request: ' + e);
        try { $done({}); } catch(e2) {}
    }

} else {
    console.log('[F] Geen proxy-context.');
    try { $done({}); } catch(e) {}
}

})();
