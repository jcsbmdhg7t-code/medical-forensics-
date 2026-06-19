(function () {

var CFG = {
    verwijderCORSBlokkade: true,
    verwijderCSSVerberging: true,
    verwijderCSP: true,
    auditTrailEndpoints: [
        'GetClinicianAccessLogSettings',
        'GetClinicianAccessLogEntries',
        'GetThirdPartyAccessLogEntries',
        'access-logs',
        'AccessLog',
        'AuditTrail',
    ],
    forensischePatronen: [
        { p: /F19\.1|neusdruppelmisbruik/i,            l: 'F19.1 neusdruppelmisbruik (NB-01)' },
        { p: /361055000/,                               l: 'SNOMED 361055000 (NB-03)' },
        { p: /228273003/,                               l: 'SNOMED 228273003 drugsgebruik (NB-23)' },
        { p: /228366006/,                               l: 'SNOMED 228366006 stimulant misuse' },
        { p: /nullFlavor="UNK"/i,                       l: 'CDA nullFlavor=UNK anonieme auteur (NB-18)' },
        { p: /extension="999999"/i,                     l: 'Epic ext=999999 anonymous (NB-18)' },
        { p: /extension="373282512"/i,                  l: 'A. al-Mousawi ext (NB-05)' },
        { p: /extension="51504662"|extension="84107660"/i, l: 'N.M. Nota ext (NB-04)' },
        { p: /Epic@spaarnegasthuis\.nl/i,               l: 'Epic admin email (NB-05)' },
        { p: /DISABLEMYCONDITIONS/i,                    l: 'Feature flag DISABLEMYCONDITIONS (NB-11)' },
        { p: /DISABLEPLANOFCARE/i,                      l: 'Feature flag DISABLEPLANOFCARE (NB-11)' },
        { p: /SUBSTANCEHXQNR/i,                         l: 'SUBSTANCEHXQNR module (NB-108)' },
        { p: /AUTOGENERATESIGNATURE/i,                  l: 'AUTOGENERATESIGNATURE (NB-82)' },
        { p: /recording_capture_keystrokes=true/i,      l: 'Hotjar keystroke capture ACTIEF (NB-53)' },
        { p: /spaarne-rebuild\.productie\.hoppinger/i,  l: 'Hoppinger supply chain (NB-114)' },
        { p: /override\.css/i,                          l: 'override.css referentie (NB-53/89)' },
        { p: /hiddenProvider|CEDataExternal/i,          l: 'CSS verberging klasse (NB-12)' },
        { p: /noView\s*:\s*true/i,                      l: 'noView:true (NB-99)' },
        { p: /HANDMATIGE_EDIT_BOM/i,                    l: 'Bytemanipulatieflag (NB-13)' },
        { p: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i,       l: 'Audit trail feature flag (NB-163)' },
        { p: /GUARD\b/,                                 l: 'GUARD blok CDA (NB-56)' },
        { p: /noView\s*:\s*true/i,                      l: 'noView:true (NB-99)' },
        { p: /20260110033455/,                          l: 'KRITIEK NACHT-TIMESTAMP AVG-dag 10-01-2026 (NB-166)' },
        { p: /transactie.{0,10}77832/i,                 l: 'Transactie-ID 77832 SNOMED SUCCESS (NB-23)' },
        { p: /215672185/,                               l: 'BSN in response body' },
        { p: /0133033170/,                              l: 'MDN in response body' },
        { p: /DE36B70A/i,                               l: 'Sentry device ID DE36B70A (NB-69)' },
        { p: /hotjar\.com|hjid=/i,                      l: 'Hotjar tracker (NB-79)' },
        { p: /sentry\.io/i,                             l: 'Sentry.io telemetrie (NB-69)' },
        { p: /hoppinger\.com/i,                         l: 'Hoppinger.com (NB-114)' },
        { p: /FocusZorgTeam.*test\.authorization/i,     l: 'FocusZorgTeam test-server productie (NB-91)' },
        { p: /printBlackText/i,                         l: 'printBlackText alarmkleuren (NB-84)' },
        { p: /lucy\.css|lucy_colors/i,                  l: 'lucy.css renderingslaag (NB-71)' },
        { p: /\$lastn/i,                                l: 'FHIR $lastn re-replay (NB-109)' },
        { p: /Brijder|Parnassia.*Indigo|Indigo.*Parnassia/i, l: 'Parnassia/Brijder FHIR nooit in behandeling (NB-113)' },
    ],
};

function log(ernst, label, detail) {
    var prefix = { KRITIEK: '[!!]', HOOG: '[!]', MEDIUM: '[~]', INFO: '[i]' }[ernst] || '[?]';
    console.log(prefix + ' [F][' + ernst + '] ' + label);
    if (detail) console.log('    -> ' + String(detail).slice(0, 300));
}

function hGet(headers, name) {
    if (!headers) return '';
    var lo = name.toLowerCase();
    var keys = Object.keys(headers);
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].toLowerCase() === lo) return String(headers[keys[i]] || '');
    }
    return '';
}

function hDel(headers, name) {
    if (!headers) return;
    var lo = name.toLowerCase();
    var keys = Object.keys(headers);
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].toLowerCase() === lo) delete headers[keys[i]];
    }
}

function isAudit(url) {
    for (var i = 0; i < CFG.auditTrailEndpoints.length; i++) {
        if (url.indexOf(CFG.auditTrailEndpoints[i]) !== -1) return true;
    }
    return false;
}

function bodyStr(b) {
    if (!b) return '';
    if (typeof b === 'string') return b;
    try { return String(b); } catch (e) { return ''; }
}

function isText(ct) {
    if (!ct) return false;
    var s = ct.toLowerCase();
    return s.indexOf('text/') !== -1 ||
           s.indexOf('application/json') !== -1 ||
           s.indexOf('application/xml') !== -1 ||
           s.indexOf('application/javascript') !== -1 ||
           s.indexOf('+xml') !== -1 ||
           s.indexOf('+json') !== -1;
}

function applyCORSHeaders(headers) {
    var rm = [
        'access-control-allow-origin',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-expose-headers',
        'x-frame-options',
        'content-security-policy',
        'content-security-policy-report-only',
        'x-content-type-options',
    ];
    for (var i = 0; i < rm.length; i++) hDel(headers, rm[i]);
    headers['Access-Control-Allow-Origin'] = '*';
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE';
    headers['Access-Control-Allow-Headers'] = '*';
    headers['Access-Control-Expose-Headers'] = '*';
}

function stripCSP(headers) {
    hDel(headers, 'content-security-policy');
    hDel(headers, 'content-security-policy-report-only');
    hDel(headers, 'x-frame-options');
    hDel(headers, 'x-xss-protection');
}

function stripCSSHiding(body) {
    body = body.replace(/(\.hiddenProvider\s*\{[^}]*?)display\s*:\s*none([^}]*\})/gi, '$1display:block$2');
    body = body.replace(/(CEDataExternal\s*\{[^}]*?)display\s*:\s*none\s*!important([^}]*\})/gi, '$1display:block$2');
    body = body.replace(/(\.SRonly\s*\{[^}]*?)left\s*:\s*-\d{4,}px([^}]*\})/gi, '$1left:auto$2');
    body = body.replace(/(\.SRonly\s*\{[^}]*?)font-size\s*:\s*0px?([^}]*\})/gi, '$1font-size:inherit$2');
    body = body.replace(/class="([^"]*hiddenProvider[^"]*)"/gi, 'class="$1" data-f="1" style="display:block!important"');
    body = body.replace(/class="([^"]*CEDataExternal[^"]*)"/gi, 'class="$1" data-f="1" style="display:block!important"');
    body = body.replace(/(visibility\s*:\s*hidden)(\s*!important)?/gi, 'visibility:visible');
    body = body.replace(/(font-size\s*:\s*0)(px|em|rem)?(\s*!important)?/gi, 'font-size:inherit');
    return body;
}

function scan(body, url) {
    if (!body || body.length < 4) return;
    var su = url.split('?')[0];
    var pats = CFG.forensischePatronen;
    for (var i = 0; i < pats.length; i++) {
        var m = body.match(pats[i].p);
        if (m) {
            var idx = body.search(pats[i].p);
            var ctx = body.substring(Math.max(0, idx - 60), idx + 100).replace(/[\n\r]/g, ' ').trim();
            var ernst = pats[i].l.indexOf('KRITIEK') !== -1 ? 'KRITIEK' : 'HOOG';
            log(ernst, pats[i].l, 'URL: ' + su + ' | ...' + ctx + '...');
        }
    }
}

var isResp = false;
var isReq  = false;
try { isResp = typeof $response !== 'undefined' && $response !== null && $response !== undefined; } catch(e) {}
try { isReq  = !isResp && typeof $request !== 'undefined' && $request !== null; } catch(e) {}

if (isResp) {
    var url    = '';
    var method = '';
    var status = 0;
    var headers = {};
    var body   = '';

    try { url    = $request.url || ''; }     catch(e) {}
    try { method = $request.method || ''; }  catch(e) {}
    try { status = $response.status || 0; }  catch(e) {}
    try { headers = $response.headers ? JSON.parse(JSON.stringify($response.headers)) : {}; } catch(e) { headers = {}; }
    try { body   = bodyStr($response.body); } catch(e) { body = ''; }

    var su = url.split('?')[0];
    var origBody = body;
    var origHeaders = JSON.parse(JSON.stringify(headers));

    try {
        console.log('[F] Response: ' + method + ' ' + status + ' ' + su);

        if (!hGet(headers, 'access-control-allow-origin') && isAudit(url)) {
            log('KRITIEK', 'CORS-blokkade audit trail (NB-163)', 'Geen ACAO op ' + su);
        }
        var csp = hGet(headers, 'content-security-policy');
        if (csp) log('MEDIUM', 'CSP aanwezig', csp.slice(0, 120));

        if (isAudit(url)) {
            if (status === 403 || status === 401 || status === 0) {
                log('KRITIEK', 'Audit trail geblokkeerd HTTP ' + status + ' (NB-163)', su);
            } else {
                log('INFO', 'Audit trail bereikbaar HTTP ' + status, su);
            }
        }

        var ct = hGet(headers, 'content-type');
        if (isText(ct) || body.length > 0) {
            scan(body, url);
        }

        if (CFG.verwijderCORSBlokkade && isAudit(url)) {
            applyCORSHeaders(headers);
            log('INFO', 'CORS-blokkade verwijderd', su);
        }

        if (CFG.verwijderCSP) {
            stripCSP(headers);
        }

        var doStrip = CFG.verwijderCSSVerberging && (
            ct.indexOf('text/html') !== -1 ||
            ct.indexOf('text/css') !== -1 ||
            body.indexOf('hiddenProvider') !== -1 ||
            body.indexOf('CEDataExternal') !== -1 ||
            body.indexOf('SRonly') !== -1 ||
            body.indexOf('display:none') !== -1 ||
            body.indexOf('display: none') !== -1
        );
        if (doStrip) {
            var lenVoor = body.length;
            body = stripCSSHiding(body);
            if (body.length !== lenVoor) {
                log('KRITIEK', 'CSS verberging verwijderd (NB-12/53)', su + ' | ' + lenVoor + ' -> ' + body.length + ' bytes');
            }
        }

        if (status === 204 && url.indexOf('api') !== -1) {
            log('HOOG', 'HTTP 204 op API - mogelijke data-filtering', su);
        }

        $done({ status: status, headers: headers, body: body });

    } catch (e) {
        console.log('[F] FOUT response: ' + e);
        try {
            $done({ status: status, headers: origHeaders, body: origBody });
        } catch (e2) {
            try { $done({}); } catch(e3) {}
        }
    }

} else if (isReq) {
    var url    = '';
    var method = '';
    var headers = {};
    var body   = '';

    try { url     = $request.url || ''; }     catch(e) {}
    try { method  = $request.method || ''; }  catch(e) {}
    try { headers = $request.headers || {}; } catch(e) {}
    try { body    = bodyStr($request.body); } catch(e) {}

    var su = url.split('?')[0];

    try {
        console.log('[F] Request: ' + method + ' ' + su);

        if (isAudit(url)) log('HOOG', 'Audit trail request ' + method + ' (NB-163)', su);
        if (url.indexOf('215672185') !== -1) log('INFO', 'BSN 215672185 in URL', su);
        if (url.indexOf('0133033170') !== -1) log('INFO', 'MDN 0133033170 in URL', su);

        var auth = hGet(headers, 'authorization');
        if (auth) log('INFO', 'Authorization header aanwezig', auth.slice(0, 40) + '...');

        var ck = hGet(headers, 'cookie');
        if (ck && ck.indexOf('SESSION') !== -1) log('INFO', 'Session cookie', ck.slice(0, 80));

        scan(body, url);

        $done({});

    } catch (e) {
        console.log('[F] FOUT request: ' + e);
        try { $done({}); } catch(e2) {}
    }

} else {
    console.log('[F] Geen proxy-context.');
    try { $done({}); } catch(e) {}
}

})();
