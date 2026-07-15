/**
 * ss_response.js — Storm Sniffer response interceptor
 * Logs forensic findings + removes CSP/X-Frame-Options + unhides elements
 */

var url = $request.url;
var method = $request.method;
var status = $response.status;
var headers = $response.headers || {};
var body = $response.body || '';
var su = url.indexOf('?') > -1 ? url.split('?')[0] : url;

var AUDIT_ENDPOINTS = [
    'GetClinicianAccessLogSettings', 'GetClinicianAccessLogEntries',
    'GetThirdPartyAccessLogEntries', 'access-logs', 'AccessLog', 'AuditTrail',
];

var CRITICAL_PATTERNS = [
    { re: /F19\.1|neusdruppelmisbruik/i, label: 'F19.1 neusdruppelmisbruik', nb: 'NB-01', ernst: 'KRITIEK' },
    { re: /361055000/, label: 'SNOMED 361055000 (alcoholmisbruik)', nb: 'NB-03', ernst: 'KRITIEK' },
    { re: /228273003/, label: 'SNOMED 228273003 (drugmisbruik)', nb: 'NB-23', ernst: 'KRITIEK' },
    { re: /nullFlavor="UNK"/i, label: 'CDA nullFlavor UNK', nb: 'NB-18', ernst: 'HOOG' },
    { re: /extension="999999"/i, label: 'Epic extension 999999 (anon)', nb: 'NB-18', ernst: 'KRITIEK' },
    { re: /extension="373282512"/i, label: 'al-Mousawi extension', nb: 'NB-05', ernst: 'KRITIEK' },
    { re: /DISABLEMYCONDITIONS/i, label: 'DISABLEMYCONDITIONS flag', nb: 'NB-11', ernst: 'KRITIEK' },
    { re: /DISABLEPLANOFCARE/i, label: 'DISABLEPLANOFCARE flag', nb: 'NB-11', ernst: 'KRITIEK' },
    { re: /SUBSTANCEHXQNR/i, label: 'SUBSTANCEHXQNR (substanceHxQNr)', nb: 'NB-108', ernst: 'KRITIEK' },
    { re: /AUTOGENERATESIGNATURE/i, label: 'AUTOGENERATESIGNATURE', nb: 'NB-82', ernst: 'HOOG' },
    { re: /recording_capture_keystrokes\s*=\s*true/i, label: 'Hotjar keystroke capture', nb: 'NB-53', ernst: 'KRITIEK' },
    { re: /hoppinger\.com/i, label: 'Hoppinger tracker', nb: 'NB-114', ernst: 'HOOG' },
    { re: /override\.css/i, label: 'override.css injected', nb: 'NB-53', ernst: 'HOOG' },
    { re: /hiddenProvider|CEDataExternal/i, label: 'CSS hidden classes', nb: 'NB-12', ernst: 'HOOG' },
    { re: /noView\s*:\s*true/i, label: 'noView:true CSS', nb: 'NB-99', ernst: 'HOOG' },
    { re: /20260110033455/, label: '[KRITIEK] NACHT-TIMESTAMP', nb: 'NB-166', ernst: 'KRITIEK' },
    { re: /215672185/, label: 'BSN Grothe in body', nb: 'NB-166', ernst: 'MEDIUM' },
    { re: /0133033170/, label: 'MDN Grothe in body', nb: 'NB-166', ernst: 'MEDIUM' },
    { re: /hotjar\.com/i, label: 'Hotjar', nb: 'NB-79', ernst: 'HOOG' },
    { re: /sentry\.io/i, label: 'Sentry.io telemetry', nb: 'NB-69', ernst: 'HOOG' },
    { re: /GUARD\b/, label: 'GUARD block', nb: 'NB-56', ernst: 'HOOG' },
    { re: /printBlackText/i, label: 'printBlackText class', nb: 'NB-84', ernst: 'HOOG' },
    { re: /ChipSoft\.PlatformServices/i, label: '[KRITIEK] ChipSoft API exposed', nb: 'NB-177', ernst: 'KRITIEK' },
    { re: /GetCurrentPatientAndUserObject/i, label: '[KRITIEK] ChipSoft patient object', nb: 'NB-177', ernst: 'KRITIEK' },
];

function isAudit(u) {
    for (var i = 0; i < AUDIT_ENDPOINTS.length; i++) {
        if (u.indexOf(AUDIT_ENDPOINTS[i]) > -1) return true;
    }
    return false;
}

function hGet(h, name) {
    var lo = name.toLowerCase();
    var keys = Object.keys(h || {});
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].toLowerCase() === lo) return String(h[keys[i]] || '');
    }
    return '';
}

function hDel(h, name) {
    var lo = name.toLowerCase();
    var keys = Object.keys(h || {});
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].toLowerCase() === lo) { delete h[keys[i]]; return; }
    }
}

function log(ernst, label, detail) {
    var prefix = { 'KRITIEK': '[!!]', 'HOOG': '[!]', 'MEDIUM': '[~]', 'INFO': '[i]' }[ernst] || '[?]';
    console.log(prefix + ' [F-RESP][' + ernst + '] ' + label);
    if (detail) console.log('  -> ' + String(detail).slice(0, 150));
}

try {
    console.log('[F] RESPONSE: ' + method + ' ' + status + ' ' + su.slice(-80));

    // Audit trail access
    if (isAudit(url)) {
        if (status === 403 || status === 401 || status === 0) {
            log('KRITIEK', 'NB-163 Audit trail BLOCKED HTTP ' + status, su);
        } else if (status === 200 || status === 304) {
            log('KRITIEK', 'NB-163 Audit trail ACCESSIBLE HTTP ' + status, su);
        }
    }

    // Pattern scanning
    if (body && body.length > 50) {
        for (var pi = 0; pi < CRITICAL_PATTERNS.length; pi++) {
            if (CRITICAL_PATTERNS[pi].re.test(body)) {
                var idx = body.search(CRITICAL_PATTERNS[pi].re);
                var ctx = body.substring(Math.max(0, idx - 40), idx + 70).replace(/[\n\r]/g, ' ');
                log(CRITICAL_PATTERNS[pi].ernst, CRITICAL_PATTERNS[pi].nb + ' ' + CRITICAL_PATTERNS[pi].label, '...' + ctx + '...');
            }
        }
    }

    // Security headers: remove CSP, X-Frame-Options
    hDel(headers, 'content-security-policy');
    hDel(headers, 'content-security-policy-report-only');
    hDel(headers, 'x-frame-options');
    hDel(headers, 'x-content-type-options');

    // Audit trail CORS bypass
    if (isAudit(url)) {
        var headersToRemove = [
            'access-control-allow-origin', 'access-control-allow-methods',
            'access-control-allow-headers', 'access-control-expose-headers',
            'access-control-allow-credentials', 'access-control-max-age',
        ];
        for (var ri = 0; ri < headersToRemove.length; ri++) hDel(headers, headersToRemove[ri]);
        headers['Access-Control-Allow-Origin'] = '*';
        headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
        headers['Access-Control-Allow-Headers'] = '*';
        headers['Access-Control-Expose-Headers'] = '*';
        log('INFO', 'NB-163 CORS bypass applied', su.slice(-70));
    }

    // Body transformations
    var ct = hGet(headers, 'content-type');
    if (body && ct.length > 0 && (ct.indexOf('text/html') > -1 || ct.indexOf('text/css') > -1 || ct.indexOf('application/json') > -1)) {
        var len0 = body.length;

        // Unhide CSS classes
        body = body.replace(/(\.hiddenProvider\s*\{[^}]*?)display\s*:\s*none([^}]*\})/gi, '$1display:block$2');
        body = body.replace(/(\.CEDataExternal\s*\{[^}]*?)display\s*:\s*none\s*!important([^}]*\})/gi, '$1display:block$2');
        body = body.replace(/(SRonly\s*\{[^}]*?)(?:left|position)\s*:\s*[^;]*px([^}]*\})/gi, '$1display:block$2');

        // Unhide inline styles
        body = body.replace(/class="([^"]*hiddenProvider[^"]*)"/gi, 'class="$1" style="display:block!important;visibility:visible!important"');
        body = body.replace(/class="([^"]*CEDataExternal[^"]*)"/gi, 'class="$1" style="display:block!important;visibility:visible!important"');

        if (body.length !== len0) {
            log('KRITIEK', 'NB-12/53 CSS hiding code removed', su.slice(-70));
        }
    }

    $done({ status: status, headers: headers, body: body });

} catch (e) {
    console.log('[F] RESPONSE ERROR: ' + e.message);
    $done({ status: $response.status, headers: $response.headers, body: $response.body });
}
