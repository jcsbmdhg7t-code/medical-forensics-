var url = $request.url;
var method = $request.method;
var status = $response.status;
var headers = $response.headers;
var body = $response.body;
var su = url.indexOf('?') > -1 ? url.split('?')[0] : url;

var AUDIT = ['GetClinicianAccessLogSettings','GetClinicianAccessLogEntries','GetThirdPartyAccessLogEntries','access-logs','AccessLog','AuditTrail'];
var PATTERNS = [
    [/F19\.1|neusdruppelmisbruik/i,'F19.1 neusdruppelmisbruik (NB-01)'],
    [/361055000/,'SNOMED 361055000 (NB-03)'],
    [/228273003/,'SNOMED 228273003 (NB-23)'],
    [/nullFlavor="UNK"/i,'CDA nullFlavor=UNK (NB-18)'],
    [/extension="999999"/i,'Epic ext=999999 (NB-18)'],
    [/extension="373282512"/i,'al-Mousawi ext (NB-05)'],
    [/DISABLEMYCONDITIONS/i,'DISABLEMYCONDITIONS (NB-11)'],
    [/DISABLEPLANOFCARE/i,'DISABLEPLANOFCARE (NB-11)'],
    [/SUBSTANCEHXQNR/i,'SUBSTANCEHXQNR (NB-108)'],
    [/AUTOGENERATESIGNATURE/i,'AUTOGENERATESIGNATURE (NB-82)'],
    [/recording_capture_keystrokes=true/i,'Hotjar keystroke (NB-53)'],
    [/hoppinger\.com/i,'Hoppinger (NB-114)'],
    [/override\.css/i,'override.css (NB-53/89)'],
    [/hiddenProvider|CEDataExternal/i,'CSS verberging (NB-12)'],
    [/noView\s*:\s*true/i,'noView:true (NB-99)'],
    [/20260110033455/,'[KRITIEK] NACHT-TIMESTAMP AVG (NB-166)'],
    [/215672185/,'BSN in body'],
    [/0133033170/,'MDN in body'],
    [/DE36B70A/i,'Sentry device ID (NB-69)'],
    [/hotjar\.com/i,'Hotjar tracker (NB-79)'],
    [/sentry\.io/i,'Sentry (NB-69)'],
    [/GUARD\b/,'GUARD blok (NB-56)'],
    [/printBlackText/i,'printBlackText (NB-84)']
];

function isAudit(u) {
    for (var i = 0; i < AUDIT.length; i++) {
        if (u.indexOf(AUDIT[i]) > -1) return true;
    }
    return false;
}

function hGet(h, n) {
    var lo = n.toLowerCase();
    var keys = Object.keys(h || {});
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].toLowerCase() === lo) return h[keys[i]] || '';
    }
    return '';
}

function hDel(h, n) {
    var lo = n.toLowerCase();
    var keys = Object.keys(h || {});
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].toLowerCase() === lo) delete h[keys[i]];
    }
}

function log(e, l, d) {
    var p = {KRITIEK:'[!!]',HOOG:'[!]',MEDIUM:'[~]',INFO:'[i]'}[e] || '[?]';
    console.log(p + ' [F][' + e + '] ' + l);
    if (d) console.log('    -> ' + String(d).slice(0, 200));
}

try {
    console.log('[F] Response: ' + method + ' ' + status + ' ' + su);

    if (!hGet(headers, 'access-control-allow-origin') && isAudit(url)) {
        log('KRITIEK', 'CORS-blokkade audit trail (NB-163)', su);
    }

    if (isAudit(url)) {
        if (status === 403 || status === 401 || status === 0) {
            log('KRITIEK', 'Audit trail geblokkeerd HTTP ' + status, su);
        } else {
            log('INFO', 'Audit trail bereikbaar HTTP ' + status, su);
        }
    }

    if (body) {
        for (var i = 0; i < PATTERNS.length; i++) {
            if (PATTERNS[i][0].test(body)) {
                var idx = body.search(PATTERNS[i][0]);
                var ctx = body.substring(Math.max(0, idx - 50), idx + 80).replace(/[\n\r]/g, ' ');
                var ernst = PATTERNS[i][1].indexOf('KRITIEK') > -1 ? 'KRITIEK' : 'HOOG';
                log(ernst, PATTERNS[i][1], '...' + ctx + '...');
            }
        }
    }

    if (isAudit(url)) {
        var rm = ['access-control-allow-origin','access-control-allow-methods','access-control-allow-headers','access-control-expose-headers','x-frame-options','content-security-policy','x-content-type-options'];
        for (var i = 0; i < rm.length; i++) hDel(headers, rm[i]);
        headers['Access-Control-Allow-Origin'] = '*';
        headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE';
        headers['Access-Control-Allow-Headers'] = '*';
        headers['Access-Control-Expose-Headers'] = '*';
        log('INFO', 'CORS verwijderd', su);
    }

    hDel(headers, 'content-security-policy');
    hDel(headers, 'content-security-policy-report-only');
    hDel(headers, 'x-frame-options');

    var ct = hGet(headers, 'content-type');
    if (body && (ct.indexOf('text/html') > -1 || ct.indexOf('text/css') > -1 || body.indexOf('hiddenProvider') > -1 || body.indexOf('CEDataExternal') > -1)) {
        var len0 = body.length;
        body = body.replace(/(\.hiddenProvider\s*\{[^}]*?)display\s*:\s*none([^}]*\})/gi, '$1display:block$2');
        body = body.replace(/(CEDataExternal\s*\{[^}]*?)display\s*:\s*none\s*!important([^}]*\})/gi, '$1display:block$2');
        body = body.replace(/(\.SRonly\s*\{[^}]*?)left\s*:\s*-\d{4,}px([^}]*\})/gi, '$1left:auto$2');
        body = body.replace(/class="([^"]*hiddenProvider[^"]*)"/gi, 'class="$1" style="display:block!important"');
        body = body.replace(/class="([^"]*CEDataExternal[^"]*)"/gi, 'class="$1" style="display:block!important"');
        if (body.length !== len0) log('KRITIEK', 'CSS verberging verwijderd (NB-12/53)', su);
    }

    $done({ status: status, headers: headers, body: body });

} catch(e) {
    console.log('[F] FOUT: ' + e);
    $done({ status: $response.status, headers: $response.headers, body: $response.body });
}
