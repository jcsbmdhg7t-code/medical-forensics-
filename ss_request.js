var url = $request.url;
var method = $request.method;
var headers = $request.headers || {};
var body = $request.body || '';
var su = url.indexOf('?') > -1 ? url.split('?')[0] : url;

var AUDIT = ['GetClinicianAccessLogSettings','GetClinicianAccessLogEntries','GetThirdPartyAccessLogEntries','access-logs','AccessLog','AuditTrail'];

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

function log(e, l, d) {
    var p = {KRITIEK:'[!!]',HOOG:'[!]',MEDIUM:'[~]',INFO:'[i]'}[e] || '[?]';
    console.log(p + ' [F][' + e + '] ' + l);
    if (d) console.log('    -> ' + String(d).slice(0, 200));
}

try {
    console.log('[F] Request: ' + method + ' ' + su);

    if (isAudit(url)) log('HOOG', 'Audit trail request ' + method + ' (NB-163)', su);
    if (url.indexOf('215672185') > -1) log('INFO', 'BSN 215672185 in URL', su);
    if (url.indexOf('0133033170') > -1) log('INFO', 'MDN 0133033170 in URL', su);

    var auth = hGet(headers, 'authorization');
    if (auth) log('INFO', 'Authorization header', auth.slice(0, 60));

    var ck = hGet(headers, 'cookie');
    if (ck && ck.indexOf('SESSION') > -1) log('INFO', 'Session cookie', ck.slice(0, 80));

    $done({});

} catch(e) {
    console.log('[F] FOUT: ' + e);
    $done({});
}
