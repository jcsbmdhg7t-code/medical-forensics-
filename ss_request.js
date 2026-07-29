/**
 * ss_request.js — Storm Sniffer request interceptor
 * Logs audit trail attempts and credentials in headers
 */

var url = $request.url;
var method = $request.method;
var headers = $request.headers || {};
var body = $request.body || '';
var su = url.indexOf('?') > -1 ? url.split('?')[0] : url;

var AUDIT_ENDPOINTS = [
    'GetClinicianAccessLogSettings', 'GetClinicianAccessLogEntries',
    'GetThirdPartyAccessLogEntries', 'access-logs', 'AccessLog', 'AuditTrail',
    'audit-trail', 'AuditLog', 'GetAuditLog', 'UserAccessLog',
];

var CRITICAL_IDENTIFIERS = [
    { pattern: '215672185', label: 'BSN Grothe' },
    { pattern: '0133033170', label: 'MDN Grothe' },
    { pattern: 'Epic@spaarnegasthuis', label: 'Epic admin' },
    { pattern: 'parnassia', label: 'Parnassia' },
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

function log(ernst, label, detail) {
    var prefix = { 'KRITIEK': '[!!]', 'HOOG': '[!]', 'MEDIUM': '[~]', 'INFO': '[i]' }[ernst] || '[?]';
    console.log(prefix + ' [F-REQ][' + ernst + '] ' + label);
    if (detail) console.log('  -> ' + String(detail).slice(0, 150));
}

try {
    console.log('[F] REQUEST: ' + method + ' ' + su.slice(-80));

    // Audit trail endpoints
    if (isAudit(url)) {
        log('HOOG', 'NB-163 Audit trail endpoint attempt', method + ' ' + su);
    }

    // Identifier check
    for (var j = 0; j < CRITICAL_IDENTIFIERS.length; j++) {
        if (url.indexOf(CRITICAL_IDENTIFIERS[j].pattern) > -1 || body.indexOf(CRITICAL_IDENTIFIERS[j].pattern) > -1) {
            log('INFO', CRITICAL_IDENTIFIERS[j].label + ' in request', su.slice(-70));
        }
    }

    // Auth headers
    var auth = hGet(headers, 'authorization');
    if (auth) {
        var scheme = auth.split(' ')[0];
        log('HOOG', 'NB-166 Authorization header: ' + scheme, auth.slice(0, 50) + '***');
    }

    // Session cookies
    var ck = hGet(headers, 'cookie');
    if (ck) {
        if (ck.indexOf('SESSION') > -1) log('HOOG', 'NB-166 SESSION cookie', ck.slice(0, 60) + '...');
        if (ck.indexOf('JSESSIONID') > -1) log('HOOG', 'NB-166 JSESSIONID cookie', ck.slice(0, 60) + '...');
    }

    // POST body inspection
    if (body && body.length > 10) {
        if (body.indexOf('getPatient') > -1 || body.indexOf('GetPatient') > -1) {
            log('MEDIUM', 'NB-177 Patient data request', su.slice(-70));
        }
        if (body.indexOf('authentication') > -1 || body.indexOf('login') > -1) {
            log('MEDIUM', 'NB-166 Auth attempt in body', su.slice(-70));
        }
    }

    $done({});

} catch (e) {
    console.log('[F] REQUEST ERROR: ' + e.message);
    $done({});
}
