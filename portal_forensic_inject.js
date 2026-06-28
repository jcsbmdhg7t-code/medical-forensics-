// ==UserScript==
// @name         Dossier Inspector (Grothe C/15/376914) v12.0
// @namespace    grothe-forensisch
// @version      12.0
// @description  Forensische inspectie: anti-telemetry, full-content capture, multi-decode, shadow-DOM, local files
// @include      *spaarnegasthuis*
// @include      *mijnspaarne*
// @include      *dijklander*
// @include      *mijn.dijklander*
// @include      *mychart*
// @include      *epic*
// @include      *chipsoft*
// @include      *hix*
// @include      *galaxys.net*
// @include      *gezondheidsmeter*
// @include      *uwzorgonline*
// @include      *zorgplatform*
// @include      *pgo*
// @include      *medmij*
// @include      *vzvz*
// @include      *mitz*
// @include      *mijngezondheid*
// @include      *medgemak*
// @include      *medxpert*
// @include      *ivido*
// @include      *quli*
// @include      *spreekuur*
// @include      *parnassia*
// @include      *parnassiagroep*
// @include      *brijder*
// @include      *psyq*
// @include      *viersprong*
// @include      *indigo*
// @include      *lentis*
// @include      *mentaalbeter*
// @include      *diakenhuisweg*
// @include      *emergis*
// @include      *antes*
// @include      *reiniervanarkel*
// @include      *reinier-van-arkel*
// @include      *altrecht*
// @include      *ggz*
// @include      *ggz-*
// @include      *zorggroep*
// @include      *ziekenhuis*
// @include      *zilverenkruis*
// @include      *vgz*
// @include      *menzis*
// @include      *achmea*
// @include      *ohra*
// @include      *salland*
// @include      *aevitae*
// @include      *cz.nl*
// @include      *benu*
// @include      *brocacef*
// @include      *boots*
// @include      *digid*
// @include      *yivi*
// @include      *idin*
// @include      *signicat*
// @include      *bigregister*
// @include      *cibg*
// @include      *ribiz*
// @include      *saltro*
// @include      *synlab*
// @include      *hoppinger*
// @include      *sharepoint*
// @include      *microsoftonline*
// @include      *vandermeij*
// @include      *shareeverywhere*
// @include      *commonwell*
// @include      *carequality*
// @include      *directtrust*
// @include      file://*
// @include      blob:*
// @include      data:*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function () {
'use strict';

var DOSSIER = 'Grothe C/15/376914';
var LOG_PREFIX = '[INSPECTOR]';
var VERSIE = '12.0';

// =========================================================================
// 1. CONFIGURATIE
// =========================================================================

var TELEMETRY_BLOCKLIST = [
    'hotjar.com', 'hotjar.io', 'sentry.io', 'sentry-cdn.com',
    'datadoghq.com', 'browser-intake-datadoghq', 'pendo.io',
    'vwo.com', 'wingify.com', 'google-analytics.com', 'googletagmanager.com',
    'doubleclick.net', 'segment.io', 'segment.com', 'mixpanel.com',
    'amplitude.com', 'fullstory.com', 'logrocket.com', 'mouseflow.com',
    'crazyegg.com', 'optimizely.com', 'newrelic.com', 'bugsnag.com',
    'rollbar.com', 'raygun.io', 'heap.io', 'matomo', 'piwik',
    'facebook.net', 'connect.facebook.net', 'snapchat.com', 'tiktok.com',
    'linkedin.com/li/track', 'analytics.twitter.com', 'analytics.pinterest.com',
];

var CSS_VERBERGING_KLASSEN = [
    'hiddenProvider', 'CEDataExternal', 'SRonly', 'CEAuth', 'CENoAuth',
    'noView', 'hidden-data', 'sr-only', 'visually-hidden', 'screen-reader-only',
];

var AUDIT_ENDPOINTS = [
    'GetClinicianAccessLogSettings', 'GetClinicianAccessLogEntries',
    'GetThirdPartyAccessLogEntries', 'access-logs', 'AccessLog', 'AuditTrail',
    'GetClinicianAccessLog', 'auditlog', 'audit-trail',
];

var FORENSISCHE_PATRONEN = [
    { p: /F19\.1|neusdruppelmisbruik/i,               l: 'F19.1 neusdruppelmisbruik (NB-01)',              e: 'KRITIEK' },
    { p: /361055000/,                                  l: 'SNOMED 361055000 nasal spray misuse (NB-03)',    e: 'KRITIEK' },
    { p: /228273003/,                                  l: 'SNOMED 228273003 drug misuse (NB-23)',           e: 'KRITIEK' },
    { p: /228366006/,                                  l: 'SNOMED 228366006 stimulant misuse',              e: 'HOOG'    },
    { p: /nullFlavor="UNK"/i,                          l: 'CDA nullFlavor=UNK (NB-18)',                     e: 'HOOG'    },
    { p: /extension="999999"/i,                        l: 'ext=999999 anonymous (NB-18)',                   e: 'KRITIEK' },
    { p: /extension="373282512"/i,                     l: 'A. al-Mousawi ext (NB-05)',                      e: 'KRITIEK' },
    { p: /extension="51504662"|extension="84107660"/i, l: 'N.M. Nota ext (NB-04)',                          e: 'KRITIEK' },
    { p: /extension="84126524"/i,                      l: 'Al-Mousawi AGB (NB-108)',                        e: 'KRITIEK' },
    { p: /extension="84115003"/i,                      l: 'Van der List AGB (NB-148)',                      e: 'HOOG'    },
    { p: /extension="84114458"/i,                      l: 'Blauw AGB (NB-173)',                             e: 'KRITIEK' },
    { p: /Epic@spaarnegasthuis\.nl/i,                  l: 'Epic admin email (NB-05)',                       e: 'KRITIEK' },
    { p: /DISABLEMYCONDITIONS/i,                       l: 'Feature flag DISABLEMYCONDITIONS (NB-11)',       e: 'KRITIEK' },
    { p: /DISABLEPLANOFCARE/i,                         l: 'Feature flag DISABLEPLANOFCARE (NB-11)',         e: 'KRITIEK' },
    { p: /SUBSTANCEHXQNR/i,                            l: 'SUBSTANCEHXQNR module (NB-108)',                 e: 'KRITIEK' },
    { p: /AUTOGENERATESIGNATURE/i,                     l: 'AUTOGENERATESIGNATURE (NB-82)',                  e: 'KRITIEK' },
    { p: /SEXUALACTIVITYHXQNR/i,                       l: 'Seksuele anamnese module (NB-83)',               e: 'HOOG'    },
    { p: /AUTOSYNCRECEIVEFORPERSONALINFORMATION/i,     l: 'AutoSync extern (NB-115)',                       e: 'HOOG'    },
    { p: /ExternalJump|LogExternalJumpAudit/i,         l: 'ExternalJump tracking (NB-68)',                  e: 'MEDIUM'  },
    { p: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i,          l: 'Audit trail feature flag (NB-163)',              e: 'HOOG'    },
    { p: /GUARD\b/,                                    l: 'GUARD blok CDA (NB-56)',                         e: 'HOOG'    },
    { p: /noView\s*:\s*true/i,                         l: 'noView:true (NB-99)',                            e: 'KRITIEK' },
    { p: /recording_capture_keystrokes=true/i,         l: 'Hotjar keystroke ACTIEF (NB-53)',                e: 'KRITIEK' },
    { p: /spaarne-rebuild\.productie\.hoppinger/i,     l: 'Hoppinger supply chain (NB-114)',                e: 'KRITIEK' },
    { p: /hoppinger\.com/i,                            l: 'Hoppinger.com (NB-114)',                         e: 'KRITIEK' },
    { p: /override\.css/i,                             l: 'override.css (NB-53/89)',                        e: 'KRITIEK' },
    { p: /hiddenProvider|CEDataExternal/i,             l: 'CSS verberging klasse (NB-12)',                  e: 'KRITIEK' },
    { p: /HANDMATIGE_EDIT_BOM/i,                       l: 'Bytemanipulatieflag (NB-13)',                    e: 'KRITIEK' },
    { p: /20260110033455/,                             l: 'Nacht-timestamp 10-01-2026 (NB-166)',            e: 'KRITIEK' },
    { p: /transactie.{0,10}77832/i,                    l: 'Transactie-ID 77832 (NB-23)',                    e: 'KRITIEK' },
    { p: /215672185/,                                  l: 'BSN Grothe in body',                             e: 'HOOG'    },
    { p: /0133033170/,                                 l: 'MDN Grothe in body',                             e: 'HOOG'    },
    { p: /DE36B70A/i,                                  l: 'Sentry device ID (NB-69)',                       e: 'HOOG'    },
    { p: /hotjar\.com|hjid=/i,                         l: 'Hotjar tracker (NB-79)',                         e: 'HOOG'    },
    { p: /sentry\.io/i,                                l: 'Sentry.io telemetrie (NB-69)',                   e: 'HOOG'    },
    { p: /pendo\.io/i,                                 l: 'Pendo.io tracker (NB-79)',                       e: 'HOOG'    },
    { p: /wingify|vwo\.com/i,                          l: 'VWO/Wingify (NB-85)',                            e: 'HOOG'    },
    { p: /FocusZorgTeam.*test\.authorization/i,        l: 'FocusZorgTeam test-server (NB-91)',              e: 'HOOG'    },
    { p: /printBlackText/i,                            l: 'printBlackText (NB-84)',                         e: 'MEDIUM'  },
    { p: /lucy\.css|lucy_colors/i,                     l: 'lucy.css (NB-71)',                               e: 'MEDIUM'  },
    { p: /\$lastn/i,                                   l: 'FHIR $lastn re-replay (NB-109)',                 e: 'HOOG'    },
    { p: /Brijder|Lentis|Indigo|psyQ|Viersprong/i,     l: 'Parnassia-instelling in body (NB-113)',          e: 'KRITIEK' },
    { p: /Diakenhuisweg/i,                             l: 'Parnassia hub Diakenhuisweg (NB-113)',           e: 'KRITIEK' },
    { p: /GTM-PGPCH2T/i,                               l: 'GTM tag (NB-85)',                                e: 'HOOG'    },
    { p: /ChipSoft\.PlatformServices/i,                l: 'ChipSoft HiX API (NB-177)',                      e: 'KRITIEK' },
    { p: /GetCurrentPatientAndUserObject/i,            l: 'ChipSoft patientobject (NB-177)',                e: 'KRITIEK' },
    { p: /2001702222/,                                 l: 'ChipSoft patient-ID (NB-177)',                   e: 'KRITIEK' },
    { p: /DYN_CURRENT_USER/i,                          l: 'ChipSoft session token (NB-177)',                e: 'HOOG'    },
    { p: /ComponentRequest|ComponentDownload/i,        l: 'ChipSoft component API (NB-177)',                e: 'HOOG'    },
    { p: /GetPatientDocuments/i,                       l: 'ChipSoft documents (NB-177)',                    e: 'HOOG'    },
    { p: /GetPathologyResults/i,                       l: 'ChipSoft pathologie (NB-177)',                   e: 'HOOG'    },
    { p: /GetRadiologyProcedures/i,                    l: 'ChipSoft radiologie (NB-177)',                   e: 'HOOG'    },
    { p: /GetDcrRegistrations/i,                       l: 'ChipSoft DCR (NB-177)',                          e: 'HOOG'    },
    { p: /HAAS_DOCUMENT/i,                             l: 'ChipSoft HAAS (NB-177)',                         e: 'HOOG'    },
    { p: /DigiDClusterHybrid/i,                        l: 'ChipSoft DigiD (NB-177)',                        e: 'HOOG'    },
    { p: /mijn\.dijklander\.nl/i,                      l: 'Dijklander HiX portaal (NB-177)',                e: 'HOOG'    },
    { p: /account_id\s*[:|=]\s*763232/i,               l: 'VWO tracker account_id 763232 (NB-53)',          e: 'KRITIEK' },
    { p: /hide_element.*opacity\s*:\s*0/i,             l: 'VWO opacity:0 aanval (NB-53)',                   e: 'KRITIEK' },
    { p: /vwo_uuid/i,                                  l: 'VWO UUID na weigering (NB-178)',                 e: 'HOOG'    },
    { p: /datadog.*browser-intake/i,                   l: 'Datadog RUM (NB-69)',                            e: 'HOOG'    },
    { p: /centramed\.nl/i,                             l: 'Centramed verzekeraar (NB-179)',                 e: 'HOOG'    },
    { p: /731892001702222/,                            l: 'Dijklander pseudoniem (NB-179)',                 e: 'KRITIEK' },
    { p: /SPAQQ2B2BZC6QDT/i,                           l: 'Spaarne pseudoniem (DOC0002)',                   e: 'KRITIEK' },
];

// =========================================================================
// 2. STATE
// =========================================================================

var evidenceLog = [];
var teller = 0;
var revealed = false;
var revealStore = [];
var blockedRequests = [];

// =========================================================================
// 3. ANTI-TELEMETRY (PRE-blocker, niet alleen detectie)
// =========================================================================

function isTelemetryHost(url) {
    if (!url) return false;
    var u = String(url).toLowerCase();
    for (var i = 0; i < TELEMETRY_BLOCKLIST.length; i++) {
        if (u.indexOf(TELEMETRY_BLOCKLIST[i]) !== -1) return true;
    }
    return false;
}

// sendBeacon volledig uitschakelen — meest gebruikte exfil-API
if (navigator.sendBeacon) {
    var origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
        if (isTelemetryHost(url)) {
            blockedRequests.push({ type: 'sendBeacon', url: url, ts: Date.now() });
            log('KRITIEK', 'TELEMETRY_GEBLOKKEERD', 'sendBeacon naar ' + url + ' geblokkeerd', 'NB-79', '');
            return true; // simuleer succes zodat caller geen retry doet
        }
        return origBeacon(url, data);
    };
}

// fetch wrappen — eerst telemetry-check, dán pas scannen
var origFetch = window.fetch;
window.fetch = function (input, init) {
    var url = (typeof input === 'string') ? input : (input && input.url) || '';
    if (isTelemetryHost(url)) {
        blockedRequests.push({ type: 'fetch', url: url, ts: Date.now() });
        log('KRITIEK', 'TELEMETRY_GEBLOKKEERD', 'fetch naar ' + url + ' geblokkeerd', 'NB-79', '');
        return Promise.resolve(new Response('', { status: 204, statusText: 'Blocked by Inspector' }));
    }
    if (isAudit(url)) log('HOOG', 'AUDIT_FETCH', 'Audit fetch', 'NB-163', url);
    return origFetch.apply(this, arguments).then(function (resp) {
        try {
            resp.clone().text().then(function (body) {
                if (isAudit(url) && (resp.status === 403 || resp.status === 401)) {
                    log('KRITIEK', 'AUDIT_GEBLOKKEERD', 'Audit HTTP ' + resp.status, 'NB-163', url.split('?')[0]);
                }
                scanBody(body, url);
            }).catch(function () {});
        } catch (e) {}
        return resp;
    });
};

// XHR wrappen
var origOpen = XMLHttpRequest.prototype.open;
var origSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.open = function (method, url) {
    this._fi_url = url;
    this._fi_method = method;
    if (isTelemetryHost(url)) {
        this._fi_blocked = true;
        blockedRequests.push({ type: 'xhr', url: url, ts: Date.now() });
        log('KRITIEK', 'TELEMETRY_GEBLOKKEERD', 'XHR naar ' + url + ' geblokkeerd', 'NB-79', '');
        return origOpen.call(this, method, 'about:blank');
    }
    return origOpen.apply(this, arguments);
};
XMLHttpRequest.prototype.send = function (body) {
    if (this._fi_blocked) return;
    var self = this, url = this._fi_url || '';
    if (isAudit(url)) log('HOOG', 'AUDIT_XHR', 'Audit XHR ' + this._fi_method, 'NB-163', url);
    if (typeof body === 'string') scanBody(body, url);
    this.addEventListener('load', function () {
        try {
            if (isAudit(url) && (self.status === 403 || self.status === 401)) {
                log('KRITIEK', 'AUDIT_GEBLOKKEERD', 'XHR HTTP ' + self.status, 'NB-163', url.split('?')[0]);
            }
            if (self.responseText) scanBody(self.responseText, url);
        } catch (e) {}
    });
    return origSend.apply(this, arguments);
};

// Image-pixel trackers blokkeren via mutation observer
function blockTelemetryImage(node) {
    if (node.tagName !== 'IMG' && node.tagName !== 'IFRAME' && node.tagName !== 'SCRIPT') return;
    var src = node.src || node.getAttribute('src') || '';
    if (isTelemetryHost(src)) {
        node.removeAttribute('src');
        node.remove();
        blockedRequests.push({ type: node.tagName.toLowerCase(), url: src, ts: Date.now() });
        log('KRITIEK', 'TELEMETRY_GEBLOKKEERD', node.tagName + ' naar ' + src + ' verwijderd', 'NB-79', '');
    }
}

// =========================================================================
// 4. MULTI-DECODE (base64, hex, URL, ROT13, gzip)
// =========================================================================

function printable(s) {
    if (!s) return false;
    var ok = 0;
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c > 127) ok++;
    }
    return ok / s.length > 0.85;
}

function decodeBase64(raw) {
    try {
        var d = atob(raw.replace(/\s+/g, ''));
        return printable(d) ? d : null;
    } catch (e) { return null; }
}

function decodeHex(raw) {
    try {
        if (raw.length < 8 || raw.length % 2 !== 0) return null;
        var out = '';
        for (var i = 0; i < raw.length; i += 2) {
            out += String.fromCharCode(parseInt(raw.substr(i, 2), 16));
        }
        return printable(out) ? out : null;
    } catch (e) { return null; }
}

function decodeUrl(raw) {
    try { return decodeURIComponent(raw); } catch (e) { return null; }
}

function decodeRot13(raw) {
    return raw.replace(/[a-zA-Z]/g, function (c) {
        var b = c <= 'Z' ? 65 : 97;
        return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b);
    });
}

async function decodeGzip(bytes) {
    try {
        if (typeof DecompressionStream === 'undefined') return null;
        var stream = new Response(bytes).body.pipeThrough(new DecompressionStream('gzip'));
        return await new Response(stream).text();
    } catch (e) { return null; }
}

function tryAllDecodes(raw) {
    var results = [];
    var b = decodeBase64(raw);
    if (b && b.length > 4) results.push({ type: 'base64', value: b });
    var h = decodeHex(raw);
    if (h && h.length > 4) results.push({ type: 'hex', value: h });
    if (raw.indexOf('%') !== -1) {
        var u = decodeUrl(raw);
        if (u && u !== raw) results.push({ type: 'url', value: u });
    }
    // JWT detectie: 3 base64 stukken gescheiden door .
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(raw)) {
        var parts = raw.split('.');
        try {
            var hdr = atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'));
            var pld = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
            results.push({ type: 'jwt', value: 'header: ' + hdr + '\npayload: ' + pld });
        } catch (e) {}
    }
    return results;
}

function scanEncoded(root) {
    var html = (root || document.documentElement).innerHTML;
    var seen = {};
    var found = [];
    // Base64-kandidaten
    var reB64 = /[A-Za-z0-9+/]{32,}={0,2}/g;
    var m;
    while ((m = reB64.exec(html)) !== null && found.length < 500) {
        if (seen[m[0]]) continue;
        seen[m[0]] = 1;
        var decs = tryAllDecodes(m[0]);
        decs.forEach(function (d) {
            found.push({ raw: m[0].slice(0, 60), type: d.type, decoded: d.value });
        });
    }
    // data-URI's
    document.querySelectorAll('[src],[href],[data]').forEach(function (el) {
        ['src', 'href', 'data'].forEach(function (a) {
            var v = el.getAttribute && el.getAttribute(a);
            if (v && v.indexOf('base64,') > -1) {
                var raw = v.split('base64,')[1] || '';
                var dec = decodeBase64(raw);
                if (dec) found.push({ raw: v.slice(0, 60), type: 'data-URI', decoded: dec.slice(0, 8000) });
            }
        });
    });
    return found;
}

// =========================================================================
// 5. MIME-DETECTIE via magic bytes (negeer bestandsnaam-extensie)
// =========================================================================

function detectMime(bytes) {
    if (!bytes || bytes.length < 4) return 'onbekend';
    var b = bytes;
    if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return 'application/pdf';
    if (b[0] === 0x50 && b[1] === 0x4B && b[2] === 0x03 && b[3] === 0x04) return 'application/zip';
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47) return 'image/png';
    if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return 'image/jpeg';
    if (b[0] === 0x1F && b[1] === 0x8B) return 'application/gzip';
    if (b[0] === 0x3C && b[1] === 0x3F && b[2] === 0x78 && b[3] === 0x6D) return 'application/xml';
    if (b[0] === 0x7B) return 'application/json';
    if (b[0] === 0x3C) return 'text/html';
    return 'application/octet-stream';
}

// =========================================================================
// 6. PDF stream-extractie (werkt op user-password PDFs waar stream open is)
// =========================================================================

function extractPdfStreams(text) {
    var streams = [];
    var re = /stream\s*([\s\S]*?)\s*endstream/g;
    var m;
    while ((m = re.exec(text)) !== null && streams.length < 50) {
        var content = m[1];
        // Probeer plain text
        if (printable(content) && content.length > 20) {
            streams.push({ type: 'tekst', content: content.slice(0, 5000) });
        }
    }
    // Tekst tussen BT/ET (text-objecten)
    var bt = /BT\s+([\s\S]*?)\s+ET/g;
    while ((m = bt.exec(text)) !== null && streams.length < 100) {
        streams.push({ type: 'pdf-text', content: m[1].slice(0, 2000) });
    }
    // Tj/TJ operatoren — eigenlijke leestekst
    var tj = /\(([^)]+)\)\s*Tj/g;
    var allTj = [];
    while ((m = tj.exec(text)) !== null && allTj.length < 500) {
        allTj.push(m[1]);
    }
    if (allTj.length) streams.push({ type: 'pdf-tj', content: allTj.join(' ') });
    return streams;
}

// =========================================================================
// 7. SHADOW-DOM + IFRAME-SCANNER
// =========================================================================

function walkShadowAndFrames(root, cb, depth) {
    depth = depth || 0;
    if (depth > 8) return;
    try {
        cb(root);
        var all = root.querySelectorAll('*');
        for (var i = 0; i < all.length; i++) {
            if (all[i].shadowRoot) walkShadowAndFrames(all[i].shadowRoot, cb, depth + 1);
        }
        var iframes = root.querySelectorAll('iframe');
        for (var j = 0; j < iframes.length; j++) {
            try {
                var doc = iframes[j].contentDocument;
                if (doc) walkShadowAndFrames(doc, cb, depth + 1);
            } catch (e) {} // cross-origin
        }
    } catch (e) {}
}

// =========================================================================
// 8. VERBORGEN-DETECTIE + FULL-CONTENT CAPTURE
// =========================================================================

function rgbArr(s) { var m = (s || '').match(/\d+/g); return m ? m.map(Number) : null; }
function sameColor(fg, bg) {
    var a = rgbArr(fg), b = rgbArr(bg);
    if (!a || !b) return false;
    return Math.abs(a[0] - b[0]) < 8 && Math.abs(a[1] - b[1]) < 8 && Math.abs(a[2] - b[2]) < 8;
}

function hiddenReasons(el) {
    var r = [];
    try {
        var cs = getComputedStyle(el);
        if (cs.display === 'none') r.push('display:none');
        if (cs.visibility === 'hidden' || cs.visibility === 'collapse') r.push('visibility:' + cs.visibility);
        var op = parseFloat(cs.opacity);
        if (!isNaN(op) && op < 0.06) r.push('opacity:' + cs.opacity);
        if (el.hasAttribute && el.hasAttribute('hidden')) r.push('hidden-attr');
        if (el.getAttribute && el.getAttribute('aria-hidden') === 'true') r.push('aria-hidden');
        if (parseFloat(cs.fontSize) === 0) r.push('font-size:0');
        var ti = parseFloat(cs.textIndent);
        if (!isNaN(ti) && ti < -500) r.push('text-indent off-screen');
        if (cs.clipPath === 'inset(100%)') r.push('clip verborgen');
        if (sameColor(cs.color, cs.backgroundColor)) r.push('tekst==achtergrond');
        var rect = el.getBoundingClientRect ? el.getBoundingClientRect() : { width: 1, height: 1 };
        if ((rect.width === 0 || rect.height === 0) && (el.textContent || '').trim()) r.push('nul-grootte');
        if (rect.bottom < -2000 || rect.right < -2000) r.push('ver buiten beeld');
        var cls = (el.className || '').toString();
        for (var i = 0; i < CSS_VERBERGING_KLASSEN.length; i++) {
            if (cls.indexOf(CSS_VERBERGING_KLASSEN[i]) !== -1) r.push('class:' + CSS_VERBERGING_KLASSEN[i]);
        }
    } catch (e) {}
    return r;
}

function cssPath(el) {
    try {
        var parts = [], n = el;
        while (n && n.nodeType === 1 && parts.length < 8) {
            var s = n.tagName.toLowerCase();
            if (n.id) { s += '#' + n.id; parts.unshift(s); break; }
            if (typeof n.className === 'string') {
                var c = n.className.trim().split(/\s+/).slice(0, 2).join('.');
                if (c) s += '.' + c;
            }
            parts.unshift(s);
            n = n.parentElement;
        }
        return parts.join(' > ');
    } catch (e) { return el.tagName ? el.tagName.toLowerCase() : '?'; }
}

function scanHidden() {
    var out = [];
    walkShadowAndFrames(document, function (root) {
        var els;
        try { els = root.querySelectorAll('*'); } catch (e) { return; }
        for (var i = 0; i < els.length; i++) {
            var el = els[i];
            var reasons = hiddenReasons(el);
            if (!reasons.length) continue;
            var full = (el.textContent || '').trim();
            if (!full) continue;
            // ouder ook verborgen? alleen relevant als kind eigen tekst heeft
            try {
                if (el.parentElement && hiddenReasons(el.parentElement).length) {
                    var direct = '';
                    for (var j = 0; j < el.childNodes.length; j++) {
                        if (el.childNodes[j].nodeType === 3) direct += el.childNodes[j].nodeValue;
                    }
                    if (!direct.trim()) continue;
                }
            } catch (e) {}
            out.push({
                pad: cssPath(el),
                reden: reasons.join(', '),
                inhoud_volledig: full,
                origineel_style: el.getAttribute && el.getAttribute('style') || '',
                tag: el.tagName,
                class: (el.className || '').toString(),
            });
        }
    });
    return out;
}

// =========================================================================
// 9. SCAN BODY (patternen)
// =========================================================================

function isAudit(url) {
    for (var i = 0; i < AUDIT_ENDPOINTS.length; i++) {
        if (url.indexOf(AUDIT_ENDPOINTS[i]) !== -1) return true;
    }
    return false;
}

function scanBody(body, url) {
    if (!body || body.length < 4) return;
    var su = (url || '').split('?')[0];
    for (var i = 0; i < FORENSISCHE_PATRONEN.length; i++) {
        var p = FORENSISCHE_PATRONEN[i];
        var m = body.match(p.p);
        if (m) {
            var idx = body.search(p.p);
            var ctx = body.substring(Math.max(0, idx - 80), idx + 200).replace(/[\n\r]/g, ' ').trim();
            var nb = (p.l.match(/NB-[\d\/]+/) || ['NB-??'])[0];
            log(p.e, 'PATROON', p.l, nb, 'URL: ' + su + ' | ctx: ' + ctx);
        }
    }
}

// =========================================================================
// 10. HASH + LOG
// =========================================================================

async function sha256(t) {
    if (!crypto || !crypto.subtle) return 'nohash';
    try {
        var data = new TextEncoder().encode(t);
        var buf = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(buf))
            .map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    } catch (e) { return 'nohash'; }
}

function log(ernst, cat, omschr, nb, ctx) {
    teller++;
    var ts = new Date().toISOString();
    var bev = {
        nr: teller, ernst: ernst, categorie: cat,
        omschrijving: omschr, nb: nb,
        context: (ctx || '').slice(0, 1500),
        tijdstempel: ts, url: location.href,
    };
    evidenceLog.push(bev);
    sha256(omschr + '|' + nb + '|' + ts + '|' + (ctx || '').slice(0, 200)).then(function (h) { bev.sha256 = h; });
    var pre = { KRITIEK: '[!!]', HOOG: '[!]', MEDIUM: '[~]', INFO: '[i]' }[ernst] || '[?]';
    console.log(pre + ' ' + LOG_PREFIX + '[' + ernst + '] ' + cat + ': ' + omschr + ' | ' + nb);
    if (ctx) console.log('    -> ' + ctx.slice(0, 250));
    updatePaneel();
    return bev;
}

// =========================================================================
// 11. REVEAL & CAPTURE (full content) + DELETE-capture
// =========================================================================

function revealAll() {
    if (revealed) return;
    revealStore = [];
    walkShadowAndFrames(document, function (root) {
        var els;
        try { els = root.querySelectorAll('*'); } catch (e) { return; }
        for (var i = 0; i < els.length; i++) {
            var el = els[i];
            if (hiddenReasons(el).length && (el.textContent || '').trim()) {
                revealStore.push({ el: el, css: el.getAttribute('style') });
                try {
                    el.style.setProperty('outline', '2px solid #d00', 'important');
                    el.style.setProperty('display', 'inline-block', 'important');
                    el.style.setProperty('visibility', 'visible', 'important');
                    el.style.setProperty('opacity', '1', 'important');
                    el.style.setProperty('text-indent', '0', 'important');
                    el.style.setProperty('clip-path', 'none', 'important');
                    el.style.setProperty('font-size', 'inherit', 'important');
                    el.removeAttribute('aria-hidden');
                    el.removeAttribute('hidden');
                    log('KRITIEK', 'ONTHULD', 'Verborgen onthuld: ' + (el.textContent || '').trim().slice(0, 200),
                        'NB-12/53', 'pad=' + cssPath(el) + ' redenen=' + hiddenReasons(el).join(','));
                } catch (e) {}
            }
        }
    });
    revealed = true;
}

function restoreReveal() {
    if (!revealed) return;
    revealStore.forEach(function (s) {
        try {
            if (s.css == null) s.el.removeAttribute('style');
            else s.el.setAttribute('style', s.css);
        } catch (e) {}
    });
    revealStore = [];
    revealed = false;
}

// MutationObserver — vang verwijderde nodes MET volledige inhoud
var domObserver = new MutationObserver(function (muts) {
    muts.forEach(function (mut) {
        mut.removedNodes.forEach(function (node) {
            if (node.nodeType !== 1) return;
            var inhoud = (node.textContent || '').trim();
            if (!inhoud) return;
            // Patroon-match?
            for (var i = 0; i < FORENSISCHE_PATRONEN.length; i++) {
                if (FORENSISCHE_PATRONEN[i].p.test(inhoud)) {
                    var nb = (FORENSISCHE_PATRONEN[i].l.match(/NB-[\d\/]+/) || ['NB-??'])[0];
                    log('KRITIEK', 'VERWIJDERD_MET_PATROON', FORENSISCHE_PATRONEN[i].l + ' — VOLLEDIGE INHOUD',
                        nb, 'verwijderd_tag=' + node.tagName + ' inhoud=' + inhoud);
                    return;
                }
            }
            if (inhoud.length > 20) {
                log('HOOG', 'NODE_VERWIJDERD', 'Node uit DOM verwijderd met inhoud',
                    'NB-99', 'tag=' + node.tagName + ' inhoud=' + inhoud);
            }
        });
        mut.addedNodes.forEach(function (node) {
            if (node.nodeType !== 1) return;
            blockTelemetryImage(node);
            if (node.style && (node.style.display === 'none' || node.style.visibility === 'hidden')) {
                var tekst = (node.textContent || '').trim();
                if (tekst.length > 10) {
                    log('HOOG', 'VERBORGEN_TOEGEVOEGD', 'Node toegevoegd als verborgen — inhoud: ' + tekst,
                        'NB-62/99', 'tag=' + node.tagName);
                }
            }
        });
        if (mut.type === 'attributes' && mut.attributeName === 'style') {
            var el = mut.target;
            if (el.style && el.style.display === 'none') {
                var t = (el.textContent || '').trim();
                log('HOOG', 'STIJL_NAAR_VERBORGEN', 'display:none ingesteld — inhoud: ' + t,
                    'NB-12/99', 'pad=' + cssPath(el));
            }
        }
    });
});

function startObserver() {
    if (document.body) {
        domObserver.observe(document.body, {
            childList: true, subtree: true,
            attributes: true, attributeFilter: ['style', 'class', 'hidden', 'aria-hidden'],
        });
    } else {
        setTimeout(startObserver, 50);
    }
}

// =========================================================================
// 12. EXPORTS (JSON + HTML rapport + plaintext)
// =========================================================================

function buildReport(hidden, decoded, pdfStreams) {
    var ts = new Date().toISOString();
    var data = {
        meta: {
            dossier: DOSSIER, versie: VERSIE,
            export: ts, url: location.href, userAgent: navigator.userAgent,
            totaalBevindingen: evidenceLog.length,
            geblokkeerdeTelemetry: blockedRequests.length,
        },
        samenvatting: (function () {
            var s = {};
            evidenceLog.forEach(function (b) { s[b.ernst] = (s[b.ernst] || 0) + 1; });
            return s;
        })(),
        bevindingen: evidenceLog,
        verborgen_elementen: hidden || [],
        gedecodeerd: decoded || [],
        pdf_streams: pdfStreams || [],
        geblokkeerde_telemetry: blockedRequests,
    };
    return data;
}

function esc(s) {
    return (s == null ? '' : String(s)).replace(/[&<>]/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c];
    });
}

function buildHtml(data) {
    var h = '<!doctype html><meta charset=utf-8><title>Dossier rapport ' + esc(data.meta.export) + '</title>';
    h += '<style>body{font:13px/1.5 -apple-system,Arial;margin:16px;color:#111;max-width:1400px}';
    h += 'h2{margin-top:22px;border-bottom:2px solid #333;padding-bottom:4px}';
    h += 'table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px}';
    h += 'td,th{border:1px solid #ccc;padding:6px;vertical-align:top;text-align:left}';
    h += 'td.i{white-space:pre-wrap;font-family:ui-monospace,monospace;word-break:break-word;max-width:600px}';
    h += '.k{background:#fdd}.h{background:#fed}.m{background:#ffd}</style>';
    h += '<h1>Dossier Inspector rapport — ' + esc(DOSSIER) + ' v' + esc(VERSIE) + '</h1>';
    h += '<p><b>Pagina:</b> ' + esc(data.meta.url) + '<br><b>Tijd:</b> ' + esc(data.meta.export) + '</p>';
    h += '<p><b>Samenvatting:</b> ' + Object.keys(data.samenvatting).map(function (k) {
        return k + '=' + data.samenvatting[k];
    }).join(' | ') + ' | telemetrie geblokkeerd=' + data.geblokkeerde_telemetry.length + '</p>';

    h += '<h2>1. Bevindingen (' + data.bevindingen.length + ')</h2>';
    if (data.bevindingen.length) {
        h += '<table><tr><th>Nr</th><th>Ernst</th><th>Cat</th><th>NB</th><th>Omschrijving</th><th>Context</th></tr>';
        data.bevindingen.forEach(function (b) {
            var cl = { KRITIEK: 'k', HOOG: 'h', MEDIUM: 'm' }[b.ernst] || '';
            h += '<tr class="' + cl + '"><td>' + b.nr + '</td><td>' + esc(b.ernst) + '</td><td>' + esc(b.categorie) + '</td><td>' + esc(b.nb) + '</td><td>' + esc(b.omschrijving) + '</td><td class=i>' + esc(b.context) + '</td></tr>';
        });
        h += '</table>';
    }

    h += '<h2>2. Verborgen elementen met VOLLEDIGE inhoud (' + data.verborgen_elementen.length + ')</h2>';
    if (data.verborgen_elementen.length) {
        h += '<table><tr><th>Pad</th><th>Reden</th><th>Tag</th><th>Inhoud (volledig)</th></tr>';
        data.verborgen_elementen.forEach(function (v) {
            h += '<tr><td class=i>' + esc(v.pad) + '</td><td>' + esc(v.reden) + '</td><td>' + esc(v.tag) + '</td><td class=i>' + esc(v.inhoud_volledig) + '</td></tr>';
        });
        h += '</table>';
    }

    h += '<h2>3. Gedecodeerde inhoud (' + data.gedecodeerd.length + ')</h2>';
    if (data.gedecodeerd.length) {
        h += '<table><tr><th>Type</th><th>Bron</th><th>Decoded</th></tr>';
        data.gedecodeerd.forEach(function (d) {
            h += '<tr><td>' + esc(d.type) + '</td><td class=i>' + esc(d.raw) + '</td><td class=i>' + esc(d.decoded) + '</td></tr>';
        });
        h += '</table>';
    }

    h += '<h2>4. PDF-streams (' + data.pdf_streams.length + ')</h2>';
    if (data.pdf_streams.length) {
        h += '<table><tr><th>Type</th><th>Inhoud</th></tr>';
        data.pdf_streams.forEach(function (s) {
            h += '<tr><td>' + esc(s.type) + '</td><td class=i>' + esc(s.content) + '</td></tr>';
        });
        h += '</table>';
    }

    h += '<h2>5. Geblokkeerde telemetrie (' + data.geblokkeerde_telemetry.length + ')</h2>';
    if (data.geblokkeerde_telemetry.length) {
        h += '<table><tr><th>Type</th><th>URL</th><th>Tijd</th></tr>';
        data.geblokkeerde_telemetry.forEach(function (b) {
            h += '<tr><td>' + esc(b.type) + '</td><td class=i>' + esc(b.url) + '</td><td>' + new Date(b.ts).toISOString() + '</td></tr>';
        });
        h += '</table>';
    }
    return h;
}

function download(filename, content, mime) {
    try {
        var blob = new Blob([content], { type: mime || 'text/plain' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url; a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    } catch (e) { console.error('Download fout:', e); }
}

async function pdfMode() {
    // Check of huidige pagina PDF is (file:// of inline)
    try {
        var resp = await fetch(location.href);
        var ab = await resp.arrayBuffer();
        var bytes = new Uint8Array(ab);
        var mime = detectMime(bytes);
        if (mime !== 'application/pdf') return [];
        var text = new TextDecoder('latin1').decode(bytes);
        return extractPdfStreams(text);
    } catch (e) { return []; }
}

async function exportAll() {
    var hidden = scanHidden();
    var decoded = scanEncoded(document);
    var pdfStreams = await pdfMode();
    var data = buildReport(hidden, decoded, pdfStreams);
    var ts = new Date().toISOString().replace(/[:.]/g, '-');
    download('inspector_' + ts + '.json', JSON.stringify(data, null, 2), 'application/json');
    download('inspector_' + ts + '.html', buildHtml(data), 'text/html');
    log('INFO', 'EXPORT', 'Rapport geëxporteerd: ' + evidenceLog.length + ' bevindingen, ' + hidden.length + ' verborgen, ' + decoded.length + ' gedecodeerd, ' + pdfStreams.length + ' PDF-streams', 'NB-export', '');
}

// =========================================================================
// 13. UI — niet-blokkerende drawer (rechts, collapsible, transparant)
// =========================================================================

var paneelEl = null;

function bouwPaneel() {
    if (paneelEl || !document.body) return;
    paneelEl = document.createElement('div');
    paneelEl.id = 'fi-drawer';
    paneelEl.style.cssText = [
        'position:fixed', 'top:50%', 'right:0', 'transform:translateY(-50%)',
        'z-index:2147483647', 'background:rgba(20,20,20,.92)', 'color:#fff',
        'font:11px ui-monospace,Menlo,monospace', 'border-radius:8px 0 0 8px',
        'box-shadow:-2px 2px 12px rgba(0,0,0,.5)', 'transition:width .2s',
        'overflow:hidden', 'max-height:80vh', 'opacity:.5',
    ].join(';');
    paneelEl.onmouseenter = function () { paneelEl.style.opacity = '1'; };
    paneelEl.onmouseleave = function () { paneelEl.style.opacity = '.5'; };

    var tab = document.createElement('div');
    tab.style.cssText = 'padding:4px 8px;cursor:pointer;background:#003399;text-align:center;writing-mode:vertical-rl;min-height:60px';
    tab.textContent = '[F] Inspector';
    tab.onclick = function () { toggleOpen(); };

    var body = document.createElement('div');
    body.id = 'fi-body';
    body.style.cssText = 'display:none;width:280px;padding:8px;max-height:80vh;overflow-y:auto';

    body.innerHTML =
        '<div id="fi-count" style="font-weight:bold;margin-bottom:8px;color:#ff5">[0 bevindingen]</div>' +
        '<button data-act="scan"   style="display:block;width:100%;margin:3px 0;padding:6px;background:#003399;color:#fff;border:0;border-radius:4px;cursor:pointer">Scan + export</button>' +
        '<button data-act="reveal" style="display:block;width:100%;margin:3px 0;padding:6px;background:#cc0000;color:#fff;border:0;border-radius:4px;cursor:pointer">Toggle verborgen</button>' +
        '<button data-act="decode" style="display:block;width:100%;margin:3px 0;padding:6px;background:#666;color:#fff;border:0;border-radius:4px;cursor:pointer">Alleen decode</button>' +
        '<button data-act="pdf"    style="display:block;width:100%;margin:3px 0;padding:6px;background:#666;color:#fff;border:0;border-radius:4px;cursor:pointer">PDF-streams</button>' +
        '<button data-act="json"   style="display:block;width:100%;margin:3px 0;padding:6px;background:#444;color:#fff;border:0;border-radius:4px;cursor:pointer">Snelle JSON</button>' +
        '<div id="fi-stats" style="margin-top:8px;padding-top:8px;border-top:1px solid #444;font-size:10px;color:#aaa"></div>';

    paneelEl.appendChild(tab);
    paneelEl.appendChild(body);
    document.body.appendChild(paneelEl);

    body.addEventListener('click', function (e) {
        var act = e.target && e.target.getAttribute('data-act');
        if (!act) return;
        if (act === 'scan') exportAll();
        if (act === 'reveal') {
            if (revealed) restoreReveal(); else revealAll();
            updatePaneel();
        }
        if (act === 'decode') {
            var d = scanEncoded(document);
            download('decoded_' + Date.now() + '.json', JSON.stringify(d, null, 2), 'application/json');
        }
        if (act === 'pdf') {
            pdfMode().then(function (s) {
                download('pdf_streams_' + Date.now() + '.json', JSON.stringify(s, null, 2), 'application/json');
            });
        }
        if (act === 'json') {
            download('inspector_quick_' + Date.now() + '.json',
                JSON.stringify(buildReport([], [], []), null, 2),
                'application/json');
        }
    });

    // Touch-draggable voor mobiel
    var drag = false, oy = 0;
    tab.addEventListener('touchstart', function (e) {
        drag = true; oy = e.touches[0].clientY - paneelEl.offsetTop;
    }, { passive: true });
    document.addEventListener('touchmove', function (e) {
        if (!drag) return;
        paneelEl.style.top = (e.touches[0].clientY - oy) + 'px';
        paneelEl.style.transform = 'none';
    }, { passive: true });
    document.addEventListener('touchend', function () { drag = false; });
}

function toggleOpen() {
    if (!paneelEl) return;
    var b = paneelEl.querySelector('#fi-body');
    b.style.display = b.style.display === 'none' ? 'block' : 'none';
}

function updatePaneel() {
    if (!paneelEl) return;
    var cnt = paneelEl.querySelector('#fi-count');
    var stats = paneelEl.querySelector('#fi-stats');
    if (cnt) cnt.textContent = '[' + evidenceLog.length + ' bevindingen]';
    if (stats) {
        var s = { KRITIEK: 0, HOOG: 0, MEDIUM: 0 };
        evidenceLog.forEach(function (b) { if (s[b.ernst] != null) s[b.ernst]++; });
        stats.innerHTML = '<div>KRITIEK: <b style="color:#f55">' + s.KRITIEK + '</b></div>' +
            '<div>HOOG: <b style="color:#fa5">' + s.HOOG + '</b></div>' +
            '<div>MEDIUM: <b style="color:#fd5">' + s.MEDIUM + '</b></div>' +
            '<div>Telemetrie geblokkeerd: <b style="color:#5f5">' + blockedRequests.length + '</b></div>';
    }
}

// =========================================================================
// 14. INIT
// =========================================================================

function init() {
    startObserver();
    bouwPaneel();
    // Initiële scan van de pagina-source
    try { scanBody(document.documentElement.outerHTML, location.href); } catch (e) {}
    // Auto-decode initieel als pagina al geladen is
    if (document.readyState !== 'loading') {
        setTimeout(function () {
            scanEncoded(document); // alleen scan, geen export
        }, 1000);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

window.dossierInspector = {
    log: evidenceLog,
    blocked: blockedRequests,
    export: exportAll,
    reveal: revealAll,
    restore: restoreReveal,
    scan: scanEncoded,
    pdf: pdfMode,
};

console.log(LOG_PREFIX + ' Dossier Inspector v' + VERSIE + ' actief | ' + DOSSIER + ' | ' + location.href);

})();
