// ==UserScript==
// @name         Forensisch Scanner — MijnSpaarneGasthuis / Epic MyChart
// @namespace    forensisch-grothe
// @version      1.1
// @description  Volledig forensisch net: DOM-scan, XHR/fetch-interceptie, feature flags, verborgen elementen
// @author       forensisch-grothe
// ── Spaarne Gasthuis portalen ──
// @match        https://www.mijnspaarnegasthuis.nl/*
// @match        https://*.mijnspaarnegasthuis.nl/*
// @match        https://spaarnegasthuis.nl/*
// @match        https://*.spaarnegasthuis.nl/*
// ── Epic MyChart infrastructuur ──
// @match        https://*.epichosted.com/*
// @match        https://*.epic.com/*
// @match        https://*.epicsystems.com/*
// @match        https://*.myepichost.com/*
// @match        https://*.mychartcentral.com/*
// ── MedMij / PGO authenticatie ──
// @match        https://*.medmij.nl/*
// @match        https://medmij.nl/*
// @match        https://*.mijnggz.nl/*
// @match        https://*.dvza.nl/*
// @match        https://*.heliview.nl/*
// ── DigiD authenticatie ──
// @match        https://digid.nl/*
// @match        https://www.digid.nl/*
// @match        https://*.digid.nl/*
// ── Quli / quliRedirect flow ──
// @match        https://*.quli.nl/*
// @match        https://quli.nl/*
// ── ZORG-AB / Whitelist PGO aanbieders ──
// @match        https://*.zorgab.nl/*
// @match        https://zorgab.nl/*
// ── VZVZ / AORTA ──
// @match        https://*.vzvz.nl/*
// @match        https://*.aorta.nl/*
// ── Vecozo (zorgverzekering koppeling) ──
// @match        https://*.vecozo.nl/*
// ── Ons.app / andere PGO portalen ──
// @match        https://*.ons.nl/*
// @match        https://*.mijnzorgapp.nl/*
// @match        https://*.patientportaal.nl/*
// ── CDN / statische assets Epic ──
// @match        https://*.epiccdn.com/*
// @match        https://*.epicstatic.com/*
// @grant        GM_setClipboard
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_notification
// @run-at       document-start
// ==/UserScript==

(function () {
'use strict';

// ══════════════════════════════════════════════════════════════
// PATRONEN — gesynchroniseerd met loon_forensisch.js (NB-01 t/m NB-181)
// ══════════════════════════════════════════════════════════════
var PATRONEN = [
    { p: /F19\.1/i,                                      nb: 'NB-01' },
    { p: /neusdruppelmisbruik/i,                         nb: 'NB-01' },
    { p: /361055000/,                                    nb: 'NB-03' },
    { p: /228273003/,                                    nb: 'NB-23' },
    { p: /228366006/,                                    nb: 'NB-23b' },
    { p: /266927001/,                                    nb: 'NB-23c' },
    { p: /F60\.31|borderline\s*persoon/i,                nb: 'NB-xx' },
    { p: /transactie.{0,10}77832/i,                      nb: 'NB-23' },
    { p: /nullFlavor\s*=\s*["']?UNK/i,                  nb: 'NB-18' },
    { p: /extension\s*=\s*["']?999999/i,                nb: 'NB-18' },
    { p: /GUARD\b/,                                      nb: 'NB-56' },
    { p: /HANDMATIGE_EDIT_BOM/i,                         nb: 'NB-13' },
    { p: /extension\s*=\s*["']?51504662/i,               nb: 'NB-04' },
    { p: /extension\s*=\s*["']?84107660/i,               nb: 'NB-04' },
    { p: /extension\s*=\s*["']?373282512/i,              nb: 'NB-05' },
    { p: /Epic@spaarnegasthuis\.nl/i,                    nb: 'NB-05' },
    { p: /DISABLEMYCONDITIONS/i,                         nb: 'NB-11' },
    { p: /DISABLEPLANOFCARE/i,                           nb: 'NB-11' },
    { p: /SUBSTANCEHXQNR/i,                              nb: 'NB-108' },
    { p: /AUTOGENERATESIGNATURE/i,                       nb: 'NB-82' },
    { p: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i,            nb: 'NB-163' },
    { p: /noView\s*:\s*true/i,                           nb: 'NB-99' },
    { p: /SEXUALACTIVITYHXQNR/i,                         nb: 'NB-83' },
    { p: /AUTOSYNCRECEIVEFORPERSONALINFORMATION/i,       nb: 'NB-115' },
    { p: /ExternalJump|LogExternalJumpAudit/i,           nb: 'NB-68' },
    { p: /hiddenProvider/i,                              nb: 'NB-12' },
    { p: /CEDataExternal/i,                              nb: 'NB-12' },
    { p: /WoundListSection/i,                            nb: 'NB-12' },
    { p: /printBlackText/i,                              nb: 'NB-84' },
    { p: /override\.css/i,                               nb: 'NB-89' },
    { p: /lucy\.css|lucy_colors/i,                       nb: 'NB-71' },
    { p: /recording_capture_keystrokes\s*=\s*true/i,    nb: 'NB-53' },
    { p: /hotjar\.com|hjid\s*=/i,                        nb: 'NB-79' },
    { p: /sentry\.io/i,                                  nb: 'NB-69' },
    { p: /DE36B70A/i,                                    nb: 'NB-69' },
    { p: /datadog.*browser-intake|browser-intake.*datadoghq/i, nb: 'NB-69' },
    { p: /pendo\.io/i,                                   nb: 'NB-79' },
    { p: /wingify|vwo\.com/i,                            nb: 'NB-79' },
    { p: /qualtrics\.com/i,                              nb: 'NB-79' },
    { p: /segment\.io|segment\.com/i,                    nb: 'NB-79' },
    { p: /kameleoon/i,                                   nb: 'NB-79' },
    { p: /GTM-PGPCH2T/i,                                 nb: 'NB-85' },
    { p: /account_id\s*[:=]\s*763232/i,                  nb: 'NB-178' },
    { p: /vwo_uuid/i,                                    nb: 'NB-178' },
    { p: /hide_element.*opacity.*0|body.*opacity.*0.*important/i, nb: 'NB-178' },
    { p: /body\s*\{[^}]*opacity\s*:\s*0/i,               nb: 'NB-178' },
    { p: /SESSION_ID\s*[=:]\s*[A-F0-9]{20,}/i,          nb: 'NB-79' },
    { p: /hoppinger\.com/i,                              nb: 'NB-114' },
    { p: /spaarne-rebuild\.productie\.hoppinger/i,       nb: 'NB-114' },
    { p: /FocusZorgTeam.*test/i,                         nb: 'NB-91' },
    { p: /centramed\.nl/i,                               nb: 'NB-179' },
    { p: /Brijder|Parnassia.*Indigo/i,                   nb: 'NB-113' },
    { p: /ChipSoft\.PlatformServices/i,                  nb: 'NB-177' },
    { p: /GetCurrentPatientAndUserObject/i,               nb: 'NB-177' },
    { p: /GetPatientDocuments/i,                         nb: 'NB-177' },
    { p: /GetPathologyResults/i,                         nb: 'NB-177' },
    { p: /GetDcrRegistrations/i,                         nb: 'NB-177' },
    { p: /DigiDClusterHybrid/i,                          nb: 'NB-177' },
    { p: /DYN_CURRENT_USER/i,                            nb: 'NB-177' },
    { p: /PATIENT_PATIENT/i,                             nb: 'NB-177' },
    { p: /2001702222/,                                   nb: 'NB-177' },
    { p: /GetThirdPartyAccessLogEntries/i,               nb: 'NB-163' },
    { p: /GetUserAuditTrail/i,                           nb: 'NB-163' },
    { p: /GetPatientAuditLog/i,                          nb: 'NB-163' },
    { p: /MyAuditTrail/i,                                nb: 'NB-163' },
    { p: /AuditTrail/i,                                  nb: 'NB-163' },
    { p: /AccessAuditLog/i,                              nb: 'NB-163' },
    { p: /PatientAccessLog/i,                            nb: 'NB-163' },
    { p: /AccessLog|access-logs/i,                       nb: 'NB-163' },
    { p: /GetBreachLog/i,                                nb: 'NB-163' },
    { p: /\/AuditLog\b|\/AuditEvent\b/i,                 nb: 'NB-163' },
    { p: /AuditEvent/i,                                  nb: 'NB-163' },
    { p: /who.{0,20}accessed|clinician.{0,20}access/i,  nb: 'NB-163' },
    { p: /heeft.{0,20}ingezien|heeft.{0,20}bekeken/i,   nb: 'NB-163' },
    { p: /WhoViewedMyHealthRecord/i,                     nb: 'NB-163' },
    { p: /ViewedBy|AccessedBy/i,                         nb: 'NB-163' },
    { p: /ClinicianAccess/i,                             nb: 'NB-163' },
    { p: /FHIR\/R4\/AuditEvent/i,                        nb: 'NB-163' },
    { p: /api\/epic.*AuditLog/i,                         nb: 'NB-163' },
    { p: /accesslogs\.clinician/i,                       nb: 'NB-163' },
    { p: /WhosAccessedMyRecord/i,                        nb: 'NB-163' },
    { p: /ColumnLabelAccessor/i,                         nb: 'NB-163' },
    { p: /RecordAccessed/i,                              nb: 'NB-163' },
    { p: /@epic-px\/access-logs/i,                       nb: 'NB-163' },
    { p: /Wie heeft mijn dossier ingezien/i,             nb: 'NB-163' },
    { p: /GENETICHXQNR/i,                                nb: 'NB-180' },
    { p: /genetic-profile|genetisch\s*profiel/i,         nb: 'NB-180' },
    { p: /epic\.px\.client\.genomics/i,                  nb: 'NB-180' },
    { p: /@epic-px\/genomics/i,                          nb: 'NB-180' },
    { p: /genomics_drugindicator|genomics_diseaseindicator/i, nb: 'NB-180' },
    { p: /GeneticProfileLink|geneticProfileLink/i,       nb: 'NB-180' },
    { p: /GenomicIndicator|VariantList/i,                nb: 'NB-180' },
    { p: /allelicState|allelicPhase|mosaicism/i,         nb: 'NB-180' },
    { p: /DNAChangeType|variantTypeLabel|FindingType/i,  nb: 'NB-180' },
    { p: /CytogeneticLocation/i,                         nb: 'NB-180' },
    { p: /Mijn genetisch profiel/i,                      nb: 'NB-180' },
    { p: /ISABELGROTHE/,                                 nb: 'NB-181' },
    { p: /NNNNNNNNN/,                                    nb: 'NB-181' },
    { p: /\bSZMRN\b/,                                    nb: 'NB-181' },
    { p: /VOLLEDIGPROFIEL/i,                             nb: 'NB-181' },
    { p: /H2GDEBUG/i,                                    nb: 'NB-181' },
    { p: /20260110033455/,                               nb: 'NB-166' },
    { p: /215672185/,                                    nb: 'NB-166' },
    { p: /0133033170/,                                   nb: 'NB-166' },
    { p: /\$lastn/i,                                     nb: 'NB-109' },
    { p: /quliRedirect/i,                                nb: 'MEDMIJ' },
];

// ══════════════════════════════════════════════════════════════
// NETWERK-INTERCEPTIE — XHR en fetch (document-start zodat niets ontsnapt)
// ══════════════════════════════════════════════════════════════
var netwerkLog = [];

function logNetwerk(methode, url, status, body, richting) {
    var ts = new Date().toISOString().slice(0, 19).replace('T', ' ');
    var hits = scanTekst(body || '', url);
    var entry = {
        t: ts,
        m: methode,
        u: url,
        s: status,
        r: richting,
        nb: hits.map(function(h) { return h.nb; }).join(','),
        body: (body || '').slice(0, 200000)
    };
    netwerkLog.push(entry);
    slaNetlogOp(entry);

    if (hits.length > 0) {
        console.warn('[FORENSISCH ' + richting + ' TREFFER] ' + hits.map(function(h) {
            return h.nb + ':' + h.match;
        }).join(' | ') + ' — ' + url);
    }
}

// XHR interceptie
var _XHR = window.XMLHttpRequest;
function ForensischXHR() {
    var xhr = new _XHR();
    var _methode = 'GET', _url = '';
    var origOpen = xhr.open.bind(xhr);
    var origSend = xhr.send.bind(xhr);

    xhr.open = function(methode, url) {
        _methode = methode;
        _url = url;
        return origOpen.apply(xhr, arguments);
    };

    xhr.send = function(reqBody) {
        if (reqBody) logNetwerk(_methode, _url, 0, String(reqBody), 'XHR-REQ');
        xhr.addEventListener('load', function() {
            logNetwerk(_methode, _url, xhr.status, xhr.responseText || '', 'XHR-RESP');
        });
        return origSend.apply(xhr, arguments);
    };

    return xhr;
}
ForensischXHR.prototype = _XHR.prototype;
window.XMLHttpRequest = ForensischXHR;

// Fetch interceptie
var _fetch = window.fetch;
window.fetch = function(input, init) {
    var url = (typeof input === 'string') ? input : (input.url || String(input));
    var methode = (init && init.method) || 'GET';
    var reqBody = (init && init.body) ? String(init.body) : '';
    if (reqBody) logNetwerk(methode, url, 0, reqBody, 'FETCH-REQ');

    return _fetch.apply(this, arguments).then(function(resp) {
        var status = resp.status;
        return resp.clone().text().then(function(tekst) {
            logNetwerk(methode, url, status, tekst, 'FETCH-RESP');
            return resp;
        });
    });
};

// ══════════════════════════════════════════════════════════════
// OPSLAG — GM_setValue per chunk
// ══════════════════════════════════════════════════════════════
function slaNetlogOp(entry) {
    try {
        var chunk = parseInt(GM_getValue('for_chunk', '0')) || 0;
        var key = 'for_net_' + chunk;
        var bestaand = GM_getValue(key, '[]');
        var log;
        try { log = JSON.parse(bestaand); } catch(e) { log = []; }
        log.push(entry);
        GM_setValue(key, JSON.stringify(log));
        if (log.length >= 200) {
            GM_setValue('for_chunk', String(chunk + 1));
        }
    } catch(e) {}
}

// ══════════════════════════════════════════════════════════════
// SCAN FUNCTIES
// ══════════════════════════════════════════════════════════════
function scanTekst(tekst, bron) {
    var hits = [], gezien = {};
    if (!tekst || tekst.length < 2) return hits;
    for (var i = 0; i < PATRONEN.length; i++) {
        var pat = PATRONEN[i];
        var m = pat.p.exec(tekst);
        if (m) {
            var sleutel = pat.nb + '::' + m[0].slice(0, 30);
            if (!gezien[sleutel]) {
                gezien[sleutel] = true;
                var start = Math.max(0, m.index - 60);
                var eind = Math.min(tekst.length, m.index + m[0].length + 60);
                hits.push({
                    nb: pat.nb,
                    match: m[0].slice(0, 80),
                    context: tekst.slice(start, eind).replace(/\s+/g, ' '),
                    bron: bron || ''
                });
            }
        }
    }
    return hits;
}

function epicFeatureVlaggen() {
    var html = document.documentElement.innerHTML || '';
    var vlaggen = [];
    var m = html.match(/"([A-Z][A-Z0-9_]{3,40})"(?:,"[A-Z][A-Z0-9_]{3,40}"){10,}/);
    if (m) {
        var raw = m[0].match(/"([A-Z][A-Z0-9_]{3,40})"/g);
        if (raw) vlaggen = raw.map(function(v) { return v.replace(/"/g, ''); });
    }
    try {
        if (window.EpicPx && window.EpicPx._featureFlags) {
            Object.keys(window.EpicPx._featureFlags).forEach(function(k) {
                if (vlaggen.indexOf(k) === -1) vlaggen.push(k);
            });
        }
    } catch(e) {}
    return vlaggen;
}

function verborgenElementen() {
    var resultaten = [];
    var alle = document.querySelectorAll('*');
    for (var i = 0; i < alle.length; i++) {
        var el = alle[i];
        try {
            var cs = window.getComputedStyle(el);
            var reden = '';
            if (cs.display === 'none') reden = 'display:none';
            else if (cs.visibility === 'hidden') reden = 'visibility:hidden';
            else if (parseFloat(cs.opacity) === 0) reden = 'opacity:0';
            else if (parseFloat(cs.height) === 0 && cs.overflow === 'hidden') reden = 'height:0+overflow:hidden';
            if (reden) {
                var tekst = (el.textContent || '').trim().slice(0, 100);
                if (tekst.length > 3) {
                    resultaten.push(reden + ' | ' + el.tagName + ' | ' + tekst);
                }
            }
        } catch(e) {}
    }
    return resultaten;
}

// ══════════════════════════════════════════════════════════════
// HOOFD SCAN
// ══════════════════════════════════════════════════════════════
function voerScanUit() {
    var rapport = [];
    var ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
    rapport.push('══════════════════════════════════════════════════════');
    rapport.push('FORENSISCH RAPPORT — Tampermonkey');
    rapport.push('Tijdstip : ' + ts);
    rapport.push('URL      : ' + window.location.href);
    rapport.push('══════════════════════════════════════════════════════');

    // 1. HTML + scripts scannen
    var alleTekst = (document.documentElement.innerHTML || '');
    var domHits = scanTekst(alleTekst, 'DOM/HTML');
    rapport.push('\n─── PATROON TREFFERS (' + domHits.length + ') ───');
    if (domHits.length === 0) {
        rapport.push('  (geen bekende patronen in DOM gevonden)');
    } else {
        domHits.forEach(function(h) {
            rapport.push('  [' + h.nb + '] ' + h.match);
            rapport.push('    context: ' + h.context);
        });
    }

    // 2. Epic feature flags
    var vlaggen = epicFeatureVlaggen();
    var kritiek = [
        'DISABLEMYCONDITIONS','DISABLEPLANOFCARE','USERAUDITTRAIL','MYCHARTAUDITTRAIL',
        'SUBSTANCEHXQNR','SEXUALACTIVITYHXQNR','AUTOGENERATESIGNATURE',
        'AUTOSYNCRECEIVEFORPERSONALINFORMATION','GENETICHXQNR','VIEWHIDDENRESULTS',
        'H2GDEBUG','ISABELGROTHE','NNNNNNNNN','SZMRN','VOLLEDIGPROFIEL'
    ];
    rapport.push('\n─── EPIC FEATURE FLAGS (' + vlaggen.length + ' actief) ───');
    kritiek.forEach(function(f) {
        var aan = vlaggen.indexOf(f) !== -1;
        rapport.push('  ' + (aan ? '✓ AAN  ' : '✗ UIT  ') + f);
    });
    rapport.push('\n  Alle ' + vlaggen.length + ' actieve flags:');
    rapport.push('  ' + vlaggen.join(', '));

    // 3. Verborgen elementen
    var verborgen = verborgenElementen();
    rapport.push('\n─── VERBORGEN ELEMENTEN (' + verborgen.length + ') ───');
    verborgen.slice(0, 50).forEach(function(v) { rapport.push('  ' + v); });
    if (verborgen.length > 50) rapport.push('  ... en ' + (verborgen.length - 50) + ' meer');

    // 4. Cookies
    rapport.push('\n─── COOKIES ───');
    var cookies = document.cookie.split(';');
    cookies.forEach(function(c) { rapport.push('  ' + c.trim()); });

    // 5. localStorage
    rapport.push('\n─── LOCALSTORAGE (' + localStorage.length + ' items) ───');
    for (var i = 0; i < Math.min(localStorage.length, 100); i++) {
        var k = localStorage.key(i);
        var v = (localStorage.getItem(k) || '').slice(0, 500);
        rapport.push('  [' + k + '] ' + v);
    }

    // 6. sessionStorage
    rapport.push('\n─── SESSIONSTORAGE (' + sessionStorage.length + ' items) ───');
    for (var j = 0; j < Math.min(sessionStorage.length, 100); j++) {
        var sk = sessionStorage.key(j);
        var sv = (sessionStorage.getItem(sk) || '').slice(0, 500);
        rapport.push('  [' + sk + '] ' + sv);
    }

    // 7. Netwerk tot nu toe (XHR/fetch onderschept)
    rapport.push('\n─── NETWERKAANVRAGEN ONDERSCHEPT (' + netwerkLog.length + ') ───');
    netwerkLog.forEach(function(e) {
        var lijn = '  [' + e.t + '] ' + e.r + ' ' + e.m + ' ' + e.s + ' ' + e.u;
        if (e.nb) lijn += ' → [' + e.nb + ']';
        rapport.push(lijn);
    });

    // 8. NB hits in netwerk
    var nbNetHits = netwerkLog.filter(function(e) { return e.nb; });
    if (nbNetHits.length > 0) {
        rapport.push('\n─── NB-TREFFERS IN NETWERK (' + nbNetHits.length + ') ───');
        nbNetHits.forEach(function(e) {
            rapport.push('  [' + e.nb + '] ' + e.m + ' ' + e.u);
            rapport.push('    body fragment: ' + e.body.slice(0, 300));
        });
    }

    rapport.push('\n══════════════════════════════════════════════════════');
    rapport.push('EINDE RAPPORT');
    rapport.push('══════════════════════════════════════════════════════');

    return rapport.join('\n');
}

// ══════════════════════════════════════════════════════════════
// UI — floating knop + overlay
// ══════════════════════════════════════════════════════════════
function toonOverlay(tekst) {
    var bestaand = document.getElementById('__for_tm_overlay__');
    if (bestaand) bestaand.parentNode.removeChild(bestaand);

    var overlay = document.createElement('div');
    overlay.id = '__for_tm_overlay__';
    overlay.style.cssText = [
        'position:fixed','top:0','left:0','width:100%','height:100%',
        'background:rgba(0,0,0,0.95)','color:#00ff41','font-family:monospace',
        'font-size:11px','z-index:2147483647','overflow:auto','padding:16px',
        'box-sizing:border-box','white-space:pre-wrap','word-break:break-all'
    ].join(';');

    var knoppen = document.createElement('div');
    knoppen.style.cssText = 'position:sticky;top:0;background:#111;padding:8px;margin-bottom:12px;display:flex;gap:8px;';

    var knopKopieer = document.createElement('button');
    knopKopieer.textContent = 'KOPIEER';
    knopKopieer.style.cssText = 'background:#00ff41;color:#000;border:none;padding:6px 14px;font-weight:bold;cursor:pointer;font-family:monospace;';
    knopKopieer.addEventListener('click', function() {
        try {
            GM_setClipboard(tekst);
            knopKopieer.textContent = 'GEKOPIEERD';
            setTimeout(function() { knopKopieer.textContent = 'KOPIEER'; }, 2000);
        } catch(e) {
            navigator.clipboard.writeText(tekst).catch(function() {
                var ta = document.createElement('textarea');
                ta.value = tekst;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                knopKopieer.textContent = 'GEKOPIEERD';
            });
        }
    });

    var knopNetwerk = document.createElement('button');
    knopNetwerk.textContent = 'NETWERK (' + netwerkLog.length + ')';
    knopNetwerk.style.cssText = 'background:#0088ff;color:#fff;border:none;padding:6px 14px;font-weight:bold;cursor:pointer;font-family:monospace;';
    knopNetwerk.addEventListener('click', function() {
        var netTekst = netwerkLog.map(function(e) {
            return '[' + e.t + '] ' + e.r + ' ' + e.m + ' HTTP' + e.s + '\n'
                 + 'URL: ' + e.u + '\n'
                 + (e.nb ? 'NB: ' + e.nb + '\n' : '')
                 + 'BODY:\n' + e.body + '\n' + '─'.repeat(60);
        }).join('\n');
        GM_setClipboard(netTekst || 'Geen netwerk gelogd.');
        knopNetwerk.textContent = 'GEKOPIEERD!';
        setTimeout(function() { knopNetwerk.textContent = 'NETWERK (' + netwerkLog.length + ')'; }, 2000);
    });

    var knopSluit = document.createElement('button');
    knopSluit.textContent = 'SLUIT';
    knopSluit.style.cssText = 'background:#ff3333;color:#fff;border:none;padding:6px 14px;font-weight:bold;cursor:pointer;font-family:monospace;';
    knopSluit.addEventListener('click', function() {
        overlay.parentNode.removeChild(overlay);
    });

    knoppen.appendChild(knopKopieer);
    knoppen.appendChild(knopNetwerk);
    knoppen.appendChild(knopSluit);

    var inhoud = document.createElement('div');
    inhoud.textContent = tekst;

    overlay.appendChild(knoppen);
    overlay.appendChild(inhoud);
    document.documentElement.appendChild(overlay);
}

function maakDrijvendeKnop() {
    var knop = document.createElement('button');
    knop.id = '__for_tm_btn__';
    knop.textContent = '🔍 FOR';
    knop.style.cssText = [
        'position:fixed','bottom:20px','right:20px','z-index:2147483646',
        'background:#ff3333','color:#fff','border:none','border-radius:50%',
        'width:52px','height:52px','font-size:11px','font-weight:bold',
        'cursor:pointer','box-shadow:0 2px 8px rgba(0,0,0,0.5)',
        'font-family:monospace'
    ].join(';');
    knop.addEventListener('click', function() {
        var rapport = voerScanUit();
        toonOverlay(rapport);
    });
    document.documentElement.appendChild(knop);
}

// ══════════════════════════════════════════════════════════════
// START
// ══════════════════════════════════════════════════════════════
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        setTimeout(maakDrijvendeKnop, 1000);
    });
} else {
    setTimeout(maakDrijvendeKnop, 1000);
}

// Automatische scan na 3 seconden (Epic heeft tijd nodig om te laden)
setTimeout(function() {
    var rapport = voerScanUit();
    console.log('[FORENSISCH AUTO-SCAN]');
    console.log(rapport);
    // GM_notification voor treffers
    var vlaggen = epicFeatureVlaggen();
    var kritiekAan = ['DISABLEMYCONDITIONS','DISABLEPLANOFCARE','H2GDEBUG','ISABELGROTHE']
        .filter(function(f) { return vlaggen.indexOf(f) !== -1; });
    if (kritiekAan.length > 0) {
        try {
            GM_notification({
                title: 'Forensisch — Kritieke flags',
                text: kritiekAan.join(', '),
                timeout: 6000
            });
        } catch(e) {}
    }
}, 3000);

})();
