// ==UserScript==
// @name         Forensisch Scanner — MijnSpaarneGasthuis / Epic MyChart
// @namespace    forensisch-grothe
// @version      1.4
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
        if (el.id && el.id.indexOf('__for_') === 0) continue;
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

// Onthul verborgen elementen IN de portal — zichtbaar maken met gele markering
function onthulVerborgen() {
    var onthuld = 0;
    var alle = document.querySelectorAll('*');
    for (var i = 0; i < alle.length; i++) {
        var el = alle[i];
        if (el.id && el.id.indexOf('__for_') === 0) continue;
        if (el.getAttribute('data-for-onthuld')) continue;
        try {
            var cs = window.getComputedStyle(el);
            var reden = '';
            if (cs.display === 'none') reden = 'display:none';
            else if (cs.visibility === 'hidden') reden = 'visibility:hidden';
            else if (parseFloat(cs.opacity) === 0) reden = 'opacity:0';
            else if (parseFloat(cs.height) === 0 && cs.overflow === 'hidden') reden = 'height:0+overflow:hidden';
            if (!reden) continue;
            var tekst = (el.textContent || '').trim();
            if (tekst.length < 2) continue;

            // Maak zichtbaar — !important overschrijft pagina-CSS
            el.style.cssText += ';display:block!important;visibility:visible!important;opacity:1!important;height:auto!important;overflow:visible!important;max-height:none!important;clip:auto!important;';
            // Gele markering
            el.style.setProperty('outline', '2px dashed #f59e0b', 'important');
            el.style.setProperty('background-color', 'rgba(245,158,11,0.08)', 'important');
            el.setAttribute('data-for-onthuld', reden);

            // Label: klein geel bannetje bovenaan het element
            var label = document.createElement('div');
            label.className = '__for_label__';
            label.textContent = '▲ WAS VERBORGEN — ' + reden;
            label.style.cssText = [
                'display:block!important','visibility:visible!important','opacity:1!important',
                'background:#f59e0b','color:#000','font-size:10px','line-height:1.4',
                'font-family:monospace','font-weight:bold','padding:2px 8px',
                'border-radius:2px 2px 0 0','margin-bottom:2px',
                'pointer-events:none','position:relative','z-index:2147483640'
            ].join(';');
            el.insertBefore(label, el.firstChild);
            onthuld++;
        } catch(e) {}
    }
    return onthuld;
}

// Herstel — verwijder alle forensische markeringen
function herstelVerborgen() {
    var labels = document.querySelectorAll('.__for_label__');
    for (var i = 0; i < labels.length; i++) {
        try { labels[i].parentNode.removeChild(labels[i]); } catch(e) {}
    }
    var gemarkeerd = document.querySelectorAll('[data-for-onthuld]');
    for (var j = 0; j < gemarkeerd.length; j++) {
        var el = gemarkeerd[j];
        var reden = el.getAttribute('data-for-onthuld');
        el.removeAttribute('data-for-onthuld');
        try {
            if (reden === 'display:none')              el.style.removeProperty('display');
            if (reden === 'visibility:hidden')         el.style.removeProperty('visibility');
            if (reden === 'opacity:0')                 el.style.removeProperty('opacity');
            if (reden === 'height:0+overflow:hidden')  { el.style.removeProperty('height'); el.style.removeProperty('overflow'); }
            el.style.removeProperty('outline');
            el.style.removeProperty('background-color');
            el.style.removeProperty('max-height');
        } catch(e) {}
    }
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
// UI — zijpaneel rechts (portaal blijft zichtbaar links)
// ══════════════════════════════════════════════════════════════
function toonZijpaneel(tekst) {
    var bestaand = document.getElementById('__for_tm_paneel__');
    if (bestaand) bestaand.parentNode.removeChild(bestaand);

    var paneel = document.createElement('div');
    paneel.id = '__for_tm_paneel__';
    paneel.style.cssText = [
        'position:fixed','top:0','right:0','width:340px','max-width:90vw',
        'height:100%','background:rgba(10,12,18,0.97)',
        'color:#00ff41','font-family:SFMono-Regular,Menlo,monospace',
        'font-size:11px','z-index:2147483647','display:flex',
        'flex-direction:column','box-sizing:border-box',
        'border-left:2px solid #00e57a',
        'box-shadow:-4px 0 24px rgba(0,0,0,0.7)'
    ].join(';');

    // Vaste knoppenbalk bovenaan
    var balk = document.createElement('div');
    balk.style.cssText = [
        'flex-shrink:0','background:#0d0f16',
        'border-bottom:1px solid #1a2030',
        'padding:8px 10px','display:flex','gap:6px',
        'align-items:center','flex-wrap:wrap'
    ].join(';');

    var s = 'border:none;padding:7px 12px;font-weight:bold;cursor:pointer;font-family:monospace;font-size:12px;border-radius:3px;';

    function maakKnop(label, bg, fg) {
        var k = document.createElement('button');
        k.textContent = label;
        k.style.cssText = s + 'background:' + bg + ';color:' + fg + ';';
        return k;
    }

    var kSluit    = maakKnop('✕ SLUIT',   '#cc2222', '#fff');
    var kKopieer  = maakKnop('KOPIEER',   '#00c853', '#000');
    var kNetwerk  = maakKnop('NETWERK',   '#0077cc', '#fff');
    var kOnthul   = maakKnop('ONTHUL',    '#f59e0b', '#000');
    var kHerstel  = maakKnop('HERSTEL',   '#334',    '#aaa');

    kSluit.addEventListener('click', function() {
        paneel.parentNode.removeChild(paneel);
    });

    kKopieer.addEventListener('click', function() {
        function doCopy(t) {
            try { GM_setClipboard(t); return; } catch(e) {}
            try { navigator.clipboard.writeText(t); return; } catch(e) {}
            var ta = document.createElement('textarea');
            ta.value = t; document.body.appendChild(ta);
            ta.select(); document.execCommand('copy');
            document.body.removeChild(ta);
        }
        doCopy(tekst);
        kKopieer.textContent = '✓ OK';
        setTimeout(function() { kKopieer.textContent = 'KOPIEER'; }, 2000);
    });

    kNetwerk.addEventListener('click', function() {
        var nt = netwerkLog.map(function(e) {
            return '[' + e.t + '] ' + e.r + ' ' + e.m + ' HTTP' + e.s + '\n'
                 + 'URL: ' + e.u + '\n'
                 + (e.nb ? 'NB: ' + e.nb + '\n' : '')
                 + 'BODY:\n' + e.body + '\n────────────────────────────────';
        }).join('\n');
        function doCopy(t) {
            try { GM_setClipboard(t); return; } catch(e) {}
            try { navigator.clipboard.writeText(t); } catch(e) {}
        }
        doCopy(nt || 'Geen netwerk.');
        kNetwerk.textContent = '✓ OK';
        setTimeout(function() { kNetwerk.textContent = 'NETWERK'; }, 2000);
    });

    kOnthul.addEventListener('click', function() {
        var n = onthulVerborgen();
        kOnthul.textContent = '▲ ' + n + ' ONTHULD';
        setTimeout(function() { kOnthul.textContent = 'ONTHUL'; }, 3000);
    });

    kHerstel.addEventListener('click', function() {
        herstelVerborgen();
        kHerstel.textContent = '↩ HERSTELD';
        setTimeout(function() { kHerstel.textContent = 'HERSTEL'; }, 2000);
    });

    balk.appendChild(kSluit);
    balk.appendChild(kKopieer);
    balk.appendChild(kNetwerk);
    balk.appendChild(kOnthul);
    balk.appendChild(kHerstel);

    // Telregel: samenvatting bovenaan
    var samenvatting = document.createElement('div');
    samenvatting.id = '__for_tm_samenvatting__';
    samenvatting.style.cssText = [
        'flex-shrink:0','padding:6px 10px',
        'font-size:10px','color:#4a9','background:#0d1117',
        'border-bottom:1px solid #1a2030','line-height:1.5'
    ].join(';');
    samenvatting.textContent = '⟳ Scannen…';

    // Scrollbaar tekstgebied
    var inhoud = document.createElement('div');
    inhoud.style.cssText = [
        'flex:1','overflow-y:auto','overflow-x:hidden',
        'padding:10px 12px','white-space:pre-wrap','word-break:break-all',
        'line-height:1.55','-webkit-overflow-scrolling:touch'
    ].join(';');
    inhoud.textContent = tekst;

    paneel.appendChild(balk);
    paneel.appendChild(samenvatting);
    paneel.appendChild(inhoud);
    var doel = document.body || document.documentElement;
    doel.appendChild(paneel);
    return samenvatting;
}

function bijwerkSamenvatting(el, domHits, vlaggenAan, onthuld, netwerk) {
    if (!el) return;
    var regels = [
        '● DOM-treffers: ' + domHits,
        '● Kritieke flags: ' + vlaggenAan,
        '● Onthuld: ' + onthuld + ' verborgen elem.',
        '● Netwerk: ' + netwerk + ' verzoeken'
    ];
    el.textContent = regels.join('   ');
}

function maakDrijvendeKnop() {
    if (document.getElementById('__for_tm_btn__')) return;
    var knop = document.createElement('button');
    knop.id = '__for_tm_btn__';
    knop.textContent = '🔍';
    knop.style.cssText = [
        'position:fixed','bottom:24px','right:24px','z-index:2147483647',
        'background:#cc2222','color:#fff','border:2px solid #fff',
        'border-radius:50%','width:52px','height:52px','font-size:20px',
        'cursor:pointer','box-shadow:0 3px 12px rgba(0,0,0,0.7)',
        'line-height:1'
    ].join(';');
    knop.addEventListener('click', function() {
        var paneel = document.getElementById('__for_tm_paneel__');
        if (paneel) {
            paneel.parentNode.removeChild(paneel);
        } else {
            voerVolledigeScanUit();
        }
    });
    var doel = document.body || document.documentElement;
    doel.appendChild(knop);
}

function voerVolledigeScanUit() {
    // 1. Verborgen elementen direct onthullen in de pagina
    var onthuld = onthulVerborgen();

    // 2. Rapport genereren
    var rapport = voerScanUit();

    // 3. Zijpaneel tonen
    var samenvattingEl = toonZijpaneel(rapport);

    // 4. Samenvatting invullen
    var domHits = (rapport.match(/\[NB-/g) || []).length;
    var vlaggen = epicFeatureVlaggen();
    var kritiekAan = ['DISABLEMYCONDITIONS','DISABLEPLANOFCARE','H2GDEBUG','ISABELGROTHE','GENETICHXQNR','SZMRN','NNNNNNNNN']
        .filter(function(f) { return vlaggen.indexOf(f) !== -1; }).length;
    bijwerkSamenvatting(samenvattingEl, domHits, kritiekAan, onthuld, netwerkLog.length);

    console.log('[FORENSISCH]', rapport);

    // 5. Melding bij kritieke flags
    if (kritiekAan > 0) {
        try {
            GM_notification({
                title: 'Forensisch — ' + kritiekAan + ' kritieke flag(s)',
                text: vlaggen.filter(function(f) {
                    return ['DISABLEMYCONDITIONS','DISABLEPLANOFCARE','H2GDEBUG','ISABELGROTHE','GENETICHXQNR'].indexOf(f) !== -1;
                }).join(', '),
                timeout: 7000
            });
        } catch(e) {}
    }
}

// ══════════════════════════════════════════════════════════════
// START
// ══════════════════════════════════════════════════════════════
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        setTimeout(maakDrijvendeKnop, 500);
    });
} else {
    setTimeout(maakDrijvendeKnop, 500);
}

// Automatische scan na 4 seconden
setTimeout(function() {
    maakDrijvendeKnop();
    voerVolledigeScanUit();
}, 4000);

})();
