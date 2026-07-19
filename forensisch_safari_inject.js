/**
 * FORENSISCH SAFARI INJECT SCRIPT
 *
 * Doel: volledig forensisch net over de huidige pagina gooien in Safari iOS.
 * Werkt als:
 *   A) Bookmarklet — sla op als bladwijzer, tik aan op de pagina
 *   B) Shortcuts — Acties → "Voer JavaScript uit op webpagina"
 *
 * Filosofie: ALLES vastleggen. Patronen zijn extra markering, geen filter.
 * Scant: zichtbare tekst, verborgen elementen, script-tags, Epic globals,
 *        feature flags, cookies, localStorage, sessionStorage, attributen.
 */

(function () {
'use strict';

// ══════════════════════════════════════════════════════════════
// PATRONEN — exact gesynchroniseerd met loon_forensisch.js
// ══════════════════════════════════════════════════════════════
var PATRONEN = [
    // Medische codes
    { p: /F19\.1/i,                                      nb: 'NB-01' },
    { p: /neusdruppelmisbruik/i,                         nb: 'NB-01' },
    { p: /361055000/,                                    nb: 'NB-03' },
    { p: /228273003/,                                    nb: 'NB-23' },
    { p: /228366006/,                                    nb: 'NB-23b' },
    { p: /266927001/,                                    nb: 'NB-23c' },
    { p: /F60\.31|borderline\s*persoon/i,                nb: 'NB-xx' },
    { p: /transactie.{0,10}77832/i,                      nb: 'NB-23' },
    // Anonieme CDA-auteurs
    { p: /nullFlavor\s*=\s*["']?UNK/i,                  nb: 'NB-18' },
    { p: /extension\s*=\s*["']?999999/i,                nb: 'NB-18' },
    { p: /GUARD\b/,                                      nb: 'NB-56' },
    { p: /HANDMATIGE_EDIT_BOM/i,                         nb: 'NB-13' },
    // Zorgverlener IDs
    { p: /extension\s*=\s*["']?51504662/i,               nb: 'NB-04' },
    { p: /extension\s*=\s*["']?84107660/i,               nb: 'NB-04' },
    { p: /extension\s*=\s*["']?373282512/i,              nb: 'NB-05' },
    { p: /Epic@spaarnegasthuis\.nl/i,                    nb: 'NB-05' },
    // Epic feature flags — toegang
    { p: /DISABLEMYCONDITIONS/i,                         nb: 'NB-11' },
    { p: /DISABLEPLANOFCARE/i,                           nb: 'NB-11' },
    { p: /SUBSTANCEHXQNR/i,                              nb: 'NB-108' },
    { p: /AUTOGENERATESIGNATURE/i,                       nb: 'NB-82' },
    { p: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i,            nb: 'NB-163' },
    { p: /noView\s*:\s*true/i,                           nb: 'NB-99' },
    { p: /SEXUALACTIVITYHXQNR/i,                         nb: 'NB-83' },
    { p: /AUTOSYNCRECEIVEFORPERSONALINFORMATION/i,       nb: 'NB-115' },
    { p: /ExternalJump|LogExternalJumpAudit/i,           nb: 'NB-68' },
    // CSS verbergen
    { p: /hiddenProvider/i,                              nb: 'NB-12' },
    { p: /CEDataExternal/i,                              nb: 'NB-12' },
    { p: /WoundListSection/i,                            nb: 'NB-12' },
    { p: /printBlackText/i,                              nb: 'NB-84' },
    { p: /override\.css/i,                               nb: 'NB-89' },
    { p: /lucy\.css|lucy_colors/i,                       nb: 'NB-71' },
    // Trackers
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
    // Supply chain
    { p: /hoppinger\.com/i,                              nb: 'NB-114' },
    { p: /spaarne-rebuild\.productie\.hoppinger/i,       nb: 'NB-114' },
    { p: /FocusZorgTeam.*test/i,                         nb: 'NB-91' },
    { p: /centramed\.nl/i,                               nb: 'NB-179' },
    { p: /Brijder|Parnassia.*Indigo/i,                   nb: 'NB-113' },
    // ChipSoft HiX
    { p: /ChipSoft\.PlatformServices/i,                  nb: 'NB-177' },
    { p: /GetCurrentPatientAndUserObject/i,               nb: 'NB-177' },
    { p: /GetPatientDocuments/i,                         nb: 'NB-177' },
    { p: /GetPathologyResults/i,                         nb: 'NB-177' },
    { p: /GetDcrRegistrations/i,                         nb: 'NB-177' },
    { p: /DigiDClusterHybrid/i,                          nb: 'NB-177' },
    { p: /DYN_CURRENT_USER/i,                            nb: 'NB-177' },
    { p: /PATIENT_PATIENT/i,                             nb: 'NB-177' },
    { p: /2001702222/,                                   nb: 'NB-177' },
    // Clinician access log
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
    // Genetisch profiel (NB-180)
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
    // Verdachte vlaggen (NB-181)
    { p: /ISABELGROTHE/,                                 nb: 'NB-181' },
    { p: /NNNNNNNNN/,                                    nb: 'NB-181' },
    { p: /\bSZMRN\b/,                                    nb: 'NB-181' },
    { p: /VOLLEDIGPROFIEL/i,                             nb: 'NB-181' },
    { p: /H2GDEBUG/i,                                    nb: 'NB-181' },
    // Tijdstempels / identifiers
    { p: /20260110033455/,                               nb: 'NB-166' },
    { p: /215672185/,                                    nb: 'NB-166' },
    { p: /0133033170/,                                   nb: 'NB-166' },
    // FHIR / MedMij
    { p: /\$lastn/i,                                     nb: 'NB-109' },
    { p: /quliRedirect/i,                                nb: 'MEDMIJ' },
];

// ══════════════════════════════════════════════════════════════
// HULPFUNCTIES
// ══════════════════════════════════════════════════════════════

function scanTekst(tekst, bron) {
    var hits = [];
    if (!tekst || tekst.length < 2) return hits;
    var gezien = {};
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
                    bron: bron
                });
            }
        }
    }
    return hits;
}

function alleScriptInhoud() {
    var scripts = document.querySelectorAll('script');
    var teksten = [];
    for (var i = 0; i < scripts.length; i++) {
        var inhoud = scripts[i].textContent || scripts[i].innerText || '';
        if (inhoud.trim().length > 0) teksten.push(inhoud);
    }
    return teksten.join('\n');
}

function alleDOMTekst() {
    return document.documentElement.innerHTML || '';
}

function epicFeatureVlaggen() {
    var resultaat = [];
    try {
        var html = alleDOMTekst();
        // Zoek de feature flag array — grote array van hoofdletterstrings
        var m = html.match(/"([A-Z][A-Z0-9_]{3,40})"(?:,"[A-Z][A-Z0-9_]{3,40}"){10,}/);
        if (m) {
            var vlaggen = m[0].match(/"([A-Z][A-Z0-9_]{3,40})"/g);
            if (vlaggen) {
                resultaat = vlaggen.map(function(v) { return v.replace(/"/g, ''); });
            }
        }
    } catch (e) {}

    // Probeer ook via window.EpicPx of andere Epic globals
    try {
        if (window.EpicPx && window.EpicPx._featureFlags) {
            resultaat = resultaat.concat(Object.keys(window.EpicPx._featureFlags));
        }
    } catch (e) {}

    return resultaat;
}

function epicScriptUpdates() {
    var resultaat = {};
    try {
        var html = alleDOMTekst();
        var m = html.match(/EpicPx\.scriptUpdates\s*=\s*\{([^}]+)\}/);
        if (m) {
            var paren = m[1].match(/'([^']+)'\s*:\s*"([^"]+)"/g);
            if (paren) {
                paren.forEach(function(p) {
                    var del = p.match(/'([^']+)'\s*:\s*"([^"]+)"/);
                    if (del) resultaat[del[1]] = del[2].slice(0, 12) + '...';
                });
            }
        }
    } catch (e) {}
    return resultaat;
}

function verborgenElementen() {
    var resultaat = [];
    try {
        var els = document.querySelectorAll('*');
        for (var i = 0; i < els.length; i++) {
            var el = els[i];
            var stijl = window.getComputedStyle(el);
            var tekst = (el.textContent || '').trim();
            if (!tekst || tekst.length < 3) continue;
            var verborgen = false;
            var reden = '';
            if (stijl.display === 'none') { verborgen = true; reden = 'display:none'; }
            else if (stijl.visibility === 'hidden') { verborgen = true; reden = 'visibility:hidden'; }
            else if (parseFloat(stijl.opacity) === 0) { verborgen = true; reden = 'opacity:0'; }
            else if (stijl.height === '0px' && stijl.overflow === 'hidden') { verborgen = true; reden = 'height:0+hidden'; }
            if (verborgen) {
                resultaat.push({
                    tag: el.tagName,
                    klassen: el.className ? String(el.className).slice(0, 60) : '',
                    reden: reden,
                    tekst: tekst.slice(0, 200)
                });
            }
        }
    } catch (e) {}
    return resultaat.slice(0, 50);
}

function cookieDump() {
    try { return document.cookie || '(geen)'; } catch (e) { return '(fout: ' + e + ')'; }
}

function localStorageDump() {
    var items = [];
    try {
        for (var i = 0; i < localStorage.length; i++) {
            var k = localStorage.key(i);
            var v = localStorage.getItem(k);
            items.push(k + ' = ' + (v || '').slice(0, 200));
        }
    } catch (e) { items.push('(fout: ' + e + ')'); }
    return items;
}

function sessionStorageDump() {
    var items = [];
    try {
        for (var i = 0; i < sessionStorage.length; i++) {
            var k = sessionStorage.key(i);
            var v = sessionStorage.getItem(k);
            items.push(k + ' = ' + (v || '').slice(0, 200));
        }
    } catch (e) { items.push('(fout: ' + e + ')'); }
    return items;
}

function netwerkaanvragen() {
    // Performance entries vastleggen (XHR/fetch die al gedaan zijn)
    var urls = [];
    try {
        var entries = performance.getEntriesByType('resource');
        for (var i = 0; i < entries.length; i++) {
            var url = entries[i].name;
            if (url && (url.includes('spaarne') || url.includes('epic') || url.includes('mychart') || url.includes('chipsoft') || url.includes('medmij'))) {
                urls.push({
                    url: url.slice(0, 200),
                    type: entries[i].initiatorType,
                    duur: Math.round(entries[i].duration) + 'ms'
                });
            }
        }
    } catch (e) {}
    return urls;
}

// ══════════════════════════════════════════════════════════════
// HOOFDSCAN
// ══════════════════════════════════════════════════════════════

function voerScanUit() {
    var LOG = [];
    var alleTreffers = [];

    LOG.push('=== FORENSISCH SAFARI SCAN ===');
    LOG.push('URL: ' + location.href);
    LOG.push('Tijd: ' + new Date().toISOString().slice(0, 19).replace('T', ' '));
    LOG.push('');

    // 1. Scan volledige HTML (inclusief script-tags)
    LOG.push('--- STAP 1: HTML + scripts scannen ---');
    var volledigeHTML = alleDOMTekst();
    LOG.push('HTML-grootte: ' + volledigeHTML.length + ' bytes');
    var htmlTreffers = scanTekst(volledigeHTML, 'HTML/script');
    alleTreffers = alleTreffers.concat(htmlTreffers);
    LOG.push('Treffers in HTML: ' + htmlTreffers.length);
    LOG.push('');

    // 2. Epic feature vlaggen
    LOG.push('--- STAP 2: Epic feature flags ---');
    var vlaggen = epicFeatureVlaggen();
    if (vlaggen.length > 0) {
        LOG.push('Totaal vlaggen: ' + vlaggen.length);

        // Kritieke vlaggen controleren
        var kritiek = ['DISABLEMYCONDITIONS', 'DISABLEPLANOFCARE', 'USERAUDITTRAIL',
                        'MYCHARTAUDITTRAIL', 'SUBSTANCEHXQNR', 'SEXUALACTIVITYHXQNR',
                        'AUTOGENERATESIGNATURE', 'AUTOSYNCRECEIVEFORPERSONALINFORMATION',
                        'GENETICHXQNR', 'VIEWHIDDENRESULTS', 'H2GDEBUG',
                        'ISABELGROTHE', 'NNNNNNNNN', 'SZMRN', 'VOLLEDIGPROFIEL'];
        kritiek.forEach(function(v) {
            var aanwezig = vlaggen.indexOf(v) >= 0;
            LOG.push('  ' + (aanwezig ? '[AAN] ' : '[UIT] ') + v);
        });

        LOG.push('');
        LOG.push('Alle vlaggen (gesorteerd):');
        vlaggen.slice().sort().forEach(function(v) { LOG.push('  ' + v); });
    } else {
        LOG.push('(geen vlaggen gevonden — pagina nog niet volledig geladen?)');
    }
    LOG.push('');

    // 3. Geladen Epic modules
    LOG.push('--- STAP 3: Geladen Epic modules ---');
    var modules = epicScriptUpdates();
    var modNamen = Object.keys(modules);
    if (modNamen.length > 0) {
        LOG.push('Geladen modules: ' + modNamen.length);
        modNamen.forEach(function(naam) {
            var interessant = naam.includes('genetic') || naam.includes('genomic') ||
                              naam.includes('access-log') || naam.includes('audit');
            LOG.push((interessant ? '  [!] ' : '  ') + naam + ' → ' + modules[naam]);
        });
    } else {
        LOG.push('(geen scriptUpdates gevonden)');
    }
    LOG.push('');

    // 4. Verborgen elementen
    LOG.push('--- STAP 4: Verborgen DOM-elementen ---');
    var verborgen = verborgenElementen();
    if (verborgen.length > 0) {
        LOG.push('Verborgen elementen: ' + verborgen.length);
        verborgen.forEach(function(el) {
            LOG.push('  [' + el.reden + '] <' + el.tag + ' class="' + el.klassen + '"> ' + el.tekst.slice(0, 100));
        });
    } else {
        LOG.push('(geen verborgen elementen gevonden)');
    }
    LOG.push('');

    // 5. Cookies
    LOG.push('--- STAP 5: Cookies ---');
    var cookies = cookieDump();
    LOG.push(cookies);
    LOG.push('');

    // 6. LocalStorage
    LOG.push('--- STAP 6: localStorage ---');
    var ls = localStorageDump();
    if (ls.length === 0) { LOG.push('(leeg)'); }
    else { ls.forEach(function(i) { LOG.push('  ' + i); }); }
    LOG.push('');

    // 7. SessionStorage
    LOG.push('--- STAP 7: sessionStorage ---');
    var ss = sessionStorageDump();
    if (ss.length === 0) { LOG.push('(leeg)'); }
    else { ss.forEach(function(i) { LOG.push('  ' + i); }); }
    LOG.push('');

    // 8. Netwerkaanvragen (performance entries)
    LOG.push('--- STAP 8: Relevante netwerkaanvragen (performance) ---');
    var nw = netwerkaanvragen();
    if (nw.length === 0) { LOG.push('(geen of niet bereikbaar)'); }
    else {
        nw.forEach(function(r) {
            LOG.push('  [' + r.type + ' ' + r.duur + '] ' + r.url);
        });
    }
    LOG.push('');

    // 9. NB-treffers samenvatting
    LOG.push('═══════════════════════════════════');
    LOG.push('NB-TREFFERS SAMENVATTING');
    LOG.push('═══════════════════════════════════');
    if (alleTreffers.length === 0) {
        LOG.push('Geen bekende patronen aangetroffen.');
    } else {
        // Groepeer per NB-nummer
        var perNB = {};
        alleTreffers.forEach(function(t) {
            if (!perNB[t.nb]) perNB[t.nb] = [];
            perNB[t.nb].push(t);
        });
        Object.keys(perNB).sort().forEach(function(nb) {
            LOG.push('[' + nb + '] ' + perNB[nb].length + 'x');
            perNB[nb].forEach(function(t) {
                LOG.push('  match: ' + t.match);
                LOG.push('  context: ...' + t.context + '...');
            });
        });
    }
    LOG.push('');
    LOG.push('Totaal treffers: ' + alleTreffers.length);
    LOG.push('Scan voltooid: ' + new Date().toISOString().slice(0, 19).replace('T', ' '));

    return LOG.join('\n');
}

// ══════════════════════════════════════════════════════════════
// UI — overlay tonen in de pagina
// ══════════════════════════════════════════════════════════════

function toonOverlay(rapport) {
    // Verwijder eventueel eerder overlay
    var oud = document.getElementById('__forensisch_overlay__');
    if (oud) oud.parentNode.removeChild(oud);

    var overlay = document.createElement('div');
    overlay.id = '__forensisch_overlay__';
    overlay.style.cssText = [
        'position:fixed', 'top:0', 'left:0', 'right:0', 'bottom:0',
        'background:rgba(0,0,0,0.92)', 'color:#00ff41', 'font-family:monospace',
        'font-size:11px', 'z-index:2147483647', 'overflow:hidden',
        'display:flex', 'flex-direction:column', 'padding:0'
    ].join(';');

    // Balk bovenaan
    var balk = document.createElement('div');
    balk.style.cssText = 'background:#111;padding:8px 12px;display:flex;align-items:center;gap:8px;flex-shrink:0;border-bottom:1px solid #00ff41';
    balk.innerHTML = '<span style="color:#00ff41;font-weight:bold;font-size:13px">FORENSISCH SCAN</span>' +
        '<span style="color:#888;font-size:10px">' + location.hostname + '</span>' +
        '<span style="margin-left:auto;display:flex;gap:8px">' +
        '<button id="__for_copy__" style="background:#00ff41;color:#000;border:none;padding:4px 10px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:3px">KOPIEER</button>' +
        '<button id="__for_sluit__" style="background:#333;color:#fff;border:1px solid #555;padding:4px 10px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:3px">SLUIT</button>' +
        '</span>';

    // Tekst-inhoud
    var inhoud = document.createElement('pre');
    inhoud.style.cssText = 'flex:1;overflow:auto;margin:0;padding:12px;white-space:pre-wrap;word-break:break-all;line-height:1.4';
    inhoud.textContent = rapport;

    overlay.appendChild(balk);
    overlay.appendChild(inhoud);
    document.body.appendChild(overlay);

    // Knopfuncties
    document.getElementById('__for_copy__').addEventListener('click', function () {
        try {
            navigator.clipboard.writeText(rapport).then(function() {
                var btn = document.getElementById('__for_copy__');
                if (btn) { btn.textContent = 'GEKOPIEERD!'; setTimeout(function() { if (btn) btn.textContent = 'KOPIEER'; }, 2000); }
            }).catch(function() {
                // Fallback voor oudere iOS
                var ta = document.createElement('textarea');
                ta.value = rapport;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.focus();
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
            });
        } catch (e) {}
    });

    document.getElementById('__for_sluit__').addEventListener('click', function () {
        var el = document.getElementById('__forensisch_overlay__');
        if (el) el.parentNode.removeChild(el);
    });
}

// ══════════════════════════════════════════════════════════════
// VOOR SHORTCUTS: ook een return-waarde geven
// ══════════════════════════════════════════════════════════════

function runMain() {
    var rapport = voerScanUit();
    toonOverlay(rapport);
    // Shortcuts "Voer JavaScript uit" pakt de return-waarde op
    return rapport;
}

// Start
try {
    runMain();
} catch (e) {
    alert('Forensisch scan fout: ' + e);
}

})();
