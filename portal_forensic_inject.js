// ==UserScript==
// @name         Forensisch Monitor (Grothe C/15/376914)
// @namespace    grothe-forensisch
// @version      11.0
// @description  Detecteert verborgen audit/CSS/SNOMED/Epic/ChipSoft/VWO-patronen in zorgportaal-responses
// @include      *spaarnegasthuis*
// @include      *dijklander*
// @include      *mychart*
// @include      *epic*
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
// @include      *brijder*
// @include      *psyq*
// @include      *viersprong*
// @include      *indigo*
// @include      *ggz*
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
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function () {
'use strict';

var DOSSIER = 'Grothe C/15/376914';
var LOG_PREFIX = '[FORENSISCH]';

var CSS_VERBERGING_KLASSEN = [
    'hiddenProvider', 'CEDataExternal', 'SRonly', 'CEAuth', 'CENoAuth',
    'noView', 'hidden-data', 'sr-only',
];

var VERDACHTE_INLINE_STIJLEN = [
    { prop: 'display',    waarde: 'none',    ernst: 'KRITIEK', nb: 'NB-12/53' },
    { prop: 'visibility', waarde: 'hidden',  ernst: 'HOOG',    nb: 'NB-12' },
    { prop: 'fontSize',   waarde: '0px',     ernst: 'HOOG',    nb: 'NB-53' },
    { prop: 'left',       max: -5000,        ernst: 'HOOG',    nb: 'NB-53 SRonly' },
    { prop: 'color',      waarde: '#ffffff', ernst: 'MEDIUM',  nb: 'NB-12 wit-op-wit' },
    { prop: 'opacity',    waarde: '0',       ernst: 'MEDIUM',  nb: 'NB-12' },
];

var CFG = {
    auditTrailEndpoints: [
        'GetClinicianAccessLogSettings', 'GetClinicianAccessLogEntries',
        'GetThirdPartyAccessLogEntries', 'access-logs', 'AccessLog', 'AuditTrail',
        'GetClinicianAccessLog', 'auditlog', 'audit-trail',
    ],
    forensischePatronen: [
        { p: /F19\.1|neusdruppelmisbruik/i,               l: 'F19.1 neusdruppelmisbruik (NB-01)',              ernst: 'KRITIEK' },
        { p: /361055000/,                                  l: 'SNOMED 361055000 nasal spray misuse (NB-03)',    ernst: 'KRITIEK' },
        { p: /228273003/,                                  l: 'SNOMED 228273003 drug misuse (NB-23)',           ernst: 'KRITIEK' },
        { p: /228366006/,                                  l: 'SNOMED 228366006 stimulant misuse',             ernst: 'HOOG'    },
        { p: /nullFlavor="UNK"/i,                          l: 'CDA nullFlavor=UNK anonieme auteur (NB-18)',    ernst: 'HOOG'    },
        { p: /extension="999999"/i,                        l: 'Epic ext=999999 anonymous (NB-18)',             ernst: 'KRITIEK' },
        { p: /extension="373282512"/i,                     l: 'A. al-Mousawi ext (NB-05)',                     ernst: 'KRITIEK' },
        { p: /extension="51504662"|extension="84107660"/i, l: 'N.M. Nota ext (NB-04)',                         ernst: 'KRITIEK' },
        { p: /Epic@spaarnegasthuis\.nl/i,                  l: 'Epic admin email (NB-05)',                      ernst: 'KRITIEK' },
        { p: /DISABLEMYCONDITIONS/i,                       l: 'Feature flag DISABLEMYCONDITIONS (NB-11)',      ernst: 'KRITIEK' },
        { p: /DISABLEPLANOFCARE/i,                         l: 'Feature flag DISABLEPLANOFCARE (NB-11)',        ernst: 'KRITIEK' },
        { p: /SUBSTANCEHXQNR/i,                            l: 'SUBSTANCEHXQNR module (NB-108)',                ernst: 'KRITIEK' },
        { p: /AUTOGENERATESIGNATURE/i,                     l: 'AUTOGENERATESIGNATURE (NB-82)',                 ernst: 'KRITIEK' },
        { p: /SEXUALACTIVITYHXQNR/i,                       l: 'Seksuele anamnese module (NB-83)',              ernst: 'HOOG'    },
        { p: /AUTOSYNCRECEIVEFORPERSONALINFORMATION/i,     l: 'AutoSync extern bronsysteem (NB-115)',          ernst: 'HOOG'    },
        { p: /ExternalJump|LogExternalJumpAudit/i,         l: 'ExternalJump tracking (NB-68)',                 ernst: 'MEDIUM'  },
        { p: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i,          l: 'Audit trail feature flag (NB-163)',             ernst: 'HOOG'    },
        { p: /GUARD\b/,                                    l: 'GUARD blok CDA (NB-56)',                        ernst: 'HOOG'    },
        { p: /noView\s*:\s*true/i,                         l: 'noView:true (NB-99)',                           ernst: 'KRITIEK' },
        { p: /recording_capture_keystrokes=true/i,         l: 'Hotjar keystroke capture ACTIEF (NB-53)',       ernst: 'KRITIEK' },
        { p: /spaarne-rebuild\.productie\.hoppinger/i,     l: 'Hoppinger supply chain (NB-114)',               ernst: 'KRITIEK' },
        { p: /hoppinger\.com/i,                            l: 'Hoppinger.com (NB-114)',                        ernst: 'KRITIEK' },
        { p: /override\.css/i,                             l: 'override.css referentie (NB-53/89)',            ernst: 'KRITIEK' },
        { p: /hiddenProvider|CEDataExternal/i,             l: 'CSS verberging klasse (NB-12)',                 ernst: 'KRITIEK' },
        { p: /HANDMATIGE_EDIT_BOM/i,                       l: 'Bytemanipulatieflag (NB-13)',                   ernst: 'KRITIEK' },
        { p: /20260110033455/,                             l: 'KRITIEK NACHT-TIMESTAMP 10-01-2026 (NB-166)',   ernst: 'KRITIEK' },
        { p: /transactie.{0,10}77832/i,                    l: 'Transactie-ID 77832 SNOMED SUCCESS (NB-23)',    ernst: 'KRITIEK' },
        { p: /215672185/,                                  l: 'BSN Grothe in response body',                  ernst: 'HOOG'    },
        { p: /0133033170/,                                 l: 'MDN Grothe in response body',                  ernst: 'HOOG'    },
        { p: /DE36B70A/i,                                  l: 'Sentry device ID DE36B70A (NB-69)',             ernst: 'HOOG'    },
        { p: /hotjar\.com|hjid=/i,                         l: 'Hotjar tracker (NB-79)',                        ernst: 'HOOG'    },
        { p: /sentry\.io/i,                                l: 'Sentry.io telemetrie (NB-69)',                  ernst: 'HOOG'    },
        { p: /pendo\.io/i,                                 l: 'Pendo.io tracker (NB-79)',                      ernst: 'HOOG'    },
        { p: /wingify|vwo\.com/i,                          l: 'VWO/Wingify India content-injectie (NB-85)',    ernst: 'HOOG'    },
        { p: /FocusZorgTeam.*test\.authorization/i,        l: 'FocusZorgTeam test-server productie (NB-91)',   ernst: 'HOOG'    },
        { p: /printBlackText/i,                            l: 'printBlackText alarmkleuren (NB-84)',           ernst: 'MEDIUM'  },
        { p: /lucy\.css|lucy_colors/i,                     l: 'lucy.css renderingslaag (NB-71)',               ernst: 'MEDIUM'  },
        { p: /\$lastn/i,                                   l: 'FHIR $lastn re-replay (NB-109)',                ernst: 'HOOG'    },
        { p: /Brijder|Parnassia.*Indigo|Indigo.*Parnassia/i, l: 'Parnassia/Brijder nooit in behandeling (NB-113)', ernst: 'KRITIEK' },
        { p: /GTM-PGPCH2T/i,                               l: 'GTM tag GTM-PGPCH2T (NB-85)',                   ernst: 'HOOG'    },
        { p: /ChipSoft\.PlatformServices/i,                l: 'KRITIEK ChipSoft HiX API blootgesteld (NB-177)',  ernst: 'KRITIEK' },
        { p: /GetCurrentPatientAndUserObject/i,            l: 'KRITIEK ChipSoft patientobject gelekt (NB-177)', ernst: 'KRITIEK' },
        { p: /PATIENT_PATIENT.*2001702222|2001702222.*PATIENT_PATIENT/, l: 'KRITIEK ChipSoft patient-ID Grothe in response (NB-177)', ernst: 'KRITIEK' },
        { p: /2001702222/,                                 l: 'KRITIEK ChipSoft patient-ID Grothe (NB-177)',     ernst: 'KRITIEK' },
        { p: /DYN_CURRENT_USER/i,                          l: 'ChipSoft HiX session token type (NB-177)',        ernst: 'HOOG'    },
        { p: /ComponentRequest|ComponentDownload/i,        l: 'ChipSoft HiX component API (NB-177)',             ernst: 'HOOG'    },
        { p: /GetPatientDocuments/i,                       l: 'ChipSoft patientdocumenten opgehaald (NB-177)',   ernst: 'HOOG'    },
        { p: /GetPathologyResults/i,                       l: 'ChipSoft pathologieresultaten (NB-177)',          ernst: 'HOOG'    },
        { p: /GetRadiologyProcedures/i,                    l: 'ChipSoft radiologieprocedures (NB-177)',          ernst: 'HOOG'    },
        { p: /GetDcrRegistrations/i,                       l: 'ChipSoft DCR toestemmingen (NB-177)',             ernst: 'HOOG'    },
        { p: /HAAS_DOCUMENT/i,                             l: 'ChipSoft HAAS document type (NB-177)',            ernst: 'HOOG'    },
        { p: /DigiDClusterHybrid/i,                        l: 'ChipSoft DigiD authenticatie flow (NB-177)',      ernst: 'HOOG'    },
        { p: /mijn\.dijklander\.nl/i,                      l: 'Dijklander HiX portaal actief (NB-177)',          ernst: 'HOOG'    },
        { p: /account_id\s*[:|=]\s*763232/i,               l: 'KRITIEK VWO tracker account_id=763232 (NB-53)',   ernst: 'KRITIEK' },
        { p: /hide_element.*opacity\s*:\s*0|body.*opacity.*0.*important/i, l: 'KRITIEK VWO body opacity:0 aanval (NB-53)', ernst: 'KRITIEK' },
        { p: /vwo_uuid/i,                                  l: 'VWO UUID tracking na weigering (NB-178)',         ernst: 'HOOG'    },
        { p: /WoundListSection.*display.*none|display.*none.*WoundListSection/i, l: 'CSS verberging wondensectie (NB-12)', ernst: 'KRITIEK' },
        { p: /SharingHub.*display.*none|display.*none.*SharingHub/i,             l: 'CSS verberging gezondheidsdelen (NB-12)', ernst: 'KRITIEK' },
        { p: /sharerecord.*display.*none|display.*none.*sharerecord/i,           l: 'CSS verberging dossier delen (NB-12)', ernst: 'KRITIEK' },
        { p: /documents.*display.*none|mode=documents.*display.*none/i,          l: 'CSS verberging documentenlink (NB-12)', ernst: 'KRITIEK' },
        { p: /datadog.*browser-intake|browser-intake.*datadoghq/i,               l: 'Datadog RUM telemetrie (NB-69)',        ernst: 'HOOG'    },
        { p: /centramed\.nl/i,                             l: 'Centramed aansprakelijkheidsverzekeraar (NB-179)', ernst: 'HOOG'   },
    ],
};

var VERDACHTE_KNOP_TEKSTEN = [
    /meer laden/i, /load more/i, /toon meer/i, /show all/i, /alle resultaten/i,
];

var meerLadenTeller = 0;
var evidenceLog = [];
var bevindingTeller = 0;

async function sha256(tekst) {
    var data = new TextEncoder().encode(tekst);
    var hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer)).map(function (b) {
        return b.toString(16).padStart(2, '0');
    }).join('');
}

async function logBevinding(ernst, categorie, omschrijving, nb, context) {
    context = context || '';
    bevindingTeller++;
    var tijdstempel = new Date().toISOString();
    var hash = await sha256(omschrijving + '|' + nb + '|' + tijdstempel + '|' + context.slice(0, 200));
    var bevinding = {
        nr: bevindingTeller, ernst: ernst, categorie: categorie,
        omschrijving: omschrijving, nb: nb,
        context: context.slice(0, 500), tijdstempel: tijdstempel,
        url: window.location.href, sha256: hash,
    };
    evidenceLog.push(bevinding);
    var prefix = { KRITIEK: '[!!]', HOOG: '[!]', MEDIUM: '[~]', INFO: '[i]' }[ernst] || '[?]';
    console.log(prefix + ' ' + LOG_PREFIX + '[' + ernst + '] ' + categorie + ': ' + omschrijving);
    console.log('    NB: ' + nb + ' | SHA256: ' + hash);
    if (context) console.log('    -> ' + context.slice(0, 200));
    if (ernst === 'KRITIEK') toonMarker(omschrijving, nb);
    return bevinding;
}

function toonMarker(tekst, nb) {
    var container = document.getElementById('fg-marker-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'fg-marker-container';
        container.style.cssText = 'position:fixed;top:10px;right:10px;z-index:2147483647;' +
            'display:flex;flex-direction:column;gap:4px;max-width:400px;font-family:monospace';
        if (document.body) document.body.appendChild(container);
    }
    var marker = document.createElement('div');
    marker.style.cssText = 'background:#cc0000;color:#fff;padding:6px 10px;border-radius:4px;' +
        'font-size:11px;line-height:1.4;box-shadow:0 2px 8px rgba(0,0,0,.5)';
    marker.textContent = '[!!] ' + nb + ': ' + tekst.slice(0, 80);
    container.appendChild(marker);
    setTimeout(function () { marker.remove(); }, 18000);
}

function isAudit(url) {
    for (var i = 0; i < CFG.auditTrailEndpoints.length; i++) {
        if (url.indexOf(CFG.auditTrailEndpoints[i]) !== -1) return true;
    }
    return false;
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
            var nb = (pats[i].l.match(/NB-[\d\/]+/) || ['NB-??'])[0];
            logBevinding(pats[i].ernst, 'SCAN', pats[i].l, nb, 'URL: ' + su + ' | ...' + ctx + '...');
        }
    }
}

function stripCSSHiding(root) {
    var sels = '.hiddenProvider,.CEDataExternal,.SRonly,.noView,.hidden-data,.sr-only,' +
        '[style*="display:none"],[style*="display: none"],[style*="visibility:hidden"]';
    var els;
    try { els = root.querySelectorAll(sels); } catch (e) { return; }
    els.forEach(function (el) {
        el.style.setProperty('display', 'block', 'important');
        el.style.setProperty('visibility', 'visible', 'important');
        el.style.setProperty('font-size', 'inherit', 'important');
        el.removeAttribute('aria-hidden');
        el.setAttribute('data-f', '1');
        var tekst = el.textContent && el.textContent.trim();
        if (tekst && tekst.length > 5) {
            logBevinding('KRITIEK', 'CSS_VERBERGING_ONTHULD',
                'Verborgen element onthuld: ' + tekst.slice(0, 100),
                'NB-12/53', 'tag=' + el.tagName + ' class=' + (el.className || '').slice(0, 60));
        }
    });
}

var domObserver = new MutationObserver(function (muts) {
    muts.forEach(function (mut) {
        mut.removedNodes.forEach(function (node) {
            if (node.nodeType !== 1) return;
            var tekst = node.textContent || '';
            VERDACHTE_KNOP_TEKSTEN.forEach(function (pat) {
                if (pat.test(tekst)) {
                    meerLadenTeller++;
                    logBevinding('KRITIEK', 'MEER_LADEN_VERWIJDERD',
                        '"Meer laden"-knop verwijderd (teller: ' + meerLadenTeller + ')',
                        'NB-99', 'tekst="' + tekst.trim().slice(0, 80) + '"');
                }
            });
            for (var i = 0; i < CFG.forensischePatronen.length; i++) {
                if (CFG.forensischePatronen[i].p.test(tekst)) {
                    var nb2 = (CFG.forensischePatronen[i].l.match(/NB-[\d\/]+/) || ['NB-??'])[0];
                    logBevinding('KRITIEK', 'DIAGNOSE_VERWIJDERD',
                        'Inhoud met forensisch patroon verwijderd: ' + CFG.forensischePatronen[i].l,
                        nb2, 'verwijderd="' + tekst.slice(0, 200) + '"');
                    break;
                }
            }
        });

        mut.addedNodes.forEach(function (node) {
            if (node.nodeType !== 1) return;
            if (node.style && (node.style.display === 'none' || node.style.visibility === 'hidden')) {
                var tekst = (node.textContent || '').trim();
                if (tekst.length > 10) {
                    logBevinding('HOOG', 'VERBORGEN_ELEMENT_TOEGEVOEGD',
                        'Verborgen element met inhoud dynamisch toegevoegd',
                        'NB-62/99', 'tekst="' + tekst.slice(0, 100) + '"');
                }
            }
            CSS_VERBERGING_KLASSEN.forEach(function (cls) {
                if (node.classList && node.classList.contains(cls)) {
                    logBevinding('KRITIEK', 'VERBERGING_KLASSE_TOEGEVOEGD',
                        'Element met .' + cls + ' dynamisch toegevoegd',
                        'NB-12/53', 'tekst="' + (node.textContent || '').trim().slice(0, 80) + '"');
                }
            });
        });

        if (mut.type === 'attributes' && mut.attributeName === 'style') {
            var el = mut.target;
            if (el.style && el.style.display === 'none') {
                logBevinding('HOOG', 'STIJL_VERBERGING',
                    'display:none dynamisch ingesteld via stijlattribuut',
                    'NB-12/99', 'tag=' + el.tagName + ' class=' + (el.className || '').slice(0, 60));
                el.style.setProperty('display', 'block', 'important');
            }
        }
    });
});

function startDomWatch() {
    if (document.body) {
        stripCSSHiding(document.body);
        domObserver.observe(document.body, {
            childList: true, subtree: true,
            attributes: true, attributeFilter: ['style', 'class', 'hidden'],
        });
    } else {
        setTimeout(startDomWatch, 50);
    }
}
startDomWatch();

var origFetch = window.fetch;
window.fetch = function (input, init) {
    var url = (typeof input === 'string') ? input : (input && input.url) || '';
    if (isAudit(url)) logBevinding('HOOG', 'AUDIT_FETCH', 'Audit trail fetch (NB-163)', 'NB-163', url);

    return origFetch.apply(this, arguments).then(function (resp) {
        try {
            resp.clone().text().then(function (body) {
                if (isAudit(url) && (resp.status === 403 || resp.status === 401 || resp.status === 0)) {
                    logBevinding('KRITIEK', 'AUDIT_GEBLOKKEERD',
                        'Audit trail Fetch geblokkeerd HTTP ' + resp.status + ' (NB-163)',
                        'NB-163', 'url=' + url.split('?')[0]);
                }
                scan(body, url);
            }).catch(function () {});
        } catch (e) {}
        return resp;
    });
};

var origOpen = XMLHttpRequest.prototype.open;
var origSend = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open = function (method, url) {
    this._f_url = url;
    this._f_method = method;
    return origOpen.apply(this, arguments);
};

XMLHttpRequest.prototype.send = function (body) {
    var self = this;
    var url = this._f_url || '';

    if (isAudit(url)) logBevinding('HOOG', 'AUDIT_XHR',
        'Audit trail XHR ' + (this._f_method || '') + ' (NB-163)', 'NB-163', url);
    if (typeof body === 'string') scan(body, url);

    this.addEventListener('load', function () {
        try {
            if (isAudit(url) && (self.status === 403 || self.status === 401 || self.status === 0)) {
                logBevinding('KRITIEK', 'AUDIT_GEBLOKKEERD',
                    'Audit trail XHR geblokkeerd HTTP ' + self.status + ' (NB-163)',
                    'NB-163', 'url=' + url.split('?')[0]);
            }
            if (self.responseText) scan(self.responseText, url);
        } catch (e) {}
    });

    return origSend.apply(this, arguments);
};

function downloadEvidence() {
    var ts = new Date().toISOString().replace(/[:.]/g, '-');
    var data = {
        meta: {
            dossier: DOSSIER, versie: '10.0',
            exportTijdstip: new Date().toISOString(),
            url: window.location.href, userAgent: navigator.userAgent,
            totaalBevindingen: evidenceLog.length,
        },
        samenvatting: (function () {
            var s = {};
            evidenceLog.forEach(function (b) { s[b.ernst] = (s[b.ernst] || 0) + 1; });
            return s;
        })(),
        bevindingen: evidenceLog,
    };
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'forensisch_evidence_' + ts + '.json';
    a.click();
    console.log(LOG_PREFIX + ' Evidence geexporteerd: ' + evidenceLog.length + ' bevindingen');
}

function voegExportKnopToe() {
    if (document.getElementById('fg-export-btn')) return;
    var knop = document.createElement('button');
    knop.id = 'fg-export-btn';
    knop.style.cssText = 'position:fixed;bottom:10px;right:10px;z-index:2147483647;' +
        'background:#003399;color:#fff;border:none;padding:8px 14px;' +
        'border-radius:6px;font-family:monospace;font-size:12px;cursor:pointer;' +
        'box-shadow:0 2px 8px rgba(0,0,0,.4)';
    knop.onclick = downloadEvidence;
    setInterval(function () {
        knop.textContent = '[F] Evidence (' + evidenceLog.length + ')';
    }, 1500);
    knop.textContent = '[F] Evidence (0)';
    if (document.body) document.body.appendChild(knop);
}

window.downloadForensischEvidence = downloadEvidence;
window.forensischLog = evidenceLog;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', voegExportKnopToe);
} else {
    voegExportKnopToe();
}

console.log(LOG_PREFIX + ' Forensisch Monitor v10.0 actief | Dossier: ' + DOSSIER + ' | URL: ' + window.location.href);

})();