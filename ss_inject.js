var url = $request.url;
var status = $response.status;
var headers = $response.headers;
var body = $response.body || '';

function hGet(h, n) {
    var lo = n.toLowerCase();
    var keys = Object.keys(h || {});
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].toLowerCase() === lo) return String(h[keys[i]] || '');
    }
    return '';
}

function forensischInject() {
    var PATRONEN = [
        [/DISABLEMYCONDITIONS/i,                   'NB-11 DISABLEMYCONDITIONS'],
        [/DISABLEPLANOFCARE/i,                      'NB-11 DISABLEPLANOFCARE'],
        [/SUBSTANCEHXQNR/i,                         'NB-108 SUBSTANCEHXQNR'],
        [/AUTOGENERATESIGNATURE/i,                  'NB-82 AUTOGENERATESIGNATURE'],
        [/USERAUDITTRAIL|MYCHARTAUDITTRAIL/i,       'NB-163 Audit trail flag'],
        [/F19\.1|neusdruppelmisbruik/i,             'NB-01 F19.1 neusdruppelmisbruik'],
        [/361055000/,                               'NB-03 SNOMED 361055000'],
        [/228273003/,                               'NB-23 SNOMED 228273003'],
        [/extension="373282512"/i,                  'NB-05 al-Mousawi ext'],
        [/extension="999999"/i,                     'NB-18 anonieme auteur'],
        [/nullFlavor="UNK"/i,                       'NB-18 nullFlavor UNK'],
        [/GUARD\b/,                                 'NB-56 GUARD blok'],
        [/noView\s*:\s*true/i,                      'NB-99 noView:true'],
        [/hotjar|hjid=/i,                           'NB-53 Hotjar'],
        [/recording_capture_keystrokes\s*=\s*true/i,'NB-53 Hotjar keystroke ACTIEF'],
        [/sentry\.io/i,                             'NB-69 Sentry.io'],
        [/hoppinger\.com/i,                         'NB-114 Hoppinger'],
        [/override\.css/i,                          'NB-53 override.css'],
        [/hiddenProvider|CEDataExternal/i,          'NB-12 CSS verberging'],
        [/printBlackText/i,                         'NB-84 printBlackText'],
        [/20260110033455/,                          'KRITIEK NB-166 NACHT-TIMESTAMP'],
        [/215672185/,                               'BSN Grothe in response'],
        [/0133033170/,                              'MDN Grothe in response'],
        [/HANDMATIGE_EDIT_BOM/i,                    'NB-13 bytemanipulatieflag'],
        [/Epic@spaarnegasthuis\.nl/i,               'NB-05 Epic admin email'],
        [/FocusZorgTeam.*test\.authorization/i,     'NB-91 test-server in productie'],
        [/lucy\.css|lucy_colors/i,                  'NB-71 lucy.css'],
        [/\$lastn/i,                                'NB-109 FHIR $lastn'],
        [/Brijder|Parnassia.*Indigo|Indigo.*Parnassia/i, 'NB-113 Parnassia/Brijder'],
    ];

    var AUDIT_URLS = [
        'GetClinicianAccessLogSettings', 'GetClinicianAccessLogEntries',
        'GetThirdPartyAccessLogEntries', 'access-logs', 'AuditTrail',
    ];

    var gevonden = [];

    function toon(ernst, bericht) {
        var kleur = ernst === 'KRITIEK' ? '#cc0000' : ernst === 'HOOG' ? '#cc6600' : '#888800';
        var el = document.createElement('div');
        el.style.cssText = 'position:fixed;bottom:' + (8 + gevonden.length * 30) + 'px;left:8px;z-index:2147483647;' +
            'background:' + kleur + ';color:#fff;padding:4px 10px;font:11px/1.4 monospace;' +
            'border-radius:3px;max-width:380px;word-break:break-all;pointer-events:none;' +
            'box-shadow:0 1px 6px rgba(0,0,0,.6)';
        el.textContent = '[F] ' + bericht;
        if (document.body) document.body.appendChild(el);
        console.warn('[FORENSISCH][' + ernst + '] ' + bericht);
    }

    function scanTekst(txt, bron) {
        if (!txt || txt.length < 5) return;
        for (var i = 0; i < PATRONEN.length; i++) {
            if (PATRONEN[i][0].test(txt)) {
                var label = PATRONEN[i][1];
                if (gevonden.indexOf(label) < 0) {
                    gevonden.push(label);
                    var ernst = label.indexOf('KRITIEK') > -1 || /NB-0[0-9]/.test(label) ? 'KRITIEK' : 'HOOG';
                    toon(ernst, label + (bron ? ' [' + String(bron).split('?')[0].slice(-35) + ']' : ''));
                }
            }
        }
    }

    function isAudit(u) {
        for (var i = 0; i < AUDIT_URLS.length; i++) {
            if (u.indexOf(AUDIT_URLS[i]) > -1) return true;
        }
        return false;
    }

    var _xhrOpen = XMLHttpRequest.prototype.open;
    var _xhrSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (m, u) {
        this._f_url = u;
        return _xhrOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function (b) {
        var self = this;
        var u = this._f_url || '';
        if (isAudit(u)) {
            this.addEventListener('load', function () {
                if (self.status === 403 || self.status === 401 || self.status === 0) {
                    toon('KRITIEK', 'NB-163 AUDIT GEBLOKKEERD HTTP ' + self.status + ' ' + u.split('?')[0].slice(-50));
                } else {
                    console.log('[FORENSISCH] Audit bereikbaar HTTP ' + self.status + ' ' + u.split('?')[0]);
                }
            });
        }
        this.addEventListener('load', function () { scanTekst(self.responseText, u); });
        return _xhrSend.apply(this, arguments);
    };

    var _fetch = window.fetch;
    window.fetch = function (input, init) {
        var u = typeof input === 'string' ? input : (input && input.url) || '';
        return _fetch.apply(window, arguments).then(function (resp) {
            if (isAudit(u) && (resp.status === 403 || resp.status === 401 || resp.status === 0)) {
                toon('KRITIEK', 'NB-163 AUDIT GEBLOKKEERD HTTP ' + resp.status + ' ' + u.split('?')[0].slice(-50));
            }
            resp.clone().text().then(function (t) { scanTekst(t, u); }).catch(function () {});
            return resp;
        });
    };

    var obs = new MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
            for (var j = 0; j < muts[i].removedNodes.length; j++) {
                var n = muts[i].removedNodes[j];
                if (n.nodeType === 1 && n.textContent) scanTekst(n.textContent, location.href);
            }
            for (var k = 0; k < muts[i].addedNodes.length; k++) {
                var a = muts[i].addedNodes[k];
                if (a.nodeType !== 1) continue;
                if (a.style && (a.style.display === 'none' || a.style.visibility === 'hidden')) {
                    var t = a.textContent && a.textContent.trim();
                    if (t && t.length > 10) toon('HOOG', 'NB-99 Verborgen element toegevoegd: ' + t.slice(0, 70));
                }
                scanTekst(a.textContent, location.href);
            }
        }
    });

    function start() {
        var hid = document.querySelectorAll(
            '.hiddenProvider,.CEDataExternal,.SRonly,.noView,.hidden-data,.sr-only,[style*="display:none"],[style*="display: none"]'
        );
        for (var i = 0; i < hid.length; i++) {
            hid[i].style.setProperty('display', 'block', 'important');
            hid[i].style.setProperty('visibility', 'visible', 'important');
            var tekst = hid[i].textContent && hid[i].textContent.trim();
            if (tekst && tekst.length > 5) toon('KRITIEK', 'NB-12 Verborgen element onthuld: ' + tekst.slice(0, 80));
        }
        scanTekst(document.documentElement.innerHTML, location.href);
        obs.observe(document.documentElement, { childList: true, subtree: true });
        console.log('[FORENSISCH] Inject actief op ' + location.href);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
}

try {
    var ct = hGet(headers, 'content-type').toLowerCase();
    if (ct.indexOf('text/html') !== -1 && body) {
        body = body.replace(/<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*(\/?>|>)/gi, '');
        var injectCode = '(' + forensischInject.toString() + ')();';
        var scriptTag = '<script data-forensisch="1">' + injectCode + '<\/script>';
        if (/<\/body>/i.test(body)) {
            body = body.replace(/<\/body>/i, scriptTag + '</body>');
        } else if (/<\/html>/i.test(body)) {
            body = body.replace(/<\/html>/i, scriptTag + '</html>');
        } else {
            body = body + scriptTag;
        }
        console.log('[F] Inject: ' + url.split('?')[0]);
    }
    $done({ status: status, headers: headers, body: body });
} catch (e) {
    console.log('[F] Inject FOUT: ' + e);
    $done({ status: $response.status, headers: $response.headers, body: $response.body });
}
