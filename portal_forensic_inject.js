/**
 * portal_forensic_inject.js — Portal-level forensic detection
 * Injected into medical portal HTML; detects hidden text, encoded data, telemetry
 */

function portalForensicInject() {
    var NB_PATTERNS = [
        { re: /DISABLEMYCONDITIONS/i, nb: 'NB-11', severity: 'CRITICAL' },
        { re: /DISABLEPLANOFCARE/i, nb: 'NB-11', severity: 'CRITICAL' },
        { re: /SUBSTANCEHXQNR/i, nb: 'NB-108', severity: 'CRITICAL' },
        { re: /AUTOGENERATESIGNATURE/i, nb: 'NB-82', severity: 'HIGH' },
        { re: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i, nb: 'NB-163', severity: 'HIGH' },
        { re: /F19\.1|neusdruppelmisbruik/i, nb: 'NB-01', severity: 'CRITICAL' },
        { re: /361055000/, nb: 'NB-03', severity: 'CRITICAL' },
        { re: /228273003/, nb: 'NB-23', severity: 'CRITICAL' },
        { re: /extension="373282512"/i, nb: 'NB-05', severity: 'CRITICAL' },
        { re: /extension="999999"/i, nb: 'NB-18', severity: 'CRITICAL' },
        { re: /nullFlavor="UNK"/i, nb: 'NB-18', severity: 'HIGH' },
        { re: /GUARD\b/, nb: 'NB-56', severity: 'HIGH' },
        { re: /noView\s*:\s*true/i, nb: 'NB-99', severity: 'HIGH' },
        { re: /hotjar|hjid=/i, nb: 'NB-53', severity: 'HIGH' },
        { re: /recording_capture_keystrokes\s*=\s*true/i, nb: 'NB-53', severity: 'CRITICAL' },
        { re: /sentry\.io/i, nb: 'NB-69', severity: 'HIGH' },
        { re: /hoppinger\.com/i, nb: 'NB-114', severity: 'HIGH' },
        { re: /override\.css/i, nb: 'NB-53', severity: 'HIGH' },
        { re: /hiddenProvider|CEDataExternal/i, nb: 'NB-12', severity: 'HIGH' },
        { re: /printBlackText/i, nb: 'NB-84', severity: 'HIGH' },
        { re: /20260110033455/, nb: 'NB-166', severity: 'CRITICAL' },
        { re: /215672185/, nb: 'NB-BSN', severity: 'MEDIUM' },
        { re: /0133033170/, nb: 'NB-MDN', severity: 'MEDIUM' },
        { re: /ChipSoft\.PlatformServices/i, nb: 'NB-177', severity: 'CRITICAL' },
        { re: /GetCurrentPatientAndUserObject/i, nb: 'NB-177', severity: 'CRITICAL' },
    ];

    var AUDIT_URLS = [
        'GetClinicianAccessLogSettings', 'GetClinicianAccessLogEntries',
        'GetThirdPartyAccessLogEntries', 'access-logs', 'AuditTrail',
    ];

    var findings = new Set();
    var findingsList = [];

    function toon(severity, message) {
        var id = severity + ':' + message;
        if (findings.has(id)) return;
        findings.add(id);
        findingsList.push({ severity: severity, message: message, timestamp: new Date().toISOString() });

        var color = severity === 'CRITICAL' ? '#cc0000' : severity === 'HIGH' ? '#cc6600' : '#888800';
        var el = document.createElement('div');
        el.style.cssText = 'position:fixed;bottom:' + (8 + findingsList.length * 28) + 'px;left:8px;z-index:2147483647;' +
            'background:' + color + ';color:#fff;padding:3px 8px;font:10px/1.3 monospace;border-radius:2px;' +
            'max-width:350px;word-break:break-all;pointer-events:auto;cursor:pointer;' +
            'box-shadow:0 2px 8px rgba(0,0,0,.8);';
        el.textContent = '[F] ' + severity.slice(0, 3) + ' ' + message;
        if (document.body) document.body.appendChild(el);
        console.warn('[FORENSISCH][' + severity + '] ' + message);
        setTimeout(function() { try { el.remove(); } catch (e) {} }, 8000);
    }

    function scanText(text, source) {
        if (!text || text.length < 5) return;
        for (var i = 0; i < NB_PATTERNS.length; i++) {
            if (NB_PATTERNS[i].re.test(text)) {
                var msg = NB_PATTERNS[i].nb + ' found' + (source ? ' in ' + String(source).slice(-30) : '');
                toon(NB_PATTERNS[i].severity, msg);
            }
        }
    }

    function isAudit(u) {
        for (var i = 0; i < AUDIT_URLS.length; i++) {
            if (u.indexOf(AUDIT_URLS[i]) > -1) return true;
        }
        return false;
    }

    // Hook XMLHttpRequest
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
            toon('CRITICAL', 'NB-163 audit trail XHR: ' + u.split('?')[0].slice(-40));
        }
        this.addEventListener('load', function () {
            if (self.status === 403 || self.status === 401 || self.status === 0) {
                toon('CRITICAL', 'NB-163 audit blocked HTTP ' + self.status);
            }
            scanText(self.responseText, u);
        });
        this.addEventListener('error', function () { console.warn('[FORENSISCH] XHR error: ' + u); });
        return _xhrSend.apply(this, arguments);
    };

    // Hook fetch
    var _fetch = window.fetch;
    window.fetch = function (input, init) {
        var u = typeof input === 'string' ? input : (input && input.url) || '';
        return _fetch.apply(window, arguments).then(function (resp) {
            if (isAudit(u)) {
                toon('CRITICAL', 'NB-163 audit trail fetch: ' + u.split('?')[0].slice(-40));
            }
            if (resp.status === 403 || resp.status === 401 || resp.status === 0) {
                toon('CRITICAL', 'NB-163 audit blocked HTTP ' + resp.status);
            }
            resp.clone().text().then(function (t) { scanText(t, u); }).catch(function () {});
            return resp;
        }).catch(function (e) {
            console.warn('[FORENSISCH] Fetch error:', e);
        });
    };

    // Reveal hidden elements
    function start() {
        var hid = document.querySelectorAll(
            '.hiddenProvider,.CEDataExternal,.SRonly,.noView,.hidden-data,.sr-only,[style*="display:none"],[style*="display: none"],[style*="visibility:hidden"]'
        );
        for (var i = 0; i < hid.length; i++) {
            hid[i].style.setProperty('display', 'block', 'important');
            hid[i].style.setProperty('visibility', 'visible', 'important');
            var text = hid[i].textContent && hid[i].textContent.trim();
            if (text && text.length > 10) {
                toon('CRITICAL', 'NB-12 hidden element: ' + text.slice(0, 50));
                scanText(text, 'hidden-element');
            }
        }

        scanText(document.documentElement.outerHTML, window.location.href);

        // Mutation observer
        var obs = new MutationObserver(function (muts) {
            for (var i = 0; i < muts.length; i++) {
                for (var j = 0; j < muts[i].addedNodes.length; j++) {
                    var node = muts[i].addedNodes[j];
                    if (node.nodeType === 1 && node.style && node.style.display === 'none') {
                        var txt = node.textContent && node.textContent.trim();
                        if (txt && txt.length > 5) {
                            toon('HIGH', 'NB-99 hidden element added: ' + txt.slice(0, 50));
                            scanText(txt, 'mutation');
                        }
                    }
                }
            }
        });
        obs.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'class'] });

        window.addEventListener('beforeunload', function () {
            if (obs) obs.disconnect();
        });

        console.log('[FORENSISCH] Portal inject active on ' + window.location.href);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
}

try {
    (portalForensicInject)();
} catch (e) {
    console.error('[FORENSISCH] Portal inject error:', e);
}
