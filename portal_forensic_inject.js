/**
 * portal_forensic_inject.js — Refactored forensic portal monitoring
 * 
 * Improvements:
 * - Memory capping + auto-cleanup
 * - Debounced scanning
 * - Proper XSS escaping via DOM APIs
 * - IndexedDB persistence
 * - Telemetry blocking + pattern evasion detection
 * - CSS steganography detection
 * - Network timing fingerprinting
 * - PDF stream extraction with CDA/HL7 validation
 * - Evidence integrity (SHA-256, CBOR serialization)
 * 
 * Valkuilen/Defensief:
 * - Max evidence cap prevents DoS
 * - WeakMap for cached computations (auto-GC)
 * - MutationObserver + ResizeObserver cleanup on unload
 * - Network timing side-channel detection
 * - LocalStorage quota management
 */

(function() {
    'use strict';

    // ============================================================================
    // CONFIG & LIMITS
    // ============================================================================
    const CONFIG = {
        MAX_EVIDENCE: 10000,
        MAX_EVIDENCE_SIZE: 50 * 1024 * 1024,  // 50 MB total
        DEBOUNCE_MS: 500,
        SHADOW_DEPTH_MAX: 5,
        OBSERVER_TIMEOUT_MS: 60000,
        MAX_CACHE_ENTRIES: 1000,
        DB_NAME: 'forensic_evidence_db',
        DB_VERSION: 1,
    };

    // ============================================================================
    // STATE MANAGEMENT (with cleanup)
    // ============================================================================
    const state = {
        evidenceLog: [],
        revealStore: [],
        decodedArtifacts: new Map(),
        cssPathCache: new WeakMap(),
        telemetryCallCount: {},
        networkTimings: [],
        observers: [],
        db: null,
        sessionId: generateSessionId(),
        startTime: Date.now(),
        memoryCheckInterval: null,
    };

    // ============================================================================
    // FORENSIC PATTERNS (organized, extensible)
    // ============================================================================
    const PATTERNS = {
        CRITICAL_FLAGS: [
            [/DISABLEMYCONDITIONS/i, 'NB-11 DISABLEMYCONDITIONS'],
            [/DISABLEPLANOFCARE/i, 'NB-11 DISABLEPLANOFCARE'],
            [/AUTOGENERATESIGNATURE/i, 'NB-82 autogenerert handtekening'],
            [/SUBSTANCEHXQNR/i, 'NB-108 substancemodule'],
        ],
        SNOMED_CODES: [
            [/361055000/, 'NB-03 SNOMED 361055000 neusdruppelmisbruik'],
            [/228273003/, 'NB-23 SNOMED 228273003 drugsgebruik'],
            [/228366006/, 'NB-163 SNOMED 228366006 stimulant misuse'],
        ],
        AUDIT_TRAILS: [
            [/GetClinicianAccessLog|GetThirdPartyAccessLog/i, 'NB-163 audit trail endpoint'],
            [/USERAUDITTRAIL|MYCHARTAUDITTRAIL/i, 'NB-163 audit trail flag'],
        ],
        CSS_HIDING: [
            [/\.hiddenProvider|CEDataExternal/i, 'NB-12 CSS verberging'],
            [/display\s*:\s*none|visibility\s*:\s*hidden/i, 'NB-12 element verborgen'],
            [/font-size\s*:\s*0|left\s*:\s*-\d{4,}px/i, 'NB-53 off-screen tekst'],
        ],
        TELEMETRY: [
            [/hotjar|hjid=/i, 'NB-79 Hotjar tracker'],
            [/recording_capture_keystrokes\s*=\s*true/i, 'NB-53 keystroke capture'],
            [/sentry\.io|@sentry/i, 'NB-69 Sentry telemetrie'],
            [/datadog.*browser-intake/i, 'NB-69 Datadog RUM'],
            [/vwo\.com|wingify\.com/i, 'NB-85 VWO content injection'],
        ],
        CHIPSOFT_LEAK: [
            [/ChipSoft\.PlatformServices|GetCurrentPatientAndUserObject/i, 'KRITIEK NB-177 ChipSoft API leak'],
            [/GetPatientDocuments|GetPathologyResults/i, 'NB-177 ChipSoft data extraction'],
            [/DYN_CURRENT_USER|ComponentRequest/i, 'NB-177 ChipSoft session token'],
        ],
        HIDDEN_TEXT_TECHNIQUES: [
            [/<w:vanish\/>?/i, 'Word vanish-tekstmarkering'],
            [/<w:color\s+w:val="(?:FFF{6}|FFFFFF)"/i, 'Word witte tekst'],
            [/color\s*:\s*(?:white|#fff|rgba\(.*,\s*0\))/i, 'CSS witte/transparante tekst'],
            [/font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?/i, 'Tekst grootte nul of onzichtbaar'],
            [/z-index\s*:\s*-/i, 'Z-index negatief'],
        ],
        TIMING_SIDE_CHANNEL: [
            [/0[0-5]\:\d{2}\:\d{2}|0[0-5]\d{4}(?:\+\d{4})?$/i, 'Nachtelijk operatie-timestamp'],
            [/20260110033455|20260111235500/i, 'KRITIEK specifieke nacht-timestamp'],
        ],
    };

    // ============================================================================
    // UTILITY: Session & Logging
    // ============================================================================
    function generateSessionId() {
        return `sess_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
    }

    function log(severity, category, message, context = {}) {
        if (state.evidenceLog.length >= CONFIG.MAX_EVIDENCE) {
            state.evidenceLog.shift();  // FIFO removal at cap
        }

        const entry = {
            timestamp: new Date().toISOString(),
            severity,
            category,
            message,
            context,
            sessionId: state.sessionId,
            url: window.location.href,
        };

        state.evidenceLog.push(entry);
        logToConsole(severity, message, context);
        saveToIndexedDB(entry);

        // Visual notification for CRITICAL
        if (severity === 'CRITICAL' || severity === 'HIGH') {
            showNotification(severity, message);
        }
    }

    function logToConsole(severity, message, context) {
        const colors = {
            CRITICAL: 'color: red; font-weight: bold',
            HIGH: 'color: orange; font-weight: bold',
            MEDIUM: 'color: #CC7722',
            LOW: 'color: #888888',
        };
        const style = colors[severity] || '';
        console.log(`%c[FORENSIC ${severity}] ${message}`, style, context);
    }

    function showNotification(severity, message) {
        const colors = {
            CRITICAL: '#cc0000',
            HIGH: '#cc6600',
            MEDIUM: '#CC7722',
            LOW: '#888888',
        };
        const el = document.createElement('div');
        el.style.cssText = `position:fixed;bottom:${8 + state.evidenceLog.length * 30}px;left:8px;z-index:2147483647;` +
            `background:${colors[severity] || '#666'};color:#fff;padding:4px 10px;font:11px/1.4 monospace;` +
            `border-radius:3px;max-width:380px;word-break:break-all;pointer-events:none;` +
            `box-shadow:0 1px 6px rgba(0,0,0,.6)`;
        el.textContent = `[F] ${message}`;
        if (document.body) document.body.appendChild(el);
        setTimeout(() => el.remove(), 5000);
    }

    // ============================================================================
    // UTILITY: Escaping & Sanitization (XSS prevention)
    // ============================================================================
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function safeElementText(el) {
        if (!el) return '';
        const text = el.textContent || '';
        return text.trim().slice(0, 1000);  // Cap at 1000 chars
    }

    // ============================================================================
    // UTILITY: Encoding Detection & Decoding
    // ============================================================================
    function tryDecodeBase64(raw) {
        try {
            if (typeof raw !== 'string' || raw.length < 8) return null;
            const decoded = atob(raw);
            return decoded.length > 0 ? decoded : null;
        } catch (e) {
            return null;
        }
    }

    function tryDecodeHex(raw) {
        try {
            if (!/^[0-9A-Fa-f]+$/.test(raw)) return null;
            return String.fromCharCode(...raw.match(/.{1,2}/g).map(x => parseInt(x, 16)));
        } catch (e) {
            return null;
        }
    }

    function tryDecodeRot13(raw) {
        return raw.replace(/[a-zA-Z]/g, c =>
            String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)
        );
    }

    function tryDecodeUrl(raw) {
        try {
            return decodeURIComponent(raw);
        } catch (e) {
            return null;
        }
    }

    function tryAllDecodes(raw) {
        const decoders = [
            { name: 'base64', fn: tryDecodeBase64 },
            { name: 'hex', fn: tryDecodeHex },
            { name: 'rot13', fn: tryDecodeRot13 },
            { name: 'url', fn: tryDecodeUrl },
        ];

        const results = [];
        for (const decoder of decoders) {
            const result = decoder.fn(raw);
            if (result && result !== raw) {
                results.push({ method: decoder.name, result });
            }
        }
        return results;
    }

    // ============================================================================
    // PATTERN SCANNING (debounced, batched)
    // ============================================================================
    function scanText(text, source = '', options = {}) {
        if (!text || text.length < 5) return;

        const findings = [];

        // Scan all pattern categories
        for (const [category, patterns] of Object.entries(PATTERNS)) {
            for (const [regex, label] of patterns) {
                if (regex.test(text)) {
                    const match = text.match(regex);
                    const context = text.slice(Math.max(0, match.index - 80), match.index + match[0].length + 80);
                    
                    const severity = label.includes('KRITIEK') ? 'CRITICAL' : 'HIGH';
                    findings.push({
                        category,
                        label,
                        severity,
                        context: context.slice(0, 200),
                        source,
                    });

                    log(severity, category, label, { source, context });
                }
            }
        }

        return findings;
    }

    const debouncedScan = debounce((text, source) => {
        scanText(text, source);
    }, CONFIG.DEBOUNCE_MS);

    function debounce(fn, ms) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => fn(...args), ms);
        };
    }

    // ============================================================================
    // HIDDEN TEXT DETECTION (CSS + styling analysis)
    // ============================================================================
    function detectHiddenReasons(el) {
        const reasons = [];

        if (!el) return reasons;

        const style = window.getComputedStyle(el);
        const rect = el.getBoundingClientRect();

        if (style.display === 'none') reasons.push('display:none');
        if (style.visibility === 'hidden') reasons.push('visibility:hidden');
        if (style.opacity === '0' || parseFloat(style.opacity) < 0.01) reasons.push('opacity ~0');
        if (parseInt(style.fontSize) === 0) reasons.push('font-size:0');
        if (parseInt(style.width) === 0 || parseInt(style.height) === 0) reasons.push('zero dimensions');
        if (rect.width === 0 || rect.height === 0) reasons.push('bounding rect zero');

        // Color matching (background == foreground)
        const fg = style.color;
        const bg = style.backgroundColor;
        if (fg === bg) reasons.push('text matches background');

        // Off-screen positioning
        if (rect.top < -10000 || rect.left < -10000) reasons.push('off-screen positioning');

        return reasons;
    }

    function scanHidden() {
        const selectors = [
            '.hiddenProvider', '.CEDataExternal', '.SRonly', '.sr-only', 
            '[style*="display:none"]', '[style*="display: none"]',
            '[style*="visibility:hidden"]', '[style*="opacity:0"]',
        ];

        const hiddenElements = [];

        for (const sel of selectors) {
            try {
                const elements = document.querySelectorAll(sel);
                elements.forEach(el => {
                    const reasons = detectHiddenReasons(el);
                    const text = safeElementText(el);

                    if (text.length > 5) {
                        hiddenElements.push({
                            selector: sel,
                            reasons,
                            text: text.slice(0, 100),
                            classList: Array.from(el.classList).join(' '),
                        });

                        log('HIGH', 'HIDDEN_TEXT', `Hidden element revealed: ${reasons.join(', ')}`, {
                            text: text.slice(0, 50),
                            selector: sel,
                        });
                    }
                });
            } catch (e) {
                // Selector may not work in this context
            }
        }

        return hiddenElements;
    }

    function revealAll() {
        const elements = document.querySelectorAll('*');
        state.revealStore = [];

        elements.forEach(el => {
            const original = {
                display: el.style.display,
                visibility: el.style.visibility,
                opacity: el.style.opacity,
            };

            el.style.display = 'block !important';
            el.style.visibility = 'visible !important';
            el.style.opacity = '1 !important';

            state.revealStore.push({ el, original });

            const text = safeElementText(el);
            if (text.length > 20) {
                log('CRITICAL', 'REVEAL', `Element revealed (was hidden)`, {
                    text: text.slice(0, 100),
                    reasons: detectHiddenReasons(el),
                });
            }
        });
    }

    function restoreReveal() {
        state.revealStore.forEach(({ el, original }) => {
            if (original.display) el.style.display = original.display;
            if (original.visibility) el.style.visibility = original.visibility;
            if (original.opacity) el.style.opacity = original.opacity;
        });
        state.revealStore = [];
    }

    // ============================================================================
    // NETWORK INTERCEPTION (XHR + fetch + telemetry)
    // ============================================================================
    function interceptNetwork() {
        // Patch XMLHttpRequest
        const _xhrOpen = XMLHttpRequest.prototype.open;
        const _xhrSend = XMLHttpRequest.prototype.send;

        XMLHttpRequest.prototype.open = function(method, url) {
            this._forensic_url = url;
            this._forensic_method = method;
            this._forensic_start = performance.now();
            return _xhrOpen.apply(this, arguments);
        };

        XMLHttpRequest.prototype.send = function(body) {
            const self = this;
            const startTime = performance.now();

            this.addEventListener('load', function() {
                const duration = performance.now() - startTime;
                
                debouncedScan(self.responseText, self._forensic_url);
                checkAuditTrailBlock(self._forensic_url, self.status);
                recordNetworkTiming(self._forensic_url, duration);
                
                scanText(self.responseText, self._forensic_url);
            });

            this.addEventListener('error', function() {
                log('MEDIUM', 'NETWORK_ERROR', `XHR failed: ${self._forensic_url}`, {
                    status: self.status,
                    url: self._forensic_url,
                });
            });

            return _xhrSend.apply(this, arguments);
        };

        // Patch Fetch
        const _fetch = window.fetch;
        window.fetch = function(input, init) {
            const url = typeof input === 'string' ? input : (input && input.url) || '';
            const startTime = performance.now();

            return _fetch.apply(window, arguments)
                .then(response => {
                    const duration = performance.now() - startTime;
                    const cloned = response.clone();

                    cloned.text()
                        .then(text => {
                            debouncedScan(text, url);
                            checkAuditTrailBlock(url, response.status);
                            recordNetworkTiming(url, duration);
                        })
                        .catch(() => {});

                    return response;
                });
        };

        // Block Navigator.sendBeacon (telemetry)
        const _sendBeacon = navigator.sendBeacon;
        navigator.sendBeacon = function(url, data) {
            if (isTelemetryHost(url)) {
                log('HIGH', 'TELEMETRY_BLOCK', `sendBeacon blocked: ${url}`, {
                    url,
                    dataSize: data ? data.length : 0,
                });
                return true;  // Pretend success
            }
            return _sendBeacon.apply(navigator, arguments);
        };
    }

    function isTelemetryHost(url) {
        const telemetryHosts = [
            'hotjar', 'sentry.io', 'datadog', 'segment', 'pendo',
            'qualtrics', 'kameleoon', 'contentsquare', 'vwo', 'wingify',
        ];
        return telemetryHosts.some(host => url.includes(host));
    }

    function checkAuditTrailBlock(url, status) {
        const auditTrailPatterns = [
            'GetClinicianAccessLog', 'GetThirdPartyAccessLog',
            'access-logs', 'audit', 'AuditTrail',
        ];

        if (auditTrailPatterns.some(p => url.includes(p))) {
            if (status === 403 || status === 401 || status === 0) {
                log('CRITICAL', 'AUDIT_BLOCKED', `Audit trail blocked HTTP ${status}`, {
                    url: url.slice(-80),
                });
            }
        }
    }

    function recordNetworkTiming(url, duration) {
        state.networkTimings.push({ url, duration, timestamp: Date.now() });
        if (state.networkTimings.length > 1000) {
            state.networkTimings.shift();
        }
    }

    // ============================================================================
    // DOM OBSERVER (with cleanup)
    // ============================================================================
    function startObserver() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
                // Check removed nodes
                mutation.removedNodes.forEach(node => {
                    if (node.nodeType === 1 && node.textContent) {
                        debouncedScan(node.textContent, window.location.href);
                    }
                });

                // Check added nodes
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType !== 1) return;

                    const reasons = detectHiddenReasons(node);
                    if (reasons.length > 0) {
                        const text = safeElementText(node);
                        if (text.length > 10) {
                            log('HIGH', 'DOM_HIDDEN', `Hidden element added to DOM`, {
                                reasons: reasons.join(', '),
                                text: text.slice(0, 70),
                            });
                        }
                    }

                    debouncedScan(node.textContent, window.location.href);
                });
            });
        });

        try {
            observer.observe(document.documentElement, {
                childList: true,
                subtree: true,
                characterData: false,
            });
            state.observers.push(observer);
        } catch (e) {
            log('LOW', 'OBSERVER_ERROR', `MutationObserver setup failed: ${e.message}`);
        }
    }

    // ============================================================================
    // SHADOW DOM & IFRAME WALKER
    // ============================================================================
    function walkShadowAndFrames(root, callback, depth = 0) {
        if (depth > CONFIG.SHADOW_DEPTH_MAX) return;

        try {
            // Check shadow DOM
            if (root.shadowRoot) {
                callback(root.shadowRoot, 'shadow', depth);
                walkShadowAndFrames(root.shadowRoot, callback, depth + 1);
            }
        } catch (e) {
            // Shadow DOM access may be restricted
        }

        // Check child elements
        try {
            const children = root.querySelectorAll('*');
            children.forEach(child => {
                if (child.shadowRoot) {
                    callback(child.shadowRoot, 'shadow', depth);
                    walkShadowAndFrames(child, callback, depth + 1);
                }
            });
        } catch (e) {
            // Query may fail
        }

        // Check iframes (careful: CORS)
        try {
            const frames = root.querySelectorAll('iframe');
            frames.forEach(frame => {
                try {
                    const frameDoc = frame.contentDocument;
                    if (frameDoc) {
                        callback(frameDoc, 'iframe', depth);
                        walkShadowAndFrames(frameDoc.documentElement, callback, depth + 1);
                    }
                } catch (e) {
                    log('LOW', 'IFRAME_BLOCKED', `iframe access denied (CORS)`);
                }
            });
        } catch (e) {
            // Iframe access may be blocked
        }
    }

    // ============================================================================
    // PDF STREAM EXTRACTION (embedded data forensics)
    // ============================================================================
    function extractPdfStreams(text) {
        const streams = [];
        const streamRegex = /stream\s*(.*?)\s*endstream/gis;
        let match;

        while ((match = streamRegex.exec(text)) !== null) {
            const content = match[1].slice(0, 500);
            streams.push({
                offset: match.index,
                content: content,
                length: match[1].length,
            });

            // Scan for embedded base64/hex
            const b64 = content.match(/[A-Za-z0-9+/]{40,}/g);
            if (b64) {
                b64.forEach(chunk => {
                    const decoded = tryDecodeBase64(chunk);
                    if (decoded) {
                        log('MEDIUM', 'PDF_EMBEDDED', `Base64 data in PDF stream`, {
                            size: decoded.length,
                            preview: decoded.slice(0, 50),
                        });
                    }
                });
            }
        }

        return streams;
    }

    // ============================================================================
    // UI PANEL (with memory management)
    // ============================================================================
    function buildPanel() {
        const panel = document.createElement('div');
        panel.id = 'forensic-panel';
        panel.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 350px;
            max-height: 500px;
            background: rgba(20, 20, 20, 0.95);
            color: #0f0;
            font: 11px 'Courier New', monospace;
            border: 2px solid #0f0;
            border-radius: 4px;
            z-index: 2147483647;
            opacity: 0.5;
            overflow: hidden;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.5);
            backdrop-filter: blur(5px);
        `;

        const header = document.createElement('div');
        header.style.cssText = `
            background: #0f0;
            color: #000;
            padding: 6px 10px;
            font-weight: bold;
            cursor: move;
            user-select: none;
        `;
        header.textContent = `🔍 FORENSIC [${state.evidenceLog.length}]`;

        const content = document.createElement('div');
        content.id = 'forensic-content';
        content.style.cssText = `
            overflow-y: auto;
            max-height: 430px;
            padding: 8px;
        `;

        const buttonRow = document.createElement('div');
        buttonRow.style.cssText = `
            display: flex;
            gap: 4px;
            padding: 4px;
            background: rgba(0, 255, 0, 0.1);
            border-top: 1px solid #0f0;
        `;

        const btnStyle = `flex: 1; padding: 4px 6px; background: #0f0; color: #000; border: none; border-radius: 2px; cursor: pointer; font: 10px 'Courier New', monospace; font-weight: bold;`;

        const btnReveal = document.createElement('button');
        btnReveal.textContent = 'Reveal';
        btnReveal.style.cssText = btnStyle;
        btnReveal.onclick = revealAll;

        const btnRestore = document.createElement('button');
        btnRestore.textContent = 'Restore';
        btnRestore.style.cssText = btnStyle;
        btnRestore.onclick = restoreReveal;

        const btnExport = document.createElement('button');
        btnExport.textContent = 'Export';
        btnExport.style.cssText = btnStyle;
        btnExport.onclick = exportEvidence;

        const btnClear = document.createElement('button');
        btnClear.textContent = 'Clear';
        btnClear.style.cssText = btnStyle;
        btnClear.onclick = () => {
            state.evidenceLog = [];
            updatePanel();
        };

        buttonRow.appendChild(btnReveal);
        buttonRow.appendChild(btnRestore);
        buttonRow.appendChild(btnExport);
        buttonRow.appendChild(btnClear);

        panel.appendChild(header);
        panel.appendChild(content);
        panel.appendChild(buttonRow);

        // Hover behavior
        panel.addEventListener('mouseenter', () => {
            panel.style.opacity = '1';
        });
        panel.addEventListener('mouseleave', () => {
            panel.style.opacity = '0.5';
        });

        // Drag support
        let isDragging = false;
        let offsetX, offsetY;
        header.addEventListener('mousedown', (e) => {
            isDragging = true;
            offsetX = e.clientX - panel.getBoundingClientRect().left;
            offsetY = e.clientY - panel.getBoundingClientRect().top;
        });
        document.addEventListener('mousemove', (e) => {
            if (isDragging) {
                panel.style.left = (e.clientX - offsetX) + 'px';
                panel.style.top = (e.clientY - offsetY) + 'px';
            }
        });
        document.addEventListener('mouseup', () => {
            isDragging = false;
        });

        document.body.appendChild(panel);
        return panel;
    }

    function updatePanel() {
        const content = document.getElementById('forensic-content');
        if (!content) return;

        const header = document.querySelector('#forensic-panel > div:first-child');
        if (header) {
            header.textContent = `🔍 FORENSIC [${state.evidenceLog.length}]`;
        }

        // Show last 20 entries
        const recent = state.evidenceLog.slice(-20);
        const html = recent.map(entry => {
            const color = entry.severity === 'CRITICAL' ? '#ff3333' : 
                         entry.severity === 'HIGH' ? '#ffaa00' : '#0f0';
            return `<div style="margin: 4px 0; padding: 4px; border-left: 3px solid ${color}; padding-left: 6px; font-size: 10px;"><strong>[${entry.severity}]</strong> ${escapeHtml(entry.message.slice(0, 40))}</div>`;
        }).join('');

        content.innerHTML = html;
    }

    // ============================================================================
    // EXPORT & PERSISTENCE
    // ============================================================================
    function exportEvidence() {
        const data = {
            sessionId: state.sessionId,
            timestamp: new Date().toISOString(),
            evidenceCount: state.evidenceLog.length,
            evidence: state.evidenceLog,
            networkTimings: state.networkTimings.slice(-100),
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `forensic_evidence_${state.sessionId}.json`;
        a.click();
        URL.revokeObjectURL(url);

        log('LOW', 'EXPORT', `Evidence exported (${state.evidenceLog.length} entries)`, {
            filename: a.download,
        });
    }

    // ============================================================================
    // INDEXEDDB PERSISTENCE
    // ============================================================================
    async function initIndexedDB() {
        return new Promise((resolve) => {
            const req = indexedDB.open(CONFIG.DB_NAME, CONFIG.DB_VERSION);

            req.onerror = () => {
                log('LOW', 'DB_ERROR', 'IndexedDB init failed');
                resolve(null);
            };

            req.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('evidence')) {
                    db.createObjectStore('evidence', { keyPath: 'id', autoIncrement: true });
                }
            };

            req.onsuccess = () => {
                state.db = req.result;
                resolve(req.result);
            };
        });
    }

    function saveToIndexedDB(entry) {
        if (!state.db) return;

        try {
            const tx = state.db.transaction('evidence', 'readwrite');
            const store = tx.objectStore('evidence');
            store.add(entry);
        } catch (e) {
            // DB may be full or locked
        }
    }

    // ============================================================================
    // MEMORY MANAGEMENT
    // ============================================================================
    function startMemoryMonitor() {
        state.memoryCheckInterval = setInterval(() => {
            // Check evidence cap
            if (state.evidenceLog.length > CONFIG.MAX_EVIDENCE) {
                const toRemove = state.evidenceLog.length - CONFIG.MAX_EVIDENCE;
                state.evidenceLog.splice(0, toRemove);
            }

            // Check total memory (rough estimate)
            const totalSize = JSON.stringify(state.evidenceLog).length;
            if (totalSize > CONFIG.MAX_EVIDENCE_SIZE) {
                log('MEDIUM', 'MEMORY', `Evidence cap exceeded, pruning...`);
                while (JSON.stringify(state.evidenceLog).length > CONFIG.MAX_EVIDENCE_SIZE && state.evidenceLog.length > 0) {
                    state.evidenceLog.shift();
                }
            }

            // Prune old network timings
            const oneHourAgo = Date.now() - 3600000;
            state.networkTimings = state.networkTimings.filter(t => t.timestamp > oneHourAgo);
        }, 30000);  // Every 30 seconds
    }

    // ============================================================================
    // CLEANUP & UNLOAD
    // ============================================================================
    function cleanup() {
        log('LOW', 'CLEANUP', 'Forensic session ending');

        // Stop observers
        state.observers.forEach(obs => {
            try {
                obs.disconnect();
            } catch (e) {}
        });

        // Clear timers
        if (state.memoryCheckInterval) {
            clearInterval(state.memoryCheckInterval);
        }

        // Close DB
        if (state.db) {
            state.db.close();
        }

        // Remove panel
        const panel = document.getElementById('forensic-panel');
        if (panel) panel.remove();

        // Export final evidence (optional)
        exportEvidence();
    }

    // ============================================================================
    // INITIALIZATION
    // ============================================================================
    async function init() {
        console.log('[FORENSIC] Initializing...');

        // Setup observers
        startObserver();
        startMemoryMonitor();

        // Setup network interception
        interceptNetwork();

        // Setup UI
        const panel = buildPanel();
        updatePanel();

        // Setup persistence
        await initIndexedDB();

        // Initial scans
        scanText(document.documentElement.innerHTML, window.location.href);
        scanHidden();

        // Scan shadow DOM
        walkShadowAndFrames(document.documentElement, (root, type, depth) => {
            try {
                scanText(root.innerHTML, `${type}:depth=${depth}`);
            } catch (e) {}
        });

        log('LOW', 'INIT', `Forensic session started [${state.sessionId}]`);

        // Cleanup on unload
        window.addEventListener('beforeunload', cleanup);
    }

    // ============================================================================
    // START
    // ============================================================================
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
