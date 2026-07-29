/**
 * FORENSISCH ONTSLUITER
 *
 * Gebruik A — DevTools Console: plak alles hieronder erin en druk Enter
 * Gebruik B — Bookmarklet: sla de BOOKMARKLET.txt inhoud op als bladwijzer-URL
 * Gebruik C — Tampermonkey: wrap in ==UserScript== header (onderaan dit bestand)
 *
 * Wat het doet:
 *   - Maakt ALLE visueel verborgen elementen zichtbaar
 *   - Wit-op-wit tekst → zwart op geel gemarkeerd
 *   - Doorzichtige / opacity:0 elementen → zichtbaar
 *   - Off-screen gepositioneerde elementen → teruggebracht in beeld
 *   - font-size:0 tekst → leesbaar gemaakt
 *   - display:none / visibility:hidden → zichtbaar
 *   - height:0 / width:0 / clip verberging → geopend
 *   - [hidden] attribuut → verwijderd
 *   - Elk ontsloten element krijgt rode rand + tooltip met reden
 *   - Rood banner bovenin: hoeveel elementen ontsloten
 */

(function forensischOntsluiter() {

    var VERSIE = '2.0';
    var gevonden = [];

    // Verwijder eerdere run
    var oud = document.getElementById('__fo_banner');
    if (oud) oud.remove();
    document.querySelectorAll('[data-fo]').forEach(function(el) {
        el.removeAttribute('style');
        el.removeAttribute('data-fo');
    });

    function markeer(el, redenen) {
        el.setAttribute('data-fo', redenen.join(' | '));
        el.style.setProperty('outline', '3px solid #e00', 'important');
        el.style.setProperty('outline-offset', '1px', 'important');
        // Tooltip via title (bewaard als data zodat origineel niet verloren gaat)
        var orig = el.getAttribute('title') || '';
        el.setAttribute('data-fo-orig-title', orig);
        el.setAttribute('title', '🔴 VERBORGEN: ' + redenen.join(' | ') + (orig ? ' | ' + orig : ''));
        gevonden.push({ el: el, redenen: redenen });
    }

    var alle = document.querySelectorAll('*');
    var n = alle.length;

    for (var i = 0; i < n; i++) {
        var el = alle[i];

        // Sla script/style/meta over
        var tag = el.tagName ? el.tagName.toUpperCase() : '';
        if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'META' || tag === 'HEAD') continue;

        var cs;
        try { cs = window.getComputedStyle(el); } catch(e) { continue; }

        var redenen = [];
        var heeftTekst = (el.textContent || '').trim().length > 0;

        // --- 1. display:none ---
        if (cs.display === 'none') {
            el.style.setProperty('display', 'block', 'important');
            redenen.push('display:none');
        }

        // --- 2. visibility:hidden ---
        if (cs.visibility === 'hidden') {
            el.style.setProperty('visibility', 'visible', 'important');
            redenen.push('visibility:hidden');
        }

        // --- 3. opacity:0 of bijna 0 ---
        var op = parseFloat(cs.opacity);
        if (!isNaN(op) && op < 0.05) {
            el.style.setProperty('opacity', '1', 'important');
            redenen.push('opacity:' + op);
        }

        // --- 4. font-size:0 (onzichtbare tekst) ---
        var fs = parseFloat(cs.fontSize);
        if (!isNaN(fs) && fs < 1 && heeftTekst) {
            el.style.setProperty('font-size', '14px', 'important');
            redenen.push('font-size:0');
        }

        // --- 5. Kleur gelijk aan achtergrond (wit-op-wit, etc.) ---
        if (heeftTekst && cs.color && cs.backgroundColor) {
            var kleur = cs.color.replace(/\s/g, '');
            var achter = cs.backgroundColor.replace(/\s/g, '');
            // Wit-op-wit: rgba(255,255,255,...) of rgb(255,255,255)
            var isWitTekst = /rgb\(255,255,255\)|rgba\(255,255,255,1\)/.test(kleur);
            var isWitAchter = /rgb\(255,255,255\)|rgba\(255,255,255,1\)|rgba\(0,0,0,0\)|transparent/.test(achter);
            if (kleur === achter || (isWitTekst && isWitAchter) || isWitTekst) {
                el.style.setProperty('color', '#000', 'important');
                el.style.setProperty('background-color', '#ffff00', 'important');
                redenen.push('wit-op-wit tekst');
            }
        }

        // --- 6. Off-screen positie ---
        var pos = cs.position;
        if (pos === 'absolute' || pos === 'fixed') {
            var left = parseFloat(cs.left);
            var top  = parseFloat(cs.top);
            var right = parseFloat(cs.right);
            var bottom = parseFloat(cs.bottom);
            if ((!isNaN(left) && left < -200) || (!isNaN(top) && top < -200) ||
                (!isNaN(right) && right > window.innerWidth + 200)) {
                el.style.setProperty('position', 'relative', 'important');
                el.style.setProperty('left', 'auto', 'important');
                el.style.setProperty('top', 'auto', 'important');
                el.style.setProperty('right', 'auto', 'important');
                redenen.push('off-screen (' + Math.round(left) + 'px,' + Math.round(top) + 'px)');
            }
        }

        // --- 7. height:0 of width:0 met overflow:hidden ---
        var h = parseFloat(cs.height);
        var w = parseFloat(cs.width);
        var ov = cs.overflow;
        if ((!isNaN(h) && h < 1) || (!isNaN(w) && w < 1)) {
            el.style.setProperty('min-height', '1em', 'important');
            el.style.setProperty('min-width', '10px', 'important');
            el.style.setProperty('overflow', 'visible', 'important');
            redenen.push('h/w:0');
        } else if (ov === 'hidden' && heeftTekst) {
            var rect;
            try { rect = el.getBoundingClientRect(); } catch(e) {}
            if (rect && (rect.width < 5 || rect.height < 5)) {
                el.style.setProperty('overflow', 'visible', 'important');
                redenen.push('overflow:hidden clip');
            }
        }

        // --- 8. clip / clip-path verberging ---
        var clip = cs.clip || '';
        var clipPath = cs.clipPath || '';
        if (clip && clip !== 'auto' && clip.indexOf('rect(0') !== -1) {
            el.style.setProperty('clip', 'auto', 'important');
            redenen.push('clip:rect(0)');
        }
        if (clipPath && clipPath !== 'none' && (clipPath.indexOf('inset(100%') !== -1 || clipPath.indexOf('circle(0') !== -1)) {
            el.style.setProperty('clip-path', 'none', 'important');
            redenen.push('clip-path:' + clipPath.slice(0, 30));
        }

        // --- 9. [hidden] attribuut ---
        if (el.hasAttribute('hidden')) {
            el.removeAttribute('hidden');
            redenen.push('[hidden]');
        }

        // --- 10. aria-hidden="true" (verborgen voor toegankelijkheid/scrapen) ---
        if (el.getAttribute('aria-hidden') === 'true' && heeftTekst) {
            el.setAttribute('aria-hidden', 'false');
            redenen.push('aria-hidden');
        }

        // --- 11. max-height:0 truc ---
        var mh = parseFloat(cs.maxHeight);
        if (!isNaN(mh) && mh < 1 && heeftTekst) {
            el.style.setProperty('max-height', 'none', 'important');
            el.style.setProperty('overflow', 'visible', 'important');
            redenen.push('max-height:0');
        }

        if (redenen.length > 0) markeer(el, redenen);
    }

    // --- Banner ---
    var banner = document.createElement('div');
    banner.id = '__fo_banner';
    banner.style.cssText = [
        'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
        'background:linear-gradient(135deg,#c00,#800)', 'color:#fff',
        'font:bold 13px/1.4 monospace', 'padding:6px 12px',
        'box-shadow:0 2px 8px rgba(0,0,0,.5)', 'display:flex',
        'align-items:center', 'justify-content:space-between'
    ].join(';');

    // Groepeer per reden
    var tellers = {};
    gevonden.forEach(function(g) {
        g.redenen.forEach(function(r) {
            tellers[r] = (tellers[r] || 0) + 1;
        });
    });
    var samenvatting = Object.keys(tellers).map(function(k) {
        return tellers[k] + '× ' + k;
    }).join(' · ');

    banner.innerHTML =
        '<span>🔴 FORENSISCH ONTSLUITER v' + VERSIE + ' — ' + gevonden.length + ' verborgen elementen ontsloten</span>' +
        '<span style="font-size:11px;opacity:.85">' + (samenvatting || 'niets gevonden') + '</span>' +
        '<button onclick="this.parentNode.remove()" style="background:none;border:1px solid #fff;color:#fff;padding:2px 8px;cursor:pointer;font:inherit">✕</button>';

    document.body.insertBefore(banner, document.body.firstChild);

    // Log naar console
    console.log('[FO] Forensisch Ontsluiter v' + VERSIE + ' — ' + gevonden.length + ' elementen ontsloten');
    gevonden.forEach(function(g) {
        console.log('[FO]  ' + (g.el.tagName || '?') + (g.el.id ? '#' + g.el.id : '') +
            (g.el.className ? '.' + String(g.el.className).split(' ')[0] : '') +
            ' → ' + g.redenen.join(', '));
    });

    return gevonden.length + ' elementen ontsloten';

})();

// ============================================================
// BOOKMARKLET — sla dit op als URL van een bladwijzer:
// (alles op één regel, begin met javascript:)
// ============================================================
//
// Maak een nieuwe bladwijzer in je browser.
// Geef hem naam: "🔴 Ontsluiter"
// Plak als URL de inhoud van het bestand BOOKMARKLET.txt
//
// ============================================================
// TAMPERMONKEY USERSCRIPT — automatisch op elke pagina actief
// ============================================================
/*
// ==UserScript==
// @name         🔴 Forensisch Ontsluiter
// @namespace    forensisch
// @version      2.0
// @description  Maakt alle visueel verborgen elementen zichtbaar
// @match        *://*.spaarnegasthuis.nl/*
// @match        *://*.mijnspaarnegas.nl/*
// @match        *://*.mijngezondheid.net/*
// @match        *://*.medmij.nl/*
// @grant        none
// @run-at       document-idle
// ==/UserScript==
*/
// (plak de forensischOntsluiter functie hierboven hierin)
