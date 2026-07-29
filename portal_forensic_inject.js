/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  PORTAL FORENSISCH INJECT SCRIPT                                         ║
 * ║  MijnSpaarneGasthuis / Epic MyChart — DOM-monitoring                     ║
 * ║  Dossier Grothe — Rechtbank Noord-Holland C/15/376914                    ║
 * ║  Hof van Discipline kenmerk 260153                                       ║
 * ║  Versie 1.0 — 18 juni 2026                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * GEBRUIK:
 *   Optie A — Browser DevTools Console (F12 → Console):
 *     Plak de volledige inhoud van dit bestand en druk Enter.
 *
 *   Optie B — Tampermonkey / Greasemonkey userscript:
 *     Voeg @match https://mijnspaarnegasthuis.nl/* toe in de header.
 *
 *   Optie C — Storm Sniffer / Proxyman Script Inject:
 *     Selecteer "Inject JavaScript" als rewrite-actie op het gewenste domein.
 *
 * WAT DIT SCRIPT DETECTEERT (NB-referenties uit MASTER Forensisch Dossier):
 *   NB-53/56  STYLE.XSL SRonly / GUARD-blokken / juridische authenticator
 *   NB-12     .hiddenProvider, .CEDataExternal, 63 PDFs wit-op-wit
 *   NB-11     DISABLEMYCONDITIONS, DISABLEPLANOFCARE feature flags
 *   NB-53/79  Hotjar keystroke capture, tracking scripts
 *   NB-99     Epic trace 19× geïnjecteerd, Meer-laden-knop 9× verwijderd
 *   NB-62     4233 verborgen elementen, 885 VERBORGEN_ONTHULD-entries
 *   NB-163    CORS-blokkade audit trail endpoints
 *   NB-108    SUBSTANCEHXQNR module
 *   NB-84     printBlackText alarmkleur-neutralisatie
 *   NB-114    hoppinger.com referenties in scripts
 *
 * UITVOER:
 *   - Realtime console logging (FORENSISCH prefix)
 *   - In-page opvallende marker bij kritieke bevindingen
 *   - Exportknop: downloadt JSON-logbestand met SHA-256 hashes
 */

(function () {
    'use strict';

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURATIE
    // ─────────────────────────────────────────────────────────────────────────

    const VERSIE = '1.0';
    const DOSSIER = 'Grothe C/15/376914';
    const LOG_PREFIX = '[FORENSISCH]';

    // Patronen die we in de DOM / netwerk zoeken
    const CSS_VERBERGING_KLASSEN = [
        'hiddenProvider',
        'CEDataExternal',
        'SRonly',
        'CEAuth',
        'CENoAuth',
        'noView',
        'hidden-data',
        'sr-only',
    ];

    const VERDACHTE_INLINE_STIJLEN = [
        { prop: 'display', waarde: 'none', ernst: 'KRITIEK', nb: 'NB-12/53' },
        { prop: 'visibility', waarde: 'hidden', ernst: 'HOOG', nb: 'NB-12' },
        { prop: 'fontSize', waarde: '0px', ernst: 'HOOG', nb: 'NB-53' },
        { prop: 'left', max: -5000, ernst: 'HOOG', nb: 'NB-53 SRonly' },
        { prop: 'color', waarde: '#ffffff', ernst: 'MEDIUM', nb: 'NB-12 wit-op-wit' },
        { prop: 'opacity', waarde: '0', ernst: 'MEDIUM', nb: 'NB-12' },
    ];

    const FEATURE_FLAG_PATRONEN = [
        { patroon: /DISABLEMYCONDITIONS/i, ernst: 'KRITIEK', nb: 'NB-11', omschrijving: 'DISABLEMYCONDITIONS actief' },
        { patroon: /DISABLEPLANOFCARE/i, ernst: 'KRITIEK', nb: 'NB-11', omschrijving: 'DISABLEPLANOFCARE actief' },
        { patroon: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i, ernst: 'HOOG', nb: 'NB-163', omschrijving: 'Audit trail feature flag' },
        { patroon: /AUTOGENERATESIGNATURE/i, ernst: 'KRITIEK', nb: 'NB-82', omschrijving: 'Auto-handtekening actief' },
        { patroon: /SEXUALACTIVITYHXQNR/i, ernst: 'HOOG', nb: 'NB-83', omschrijving: 'Seksuele anamnese module' },
        { patroon: /SUBSTANCEHXQNR/i, ernst: 'KRITIEK', nb: 'NB-108', omschrijving: 'SUBSTANCEHXQNR module (al-Mousawi 02-10-2024)' },
        { patroon: /AUTOSYNCRECEIVEFORPERSONALINFORMATION/i, ernst: 'HOOG', nb: 'NB-115', omschrijving: 'AutoSync extern bronsysteem' },
        { patroon: /ExternalJump|LogExternalJumpAudit/i, ernst: 'MEDIUM', nb: 'NB-68', omschrijving: 'ExternalJump tracking' },
        { patroon: /noView\s*:\s*true/i, ernst: 'KRITIEK', nb: 'NB-99', omschrijving: 'noView:true — data verborgen' },
        { patroon: /GUARD\b/i, ernst: 'HOOG', nb: 'NB-56', omschrijving: 'GUARD blok — CDA access control' },
        { patroon: /override\.css/i, ernst: 'KRITIEK', nb: 'NB-53/89', omschrijving: 'override.css referentie (MRK/JKE)' },
        { patroon: /lucy\.css|lucy_colors/i, ernst: 'MEDIUM', nb: 'NB-71', omschrijving: 'lucy.css renderingslaag' },
        { patroon: /printBlackText/i, ernst: 'MEDIUM', nb: 'NB-84', omschrijving: 'printBlackText — alarmkleuren geneutraliseerd' },
        { patroon: /hoppinger\.com|spaarne-rebuild\.productie/i, ernst: 'KRITIEK', nb: 'NB-114', omschrijving: 'Hoppinger.com in productie (supply chain lek)' },
        { patroon: /FocusZorgTeam.*test\.authorization/i, ernst: 'HOOG', nb: 'NB-91', omschrijving: 'FocusZorgTeam test-server in productie' },
    ];

    const TRACKER_PATRONEN = [
        { patroon: /hotjar|hjid=/i, ernst: 'HOOG', nb: 'NB-53/79', omschrijving: 'Hotjar tracker' },
        { patroon: /recording_capture_keystrokes\s*=\s*true/i, ernst: 'KRITIEK', nb: 'NB-53', omschrijving: 'Hotjar keystroke recording ACTIEF' },
        { patroon: /sentry\.io/i, ernst: 'HOOG', nb: 'NB-69', omschrijving: 'Sentry.io telemetrie (VS, Schrems II)' },
        { patroon: /pendo\.io/i, ernst: 'HOOG', nb: 'NB-79', omschrijving: 'Pendo.io tracker' },
        { patroon: /wingify|vwo\.com/i, ernst: 'HOOG', nb: 'NB-79/85', omschrijving: 'VWO/Wingify India content-injectie' },
        { patroon: /account_id\s*[:=]\s*763232/i, ernst: 'KRITIEK', nb: 'NB-53/178', omschrijving: 'VWO account_id=763232 (identity fingerprint)' },
        { patroon: /hide_element.*opacity.*0|body.*opacity.*0.*important/i, ernst: 'KRITIEK', nb: 'NB-53/178', omschrijving: 'VWO body opacity:0 rendering aanval' },
        { patroon: /vwo_uuid/i, ernst: 'HOOG', nb: 'NB-178', omschrijving: 'VWO UUID tracking na cookie-weigering' },
        { patroon: /qualtrics\.com/i, ernst: 'HOOG', nb: 'NB-79', omschrijving: 'Qualtrics/SAP tracker' },
        { patroon: /segment\.io|segment\.com/i, ernst: 'HOOG', nb: 'NB-79', omschrijving: 'Segment.io tracker' },
        { patroon: /kameleoon/i, ernst: 'HOOG', nb: 'NB-79', omschrijving: 'Kameleoon tracker' },
        { patroon: /GTM-PGPCH2T/i, ernst: 'HOOG', nb: 'NB-85', omschrijving: 'GTM tag GTM-PGPCH2T' },
        { patroon: /datadog.*browser-intake|browser-intake.*datadoghq/i, ernst: 'HOOG', nb: 'NB-69', omschrijving: 'Datadog RUM telemetrie (VS, Schrems II)' },
        { patroon: /DE36B70A/i, ernst: 'HOOG', nb: 'NB-69', omschrijving: 'Sentry device ID DE36B70A' },
        { patroon: /SESSION_ID\s*[=:]\s*[A-F0-9]{20,}/i, ernst: 'KRITIEK', nb: 'NB-79', omschrijving: 'Session ID blootgesteld via tracker' },
    ];

    const DIAGNOSE_PATRONEN = [
        { patroon: /F19\.1|neusdruppelmisbruik/i, ernst: 'KRITIEK', nb: 'NB-01/116', omschrijving: 'F19.1 neusdruppelmisbruik (gefabriceerd)' },
        { patroon: /361055000/i, ernst: 'KRITIEK', nb: 'NB-03', omschrijving: 'SNOMED 361055000 nasal spray misuse' },
        { patroon: /228273003/i, ernst: 'KRITIEK', nb: 'NB-23/113', omschrijving: 'SNOMED 228273003 drug misuse' },
        { patroon: /nullFlavor="UNK"/i, ernst: 'HOOG', nb: 'NB-18/47', omschrijving: 'CDA nullFlavor=UNK (anonieme auteur)' },
        { patroon: /extension="999999"/i, ernst: 'KRITIEK', nb: 'NB-18', omschrijving: 'Epic ext=999999 anonymous actor' },
        { patroon: /extension="373282512"/i, ernst: 'KRITIEK', nb: 'NB-05', omschrijving: 'ext=373282512 A. al-Mousawi' },
        { patroon: /Epic@spaarnegasthuis\.nl/i, ernst: 'KRITIEK', nb: 'NB-05', omschrijving: 'Epic admin organisatie-email' },
        { patroon: /HANDMATIGE_EDIT_BOM/i, ernst: 'KRITIEK', nb: 'NB-13', omschrijving: 'Post-creatie bytemanipulatieflag' },
        { patroon: /extension="51504662"|extension="84107660"/i, ernst: 'KRITIEK', nb: 'NB-04', omschrijving: 'N.M. Nota extension code' },
        { patroon: /228366006/i, ernst: 'KRITIEK', nb: 'NB-23b', omschrijving: 'SNOMED 228366006 stimulant misuse' },
        { patroon: /266927001/i, ernst: 'KRITIEK', nb: 'NB-23c', omschrijving: 'SNOMED 266927001 afhankelijkheid' },
        { patroon: /F60\.31|borderline/i, ernst: 'KRITIEK', nb: 'NB-xx', omschrijving: 'F60.31 borderline persoonlijkheidsstoornis' },
        { patroon: /20260110033455/, ernst: 'KRITIEK', nb: 'NB-166', omschrijving: 'NACHT-TIMESTAMP 10-01-2026 03:34:55 (AVG-dag)' },
        { patroon: /transactie.{0,10}77832/i, ernst: 'KRITIEK', nb: 'NB-23', omschrijving: 'Transactie-ID 77832 SNOMED SUCCESS' },
        { patroon: /ChipSoft\.PlatformServices/i, ernst: 'KRITIEK', nb: 'NB-177', omschrijving: 'ChipSoft HiX API blootgesteld via MijnSpaarneGasthuis' },
        { patroon: /GetCurrentPatientAndUserObject/i, ernst: 'KRITIEK', nb: 'NB-177', omschrijving: 'ChipSoft volledige patientobject gelekt' },
        { patroon: /2001702222/, ernst: 'KRITIEK', nb: 'NB-177', omschrijving: 'ChipSoft patient-ID Grothe (2001702222)' },
        { patroon: /DYN_CURRENT_USER/i, ernst: 'HOOG', nb: 'NB-177', omschrijving: 'ChipSoft HiX sessietoken type' },
        { patroon: /GetPatientDocuments/i, ernst: 'HOOG', nb: 'NB-177', omschrijving: 'ChipSoft GetPatientDocuments API' },
        { patroon: /GetDcrRegistrations/i, ernst: 'HOOG', nb: 'NB-177', omschrijving: 'ChipSoft GetDcrRegistrations toestemmingen' },
        { patroon: /DigiDClusterHybrid/i, ernst: 'HOOG', nb: 'NB-177', omschrijving: 'ChipSoft DigiD authenticatieflow' },
        { patroon: /centramed\.nl/i, ernst: 'HOOG', nb: 'NB-179', omschrijving: 'Centramed aansprakelijkheidsverzekeraar' },
        { patroon: /Brijder|Parnassia.*Indigo|Indigo.*Parnassia/i, ernst: 'KRITIEK', nb: 'NB-113', omschrijving: 'Parnassia/Brijder — nooit in behandeling' },
        { patroon: /215672185/, ernst: 'MEDIUM', nb: 'NB-166', omschrijving: 'BSN Grothe (215672185) in DOM' },
        { patroon: /0133033170/, ernst: 'MEDIUM', nb: 'NB-166', omschrijving: 'MDN Grothe (0133033170) in DOM' },
    ];

    const AUDIT_TRAIL_URLS = [
        'GetClinicianAccessLogSettings',
        'GetClinicianAccessLogEntries',
        'GetThirdPartyAccessLogEntries',
        'access-logs',
        'audit',
    ];

    // DOM-knoppen waarvan verwijdering forensisch relevant is (NB-99)
    const VERDACHTE_KNOP_TEKSTEN = [
        /meer laden/i,
        /load more/i,
        /toon meer/i,
        /show all/i,
        /alle resultaten/i,
    ];

    // Meer-laden teller (NB-99: 9× verwijderd)
    let meerLadenVerwijderdTeller = 0;
    const MAX_MEER_LADEN_VERWIJDERINGEN = 9;

    // ─────────────────────────────────────────────────────────────────────────
    // LOGGING EN EVIDENCE-OPBOUW
    // ─────────────────────────────────────────────────────────────────────────

    const evidenceLog = [];
    let bevindingTeller = 0;

    async function sha256(tekst) {
        const data = new TextEncoder().encode(tekst);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function logBevinding(ernst, categorie, omschrijving, nb, context = '') {
        bevindingTeller++;
        const tijdstempel = new Date().toISOString();
        const hash = await sha256(`${omschrijving}|${nb}|${tijdstempel}|${context.slice(0, 200)}`);
        const bevinding = {
            nr: bevindingTeller,
            ernst,
            categorie,
            omschrijving,
            nb,
            context: context.slice(0, 500),
            tijdstempel,
            url: window.location.href,
            sha256: hash,
        };
        evidenceLog.push(bevinding);

        const kleur = { KRITIEK: '#ff4444', HOOG: '#ff8800', MEDIUM: '#ffcc00', LAAG: '#88cc00' }[ernst] || '#aaaaaa';
        console.log(
            `%c${LOG_PREFIX} [${ernst}] ${categorie}`,
            `color: ${kleur}; font-weight: bold;`,
            `\n  ${omschrijving}`,
            `\n  NB: ${nb}`,
            `\n  SHA256: ${hash}`,
            context ? `\n  Context: ${context.slice(0, 200)}` : ''
        );

        if (ernst === 'KRITIEK') {
            toonKrietiekMarker(omschrijving, nb);
        }

        return bevinding;
    }

    function toonKrietiekMarker(tekst, nb) {
        const bestaand = document.getElementById('forensisch-marker-container');
        const container = bestaand || (() => {
            const el = document.createElement('div');
            el.id = 'forensisch-marker-container';
            el.style.cssText = [
                'position: fixed',
                'top: 10px',
                'right: 10px',
                'z-index: 999999',
                'display: flex',
                'flex-direction: column',
                'gap: 4px',
                'max-width: 400px',
                'font-family: monospace',
            ].join(';');
            document.body.appendChild(el);
            return el;
        })();

        const marker = document.createElement('div');
        marker.style.cssText = [
            'background: #ff0000',
            'color: white',
            'padding: 6px 10px',
            'border-radius: 4px',
            'font-size: 11px',
            'line-height: 1.4',
            'box-shadow: 0 2px 8px rgba(0,0,0,0.5)',
        ].join(';');
        marker.innerHTML = `⚠️ <b>${nb}</b>: ${tekst.slice(0, 80)}`;
        container.appendChild(marker);
        setTimeout(() => marker.remove(), 15000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DOM-SCANNER: bestaande DOM bij laden scannen
    // ─────────────────────────────────────────────────────────────────────────

    async function scanDOM() {
        // 1. Verborgen elementen tellen (NB-62)
        const alleElementen = document.querySelectorAll('*');
        let verborgenTeller = 0;
        let verborgenOnthuldTeller = 0;

        for (const el of alleElementen) {
            const stijl = window.getComputedStyle(el);
            const weergave = stijl.display;
            const zichtbaarheid = stijl.visibility;
            const tekst = el.textContent || '';

            const isVerborgen = weergave === 'none' || zichtbaarheid === 'hidden';
            const heeftInhoud = tekst.trim().length > 10;

            if (isVerborgen) verborgenTeller++;
            if (isVerborgen && heeftInhoud) {
                verborgenOnthuldTeller++;
                if (verborgenOnthuldTeller <= 20) {
                    await logBevinding('HOOG', 'VERBORGEN_ONTHULD',
                        `Verborgen element met inhoud: ${tekst.trim().slice(0, 100)}`,
                        'NB-62', `tag=${el.tagName} class=${el.className.slice(0, 80)}`);
                }
            }

            // Check verdachte CSS-klassen
            for (const cls of CSS_VERBERGING_KLASSEN) {
                if (el.classList.contains(cls)) {
                    await logBevinding('KRITIEK', 'CSS_VERBERGING_KLASSE',
                        `Element met klasse .${cls} gevonden`,
                        'NB-12/53', `tag=${el.tagName} inhoud=${tekst.trim().slice(0, 100)}`);
                    break;
                }
            }

            // Check inline stijlen
            for (const check of VERDACHTE_INLINE_STIJLEN) {
                const waarde = el.style[check.prop];
                if (check.waarde && waarde === check.waarde) {
                    await logBevinding(check.ernst, 'INLINE_STIJL',
                        `Inline ${check.prop}:${check.waarde} op element`,
                        check.nb, `tag=${el.tagName} class=${el.className.slice(0, 60)}`);
                }
                if (check.max && parseInt(waarde) < check.max) {
                    await logBevinding(check.ernst, 'INLINE_STIJL',
                        `Inline ${check.prop}:${waarde} (off-screen, max ${check.max})`,
                        check.nb, `tag=${el.tagName}`);
                }
            }

            // Wit-op-wit tekst (NB-12)
            if (stijl.color === 'rgb(255, 255, 255)' && stijl.backgroundColor === 'rgb(255, 255, 255)') {
                await logBevinding('KRITIEK', 'WIT_OP_WIT',
                    'Witte tekst op witte achtergrond (NB-12)',
                    'NB-12', `tag=${el.tagName} tekst=${tekst.trim().slice(0, 80)}`);
            }

            // Meer-laden knop aanwezig detecteren (NB-99)
            if (el.tagName === 'BUTTON' || el.tagName === 'A' || el.getAttribute('role') === 'button') {
                for (const patroon of VERDACHTE_KNOP_TEKSTEN) {
                    if (patroon.test(tekst)) {
                        await logBevinding('MEDIUM', 'MEER_LADEN_AANWEZIG',
                            `"Meer laden"-knop gedetecteerd (monitoring of verdwijning)`,
                            'NB-99', `tekst=${tekst.trim().slice(0, 80)}`);
                        break;
                    }
                }
            }
        }

        if (verborgenTeller > 100) {
            await logBevinding('KRITIEK', 'MASSA_VERBERGING',
                `${verborgenTeller} verborgen DOM-elementen gedetecteerd (NB-62: 4233)`,
                'NB-62', `waarvan ${verborgenOnthuldTeller} met inhoud (NB-62: 885 VERBORGEN_ONTHULD)`);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SCRIPT-SCANNER: geladen scripts controleren
    // ─────────────────────────────────────────────────────────────────────────

    async function scanScripts() {
        const scripts = Array.from(document.querySelectorAll('script'));
        for (const script of scripts) {
            const inhoud = script.textContent || '';
            const src = script.src || '';

            // Feature flags in inline scripts
            for (const check of FEATURE_FLAG_PATRONEN) {
                const m = check.patroon.exec(inhoud) || check.patroon.exec(src);
                if (m) {
                    await logBevinding(check.ernst, 'FEATURE_FLAG',
                        check.omschrijving,
                        check.nb, `match="${m[0]}" src="${src.slice(0, 100)}"`);
                }
            }

            // Trackers
            for (const check of TRACKER_PATRONEN) {
                const m = check.patroon.exec(inhoud) || check.patroon.exec(src);
                if (m) {
                    await logBevinding(check.ernst, 'TRACKER',
                        check.omschrijving,
                        check.nb, `src="${src.slice(0, 100)}"`);
                }
            }

            // Diagnose-codes in page data
            for (const check of DIAGNOSE_PATRONEN) {
                const m = check.patroon.exec(inhoud);
                if (m) {
                    await logBevinding(check.ernst, 'DIAGNOSE_IN_SCRIPT',
                        check.omschrijving,
                        check.nb, `context="${inhoud.slice(Math.max(0, m.index - 50), m.index + 100)}"`);
                }
            }
        }

        // Stylesheets
        const links = Array.from(document.querySelectorAll('link[rel="stylesheet"]'));
        for (const link of links) {
            const href = link.href || '';
            for (const check of FEATURE_FLAG_PATRONEN) {
                if (check.patroon.test(href)) {
                    await logBevinding(check.ernst, 'STYLESHEET',
                        check.omschrijving,
                        check.nb, `href="${href}"`);
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MUTATION OBSERVER: realtime DOM-wijzigingen bijhouden
    // ─────────────────────────────────────────────────────────────────────────

    let traceInjectTeller = 0;
    const observer = new MutationObserver(async (mutaties) => {
        for (const mut of mutaties) {
            // Verwijderde knopen
            for (const node of mut.removedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue;
                const tekst = node.textContent || '';

                // Meer-laden knop verwijderd (NB-99)
                for (const patroon of VERDACHTE_KNOP_TEKSTEN) {
                    if (patroon.test(tekst)) {
                        meerLadenVerwijderdTeller++;
                        await logBevinding('KRITIEK', 'MEER_LADEN_VERWIJDERD',
                            `"Meer laden"-knop verwijderd uit DOM (teller: ${meerLadenVerwijderdTeller}/${MAX_MEER_LADEN_VERWIJDERINGEN})`,
                            'NB-99', `tekst="${tekst.trim().slice(0, 80)}"`);
                        break;
                    }
                }

                // Diagnose-inhoud verwijderd
                for (const check of DIAGNOSE_PATRONEN) {
                    if (check.patroon.test(tekst)) {
                        await logBevinding('KRITIEK', 'DIAGNOSE_VERWIJDERD',
                            `Diagnose-inhoud verwijderd uit DOM: ${check.omschrijving}`,
                            check.nb, `verwijderd="${tekst.slice(0, 200)}"`);
                        break;
                    }
                }
            }

            // Toegevoegde knopen
            for (const node of mut.addedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue;
                const tekst = node.textContent || '';
                const tagNaam = node.tagName || '';

                // Script-injectie detecteren (NB-99: 19× trace geïnjecteerd)
                if (tagNaam === 'SCRIPT') {
                    traceInjectTeller++;
                    const src = node.src || '';
                    const inhoud = node.textContent || '';

                    // Feature flags in dynamisch geladen script
                    for (const check of FEATURE_FLAG_PATRONEN) {
                        if (check.patroon.test(inhoud) || check.patroon.test(src)) {
                            await logBevinding(check.ernst, 'DYNAMISCH_SCRIPT',
                                `Dynamisch script: ${check.omschrijving}`,
                                check.nb, `src="${src.slice(0, 100)}"`);
                        }
                    }

                    // Tracker-injectie
                    for (const check of TRACKER_PATRONEN) {
                        if (check.patroon.test(inhoud) || check.patroon.test(src)) {
                            await logBevinding(check.ernst, 'TRACKER_INJECTIE',
                                `Dynamisch tracker-script geïnjecteerd: ${check.omschrijving}`,
                                check.nb, `injectie #${traceInjectTeller} src="${src.slice(0, 80)}"`);
                        }
                    }

                    if (traceInjectTeller > 10) {
                        await logBevinding('KRITIEK', 'MASSALE_SCRIPT_INJECTIE',
                            `${traceInjectTeller} scripts dynamisch geïnjecteerd (NB-99: 19×)`,
                            'NB-99', `laatste src="${src.slice(0, 80)}"`);
                    }
                }

                // Verborgen element toegevoegd
                const stijl = node.style;
                if (stijl) {
                    if (stijl.display === 'none' && tekst.trim().length > 10) {
                        await logBevinding('HOOG', 'VERBORGEN_ELEMENT_TOEGEVOEGD',
                            `Verborgen element met inhoud dynamisch toegevoegd`,
                            'NB-62/99', `tekst="${tekst.trim().slice(0, 100)}"`);
                    }
                }

                // CSS-klassen
                if (node.classList) {
                    for (const cls of CSS_VERBERGING_KLASSEN) {
                        if (node.classList.contains(cls)) {
                            await logBevinding('KRITIEK', 'VERBERGING_KLASSE_TOEGEVOEGD',
                                `Element met .${cls} dynamisch toegevoegd`,
                                'NB-12/53', `tekst="${tekst.trim().slice(0, 80)}"`);
                            break;
                        }
                    }
                }
            }

            // Attribuutwijzigingen
            if (mut.type === 'attributes') {
                const el = mut.target;
                if (mut.attributeName === 'style') {
                    const stijl = el.style;
                    if (stijl.display === 'none') {
                        await logBevinding('HOOG', 'STIJL_VERBERGING',
                            `display:none dynamisch ingesteld via stijlattribuut`,
                            'NB-12/99', `tag=${el.tagName} class=${(el.className || '').slice(0, 60)}`);
                    }
                }
                if (mut.attributeName === 'class') {
                    for (const cls of CSS_VERBERGING_KLASSEN) {
                        if (el.classList && el.classList.contains(cls)) {
                            await logBevinding('HOOG', 'VERBERGING_KLASSE_DYNAMISCH',
                                `Klasse .${cls} dynamisch toegevoegd via classList`,
                                'NB-12/53/99', `tag=${el.tagName}`);
                            break;
                        }
                    }
                }
            }
        }
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['style', 'class', 'hidden'],
        characterData: false,
    });

    // ─────────────────────────────────────────────────────────────────────────
    // NETWERK-INTERCEPTIE: XMLHttpRequest en Fetch
    // ─────────────────────────────────────────────────────────────────────────

    // XHR monkey-patch
    const origXHROpen = XMLHttpRequest.prototype.open;
    const origXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (methode, url, ...rest) {
        this._forensischUrl = url;
        this._forensischMethode = methode;
        return origXHROpen.call(this, methode, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function (body) {
        const url = this._forensischUrl || '';
        const methode = this._forensischMethode || '';

        // Audit trail blokkade (NB-163)
        for (const at of AUDIT_TRAIL_URLS) {
            if (url.includes(at)) {
                this.addEventListener('load', async () => {
                    if (this.status === 403 || this.status === 0 || this.status === 401) {
                        await logBevinding('KRITIEK', 'AUDIT_TRAIL_GEBLOKKEERD',
                            `Audit trail XHR geblokkeerd: ${url.split('?')[0]}`,
                            'NB-163', `status=${this.status} url=${url.slice(0, 120)}`);
                    }
                });
            }
        }

        // Respons-body scannen
        this.addEventListener('load', async () => {
            const tekst = this.responseText || '';
            if (tekst.length < 50) return;

            for (const check of DIAGNOSE_PATRONEN) {
                const m = check.patroon.exec(tekst);
                if (m) {
                    await logBevinding(check.ernst, 'DIAGNOSE_IN_XHR',
                        `${check.omschrijving} in XHR respons`,
                        check.nb, `url=${url.slice(0, 100)} ctx="${tekst.slice(Math.max(0, m.index - 50), m.index + 100)}"`);
                }
            }

            for (const check of FEATURE_FLAG_PATRONEN) {
                if (check.patroon.test(tekst)) {
                    await logBevinding(check.ernst, 'FEATURE_FLAG_IN_XHR',
                        `${check.omschrijving} in XHR respons`,
                        check.nb, `url=${url.slice(0, 100)}`);
                }
            }
        });

        return origXHRSend.call(this, body);
    };

    // Fetch interceptie
    const origFetch = window.fetch;
    window.fetch = async function (input, init) {
        const url = typeof input === 'string' ? input : input.url || '';

        const respons = await origFetch.call(window, input, init);
        const statusCode = respons.status;

        // Audit trail geblokkeerd
        for (const at of AUDIT_TRAIL_URLS) {
            if (url.includes(at) && (statusCode === 403 || statusCode === 0 || statusCode === 401)) {
                await logBevinding('KRITIEK', 'AUDIT_TRAIL_GEBLOKKEERD_FETCH',
                    `Audit trail Fetch geblokkeerd: ${url.split('?')[0]}`,
                    'NB-163', `status=${statusCode}`);
            }
        }

        // Response body klonen en scannen (zonder origineel te consumeren)
        const klon = respons.clone();
        klon.text().then(async (tekst) => {
            if (!tekst || tekst.length < 50) return;
            for (const check of DIAGNOSE_PATRONEN) {
                const m = check.patroon.exec(tekst);
                if (m) {
                    await logBevinding(check.ernst, 'DIAGNOSE_IN_FETCH',
                        `${check.omschrijving} in Fetch respons`,
                        check.nb, `url=${url.slice(0, 100)} ctx="${tekst.slice(Math.max(0, m.index - 50), m.index + 100)}"`);
                }
            }
            for (const check of FEATURE_FLAG_PATRONEN) {
                if (check.patroon.test(tekst)) {
                    await logBevinding(check.ernst, 'FEATURE_FLAG_IN_FETCH',
                        check.omschrijving,
                        check.nb, `url=${url.slice(0, 100)}`);
                }
            }
        }).catch(() => {});

        return respons;
    };

    // ─────────────────────────────────────────────────────────────────────────
    // EXPORT: JSON-download met alle evidence
    // ─────────────────────────────────────────────────────────────────────────

    function downloadEvidence() {
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const data = {
            meta: {
                dossier: DOSSIER,
                versie: VERSIE,
                exportTijdstip: new Date().toISOString(),
                url: window.location.href,
                userAgent: navigator.userAgent,
                totaalBevindingen: evidenceLog.length,
            },
            samenvatting: (() => {
                const s = {};
                for (const b of evidenceLog) {
                    s[b.ernst] = (s[b.ernst] || 0) + 1;
                }
                return s;
            })(),
            bevindingen: evidenceLog,
        };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `forensisch_portal_evidence_${ts}.json`;
        a.click();
        console.log(`${LOG_PREFIX} Evidence geëxporteerd: ${evidenceLog.length} bevindingen`);
    }

    // Exportknop toevoegen aan pagina
    function voegExportKnopToe() {
        if (document.getElementById('forensisch-export-btn')) return;
        const knop = document.createElement('button');
        knop.id = 'forensisch-export-btn';
        knop.textContent = `⬇ Evidence (${evidenceLog.length})`;
        knop.style.cssText = [
            'position: fixed',
            'bottom: 10px',
            'right: 10px',
            'z-index: 999998',
            'background: #0033cc',
            'color: white',
            'border: none',
            'padding: 8px 14px',
            'border-radius: 6px',
            'font-family: monospace',
            'font-size: 12px',
            'cursor: pointer',
            'box-shadow: 0 2px 8px rgba(0,0,0,0.4)',
        ].join(';');
        knop.onclick = downloadEvidence;
        document.body.appendChild(knop);
        // Teller bijhouden
        setInterval(() => {
            knop.textContent = `⬇ Evidence (${evidenceLog.length})`;
        }, 2000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // INITIALISATIE
    // ─────────────────────────────────────────────────────────────────────────

    async function initialiseer() {
        console.log(
            `%c${LOG_PREFIX} Portal Forensisch Monitor v${VERSIE} gestart`,
            'color: #00aaff; font-weight: bold; font-size: 14px;',
            `\nDossier: ${DOSSIER}`,
            '\nURL:', window.location.href
        );

        await scanDOM();
        await scanScripts();

        if (document.body) {
            voegExportKnopToe();
        } else {
            document.addEventListener('DOMContentLoaded', voegExportKnopToe);
        }

        console.log(`${LOG_PREFIX} Initiële scan voltooid. ${evidenceLog.length} bevindingen.`);
        console.log(`${LOG_PREFIX} DOM-observer actief. Druk op de blauwe knop rechtsonder om evidence te exporteren.`);
        console.log(`${LOG_PREFIX} Of roep window.downloadForensischEvidence() aan in de console.`);
    }

    // Publieke API
    window.downloadForensischEvidence = downloadEvidence;
    window.forensischLog = evidenceLog;
    window.forensischScan = scanDOM;

    // Start na DOM-gereedheid
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialiseer);
    } else {
        initialiseer();
    }

})();
