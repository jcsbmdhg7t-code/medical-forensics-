/**
 * FORENSISCH LOON SCRIPT — alles vastleggen
 *
 * Filosofie: dit script is een volledig net, geen filter.
 * Elk request en response wordt volledig gelogd ongeacht inhoud.
 * Bekende patronen krijgen extra markering, maar alles wat
 * langskomt wordt zichtbaar — ook wat we nog niet kennen.
 *
 * LOON INSTELLING:
 *   Name: Forensisch
 *   Script Type: http-response (hoofdscript)
 *   Expressions: .*   (alles, of .*spaarnegasthuis.* voor alleen portaal)
 *   Script Location: Local → plak dit script
 *   Require Request Body: AAN
 *   Timeout: 60
 *
 *   Tweede script (requests):
 *   Script Type: http-request
 *   Require Request Body: UIT
 */

(function () {

// ── Bekende patronen — alleen voor EXTRA markering bovenop alles ──
var PATRONEN = [
    // ── Medische codes / diagnoses ──
    { p: /F19\.1/i,                                    nb: 'NB-01' },
    { p: /neusdruppelmisbruik/i,                       nb: 'NB-01' },
    { p: /361055000/,                                  nb: 'NB-03' },
    { p: /228273003/,                                  nb: 'NB-23' },
    { p: /228366006/,                                  nb: 'NB-23b' },
    { p: /266927001/,                                  nb: 'NB-23c' },
    { p: /F60\.31|borderline\s*persoon/i,              nb: 'NB-xx' },
    { p: /transactie.{0,10}77832/i,                    nb: 'NB-23' },

    // ── Anonieme/vervalste auteurs in CDA ──
    { p: /nullFlavor\s*=\s*["']?UNK/i,                nb: 'NB-18' },
    { p: /extension\s*=\s*["']?999999/i,              nb: 'NB-18' },
    { p: /GUARD\b/,                                    nb: 'NB-56' },
    { p: /HANDMATIGE_EDIT_BOM/i,                       nb: 'NB-13' },

    // ── Zorgverlener extensie codes ──
    { p: /extension\s*=\s*["']?51504662/i,             nb: 'NB-04' },
    { p: /extension\s*=\s*["']?84107660/i,             nb: 'NB-04' },
    { p: /extension\s*=\s*["']?373282512/i,            nb: 'NB-05' },
    { p: /Epic@spaarnegasthuis\.nl/i,                  nb: 'NB-05' },

    // ── Epic feature flags: toegang / rechten ──
    { p: /DISABLEMYCONDITIONS/i,                       nb: 'NB-11' },
    { p: /DISABLEPLANOFCARE/i,                         nb: 'NB-11' },
    { p: /SUBSTANCEHXQNR/i,                            nb: 'NB-108' },
    { p: /AUTOGENERATESIGNATURE/i,                     nb: 'NB-82' },
    { p: /USERAUDITTRAIL|MYCHARTAUDITTRAIL/i,          nb: 'NB-163' },
    { p: /noView\s*:\s*true/i,                         nb: 'NB-99' },

    // ── CSS klassen die data verbergen ──
    { p: /hiddenProvider/i,                            nb: 'NB-12' },
    { p: /CEDataExternal/i,                            nb: 'NB-12' },
    { p: /WoundListSection/i,                          nb: 'NB-12' },
    { p: /printBlackText/i,                            nb: 'NB-84' },
    { p: /override\.css/i,                             nb: 'NB-89' },
    { p: /lucy\.css|lucy_colors/i,                     nb: 'NB-71' },

    // ── Epic feature flags: uitgebreid ──
    { p: /SEXUALACTIVITYHXQNR/i,                       nb: 'NB-83' },
    { p: /AUTOSYNCRECEIVEFORPERSONALINFORMATION/i,     nb: 'NB-115' },
    { p: /ExternalJump|LogExternalJumpAudit/i,         nb: 'NB-68' },

    // ── Trackers / telemetrie ──
    { p: /recording_capture_keystrokes\s*=\s*true/i,  nb: 'NB-53' },
    { p: /hotjar\.com|hjid\s*=/i,                      nb: 'NB-79' },
    { p: /sentry\.io/i,                                nb: 'NB-69' },
    { p: /DE36B70A/i,                                  nb: 'NB-69' },
    { p: /datadog.*browser-intake|browser-intake.*datadoghq/i, nb: 'NB-69' },
    { p: /pendo\.io/i,                                 nb: 'NB-79' },
    { p: /wingify|vwo\.com/i,                          nb: 'NB-79' },
    { p: /qualtrics\.com/i,                            nb: 'NB-79' },
    { p: /segment\.io|segment\.com/i,                  nb: 'NB-79' },
    { p: /kameleoon/i,                                 nb: 'NB-79' },
    { p: /GTM-PGPCH2T/i,                               nb: 'NB-85' },
    { p: /account_id\s*[:=]\s*763232/i,                nb: 'NB-178' },
    { p: /vwo_uuid/i,                                  nb: 'NB-178' },
    { p: /hide_element.*opacity.*0|body.*opacity.*0.*important/i, nb: 'NB-178' },
    { p: /body\s*\{[^}]*opacity\s*:\s*0/i,             nb: 'NB-178' },
    { p: /SESSION_ID\s*[=:]\s*[A-F0-9]{20,}/i,        nb: 'NB-79' },

    // ── Supply chain / externe partijen ──
    { p: /hoppinger\.com/i,                            nb: 'NB-114' },
    { p: /spaarne-rebuild\.productie\.hoppinger/i,     nb: 'NB-114' },
    { p: /FocusZorgTeam.*test/i,                       nb: 'NB-91' },
    { p: /centramed\.nl/i,                             nb: 'NB-179' },
    { p: /Brijder|Parnassia.*Indigo/i,                 nb: 'NB-113' },

    // ── ChipSoft HiX API — rechten / toestemmingen / endpoints ──
    { p: /ChipSoft\.PlatformServices/i,                nb: 'NB-177' },
    { p: /GetCurrentPatientAndUserObject/i,            nb: 'NB-177' },
    { p: /GetPatientDocuments/i,                       nb: 'NB-177' },
    { p: /GetPathologyResults/i,                       nb: 'NB-177' },
    { p: /GetDcrRegistrations/i,                       nb: 'NB-177' },
    { p: /DigiDClusterHybrid/i,                        nb: 'NB-177' },
    { p: /DYN_CURRENT_USER/i,                          nb: 'NB-177' },
    { p: /PATIENT_PATIENT/i,                           nb: 'NB-177' },
    { p: /2001702222/,                                 nb: 'NB-177' },

    // ── Clinician access log / wie heeft mijn dossier ingezien ──
    { p: /GetThirdPartyAccessLogEntries/i,             nb: 'NB-163' },
    { p: /GetUserAuditTrail/i,                         nb: 'NB-163' },
    { p: /GetPatientAuditLog/i,                        nb: 'NB-163' },
    { p: /MyAuditTrail/i,                              nb: 'NB-163' },
    { p: /AuditTrail/i,                                nb: 'NB-163' },
    { p: /AccessAuditLog/i,                            nb: 'NB-163' },
    { p: /PatientAccessLog/i,                          nb: 'NB-163' },
    { p: /AccessLog|access-logs/i,                     nb: 'NB-163' },
    { p: /GetBreachLog/i,                              nb: 'NB-163' },
    { p: /\/AuditLog\b|\/AuditEvent\b/i,               nb: 'NB-163' },
    { p: /AuditEvent/i,                                nb: 'NB-163' },
    { p: /who.{0,20}accessed|clinician.{0,20}access/i, nb: 'NB-163' },
    { p: /heeft.{0,20}ingezien|heeft.{0,20}bekeken/i,  nb: 'NB-163' },
    { p: /WhoViewedMyHealthRecord/i,                   nb: 'NB-163' },
    { p: /ViewedBy|AccessedBy/i,                       nb: 'NB-163' },
    { p: /ClinicianAccess/i,                           nb: 'NB-163' },
    { p: /FHIR\/R4\/AuditEvent/i,                      nb: 'NB-163' },
    { p: /api\/epic.*AuditLog/i,                       nb: 'NB-163' },

    // ── Genetisch profiel module (Epic) — NB-180 ──
    { p: /GENETICHXQNR/i,                              nb: 'NB-180' },
    { p: /genetic-profile|genetisch\s*profiel/i,       nb: 'NB-180' },
    { p: /epic\.px\.client\.genomics/i,                nb: 'NB-180' },
    { p: /@epic-px\/genomics/i,                        nb: 'NB-180' },
    { p: /genomics_drugindicator|genomics_diseaseindicator/i, nb: 'NB-180' },
    { p: /GeneticProfileLink|geneticProfileLink/i,     nb: 'NB-180' },
    { p: /GenomicIndicator|VariantList/i,              nb: 'NB-180' },
    { p: /allelicState|allelicPhase|mosaicism/i,       nb: 'NB-180' },
    { p: /DNAChangeType|variantTypeLabel|FindingType/i, nb: 'NB-180' },
    { p: /CytogeneticLocation/i,                       nb: 'NB-180' },
    { p: /Mijn genetisch profiel/i,                    nb: 'NB-180' },

    // ── Clinician access log (verdiept) — NB-163 ──
    { p: /accesslogs\.clinician/i,                     nb: 'NB-163' },
    { p: /WhosAccessedMyRecord/i,                      nb: 'NB-163' },
    { p: /ColumnLabelAccessor/i,                       nb: 'NB-163' },
    { p: /RecordAccessed/i,                            nb: 'NB-163' },
    { p: /@epic-px\/access-logs/i,                     nb: 'NB-163' },
    { p: /Wie heeft mijn dossier ingezien/i,           nb: 'NB-163' },

    // ── Verdachte / onverklaarbare feature flags — NB-181 ──
    { p: /ISABELGROTHE/,                               nb: 'NB-181' },
    { p: /NNNNNNNNN/,                                  nb: 'NB-181' },
    { p: /\bSZMRN\b/,                                  nb: 'NB-181' },
    { p: /VOLLEDIGPROFIEL/i,                           nb: 'NB-181' },
    { p: /H2GDEBUG/i,                                  nb: 'NB-181' },

    // ── Tijdstempels / identifiers ──
    { p: /20260110033455/,                             nb: 'NB-166' },
    { p: /215672185/,                                  nb: 'NB-166' },
    { p: /0133033170/,                                 nb: 'NB-166' },

    // ── FHIR / MedMij ──
    { p: /\$lastn/i,                                   nb: 'NB-109' },
    { p: /quliRedirect/i,                              nb: 'MEDMIJ' },
];

var BLOKKEER_HEADERS = [
    'content-security-policy', 'content-security-policy-report-only',
    'x-frame-options', 'x-xss-protection', 'x-content-type-options',
    'strict-transport-security', 'feature-policy', 'permissions-policy',
    'cross-origin-embedder-policy', 'cross-origin-opener-policy',
    'cross-origin-resource-policy',
];

// ── hulpfuncties ──

function s(v) { return v ? String(v) : ''; }

function hGet(h, n) {
    if (!h) return '';
    var lo = n.toLowerCase(), k = Object.keys(h);
    for (var i = 0; i < k.length; i++)
        if (k[i].toLowerCase() === lo) return s(h[k[i]]);
    return '';
}

function hDel(h, n) {
    if (!h) return;
    var lo = n.toLowerCase(), k = Object.keys(h);
    for (var i = 0; i < k.length; i++)
        if (k[i].toLowerCase() === lo) { delete h[k[i]]; return; }
}

function melding(titel, sub, body) {
    try { $notification.post(titel, sub, body); } catch(e) {}
}

// ── Stap 1: log ALLE headers volledig ──
function logAlleHeaders(headers, richting) {
    if (!headers) return;
    var k = Object.keys(headers);
    console.log('[HEADERS ' + richting + '] ' + k.length + ' stuks:');
    for (var i = 0; i < k.length; i++) {
        console.log('  ' + k[i] + ': ' + s(headers[k[i]]).slice(0, 300));
    }
}

// ── Stap 2: log ALLE cookies volledig ──
function logAlleCookies(cookieStr, richting) {
    if (!cookieStr) return;
    var cookies = cookieStr.split(';');
    console.log('[COOKIES ' + richting + '] ' + cookies.length + ' cookies:');
    for (var i = 0; i < cookies.length; i++) {
        var c = cookies[i].trim();
        if (c) console.log('  ' + c);
    }
}

// ── Stap 3: extraheer ALLE waarden uit JSON — geen filter ──
function extracteerJSON(body, url) {
    if (!body || body.indexOf('{') === -1) return;
    try {
        var obj = JSON.parse(body);
        var waarden = [];
        function loop(o, pad) {
            if (o === null || o === undefined) return;
            if (typeof o === 'object') {
                var k = Object.keys(o);
                for (var i = 0; i < k.length; i++) {
                    loop(o[k[i]], pad ? pad + '.' + k[i] : k[i]);
                }
            } else {
                var v = s(o);
                if (v.length > 0) {
                    waarden.push(pad + ' = ' + v);
                }
            }
        }
        loop(obj, '');
        console.log('[JSON] ' + waarden.length + ' velden in ' + url.split('?')[0]);
        // Log alles in blokken van 20
        for (var i = 0; i < waarden.length; i += 20) {
            console.log(waarden.slice(i, i + 20).join('\n'));
        }
    } catch(e) {
        // Geen valide JSON — probeer JSON-fragmenten te vinden
        var re = /"([^"]{1,60})"\s*:\s*"([^"]{1,200})"/g, m;
        var gevonden = [];
        while ((m = re.exec(body)) !== null && gevonden.length < 100) {
            gevonden.push('"' + m[1] + '": "' + m[2] + '"');
        }
        if (gevonden.length > 0) {
            console.log('[JSON-FRAGMENT] ' + gevonden.length + ' sleutel-waarde paren:');
            console.log(gevonden.join('\n'));
        }
    }
}

// ── Stap 4: extraheer ALLE XML attributen en tekst ──
function extracteerXML(body, url) {
    if (!body || (body.indexOf('<') === -1 && body.indexOf('<?xml') === -1)) return;

    // Alle attribuut=waarde combinaties
    var attrs = [];
    var re = /(\w[\w:.-]*)\s*=\s*["']([^"']{1,300})["']/g, m;
    while ((m = re.exec(body)) !== null && attrs.length < 200) {
        var naam = m[1].toLowerCase();
        // Sla pure stijl/class attributen over
        if (naam !== 'style' && naam !== 'class' && naam !== 'id' && naam !== 'href') {
            attrs.push(m[1] + '="' + m[2] + '"');
        }
    }
    if (attrs.length > 0) {
        console.log('[XML-ATTRS] ' + attrs.length + ' attributen in ' + url.split('?')[0]);
        for (var i = 0; i < attrs.length; i += 30) {
            console.log(attrs.slice(i, i + 30).join('\n'));
        }
    }

    // Alle tekst tussen tags (leesbare inhoud) — volledig
    var tekst = body.replace(/<[^>]+>/g, '\n').replace(/\s+/g, ' ').trim();
    if (tekst.length > 10) {
        console.log('[XML-TEKST] ' + tekst.length + ' tekens totaal:');
        for (var xi = 0; xi < tekst.length; xi += 500) {
            console.log(tekst.slice(xi, xi + 500));
        }
    }
}

// ── Stap 5: decodeer en log ALLE base64 blokken ──
function logBase64(body, url) {
    var re = /[A-Za-z0-9+\/]{40,}={0,2}/g, m;
    var count = 0;
    while ((m = re.exec(body)) !== null) {
        try {
            var d = atob(m[0]);
            var leesbaar = d.replace(/[^\x20-\x7E]/g, '·');
            var ratio = (leesbaar.split('·').length - 1) / d.length;
            if (ratio < 0.4) { // meer dan 60% leesbare ASCII
                count++;
                console.log('[BASE64-' + count + '] offset ' + m.index + ', ' + leesbaar.length + ' tekens:');
                for (var bi = 0; bi < leesbaar.length; bi += 500) {
                    console.log(leesbaar.slice(bi, bi + 500));
                }
            }
        } catch(e) {}
    }
    if (count > 0) {
        console.log('[BASE64] ' + count + ' blokken gedecodeerd in ' + url.split('?')[0]);
    }
}

// ── Stap 6: markeer bekende patronen (EXTRA, niet exclusief) — geeft hits[] terug ──
function markeerBekend(body, url) {
    if (!body || body.length < 2) return [];
    var su = url.split('?')[0];
    var hits = [];
    for (var i = 0; i < PATRONEN.length; i++) {
        var re = new RegExp(PATRONEN[i].p.source, 'gi'), m;
        while ((m = re.exec(body)) !== null) {
            var idx  = m.index;
            var frag = body.substring(Math.max(0, idx - 80), idx + 150).replace(/[\n\r\t]+/g, ' ');
            console.log('[!!! ' + PATRONEN[i].nb + ' !!!] TREFFER: ...' + frag + '...');
            hits.push(PATRONEN[i].nb);
            if (re.lastIndex === idx) re.lastIndex++;
        }
    }
    if (hits.length > 0) {
        melding('🔴 ' + hits.slice(0,3).join(' ') + ' TREFFER', su.slice(-50),
            hits.length + ' bekende patronen gevonden');
    }
    return hits;
}

// ── Stap 8: sla samenvatting op in $persistentStore — rollende chunks, niets gaat verloren ──
// Chunks: forensisch_log_0, forensisch_log_1, forensisch_log_2 ...
// forensisch_chunk = huidig chunknummer
// Via Data Persistence → Export Data komen ALLE chunks mee.
function slaOpInStore(url, status, bytes, nbHits, cookieProblemen) {
    try {
        var chunk = parseInt($persistentStore.read('forensisch_chunk') || '0') || 0;
        var key = 'forensisch_log_' + chunk;
        var bestaand = $persistentStore.read(key) || '[]';
        var log;
        try { log = JSON.parse(bestaand); } catch(e) { log = []; }
        log.push({
            t: new Date().toISOString().slice(0, 19).replace('T', ' '),
            u: url.split('?')[0].slice(0, 200),
            s: status,
            b: bytes,
            nb: nbHits && nbHits.length > 0 ? nbHits.join(',') : null,
            ck: cookieProblemen && cookieProblemen.length > 0 ? cookieProblemen.join(',') : null
        });
        $persistentStore.write(JSON.stringify(log), key);
        if (log.length >= 1000) {
            var volgend = chunk + 1;
            $persistentStore.write(String(volgend), 'forensisch_chunk');
            console.log('[STORE] forensisch_log_' + chunk + ' vol (1000) → forensisch_log_' + volgend + ' gestart');
        }
    } catch(e) {
        console.log('[STORE FOUT] ' + e);
    }
}

// ── Stap 7: verwijder CSS verberging uit HTML/CSS ──
function stripVerberging(body) {
    var was = body.length;
    body = body.replace(/(\{[^}]*)\bdisplay\s*:\s*none(\s*!important)?([^}]*\})/gi, '$1display:block$3');
    body = body.replace(/\bvisibility\s*:\s*hidden(\s*!important)?/gi, 'visibility:visible');
    body = body.replace(/\bopacity\s*:\s*0(\s*!important)?/gi, 'opacity:1');
    body = body.replace(/\bfont-size\s*:\s*0(px|em|rem)?(\s*!important)?/gi, 'font-size:inherit');
    body = body.replace(/\bheight\s*:\s*0(px)?(\s*!important)?/gi, 'height:auto');
    body = body.replace(/\bmax-height\s*:\s*0(px)?(\s*!important)?/gi, 'max-height:none');
    body = body.replace(/\bclip\s*:\s*rect\s*\([^)]*\)/gi, 'clip:auto');
    body = body.replace(/\b(left|top)\s*:\s*-\d{3,}(px|em)(\s*!important)?/gi, '$1:auto');
    body = body.replace(/(<[^>]+style\s*=\s*"[^"]*)\bdisplay\s*:\s*none([^"]*")/gi, '$1display:block$2');
    body = body.replace(/\bhidden(?=\s*[>\/\s])/gi, 'data-was-hidden');
    if (body.length !== was) {
        console.log('[VERBERGING] CSS verberging verwijderd (' + (body.length - was) + ' bytes gewijzigd)');
    }
    return body;
}

// ── context ──

var isResp = false, isReq = false;
try { isResp = typeof $response !== 'undefined' && $response !== null; } catch(e) {}
try { isReq  = !isResp && typeof $request !== 'undefined' && $request !== null; } catch(e) {}

// ════════════════════════════════════════════════════════════
//  RESPONSE — volledig vastleggen
// ════════════════════════════════════════════════════════════
if (isResp) {

    var url = '', method = '', status = 0, reqHeaders = {}, respHeaders = {}, body = '', reqBody = '';
    try { url         = $request.url || ''; }         catch(e) {}
    try { method      = $request.method || ''; }       catch(e) {}
    try { status      = $response.status || 0; }       catch(e) {}
    try { reqHeaders  = $request.headers || {}; }      catch(e) {}
    try { respHeaders = $response.headers
            ? JSON.parse(JSON.stringify($response.headers)) : {}; } catch(e) { respHeaders = {}; }
    try { body        = s($response.body); }            catch(e) {}
    try { reqBody     = s($request.body); }             catch(e) {}

    var su = url.split('?')[0];
    var origBody = body, origHeaders = JSON.parse(JSON.stringify(respHeaders));

    try {
        // ── REGEL 1: log alles — url, status, grootte ──
        console.log('═══════════════════════════════════════');
        console.log('[RESPONSE] ' + method + ' ' + status + ' ' + url);
        console.log('[GROOTTE] body: ' + body.length + 'b | reqbody: ' + reqBody.length + 'b');

        // ── REGEL 2: alle response headers ──
        logAlleHeaders(respHeaders, 'RESP');

        // ── REGEL 3: alle request headers (ook vastleggen) ──
        logAlleHeaders(reqHeaders, 'REQ');

        // ── REGEL 4: alle cookies in request ──
        logAlleCookies(hGet(reqHeaders, 'cookie'), 'REQ');

        // ── REGEL 5: alle Set-Cookie headers volledig ──
        var setCookies = respHeaders['set-cookie'] || respHeaders['Set-Cookie'];
        if (setCookies) {
            console.log('[SET-COOKIE] ' + s(setCookies));
        }

        // ── REGEL 6: volledige body dump — alles, geen limiet ──
        if (body.length > 0) {
            console.log('[BODY BEGIN →] ' + body.length + ' bytes totaal');
            for (var i = 0; i < body.length; i += 500) {
                console.log(body.slice(i, i + 500));
            }
            console.log('[← BODY EINDE]');
        }

        // ── REGEL 7: request body volledig vastleggen ──
        if (reqBody.length > 0) {
            console.log('[REQ-BODY BEGIN →] ' + reqBody.length + ' bytes totaal');
            for (var ri = 0; ri < reqBody.length; ri += 500) {
                console.log(reqBody.slice(ri, ri + 500));
            }
            console.log('[← REQ-BODY EINDE]');
        }

        // ── REGEL 8: URL querystring apart ──
        if (url.indexOf('?') !== -1) {
            var qs = url.slice(url.indexOf('?') + 1);
            var params = qs.split('&');
            console.log('[URL-PARAMS] ' + params.length + ' parameters:');
            for (var pi = 0; pi < params.length; pi++) {
                console.log('  ' + decodeURIComponent(params[pi].replace(/\+/g, ' ')));
            }
        }

        // ── REGEL 9: JSON volledig uitpakken ──
        var ct = hGet(respHeaders, 'content-type').toLowerCase();
        if (ct.indexOf('json') !== -1 || body.trimLeft().charAt(0) === '{' || body.trimLeft().charAt(0) === '[') {
            extracteerJSON(body, url);
        }

        // ── REGEL 10: XML volledig uitpakken ──
        if (ct.indexOf('xml') !== -1 || body.indexOf('<?xml') !== -1 || body.indexOf('<ClinicalDocument') !== -1) {
            extracteerXML(body, url);
        }

        // ── REGEL 11: base64 decoderen en loggen ──
        logBase64(body, url);
        if (reqBody.length > 0) logBase64(reqBody, url + ' [REQ]');

        // ── REGEL 12: bekende patronen markeren (extra bovenop alles) ──
        var nbHits = markeerBekend(body, url);
        if (reqBody.length > 0) {
            var nbHitsReq = markeerBekend(reqBody, url + ' [REQ]');
            nbHits = nbHits.concat(nbHitsReq);
        }

        // ── REGEL 13: sla samenvatting op in persistent store ──
        var setCk = respHeaders['set-cookie'] || respHeaders['Set-Cookie'];
        var ckProblemen = [];
        if (setCk) {
            var ckStr = s(setCk);
            if (ckStr.toLowerCase().indexOf('secure') === -1) ckProblemen.push('geen-Secure');
            if (ckStr.toLowerCase().indexOf('httponly') === -1) ckProblemen.push('geen-HttpOnly');
            if (ckStr.toLowerCase().indexOf('samesite') === -1) ckProblemen.push('geen-SameSite');
        }
        slaOpInStore(url, status, body.length, nbHits, ckProblemen);

        // ── Verwijder blokkerende headers ──
        for (var bi = 0; bi < BLOKKEER_HEADERS.length; bi++) {
            if (hGet(respHeaders, BLOKKEER_HEADERS[bi])) {
                console.log('[HEADER-DEL] ' + BLOKKEER_HEADERS[bi]);
                hDel(respHeaders, BLOKKEER_HEADERS[bi]);
            }
        }

        // ── CORS volledig open ──
        respHeaders['Access-Control-Allow-Origin']   = '*';
        respHeaders['Access-Control-Allow-Methods']  = 'GET, POST, OPTIONS, PUT, DELETE, PATCH';
        respHeaders['Access-Control-Allow-Headers']  = '*';
        respHeaders['Access-Control-Expose-Headers'] = '*';

        // ── CSS verberging verwijderen ──
        body = stripVerberging(body);

        $done({ status: status, headers: respHeaders, body: body });

    } catch(e) {
        console.log('[FOUT] response: ' + e);
        try { $done({ status: status, headers: origHeaders, body: origBody }); }
        catch(e2) { try { $done({}); } catch(e3) {} }
    }

// ════════════════════════════════════════════════════════════
//  REQUEST — volledig vastleggen
// ════════════════════════════════════════════════════════════
} else if (isReq) {

    var url = '', method = '', headers = {}, body = '';
    try { url     = $request.url || ''; }    catch(e) {}
    try { method  = $request.method || ''; } catch(e) {}
    try { headers = $request.headers || {}; } catch(e) {}
    try { body    = s($request.body); }       catch(e) {}

    var su = url.split('?')[0];

    try {
        console.log('───────────────────────────────────────');
        console.log('[REQUEST] ' + method + ' ' + url);

        // Alle headers
        logAlleHeaders(headers, 'REQ');

        // Alle cookies
        logAlleCookies(hGet(headers, 'cookie'), 'REQ');

        // Auth tokens
        var auth = hGet(headers, 'authorization');
        if (auth) console.log('[AUTH] ' + auth.slice(0, 200));

        // URL params
        if (url.indexOf('?') !== -1) {
            var qs = url.slice(url.indexOf('?') + 1);
            var params = qs.split('&');
            console.log('[URL-PARAMS] ' + params.length + ':');
            for (var pi = 0; pi < params.length; pi++) {
                try { console.log('  ' + decodeURIComponent(params[pi].replace(/\+/g, ' '))); }
                catch(e) { console.log('  ' + params[pi]); }
            }
        }

        // Request body volledig
        if (body.length > 0) {
            console.log('[REQ-BODY BEGIN →] ' + body.length + ' bytes totaal');
            for (var rqi = 0; rqi < body.length; rqi += 500) {
                console.log(body.slice(rqi, rqi + 500));
            }
            console.log('[← REQ-BODY EINDE]');
            extracteerJSON(body, url);
            extracteerXML(body, url);
            logBase64(body, url);
            markeerBekend(body, url);
        }

        $done({});

    } catch(e) {
        console.log('[FOUT] request: ' + e);
        try { $done({}); } catch(e2) {}
    }

} else {
    console.log('[F] Geen proxy-context.');
    try { $done({}); } catch(e) {}
}

})();
