# Kapitel 7 Security Architecture - Strukturvorschlag

Status: Empfehlung, nicht implementiert.
Scope: `docs/security/threat-model.md`, Kapitel 7 `Security Architecture`.
Ziel: Kapitel 7 konsistenter, finding-zentrierter und besser scannbar darstellen, ohne Finding-IDs oder Berichtsinhalte bereits umzubauen.

## 1. Ausgangspunkt

Die aktuelle Darstellung in Kapitel 7 wirkt an mehreren Stellen inkonsistent:

- `7.4 Authorization` leitet Findings explizit aus schwachen oder fehlenden Controls ab, waehrend `7.5 Input Validation` die Findings zwar im Fliesstext nennt, sie aber nicht pro Missing Control in der Control-Tabelle ableitet oder verlinkt.
- Mehrere `Where it falls short`-Abschnitte sind lange Fliesstexte. Das erschwert Review, QA und Traceability zu konkreten Codepfaden.
- `7.5 Input Validation` vermischt Query Construction, SQL/NoSQL Injection, Output Encoding, XSS-Rendering und teilweise nicht passende Implementationstexte.
- Einige Finding-Gruppen werden als Range dargestellt, obwohl sie unterschiedliche Ursachen haben. Beispiel: `F-016` bis `F-021` sind nicht einheitlich XSS-Bypass-Findings; `F-019` betrifft Token-/Storage-Exposure und `F-020` fehlende CSP.
- `7.8 Real-time Communication / WebSocket` sagt sinngemaess, dass kein WebSocket-Stack vorhanden sei. Lokal ist aber Socket.IO registriert. Wenn daraus kein Finding abgeleitet wird, muss die Sektion das sauber sagen.
- `7.12 Dependency & Supply Chain` ist zu leer, obwohl mindestens `F-014` (`express-jwt`) und `F-003` (`notevil`) dependency-relevant sind und Parser-/File-Handling-Befunde die Library-Nutzung beruehren.

## 2. Leitprinzipien fuer die Ueberarbeitung

- Controls und Findings bleiben getrennte Konzepte: Ein Control beschreibt erwartetes Sicherheitsverhalten, ein Finding beschreibt eine konkrete Abweichung mit Evidenz.
- Jede Weak-, Missing- oder Partial-Control-Bewertung muss ihre verknuepften Findings sichtbar machen.
- Ein Finding bekommt genau einen primaeren Abschnitt. Cross-References sind erlaubt, aber keine doppelten Hauptdarstellungen.
- Query Construction ist keine allgemeine Input Validation. SQL/NoSQL Injection gehoert primaer zu sicherer Query-Erzeugung, Parameterbindung, ORM-Nutzung, Operator-Allowlisting und Typisierung.
- Output Encoding und Client-Side Rendering werden von Input Boundary Validation getrennt. XSS entsteht nicht nur durch fehlende Eingabevalidierung, sondern oft durch unsichere Ausgabe- oder Rendering-Sinks.
- Browser Security Headers und CORS sind eigene Architekturthemen. Sie sollten nicht unter Container Runtime oder XSS-Root-Cause einsortiert werden.
- Keine Finding-Ranges ueber gemischte Ursachen hinweg. Wenn drei oder mehr Findings referenziert werden, sollten sie als Bullet-Liste oder Tabelle erscheinen.
- Jeder lange Absatz wird in pruefbare Aussagen zerlegt. Als QA-Regel sollte ein Absatz ab ca. 90 Woertern oder ab drei aufgelisteten Befunden auffallen.

## 3. Empfohlene Kapitelstruktur

Die folgende Struktur orientiert sich an gaengigen Kategorien aus OWASP Top 10, OWASP ASVS 5.0 und OWASP API Security Top 10, bleibt aber auf die beobachteten Juice-Shop-Befunde zugeschnitten.

| Abschnitt | Kategorie | Zweck |
| --- | --- | --- |
| 7.1 | Control Summary | Kurze Matrix aus Kategorie, Control-Status, Finding-Links und Severity-Maximum. |
| 7.2 | Key Architectural Risks | Verdichtete Top-Risiken, keine langen Detailtexte. |
| 7.3 | Authentication | Login-, Token-Ausstellung, Reauth und sensible Aktionen. |
| 7.4 | Session Management & Token Handling | Token-Storage, JWT-Validierung, Token-Lebensdauer, Secrets. |
| 7.5 | Authorization & Object-Level Access Control | Route Guards, Rollen, Objektbesitz, IDOR/BOLA. |
| 7.6 | Query Construction & Injection Prevention | SQL/NoSQL Injection, ORM-Nutzung, Parameterbindung, Operator-Kontrolle. |
| 7.7 | Input Boundary Validation & Business Rules | Typisierung, Allowlisting, Business-Regeln, Dateitypen, Request-Grenzen. |
| 7.8 | Output Encoding & Client-Side Rendering | XSS-Sinks, Angular Sanitization Bypasses, HTML Rendering, Template-Kontexte. |
| 7.9 | Browser Security Headers & Cross-Origin Policy | CSP, CORS, Helmet, HSTS, clickjacking-relevante Header. |
| 7.10 | Cryptography & Secret Management | Schluessel, Token-Signing-Secrets, Hashing-Primitives, Secret Exposure. |
| 7.11 | Password Storage & Credential Lifecycle | Passwort-Hashing, Reset, Change Password, Reauth fuer sensible Aenderungen. |
| 7.12 | File Processing & Parser Security | Uploads, Archive, XML Parser, Zip Slip, XXE, MIME/Extension-Kontrollen. |
| 7.13 | Unsafe Code Execution & Interpreter Boundaries | `eval`, VM-Sandboxing, Template-/Expression-Evaluation. |
| 7.14 | Outbound Request Controls / SSRF | Server-side Fetches, URL-Allowlisting, Netzsegment-Blocklisten, Redirects. |
| 7.15 | Sensitive File & Management Surface Exposure | Public static dirs, logs, keys, metrics, debug/error endpoints. |
| 7.16 | Logging, Monitoring & Error Handling | Audit-Events, Security Monitoring, Fehlerantworten, Log-Schutz. |
| 7.17 | Dependency & Supply Chain | Verwundbare Libraries, transitive Risiken, Lockfile-/SBOM-Traceability. |
| 7.18 | Runtime & Container Hardening | Prozessrechte, Container-User, Environment, Deployment Defaults. |
| 7.19 | Real-time / WebSocket | Socket.IO, AuthN/AuthZ auf Events, Origin Policy, Event Abuse. |
| 7.20 | Nicht anwendbare Domaenen | AI/LLM und andere Domaenen nur dann als N/A fuehren, wenn Recon/YAML keine Nutzung zeigen; kompakt statt als eigene Textwueste. |
| 7.21 | Defense-in-Depth Assessment | Zusammenfassung uebergreifender Controls und Restrisiken. |

## 4. Konkrete Kategorie-Korrekturen

| Thema | Empfehlung |
| --- | --- |
| `F-015` | Nicht als Injection einordnen. Primaer `Authentication` oder `Password Storage & Credential Lifecycle`, weil es um fehlende Reauth beim Passwortwechsel geht. |
| `F-010` | Nicht als XSS fuehren. Primaer `Browser Security Headers & Cross-Origin Policy` beziehungsweise Security Misconfiguration, weil Wildcard-CORS ein Cross-Origin-Policy-Problem ist. |
| `F-020` | Nicht als XSS-Root-Cause darstellen. Fehlende CSP ist Defense-in-Depth und gehoert zu Browser Security Headers. |
| `F-019` | Nicht in eine XSS-Bypass-Range aufnehmen. Es betrifft Token-/Client-Storage-Exposure und gehoert zu Session Management & Token Handling. |
| `F-011` | Nicht als schlichtes `Missing Audit Logging` formulieren, wenn Logging existiert. Praeziser ist Public Log Exposure oder Management Surface Exposure. |
| `7.8 WebSocket` | Nicht als nicht vorhanden beschreiben. Korrekt: Socket.IO ist vorhanden; wenn kein Finding gemappt ist, wurde kein konkreter WebSocket-Befund abgeleitet. |
| `7.12 Dependency & Supply Chain` | Nicht leer lassen, aber praezise trennen: `express-jwt`/`jsonwebtoken` und `notevil` sind dependency-relevant; `libxmljs2`/`unzipper` gehoeren primaer zu Parser- und File-Handling, solange kein eigener Dependency-Befund gemappt ist; `sanitize-html` ist im aktuellen Threat Model nicht als Finding gemappt. |
| HTTP Security Headers | Aus `Container & Runtime` herausloesen und in `Browser Security Headers & Cross-Origin Policy` fuehren. |
| Cookie Secret | Wenn als Risiko beschrieben, entweder mit eigenem Finding/Evidenz versehen oder aus dem Finding-aehnlichen Fliesstext entfernen. |
| AI / LLM | Die bestehende N/A-Aussage sollte erhalten bleiben, aber in eine kompakte Sammelsektion fuer nicht anwendbare Domaenen wandern, solange Recon/YAML keine Nutzung zeigen. |

## 5. Rendering-Regel fuer Findings

Jedes Finding sollte in Kapitel 7 nach demselben Muster dargestellt werden:

````text
#### F-NNN - <kurzer Finding-Titel>

Category: <primaere Kategorie>
Control: <betroffenes Control>
Severity: <Critical|High|Medium|Low>
Mapped standards: <OWASP/ASVS/API/CWE Referenzen>

Summary:
<2-4 Saetze, keine Root-Cause-Mischung>

Evidence:
- <file:line> <kurze Aussage>
- <file:line> <kurze Aussage>

Code excerpt:
```typescript
<kurzer, relevanter Ausschnitt>
```

Why the current control falls short:
- <konkrete Abweichung>
- <konkrete Abweichung>
- <konkrete Abweichung>

Expected control behavior:
<kurze Beschreibung oder optionaler Pseudocode>

Impact:
<konkrete Angriffsfolge>

Recommended remediation:
- <primaere technische Aenderung>
- <Test-/QA-Ergaenzung>
````

Regeln dazu:

- Keine Evidence-Snippets ohne Dateipfad und Zeilenreferenz.
- Kein Absatz ueber ca. 90 Woerter.
- Bei drei oder mehr Ursachen, Dateien oder Findings immer Bullets oder Tabellen verwenden.
- Ein Finding darf mehrere Standards mappen, aber nur eine primaere Berichtskategorie haben.
- `Implementation` darf nur Code oder Verhalten erklaeren, das tatsaechlich zur Kategorie und zum Finding gehoert.

## 6. Beispielhafte Darstellung eines Findings

#### F-008 - IDOR in Basket Access

Category: Authorization & Object-Level Access Control  
Control: Object ownership enforcement  
Severity: High  
Mapped standards: OWASP Top 10 A01 Broken Access Control; OWASP API1:2023 Broken Object Level Authorization; CWE-639

Summary:
`GET /rest/basket/:id` ist zwar durch JWT-Authentifizierung geschuetzt, prueft aber nicht, ob der angeforderte Basket dem authentifizierten Benutzer gehoert. Damit ist Route-Level-Authorization vorhanden, Object-Level-Authorization fehlt aber an der Datenzugriffsgrenze.

Evidence:

- `server.ts:355` registriert `security.isAuthorized()` und `security.appendUserId()` fuer `/rest/basket`.
- `server.ts:601` routet `GET /rest/basket/:id` auf `retrieveBasket()`.
- `routes/basket.ts:18` selektiert den Basket nur ueber `req.params.id`.
- `routes/basket.ts:21-23` erkennt fremde Basket-IDs fuer die Challenge, blockiert die Antwort aber nicht.
- In `routes/basket.ts` ist keine Ownership-Enforcement-Pruefung gegen den authentifizierten Benutzer erkennbar.

Code excerpt:

```typescript
// server.ts
app.use('/rest/basket', security.isAuthorized(), security.appendUserId())
app.get('/rest/basket/:id', retrieveBasket())
```

```typescript
// routes/basket.ts
const id = req.params.id
const basket = await BasketModel.findOne({
  where: { id },
  include: [{ model: ProductModel, paranoid: false, as: 'Products' }]
})

challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
  const user = security.authenticatedUsers.from(req)
  return user && id && id !== 'undefined' && id !== 'null' && id !== 'NaN' && user.bid && user?.bid != parseInt(id, 10)
})

res.json(utils.queryResultToJson(basket))
```

Why the current control falls short:

- `security.isAuthorized()` bestaetigt nur, dass ein gueltiger Benutzerkontext existiert.
- Die Objekt-ID kommt direkt aus dem URL-Pfad und wird fuer die Datenbankabfrage genutzt.
- Die Abfrage enthaelt keine Bedingung auf den Besitzer des Basket-Objekts.
- Die Challenge-Erkennung in `routes/basket.ts:21-23` wertet Fremdzugriffe aus, erzwingt aber kein `403` oder `404`.
- Ein gueltig authentifizierter Benutzer kann dadurch fremde Basket-IDs testen und abrufen.

Expected control behavior:

```typescript
const user = security.authenticatedUsers.from(req)
const basket = await BasketModel.findOne({ where: { id: req.params.id } })

if (!basket || basket.UserId !== user.data.id) {
  return res.status(403).end()
}
```

Impact:
Ein Angreifer mit eigenem Konto kann Basket-IDs anderer Benutzer abrufen, wenn er deren IDs kennt oder erraten kann. Das verletzt Mandantentrennung und ist ein klassischer BOLA/IDOR-Fall.

Recommended remediation:

- Object ownership in der Query selbst oder unmittelbar nach dem Fetch erzwingen.
- Fuer nicht gefundene und nicht autorisierte Objekte ein konsistentes Fehlerverhalten definieren.
- API-Tests ergaenzen: eigener Basket erlaubt, fremder Basket verboten, nicht existierender Basket konsistent behandelt.
- QA-Regel ergaenzen: Jede Route mit `/:id` und AuthN muss auf Object-Level-Authorization geprueft werden.

## 7. QA-Agent-Regeln

Der QA-Agent sollte neben formalen Berichtskriterien auch Lesbarkeit, Mapping und semantische Konsistenz pruefen:

- Flagge Abschnitte, wenn ein Absatz laenger als ca. 90 Woerter ist.
- Flagge `Where it falls short`, wenn darin drei oder mehr Findings, Ursachen oder Codepfade als Fliesstext stehen.
- Verlange sichtbare `Linked Findings` fuer jedes Control mit Status `Missing`, `Weak` oder `Partial`.
- Pruefe, dass `security_controls[].linked_threats` aus YAML im Markdown sichtbar werden.
- Verbiete Finding-Ranges, wenn die Findings verschiedenen primaeren Kategorien angehoeren.
- Flagge Aussagen wie `No dedicated control cataloged`, wenn dieselbe Kategorie an anderer Stelle ein Control oder eine Route-Guard-Implementierung beschreibt.
- Pruefe `not applicable`-Aussagen gegen Recon-Inventar, zum Beispiel WebSocket/Socket.IO.
- Verlange fuer High/Critical Findings mindestens eine konkrete Code-Evidenz mit Datei und Zeile.
- Pruefe zusaetzlich, dass Datei:Zeile den erwarteten Codeausdruck trifft; veraltete Line-Nums muessen fehlschlagen.
- Pruefe Kategorie-Mapping gegen OWASP Top 10, OWASP ASVS und OWASP API Security Top 10.
- Stelle sicher, dass dependency-getriebene Findings auch in `Dependency & Supply Chain` referenziert werden.

## 8. Referenzrahmen

Die Struktur sollte gegen diese gaengigen Kategorien abgeglichen werden:

- OWASP Top 10:2021: `https://owasp.org/Top10/`
- OWASP Top 10:2025: `https://owasp.org/Top10/2025/` nur als bewusstes Migrationsziel; das aktuelle Threat Model referenziert `Axx:2021`.
- OWASP ASVS 5.0 Taxonomy: `https://cornucopia.owasp.org/taxonomy/asvs-5.0`
- OWASP API Security Top 10 2023: `https://owasp.org/www-project-api-security/`

Lokal verifizierte Evidenzquellen fuer die oben genannten Empfehlungen:

- `docs/security/threat-model.md`
- `docs/security/threat-model.yaml`
- `server.ts`
- `routes/basket.ts`
- `routes/changePassword.ts`
- `routes/fileUpload.ts`
- `routes/profileImageUrlUpload.ts`
- `routes/userProfile.ts`
- `routes/b2bOrder.ts`
- `lib/startup/registerWebsocketEvents.ts`
- `frontend/src/app/search-result/search-result.component.ts`
- `frontend/src/app/administration/administration.component.ts`
- `frontend/src/app/last-login-ip/last-login-ip.component.ts`
- `frontend/src/app/login/login.component.ts`
- `frontend/src/app/Services/request.interceptor.ts`

## 9. Nicht-Ziele

- Keine direkte Aenderung an `docs/security/threat-model.md`.
- Keine Aenderung an YAML-Schema, Templates, Renderer oder Tests.
- Keine Umnummerierung bestehender Findings.
- Keine neue Sicherheitsbewertung ohne zusaetzliche Code-Evidenz.

