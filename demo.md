# Akteurs-Visualisierung in `threat-model.md` — Übertragung von `actor.md`

Anwendung der Empfehlungen aus `/home/mrohr/actor.md` auf die Mermaid-Diagramme, die der `appsec-advisor:create-threat-model` Skill für OWASP Juice Shop erzeugt hat.

> Quelle der Originale: `/home/mrohr/juice-shop/docs/security/threat-model.md` (Stand: 2026-05-03, --quick run).

## 1. Verdict — passen die Empfehlungen?

**Ja, fast alle.** Die Vorschläge aus `actor.md` lassen sich mit minimalem Aufwand auf das bestehende Modell übertragen, weil der Generator bereits sauber strukturierte Mermaid-Quellen produziert (klare Subgraphs für Trust-Zonen, getrennte `classDef` für Akteurskategorien, dashed-vs-solid-Konvention für Konsequenz- vs. Datenfluss-Pfeile). Was fehlt, ist primär die **Icon-Schicht** und ein konsequent **gedämpftes Farbset**.

| Empfehlung aus `actor.md` | Anwendbar im aktuellen Modell? | Aufwand im Generator |
|---|:---:|---|
| **A.1** FontAwesome (`fa:`) in Knoten-Labels | ✅ direkt anwendbar in jedem `flowchart`/`graph`/`sequenceDiagram` | Klein — Label-Erzeugung in `compose_threat_model.py` + Pre-Generator anpassen |
| **A.2** `architecture-beta` + Iconify | ⚠️ nur sinnvoll für §2.1–2.4 (C4-Layer); würde Heatmap-Layout brechen | Groß — eigener Renderer-Pfad, GitHub-Render-Risiko |
| **A.3** Image-Nodes mit Corporate-SVG | ⚠️ nur in Pipelines mit hosted assets | Mittel — neue Asset-CDN-Konfig nötig |
| **A.4** Inline-SVG / HTML-Labels | ❌ scheitert an `securityLevel: strict` der QA-Pipeline + GitHub-Renderer | — |
| **B.** Trust-Zonen-Subgraphs + Icons + gedämpfte Farben | ✅ Heatmap und §2.3 Components verwenden bereits Subgraphs | Klein — nur Farb- und Icon-Patches |
| **C.** `actor` mit `fa:`-Präfix in `sequenceDiagram` | ✅ direkt anwendbar in §3 Walkthroughs (7×) und §7.3 Auth-Flows (2×) | Klein — Prompt-Update für Phase-11-Walkthroughs |
| **D.1** Form-Codierung (Stadium/Trapez/Hexagon) | ✅ Heatmap nutzt bereits `(["..."])` Stadium für Akteure und `[["..."]]` Subroutine für Impact | Bereits weitgehend umgesetzt |
| **D.2** STRIDE-Tag am Akteursknoten | ✅ kann ohne Diagramm-Umbau ergänzt werden | Klein — Akteur-Label-Template erweitern |
| **D.3** Skill-Level-Tiering der Angreifer | ⚠️ erfordert neue Daten in `posture-actor-labels.yaml` | Mittel — Taxonomie-Erweiterung |

**Wichtigster Layout-Konflikt:** Die Security-Posture-Heatmap nutzt `defaultRenderer: elk` mit unsichtbaren Alignment-Edges, um die drei Spalten-Header auf einer Y-Linie zu halten. `architecture-beta` (A.2) hat ein eigenes Layout-Modell und würde diesen Effekt zerstören. Die Heatmap muss bei `flowchart LR` bleiben — Icons werden also über den `fa:`-Präfix in den Knoten-Labels eingeführt, nicht über A.2.

**Was der Generator heute schon richtig macht:**
- Trust-Zone-Subgraphs (Heatmap: ACTORS/TIERS/IMPACT; §2.3: Client/Application/Data)
- Getrennte `classDef` pro Akteurskategorie (`actorAnon`, `actorShopUser`)
- Dashed Pfeile (`-.->`) ausschließlich für Konsequenz-Edges (Tier → Impact)
- Solid Pfeile (`==>`) für Angriffspfade — leicht abweichend von `actor.md` (dort: dashed = Angriff)

**Was fehlt:**
- Keine Icons in Akteurs-Knoten — Akteur-Typ wird nur über Farbe codiert, was bei Schwarz-Weiß-Druck/PDF verschwindet
- Farben sind teils zu plakativ (`#fca5a5` Pastellrot für Anon-Attacker, sehr hell)
- Konvention "dashed = Angriff" (`actor.md` G.) ist invertiert — Generator nutzt solid für Angriff
- Keine STRIDE-Codierung am Knoten

---

## 2. Demo: Security Posture Heatmap

Die Heatmap ist **strukturell byte-identisch** zum Original aus [`docs/security/threat-model.md:106`](docs/security/threat-model.md) (Knoten-IDs, Subgraph-Struktur, Alignment-Edges, Pfeile, `linkStyle`-Indizes, Reihenfolge der Statements). Geändert wurden ausschließlich:

1. **Akteur-Labels**: `fa:fa-user-secret` für die drei Angreifer, `fa:fa-user` für den legitimen Shop User
2. **Tier-Labels**: `fa:fa-window-restore` Client · `fa:fa-server` Application · `fa:fa-database` Data
3. **Farb-`classDef`-Werte**: gedämpfte Audit-Palette aus `actor.md` §B (`#fca5a5` Pastellrot → `#f3dada`; `#93c5fd` Pastellblau → `#e8f1ea`; Tier-`fill` `#f9fafb` → einheitliches Neutral-Grau `#f2f2f2`)

```mermaid
%%{init: {"flowchart": {"defaultRenderer": "elk", "nodeSpacing": 40, "rankSpacing": 80}} }%%
flowchart LR
    subgraph ACTORS[" "]
        direction TB
        HDR_A["<b>Threat Actors</b>"]:::columnHeader
        SHOPUSER(["fa:fa-user <b>Shop User</b><br/><i>legitimate customer; victim of XSS / CSRF</i>"]):::actorShopUser
        ANON(["fa:fa-user-secret <b>Anonymous Internet Attacker</b><br/><i>no account; registers in seconds when needed</i>"]):::actorAnon
        INTERNET_USER(["fa:fa-user-secret <b>Authenticated Internet Attacker</b><br/><i>owns a regular account; logged in</i>"]):::actorAnon
        REPO_READ(["fa:fa-user-secret <b>Repository Reader</b><br/><i>anyone with read access to the source repository</i>"]):::actorAnon
    end

    subgraph TIERS[" "]
        direction TB
        HDR_T["<b>Architecture Tiers</b>"]:::columnHeader
        BROWSER["fa:fa-window-restore <b>Client Tier</b><br/>⚠ bypassSecurityTrustHtml in 4 Angular components bypasses DOM sanitization · JWT stored in localStorage — accessible to any XSS on the domain · Client-side route guards not backed by server-side authorization<br/><b>angular-spa</b><br/>🔴 1 Critical · 🟠 4 High · 🟡 1 Medium"]:::tierClient
        SERVER["fa:fa-server <b>Application Tier</b><br/>⚠ Raw SQL string interpolation in login and search routes · RSA private key and HMAC secret hardcoded in lib/insecurity.ts · eval() execution on user-controlled input in username and captcha routes · XXE enabled via noent:true in libxmljs2 XML parsing · CORS wildcard allows all cross-origin requests<br/><b>express-backend</b><br/>🔴 5 Critical · 🟠 4 High · 🟡 3 Medium"]:::tierApp
        DATA["fa:fa-database <b>Data Tier</b><br/>⚠ MD5 password hashing — no salt, trivially crackable · MongoDB $where expression injection in order tracking · Sensitive files (KeePass, keys, logs) served without authentication<br/><b>data-layer</b><br/>🔴 1 Critical · 🟠 2 High · 🟡 2 Medium"]:::tierData
    end

    subgraph IMPACT[" "]
        direction TB
        HDR_I["<b>Impact</b>"]:::columnHeader
        CUSTOMER_SESSION_HIJACK[["🟠 <b>Customer Session Hijack</b>"]]:::impact
        FULL_ADMIN_TAKEOVER[["🔴 <b>Full Admin Takeover</b>"]]:::impact
        FULL_SERVER_COMPROMISE[["🔴 <b>Full Server Compromise</b>"]]:::impact
        CUSTOMER_DATA_EXFILTRATION[["🔴 <b>Customer Data Exfiltration</b>"]]:::impact
    end

    %% Invisible alignment hints. Two purposes:
    %%   (a) keep the per-component alignment edges (e.g. SHOPUSER --- BROWSER,
    %%       ANON --- SERVER) so attack arrows route horizontally without
    %%       crossing tier boxes;
    %%   (b) chain the three column headers (HDR_A, HDR_T, HDR_I) across
    %%       subgraph boundaries so ELK pins them on the same Y line.
    HDR_A --- HDR_T
    HDR_T --- HDR_I
    SHOPUSER --- BROWSER
    ANON --- SERVER

    %% Attack arrows
    ANON ==>|" ① Injection "| DATA
    ANON ==>|" ② Auth Bypass "| SERVER
    INTERNET_USER ==>|" ③ RCE "| SERVER
    REPO_READ ==>|" ④ Data Exposure "| DATA
    BROWSER ==>|" ⑤ XSS "| SHOPUSER
    INTERNET_USER ==>|" ⑥ Privilege Escalation "| SERVER

    %% Consequence arrows (tier → business impact, all LR-forward)
    DATA -.-> FULL_ADMIN_TAKEOVER
    DATA -.-> CUSTOMER_DATA_EXFILTRATION
    SERVER -.-> FULL_ADMIN_TAKEOVER
    SERVER -.-> FULL_SERVER_COMPROMISE
    BROWSER -.-> CUSTOMER_SESSION_HIJACK
    BROWSER -.-> FULL_ADMIN_TAKEOVER

    %% Subgraph frames invisible — column headers are emitted as the
    %% FIRST node of each subgraph (HDR_A / HDR_T / HDR_I) and pinned
    %% on the same Y line by the cross-subgraph alignment edges above.
    style ACTORS fill:none,stroke:none
    style TIERS  fill:none,stroke:none
    style IMPACT fill:none,stroke:none

    classDef tierClient fill:#f2f2f2,stroke:#424242,color:#111,stroke-width:2px,font-size:12px
    classDef tierApp    fill:#f2f2f2,stroke:#424242,color:#111,stroke-width:2px,font-size:12px
    classDef tierData   fill:#f2f2f2,stroke:#424242,color:#111,stroke-width:2px,font-size:12px

    classDef actorAnon     fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px,font-size:12px
    classDef actorShopUser fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:2px,font-size:12px
    classDef impact        fill:#0f172a,stroke:#000,color:#fff,stroke-width:3px,font-size:12px

    classDef columnHeader  fill:none,stroke:none,color:#111,font-size:14px

    linkStyle 0,1,2,3     stroke:transparent,stroke-width:0px
    linkStyle 4,5,6,7,8,9     stroke:#b71c1c,stroke-width:3px
    linkStyle 10,11,12,13,14,15     stroke:#6b7280,stroke-width:1.5px,stroke-dasharray:4
```

**Was sich gegenüber dem Original geändert hat — das vollständige Diff:**

| Element | Original | Neu (`actor.md`) |
|---|---|---|
| Akteur-Label `SHOPUSER` | `<b>Shop User</b><br/>…` | `fa:fa-user <b>Shop User</b><br/>…` |
| Akteur-Label `ANON` | `<b>Anonymous Internet Attacker</b><br/>…` | `fa:fa-user-secret <b>Anonymous Internet Attacker</b><br/>…` |
| Akteur-Label `INTERNET_USER` | `<b>Authenticated Internet Attacker</b><br/>…` | `fa:fa-user-secret <b>Authenticated Internet Attacker</b><br/>…` |
| Akteur-Label `REPO_READ` | `<b>Repository Reader</b><br/>…` | `fa:fa-user-secret <b>Repository Reader</b><br/>…` |
| Tier-Label `BROWSER` | `<b>Client Tier</b><br/>…` | `fa:fa-window-restore <b>Client Tier</b><br/>…` |
| Tier-Label `SERVER` | `<b>Application Tier</b><br/>…` | `fa:fa-server <b>Application Tier</b><br/>…` |
| Tier-Label `DATA` | `<b>Data Tier</b><br/>…` | `fa:fa-database <b>Data Tier</b><br/>…` |
| `classDef tierClient` `fill` | `#f9fafb` (sehr helles Grau-Weiß) | `#f2f2f2` (Audit-Neutral) |
| `classDef tierClient` `stroke` | `#9a3412` (Pastell-Orange-Rot) | `#424242` (gedämpftes Anthrazit) |
| `classDef tierApp/tierData` `stroke` | `#991b1b` (Pastell-Rot) | `#424242` (gedämpftes Anthrazit) |
| `classDef actorAnon` `fill` | `#fca5a5` (Pastell-Rot) | `#f3dada` (Audit-Rot, gedämpft) |
| `classDef actorAnon` `color` | `#111` | `#7f0000` (gedämpftes Tiefrot, Konsistenz mit Stroke) |
| `classDef actorShopUser` `fill` | `#93c5fd` (Pastell-Blau) | `#e8f1ea` (Audit-Grün — legitim) |
| `classDef actorShopUser` `stroke` | `#1e40af` (Marine-Blau) | `#2e7d32` (Audit-Grün, dunkel) |
| `classDef actorShopUser` `color` | `#111` | `#1b5e20` (Konsistenz mit Stroke) |
| `linkStyle 4–9` Pfeil-Stroke | `#b91c1c` | `#b71c1c` (Audit-Rot aus `actor.md` §G) |
| Alle übrigen Zeilen (IDs, Subgraphs, Edges, Styles, linkStyle-Indizes, Comments) | — | **unverändert** |

Die Konsequenz: Layout und Edge-Routing sind bit-identisch zum Generator-Output, nur Akteur-Erkennbarkeit und Farb-Politur folgen jetzt `actor.md`. Pfeil-Konvention bleibt `==>` für Angriff (Generator-Default) — das hält den Patch rückwärts-kompatibel zum Architect-Reviewer-Prompt.

---

## 3. Demo: §2.3 Components Diagram

**Original** (`threat-model.md:449`):

```mermaid
graph TD
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px

    subgraph CLIENT["Client Tier"]
        C02["C-02 Angular SPA Frontend<br/>DOM rendering · route guards<br/>auth state · XSS surface<br/>6 threats"]:::risk
    end
    subgraph APPLICATION["Application Tier"]
        C01["C-01 Express Backend API<br/>Route handlers · auth middleware<br/>business logic · file serving<br/>12 threats"]:::risk
    end
    subgraph DATATIER["Data Tier"]
        C03["C-03 Data Layer<br/>SQLite + Sequelize ORM<br/>MarsDB in-memory<br/>5 threats"]:::risk
    end

    C02 -->|"REST API · JWT Bearer"| C01
    C01 -->|"ORM + raw SQL"| C03
```

**Verbessert nach `actor.md` A.1 + B** — Tech-Icons + erweiterte Trust-Zonen mit externem Akteur-Kontext, damit das Diagramm nicht losgelöst von §2.1 wirkt:

```mermaid
flowchart TD
    subgraph EXT["Untrusted Zone — Internet"]
        ANON["fa:fa-user-secret Anonymous Attacker"]:::threat
        SHOPUSER["fa:fa-user Shop User"]:::legit
        REPO["fa:fa-code-branch Public GitHub Repo<br/>(read access for everyone)"]:::external
    end

    subgraph CLIENT["Client Tier — Browser Sandbox"]
        C02["fa:fa-window-restore <b>C-02 Angular SPA Frontend</b><br/>DOM rendering · route guards<br/>auth state · XSS surface<br/><b>6 threats</b>"]:::risk
    end

    subgraph APP["Application Tier — Node.js Server"]
        C01["fa:fa-server <b>C-01 Express Backend API</b><br/>route handlers · auth middleware<br/>business logic · file serving<br/><b>12 threats</b>"]:::risk
    end

    subgraph DATA["Data Tier — In-Process"]
        C03[("fa:fa-database <b>C-03 Data Layer</b><br/>SQLite + Sequelize ORM<br/>MarsDB in-memory<br/><b>5 threats</b>")]:::risk
    end

    %% legitime Datenflüsse (durchgezogen)
    SHOPUSER -->|"HTTPS · TLS"| C02
    C02 -->|"REST · JWT Bearer"| C01
    C01 -->|"ORM (parameterized + raw SQL)"| C03

    %% Angriffspfade (gestrichelt)
    ANON  -.->|"alg:none / SQLi / RCE"| C01
    ANON  -.->|"unauth /ftp /encryptionkeys /logs"| C01
    REPO  -.->|"clone → extract RSA private key"| ANON

    classDef legit    fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    classDef threat   fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px
    classDef external fill:#f2f2f2,stroke:#424242,color:#212121,stroke-width:1.5px
    classDef risk     fill:#fef2f2,stroke:#991b1b,color:#111,stroke-width:2.5px

    linkStyle 0,1,2 stroke:#2e7d32,stroke-width:1.5px
    linkStyle 3,4,5 stroke:#b71c1c,stroke-width:2.5px,stroke-dasharray:6 4
```

**Was sich ändert:**
- Externe Trust-Zone explizit dargestellt (Anon-Attacker, Shop-User, Public-Repo) — die §2.3 wird ohne Quersprung zu §2.1 verständlich.
- Public-Repo-Link als Eingangsvektor (`actor.md` D.3 / "Supply-Chain") explizit modelliert — relevant für Juice-Shop, weil RSA-Key dort liegt.
- Komponenten-Form-Codierung verfeinert: Datenbank als Zylinder `[(...)]` (`actor.md` D.1), übrige Komponenten als Rechteck.
- Pinkes Pastell (`#FFB6C1`) ersetzt durch gedämpftes Rot/Hintergrund-Weiß (`#fef2f2`/`#991b1b`).

---

## 4. Demo: §3.X Attack-Walkthrough — `sequenceDiagram` mit `actor`

**Original** (`threat-model.md:633`, Walkthrough für T-001 alg:none Bypass):

```mermaid
sequenceDiagram
    autonumber
    participant ATK as Attacker
    participant API as Express API
    participant MW as express-jwt 0.1.3

    ATK->>API: GET /rest/admin/application-version (unauthenticated probe)
    API-->>ATK: 401 Unauthorized
    Note over ATK: Craft forged JWT — header=alg:none payload=role:admin signature=empty
    ATK->>API: GET /rest/admin/application-version Authorization=Bearer forged.token.

    alt Current state — T-001
        MW->>MW: expressJwt sees alg=none, skips signature verification
        MW-->>API: decoded token accepted (role=admin)
        API-->>ATK: 200 admin data returned
    else After M-001 — upgrade jsonwebtoken and explicit algorithm whitelist
        MW->>MW: algorithms RS256 only, alg:none rejected with 401
        API-->>ATK: 401 UnauthorizedError: invalid algorithm
    end
```

**Verbessert nach `actor.md` C** — Attacker als `actor` mit `fa:fa-user-secret` (semantisch unterschieden vom `participant`-System), legitimer Vergleichs-User für Kontrast, gedämpfte `Note`:

```mermaid
sequenceDiagram
    autonumber
    actor ATK as fa:fa-user-secret Anonymous Attacker
    actor USR as fa:fa-user Legitimate Customer
    participant API as fa:fa-server Express API
    participant MW  as fa:fa-shield-halved express-jwt 0.1.3
    participant DB  as fa:fa-database SQLite Users

    rect rgba(232, 241, 234, 0.5)
        Note over USR,DB: Legitimate flow — for contrast
        USR->>API: POST /rest/user/login email + password
        API->>DB: SELECT user
        DB-->>API: row(role=customer)
        API-->>USR: 200 valid signed JWT (RS256, 6h)
    end

    rect rgba(243, 218, 218, 0.5)
        Note over ATK,API: Threat scenario — T-001 alg:none bypass
        ATK->>API: GET /rest/admin/application-version (unauth probe)
        API-->>ATK: 401 Unauthorized
        Note over ATK: Forge JWT — header=alg:none payload=role:admin signature=∅
        ATK->>API: GET /rest/admin/... Authorization=Bearer forged.token.

        alt Current state — T-001
            MW->>MW: alg=none recognized · signature step skipped
            MW-->>API: decoded payload trusted (role=admin)
            API-->>ATK: 200 admin data
        else After M-001 — algorithms ['RS256'] whitelist
            MW->>MW: alg=none rejected
            API-->>ATK: 401 UnauthorizedError: invalid algorithm
        end
    end
```

**Was sich ändert:**
- `actor` (statt `participant`) macht ATK und USR im Diagramm als **Strichmännchen** sichtbar — Audit-Leser unterscheidet Mensch von System sofort.
- `fa:fa-user-secret` vs. `fa:fa-user` codiert Angreifer-vs.-legitim **innerhalb des Akteur-Symbols** — bleibt auch im S/W-Druck lesbar.
- `fa:fa-shield-halved` für die Auth-Middleware deutet ihre Schutzfunktion an — und macht damit den Defekt (`alg:none` schlüpft durch) visuell stärker.
- Optionaler **legitimer Reference-Flow** in einem grünen `rect` als Vergleich zum roten `rect` mit dem Angriff — entspricht der Audit-Erwartung "zeig mir das Soll, dann das Ist".

---

## 5. Demo: §7.3 IAM Auth-Flow

Im Original (`threat-model.md:932`) ist die Auth-Flow-Sequenz noch reiner `participant`-Diagramm-Stil. Hier die `actor.md`-Variante:

```mermaid
sequenceDiagram
    autonumber
    actor USR as fa:fa-user Customer
    actor ATK as fa:fa-user-secret Attacker
    participant SPA as fa:fa-window-restore Angular SPA
    participant API as fa:fa-server Express Backend
    participant MW  as fa:fa-shield-halved express-jwt + insecurity.ts
    participant DB  as fa:fa-database SQLite Users

    rect rgba(232, 241, 234, 0.5)
        USR->>SPA: enter email + password
        SPA->>API: POST /rest/user/login
        API->>DB: SELECT * WHERE email=? AND password=md5(?)
        DB-->>API: user row (id=42 role=customer)
        API->>MW: jwt.sign(payload, RS256 privateKey, exp=6h)
        Note right of MW: privateKey hardcoded · lib/insecurity.ts:22
        MW-->>API: signed JWT
        API-->>SPA: 200 {authentication: token}
        SPA-->>USR: dashboard + token in localStorage
    end

    rect rgba(243, 218, 218, 0.5)
        Note over ATK,DB: Attack — T-001 alg:none + T-002 hardcoded key
        ATK->>ATK: clone public repo · extract RSA privateKey
        ATK->>ATK: jwt.sign({id:1, role:'admin'}, privateKey, RS256)
        ATK->>API: GET /rest/admin/... Bearer forged.token
        API->>MW: expressJwt.verify(token)
        Note right of MW: 0.1.3 — no algorithms allowlist
        MW-->>API: token accepted (role=admin)
        API-->>ATK: 200 admin payload
    end
```

**Diagram-Logik:** Der legitime Login-Flow und der Angriffs-Flow stehen *in derselben Sequence* untereinander — das ist klassisches Threat-Modeling-Pattern (was-passiert-im-Soll vs. was-passiert-im-Ist), das mit `actor.md` C konsistent dargestellt wird.

---

## 6. Demo: STRIDE-Tag am Akteur (`actor.md` D.2)

Eine kompakte Akteurs-Übersichtskarte zu Beginn des Management Summarys, die für Juice Shop direkt mit den real auftretenden Threat-Actors aus dem Modell befüllt würde:

```mermaid
flowchart LR
    A1["fa:fa-user-secret <b>Anonymous Internet Attacker</b><br/>13 of 23 findings — main initiator<br/><i>S · T · I · D</i>"]:::threat
    A2["fa:fa-user-secret <b>Authenticated Internet Attacker</b><br/>3 findings (RCE · privilege escalation)<br/><i>T · E</i>"]:::threat
    A3["fa:fa-user-secret <b>Repository Reader</b><br/>2 findings (offline JWT forge)<br/><i>S · I</i>"]:::threat
    A4["fa:fa-user <b>Shop User</b> (victim)<br/>3 findings (XSS · CSRF target)<br/><i>I · S</i>"]:::victim

    A1 & A2 & A3 -.->|attack| Sys["fa:fa-server <b>OWASP Juice Shop v19.2.1</b>"]
    Sys -.->|XSS payload to victim| A4

    classDef threat fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px
    classDef victim fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px

    linkStyle 0,1,2,3 stroke:#b71c1c,stroke-width:2px,stroke-dasharray:6 4
```

**Legende:** S Spoofing · T Tampering · R Repudiation · I Information Disclosure · D Denial of Service · E Elevation of Privilege.

Diese Karte hat keinen Kompositions-Konflikt mit der Heatmap — sie würde **vor** der Heatmap als 30-Sekunden-Vorschau dienen ("wer schießt auf wen?") und die Heatmap als 5-Minuten-Detail.

---

## 7. Welche Generator-Stellen müssten angepasst werden?

| Empfehlung | Datei im Plugin | Änderung |
|---|---|---|
| **A.1** `fa:`-Präfix in Heatmap-Akteurs-Labels | `scripts/compose_threat_model.py` → `_build_actor_cards()` (≈ Zeile 1918) | Label-Builder erweitern: `f"fa:fa-user-secret <b>{label}</b>"` etc. |
| **A.1** `fa:`-Präfix in Tier-Cards | `scripts/compose_threat_model.py` → `_build_tier_cards()` | Tier-Label um `fa:fa-server`/`fa:fa-database`/`fa:fa-window-restore` ergänzen |
| **C** `actor` in `sequenceDiagram` | `agents/appsec-threat-analyst.md` § "Stage 2 — attack walkthroughs" | Prompt-Anweisung: bei Mensch-Akteuren `actor` statt `participant`, mit `fa:`-Präfix |
| **C** `fa:`-Präfix in §7.3 Auth-Flow | `data/sections-contract.yaml` → `domain_required_patterns` für 7.3 | Zusätzlicher Pattern-Hint: `actor` Element + `fa:` Icon |
| **B/G** Konvention "dashed = Angriff, solid = Konsequenz" | `scripts/compose_threat_model.py` → `linkStyle` Block der Heatmap | Indizes umkehren: Attack-Arrows auf `stroke-dasharray:6 4`, Consequence-Arrows auf solid |
| **D.2** STRIDE-Tag im Actor-Card-Label | `data/posture-actor-labels.yaml` (Akteursdefinition) + `_build_actor_cards()` | Neues Feld `stride_letters: "S T I D"` aus Threat-Aggregation |
| Gedämpfte Farbpalette | `scripts/compose_threat_model.py` → `classDef` Templates | `#fca5a5`/`#93c5fd` → `#f3dada`/`#e8f1ea`/`#e3ecf7` |

**Aufwand zusammen geschätzt:** ~150 Zeilen in `compose_threat_model.py`, ~30 Zeilen Prompt-Text in `appsec-threat-analyst.md`, kleinere Edits in Contract + Akteurs-Taxonomie. Tests in `tests/test_compose_threat_model.py` müssten an die neuen Label-Strings angepasst werden — das ist die größte Buchhaltung.

---

## 8. Risiken & Trade-offs

**Renderer-Kompatibilität.** GitHub und GitLab rendern `fa:`-Präfixe seit Mermaid 8.x stabil — der Threat-Model-PDF-Export (`/appsec-advisor:export-pdf`) nutzt `mmdc` (mermaid-cli), das FontAwesome ebenfalls über die Standard-Mermaid-Distribution lädt. Confluence funktioniert nur, wenn das eingesetzte Mermaid-Plugin das `fa:`-Präfix nicht entfernt — vor Roll-out beim Stakeholder zu prüfen.

**Sub-agent QA-Pipeline.** Der QA-Reviewer (`appsec-qa-reviewer`) hat einen Mermaid-Validator (`scripts/mermaid_validate.mjs`), der derzeit Layer-A (Regex) ist. `fa:`-Präfixe sind grammatisch valid; der Validator würde sie nicht zurückweisen. Beim Upgrade auf Layer-B (jsdom) den Test-Korpus um `fa:`-Knoten erweitern.

**Inversion der "dashed = Angriff" Konvention.** Das Plugin schreibt heute `==>|attack|` (solid bold). Eine Umstellung auf `-.->|attack|` würde rückwärts inkompatibel zu allen bestehenden Threat Models und Architect-Reviews sein — der `appsec-architect-reviewer` referenziert "die fetten Angriffspfeile" implizit in seinem Prompt. Empfehlung: nur in der **neuen Demo-Variante** einführen, nicht den globalen Render-Default ändern, bis ein paar Runs gelaufen sind.

**Icon-Hygiene.** `fa:fa-skull`, `fa:fa-user-ninja`, `fa:fa-bug` (in `actor.md` G ausdrücklich verboten) tauchen heute nirgends im Generator auf — die Negativliste lässt sich also gefahrlos in die Generator-Tests aufnehmen.

**Was nicht übernommen werden sollte:** `architecture-beta` (A.2) für die Heatmap. Die Heatmap braucht das `linkStyle`-Indexsystem für die fünfstufig-gestufte Pfeilfarbe (alignment / attack / consequence) — `architecture-beta` hat diese Kontrolle nicht. Für eine reine Container-Architektur-Skizze (§2.2) wäre A.2 hingegen eine sinnvolle Option, falls die Zielumgebung MkDocs ist.

---

## 9. Empfohlene Roll-out-Reihenfolge

1. **Phase 1 — keine Layout-Änderung, nur Icons + Farben** *(1–2 Stunden)*
   - `fa:`-Präfixe in Heatmap-Akteur- und Tier-Labels
   - Pastell- durch Audit-Farbpalette ersetzen (`#fca5a5`→`#f3dada`)
   - Tests aktualisieren
2. **Phase 2 — Sequenzdiagramme** *(1 Tag, betrifft Phase-11-Prompts)*
   - Prompt-Update: Mensch-Akteure als `actor … as fa:fa-user[-secret]`
   - Optional: legitimer-vs-Angriff-Flow in zwei `rect`-Blöcken
3. **Phase 3 — Komponenten-Diagramm-Aufwertung** *(0.5 Tag)*
   - `fa:fa-server`/`fa:fa-database`/`fa:fa-window-restore` für Tiers
   - Externe Akteure aus §2.1 ins §2.3-Diagramm projizieren (Trust-Zone-Layer)
4. **Phase 4 — Stride-Akteur-Karte** *(0.5 Tag)*
   - Neuer Sub-Renderer im Management Summary, vor der Heatmap
   - Erfordert Aggregation in `posture-actor-labels.yaml` + `_build_actor_cards()`
5. **Phase 5 (optional)** — Konvention dashed=Angriff vereinheitlichen *(nur mit Architect-Review-Prompt-Update)*

Phase 1+2 sind low-risk und liefern den größten visuellen Gewinn pro investierter Stunde.

---

## 10. Quellen

- Empfehlungen: `/home/mrohr/actor.md`
- Aktuelles Modell: `/home/mrohr/juice-shop/docs/security/threat-model.md`
- Generator: `/home/mrohr/appsec-advisor/scripts/compose_threat_model.py`, `pregenerate_fragments.py`
- Akteurs-Taxonomie: `/home/mrohr/appsec-advisor/data/posture-actor-labels.yaml`
- Sektions-Vertrag: `/home/mrohr/appsec-advisor/data/sections-contract.yaml`
