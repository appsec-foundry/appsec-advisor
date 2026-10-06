## 2. Architecture Diagrams

### 2.1 System Context

Who interacts with _last-repo from the outside, and through which channels. Solid arrows show normal usage; dashed red arrows mark unauthenticated probing or exploit paths (C4 Level 1).

```mermaid
flowchart LR
    USER["End User<br/>(browser)"]
    ATTACKER["Anonymous<br/>Internet Attacker"]
    subgraph TBEDGE["Trust boundary · external → web-api (tb-1)<br/>external → ci-cd-pipeline (tb-2)"]
        SYSTEM["_last-repo"]
    end
    EXTERNAL["External HTTP Services<br/>(SSRF target)"]
    USER -->|HTTPS · normal usage| SYSTEM
    ATTACKER -.->|HTTPS · probing / exploit| SYSTEM
    SYSTEM -->|outbound · HTTPS| EXTERNAL
    classDef user     fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    classDef attacker fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px
    classDef sys      fill:#f2f2f2,stroke:#424242,color:#111,stroke-width:1.5px
    classDef ext      fill:#f2f2f2,stroke:#9e9e9e,color:#424242,stroke-dasharray:3 3,stroke-width:1px
    class USER user
    class ATTACKER attacker
    class SYSTEM sys
    class EXTERNAL ext
```

*Trust boundaries not named above: web-api → database (tb-3), web-api → external (tb-4) — every boundary is listed in [§1 Trust Boundaries](#trust-boundaries).*

**Key takeaway:** Every actor in the context interacts with _last-repo through its external interface, so authentication and input validation at that edge govern the entire attack surface.

### 2.2 Container Architecture

How the system decomposes into deployable units. Each box is a separate runtime process or service container; arrows show synchronous request paths between them. Components with ≥3 Critical findings carry a red border, ≥2 High amber (C4 Level 2).

```mermaid
flowchart TB
    subgraph Client
        BROWSER["Browser Runtime"]
    end
    subgraph TBSERVER["Trust boundary · external → web-api (tb-1)<br/>external → ci-cd-pipeline (tb-2)"]
    subgraph Application
        web_api["Express Web API"]
        auth["Authentication & Session Middleware"]
        ci_cd_pipeline["CI/CD Pipeline"]
    end
    subgraph Data
        database[("Relational Datastore")]
    end
    end
    web_api -->|SQL · Confidential| database
    classDef critical fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:3px
    classDef warning  fill:#fef3c7,stroke:#b45309,color:#78350f,stroke-width:2px
    class web_api critical
    class auth warning
```

*Trust boundaries not drawn above: web-api → database (tb-3), web-api → external (tb-4) — every boundary is listed in [§1 Trust Boundaries](#trust-boundaries).*

**Key takeaway:** The system decomposes into 0 client, 3 application and 1 data unit(s); Express Web API carries the most Critical findings (3) and bounds the worst-case blast radius.

### 2.3 Components

Who reaches each component, and through which trust zone. Browser code runs on the user's device, so the client column is part of the untrusted zone, not a zone of its own — trust changes only where traffic enters the Application tier. Solid green arrows show legitimate data flow, dashed red arrows mark intrusion vectors. The component table directly below holds source paths and linked threats per `C-NN`; per-finding evidence is in [§8 Findings Register](#8-findings-register).

```mermaid
flowchart TD
    subgraph EXT["Untrusted Zone - Internet"]
        INTERNET_ANON["fa:fa-user-secret Anonymous Internet Attacker"]:::threat
        VICTIM_REQUIRED["fa:fa-user Shop User"]:::legit
        REPO_READ["fa:fa-code-branch Internal Developer"]:::threat
    end
    subgraph APP["Application Tier"]
        web_api["fa:fa-server web-api · Express Web API<br/>+ auth + ci-cd-pipeline<br/><i>13 threats</i>"]:::risk
    end
    subgraph DATA["Data Tier"]
        database[("fa:fa-database database · Relational Datastore")]:::risk
    end
    web_api -->|"ORM · queries"| database
    INTERNET_ANON ==>|"injection · auth bypass · RCE<br/>trust boundary · tb-1, tb-2"| web_api
    REPO_READ ==>|"leaked credentials · auth bypass<br/>trust boundary · tb-1, tb-2"| web_api

    classDef legit fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    classDef threat fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px
    classDef external fill:#f2f2f2,stroke:#424242,color:#212121,stroke-width:1.5px
    classDef risk fill:#fef2f2,stroke:#991b1b,color:#111,stroke-width:2.5px
    linkStyle 0 stroke:#2e7d32,stroke-width:1.5px
    linkStyle 1,2 stroke:#ef6c00,stroke-width:3px
```

*Trust boundaries crossed by the `==>` edges above: external → web-api (tb-1), external → ci-cd-pipeline (tb-2) — every boundary is listed in [§1 Trust Boundaries](#trust-boundaries).*

**Key takeaway:** Express Web API concentrates the most findings (7 of 13 across all components); the table below maps each component to its source paths and linked threats.

| Component ID | Name | Tier | Source paths | Threats |
|---|---|---|---|---|
| web-api | Express Web API | Application | `server.js`, `routes/**/*.js`, `models/*.js` | 7 |
| auth | Authentication & Session Middleware | Application | `middleware/partnerAuth.js`, `middleware/tenantContext.js`, `server.js` | 6 |
| database | Relational Datastore | Data | `config/insecure-settings.ini` | 0 |
| ci-cd-pipeline | CI/CD Pipeline | Application | `.github/workflows/**`, `Dockerfile`, `package.json` | 0 |

### 2.4 Technology Architecture

The technology stack the system is built on. Each box names the framework or runtime that fills that role; per-component findings live in the §2.3 component table above, and the full per-finding catalogue is in [§8 Findings Register](#8-findings-register).

```mermaid
flowchart TD
    subgraph APP["Application Tier"]
        EXPRESS["fa:fa-server Express<br/><i>HTTP framework</i>"]:::risk
    end
    subgraph DATA["Data Tier"]
        ORM["fa:fa-database Sequelize ORM<br/><i>object-relational mapper</i>"]:::risk
        LOCAL_FS["fa:fa-folder-open Local FS<br/><i>uploads · logs · keys</i>"]:::risk
    end
    subgraph INFRA["Cross-Cutting"]
        INFRA_RUN["fa:fa-cube Docker<br/><i>container runtime</i>"]:::ok
        INFRA_SCM["fa:fa-code-branch GitHub (public)<br/><i>source supply chain</i>"]:::risk
    end
    EXPRESS -->|"DB driver"| ORM
    EXPRESS -->|"file I/O"| LOCAL_FS
    INFRA_SCM -.->|"build"| INFRA_RUN
    INFRA_RUN -.->|"runs"| EXPRESS

    classDef risk fill:#fef2f2,stroke:#991b1b,color:#111,stroke-width:2.5px
    classDef ok fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    linkStyle 0,1 stroke:#424242,stroke-width:1.5px
    linkStyle 2,3 stroke:#9e9e9e,stroke-width:1px,stroke-dasharray:3 3
```

**Key takeaway:** The stack spans 1 data-tier store(s) behind the application tier; injection and data-at-rest exposure track the data tier, detailed per finding in [§8 Findings Register](#8-findings-register).

> **Legend:** `-->` synchronous request/response (REST, HTTPS, gRPC) · `==>` crosses an untrusted trust boundary (security-critical) · **red border** ≥ 3 Critical threats on the component · **amber border** ≥ 2 High threats
