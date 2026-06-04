## 2. Architecture Diagrams

### 2.1 System Context

Who interacts with juice-shop from the outside, and through which channels. Solid arrows show normal usage; dashed red arrows mark unauthenticated probing or exploit paths (C4 Level 1).

```mermaid
flowchart LR
    USER["End User<br/>(browser)"]
    ATTACKER["Anonymous<br/>Internet Attacker"]
    ADMIN["Admin User"]
    SYSTEM["juice-shop"]
    EXTERNAL["External HTTP Services<br/>(SSRF target)"]
    USER -->|HTTPS · normal usage| SYSTEM
    ATTACKER -.->|HTTPS · probing / exploit| SYSTEM
    ADMIN -->|HTTPS · admin actions| SYSTEM
    SYSTEM -->|outbound · HTTPS| EXTERNAL
    classDef user     fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    classDef attacker fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px
    classDef admin    fill:#fef3c7,stroke:#b45309,color:#78350f,stroke-width:1.5px
    classDef sys      fill:#f2f2f2,stroke:#424242,color:#111,stroke-width:1.5px
    classDef ext      fill:#f2f2f2,stroke:#9e9e9e,color:#424242,stroke-dasharray:3 3,stroke-width:1px
    class USER user
    class ATTACKER attacker
    class ADMIN admin
    class SYSTEM sys
    class EXTERNAL ext
```

### 2.2 Container Architecture

How the system decomposes into deployable units. Each box is a separate runtime process or service container; arrows show synchronous request paths between them. Components with ≥3 Critical findings carry a red border, ≥2 High amber (C4 Level 2).

```mermaid
flowchart TB
    subgraph Client
        frontend_spa["Angular Single-Page Application"]
    end
    subgraph Application
        backend_api["Express REST API Backend"]
        file_upload_service["File Upload Service"]
        b2b_api["B2B Order API"]
    end
    subgraph Data
        data_persistence[("Data Layer (SQLite + MarsDB)")]
    end
    frontend_spa -->|HTTPS REST| backend_api
    backend_api -->|driver| data_persistence
    backend_api -->|in-process| file_upload_service
    backend_api -->|in-process| b2b_api
    classDef critical fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:3px
    classDef warning  fill:#fef3c7,stroke:#b45309,color:#78350f,stroke-width:2px
    class backend_api critical
    class frontend_spa warning
    class file_upload_service warning
    class b2b_api warning
```

### 2.3 Components

Who reaches each component, and through which trust zone. Four columns map external actors to the internal tiers (Client / Application / Data); solid green arrows show legitimate data flow, dashed red arrows mark intrusion vectors. The component table directly below holds source paths and linked threats per `C-NN`; per-finding evidence is in [§8 Findings Register](#8-findings-register).

```mermaid
flowchart TD
    subgraph EXT["Untrusted Zone - Internet"]
        INTERNET_ANON["fa:fa-user-secret Anonymous Internet Attacker"]:::threat
        VICTIM_REQUIRED["fa:fa-user Shop User"]:::legit
    end
    subgraph CLIENT["Client Tier"]
        frontend_spa["fa:fa-window-restore frontend-spa Angular Single-Page Appli…<br/><i>5 threats</i>"]:::risk
    end
    subgraph APP["Application Tier"]
        backend_api["fa:fa-server backend-api Express REST API Backend<br/>+ file-upload-service + b2b-api<br/><i>21 threats</i>"]:::risk
    end
    subgraph DATA["Data Tier"]
        data_persistence[("fa:fa-database data-persistence Data Layer (SQLite + MarsDB)<br/><i>3 threats</i>")]:::risk
    end
    VICTIM_REQUIRED -->|"HTTPS · TLS"| frontend_spa
    frontend_spa -->|"REST · JWT Bearer"| backend_api
    backend_api -->|"ORM · queries"| data_persistence
    INTERNET_ANON -.->|"injection · auth bypass · RCE"| backend_api
    INTERNET_ANON -.->|"XSS · client tampering · token theft"| frontend_spa

    classDef legit fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    classDef threat fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px
    classDef external fill:#f2f2f2,stroke:#424242,color:#212121,stroke-width:1.5px
    classDef risk fill:#fef2f2,stroke:#991b1b,color:#111,stroke-width:2.5px
    linkStyle 0,1,2 stroke:#2e7d32,stroke-width:1.5px
    linkStyle 3,4 stroke:#b71c1c,stroke-width:2.5px,stroke-dasharray:6 4
```

| Component ID | Name | Tier | Source paths | Threats |
|---|---|---|---|---|
| backend-api | Express REST API Backend | Application | `server.ts`, `routes/**`, `lib/**`, `app.ts` | 21 |
| frontend-spa | Angular Single-Page Application | Client | `frontend/src/**` | 5 |
| data-persistence | Data Layer (SQLite + MarsDB) | Data | `models/**`, `data/mongodb.ts`, `data/datacreator.ts`, `data/static/users.yml` | 3 |
| file-upload-service | File Upload Service | Application | `routes/fileUpload.ts`, `routes/profileImageFileUpload.ts`, `routes/profileImageUrlUpload.ts`, `routes/fileServer.ts`, `routes/keyServer.ts` | 4 |
| b2b-api | B2B Order API | Application | `routes/b2bOrder.ts`, `routes/web3Wallet.ts`, `routes/nftMint.ts`, `routes/checkKeys.ts` | 5 |

### 2.4 Technology Architecture

The technology stack the system is built on. Each box names the framework or runtime that fills that role; per-component findings live in the §2.3 component table above, and the full per-finding catalogue is in [§8 Findings Register](#8-findings-register).

```mermaid
flowchart TD
    subgraph CLIENT["Client Tier"]
        FE_ANGULAR["fa:fa-window-restore Angular SPA<br/><i>browser runtime</i>"]:::risk
    end
    subgraph APP["Application Tier"]
        RUNTIME["fa:fa-server Node.js<br/><i>JS runtime</i>"]:::risk
        EXPRESS["fa:fa-server Express<br/><i>HTTP framework</i>"]:::risk
    end
    subgraph DATA["Data Tier"]
        ORM["fa:fa-database Sequelize ORM<br/><i>object-relational mapper</i>"]:::risk
        SQLITE[("fa:fa-database SQLite<br/><i>embedded relational DB</i>")]:::risk
        MARSDB[("fa:fa-database MarsDB<br/><i>in-memory NoSQL</i>")]:::risk
        MONGO[("fa:fa-database MongoDB<br/><i>document DB</i>")]:::risk
        LOCAL_FS["fa:fa-folder-open Local FS<br/><i>uploads · logs · keys</i>"]:::risk
    end
    subgraph INFRA["Cross-Cutting"]
        INFRA_SCM["fa:fa-code-branch GitHub (public)<br/><i>source supply chain</i>"]:::risk
    end
    FE_ANGULAR -->|"HTTPS · JWT"| RUNTIME
    EXPRESS -->|"DB driver"| ORM
    EXPRESS -->|"DB driver"| SQLITE
    EXPRESS -->|"DB driver"| MARSDB
    EXPRESS -->|"DB driver"| MONGO
    EXPRESS -->|"file I/O"| LOCAL_FS
    INFRA_SCM -.->|"clone · extract secrets"| EXPRESS

    classDef risk fill:#fef2f2,stroke:#991b1b,color:#111,stroke-width:2.5px
    classDef ok fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    linkStyle 0,1,2,3,4,5 stroke:#424242,stroke-width:1.5px
    linkStyle 6 stroke:#9e9e9e,stroke-width:1px,stroke-dasharray:3 3
```

> **Legend:** **red border** ≥ 3 Critical threats on the component · **amber border** ≥ 2 High threats
