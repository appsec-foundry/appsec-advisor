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

**Key takeaway:** Every actor in the context interacts with juice-shop through its external interface, so authentication and input validation at that edge govern the entire attack surface.

### 2.2 Container Architecture

How the system decomposes into deployable units. Each box is a separate runtime process or service container; arrows show synchronous request paths between them. Components with ≥3 Critical findings carry a red border, ≥2 High amber (C4 Level 2).

```mermaid
flowchart TB
    subgraph Client
        angular_spa["Angular SPA Frontend"]
        express_backend["Express.js REST API Backend"]
    end
    subgraph Application
        file_upload_service["File Upload & Processing Service"]
        b2b_api["B2B Order Processing API"]
        auth["Authentication & Session Surface"]
        ci_cd_pipeline["CI/CD Pipeline"]
        realtime_channel["Real-time WebSocket Channel"]
    end
    subgraph Data
        data_layer[("Data Layer (SQLite + MarsDB)")]
    end
    angular_spa -->|HTTPS REST| file_upload_service
    express_backend -->|HTTPS REST| file_upload_service
    file_upload_service -->|driver| data_layer
    file_upload_service -->|in-process| b2b_api
    file_upload_service -->|in-process| auth
    file_upload_service -->|in-process| ci_cd_pipeline
    file_upload_service -->|in-process| realtime_channel
    classDef critical fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:3px
    classDef warning  fill:#fef3c7,stroke:#b45309,color:#78350f,stroke-width:2px
    class express_backend critical
    class auth critical
    class angular_spa warning
    class file_upload_service warning
    class data_layer warning
    class ci_cd_pipeline warning
    class realtime_channel warning
```

**Key takeaway:** The system decomposes into 2 client, 5 application and 1 data unit(s); Express.js REST API Backend carries the most Critical findings (5) and bounds the worst-case blast radius.

### 2.3 Components

Who reaches each component, and through which trust zone. Four columns map external actors to the internal tiers (Client / Application / Data); solid green arrows show legitimate data flow, dashed red arrows mark intrusion vectors. The component table directly below holds source paths and linked threats per `C-NN`; per-finding evidence is in [§8 Findings Register](#8-findings-register).

```mermaid
flowchart TD
    subgraph EXT["Untrusted Zone - Internet"]
        INTERNET_ANON["fa:fa-user-secret Anonymous Internet Attacker"]:::threat
        VICTIM_REQUIRED["fa:fa-user Shop User"]:::legit
    end
    subgraph CLIENT["Client Tier"]
        angular_spa["fa:fa-window-restore angular-spa Angular SPA Frontend<br/>+ express-backend<br/><i>9 threats</i>"]:::risk
    end
    subgraph APP["Application Tier"]
        file_upload_service["fa:fa-server file-upload-service File Upload & Processing S…<br/>+ b2b-api + auth + ci-cd-pipeline + realtime-channel<br/><i>5 threats</i>"]:::risk
    end
    subgraph DATA["Data Tier"]
        data_layer[("fa:fa-database data-layer Data Layer (SQLite + MarsDB)<br/><i>3 threats</i>")]:::risk
    end
    VICTIM_REQUIRED -->|"HTTPS · TLS"| angular_spa
    angular_spa -->|"REST · JWT Bearer"| file_upload_service
    file_upload_service -->|"ORM · queries"| data_layer
    INTERNET_ANON -.->|"injection · auth bypass · RCE"| file_upload_service
    INTERNET_ANON -.->|"XSS · client tampering · token theft"| angular_spa

    classDef legit fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    classDef threat fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px
    classDef external fill:#f2f2f2,stroke:#424242,color:#212121,stroke-width:1.5px
    classDef risk fill:#fef2f2,stroke:#991b1b,color:#111,stroke-width:2.5px
    linkStyle 0,1,2 stroke:#2e7d32,stroke-width:1.5px
    linkStyle 3,4 stroke:#b71c1c,stroke-width:2.5px,stroke-dasharray:6 4
```

**Key takeaway:** Express.js REST API Backend concentrates the most findings (19 of 65 across all components); the table below maps each component to its source paths and linked threats.

| Component ID | Name | Tier | Source paths | Threats |
|---|---|---|---|---|
| angular-spa | Angular SPA Frontend | Client | `frontend/src/**`, `frontend/dist/**`, `frontend/*.ts`, `frontend/*.json` | 9 |
| express-backend | Express.js REST API Backend | Client | `routes/**`, `server.ts`, `lib/**`, `app.ts`, `build/**` | 19 |
| file-upload-service | File Upload & Processing Service | Application | `routes/fileUpload.ts`, `routes/profileImageUrlUpload.ts`, `routes/profileImageFileUpload.ts`, `routes/logfileServer.ts`, `routes/keyServer.ts`, `routes/quarantineServer.ts`, `ftp/**`, `encryptionkeys/**`, `uploads/**` | 5 |
| b2b-api | B2B Order Processing API | Application | `routes/b2bOrder.ts`, `routes/checkKeys.ts` | 4 |
| data-layer | Data Layer (SQLite + MarsDB) | Data | `models/**`, `data/**`, `config/**`, `lib/mongodb.ts`, `ftp/**`, `encryptionkeys/**` | 3 |
| auth | Authentication & Session Surface | Application | `lib/insecurity.ts`, `lib/startup/registerWebsocketEvents.ts`, `routes/2fa.ts`, `routes/authenticatedUsers.ts`, `routes/login.ts`, `routes/resetPassword.ts`, `routes/saveLoginIp.ts` | 7 |
| ci-cd-pipeline | CI/CD Pipeline | Application | `.github/workflows/**`, `.gitlab-ci.yml`, `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `docker-compose*.yml`, `docker-compose*.yaml`, `compose*.yml`, `compose*.yaml`, `.dockerignore`, `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `.npmrc`, `.github/dependabot.yml`, `.github/dependabot.yaml`, `.github/renovate.json`, `renovate.json`, `.renovaterc`, `.renovaterc.json` | 14 |
| realtime-channel | Real-time WebSocket Channel | Application | `lib/challengeUtils.ts`, `lib/startup/registerWebsocketEvents.ts` | 4 |

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
        REALTIME["fa:fa-plug Socket.IO<br/><i>WebSocket</i>"]:::risk
    end
    subgraph DATA["Data Tier"]
        ORM["fa:fa-database Sequelize ORM<br/><i>object-relational mapper</i>"]:::risk
        SQLITE[("fa:fa-database SQLite<br/><i>embedded relational DB</i>")]:::risk
        MARSDB[("fa:fa-database MarsDB<br/><i>in-memory NoSQL</i>")]:::risk
        LOCAL_FS["fa:fa-folder-open Local FS<br/><i>uploads · logs · keys</i>"]:::risk
    end
    subgraph INFRA["Cross-Cutting"]
        INFRA_RUN["fa:fa-cube Docker<br/><i>container runtime</i>"]:::ok
        INFRA_SCM["fa:fa-code-branch GitHub (public)<br/><i>source supply chain</i>"]:::risk
    end
    FE_ANGULAR -->|"HTTPS · JWT"| RUNTIME
    EXPRESS -->|"DB driver"| ORM
    EXPRESS -->|"DB driver"| SQLITE
    EXPRESS -->|"DB driver"| MARSDB
    EXPRESS -->|"file I/O"| LOCAL_FS
    INFRA_SCM -.->|"build"| INFRA_RUN
    INFRA_RUN -.->|"runs"| EXPRESS

    classDef risk fill:#fef2f2,stroke:#991b1b,color:#111,stroke-width:2.5px
    classDef ok fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    linkStyle 0,1,2,3,4 stroke:#424242,stroke-width:1.5px
    linkStyle 5,6 stroke:#9e9e9e,stroke-width:1px,stroke-dasharray:3 3
```

**Key takeaway:** The stack spans 1 data-tier store(s) behind the application tier; injection and data-at-rest exposure track the data tier, detailed per finding in [§8 Findings Register](#8-findings-register).

> **Legend:** **red border** ≥ 3 Critical threats on the component · **amber border** ≥ 2 High threats
