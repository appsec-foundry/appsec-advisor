## 2. Architecture Diagrams

### 2.1 System Context

Who interacts with appsec-advisor from the outside, and through which channels. Solid arrows show normal usage; dashed red arrows mark unauthenticated probing or exploit paths (C4 Level 1).

```mermaid
flowchart LR
    USER["End User<br/>(browser)"]
    ATTACKER["Anonymous<br/>Internet Attacker"]
    SYSTEM["appsec-advisor"]
    USER -->|HTTPS · normal usage| SYSTEM
    ATTACKER -.->|HTTPS · probing / exploit| SYSTEM
    classDef user     fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    classDef attacker fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px
    classDef sys      fill:#f2f2f2,stroke:#424242,color:#111,stroke-width:1.5px
    class USER user
    class ATTACKER attacker
    class SYSTEM sys
```

### 2.2 Container Architecture

How the system decomposes into deployable units. Each box is a separate runtime process or service container; arrows show synchronous request paths between them. Components with ≥3 Critical findings carry a red border, ≥2 High amber (C4 Level 2).

```mermaid
flowchart TB
    subgraph Client
        BROWSER["Browser Runtime"]
    end
    subgraph Application
        express_app["Express Application"]
        container_infra["Container Infrastructure"]
    end
    subgraph Data
        DATA[("Data Layer")]
    end
    express_app -->|driver| DATA
    express_app -->|in-process| container_infra
    classDef critical fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:3px
    classDef warning  fill:#fef3c7,stroke:#b45309,color:#78350f,stroke-width:2px
    class express_app warning
    class container_infra warning
```

### 2.3 Components

Who reaches each component, and through which trust zone. Four columns map external actors to the internal tiers (Client / Application / Data); solid green arrows show legitimate data flow, dashed red arrows mark intrusion vectors. The component table directly below holds source paths and linked threats per `C-NN`; per-finding evidence is in [§8 Findings Register](#8-findings-register).

```mermaid
flowchart TD
    subgraph EXT["Untrusted Zone - Internet"]
        INTERNET_ANON["fa:fa-user-secret Anonymous Internet Attacker"]:::threat
        VICTIM_REQUIRED["fa:fa-user Shop User"]:::legit
        REPO_READ["fa:fa-code-branch Internal Developer"]:::threat
    end
    subgraph APP["Application Tier"]
        express_app["fa:fa-server express-app Express Application<br/>+ container-infra<br/><i>7 threats</i>"]:::risk
    end
    INTERNET_ANON -.->|"injection · auth bypass · RCE"| express_app
    REPO_READ -.->|"leaked credentials · auth bypass"| express_app

    classDef legit fill:#e8f1ea,stroke:#2e7d32,color:#1b5e20,stroke-width:1.5px
    classDef threat fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px
    classDef external fill:#f2f2f2,stroke:#424242,color:#212121,stroke-width:1.5px
    classDef risk fill:#fef2f2,stroke:#991b1b,color:#111,stroke-width:2.5px
    linkStyle 0,1 stroke:#b71c1c,stroke-width:2.5px,stroke-dasharray:6 4
```

| Component ID | Name | Tier | Source paths | Threats |
|---|---|---|---|---|
| express-app | Express Application | Application | `**/*.js`, `**/*.ts`, `server.js`, `routes/**`, `middleware/**`, `controllers/**`, `package.json`, `package-lock.json` | 7 |
| container-infra | Container Infrastructure | Application | `Dockerfile`, `docker-compose*.yml`, `docker-compose*.yaml` | 6 |

### 2.4 Technology Architecture

The technology stack the system is built on. Each box names the framework or runtime that fills that role; per-component findings live in the §2.3 component table above, and the full per-finding catalogue is in [§8 Findings Register](#8-findings-register).

```mermaid
flowchart TD
    subgraph APP["Application Tier"]
        RUNTIME["fa:fa-server Node.js<br/><i>JS runtime</i>"]:::risk
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

> **Legend:** **red border** ≥ 3 Critical threats on the component · **amber border** ≥ 2 High threats
