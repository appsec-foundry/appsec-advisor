## 3. Attack Walkthroughs

### 3.1 Attack Chain Overview

The diagrams below show how Critical findings combine into distinct attacker workflows.

#### Chain 1 — DB Compromise

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    A0(["Internet Attacker"]):::crit --> A1["T-001 SQL Injection"]:::crit
    A1 --> A2(["Full DB access"]):::crit
```

**Key takeaway:** SQL injection on the login endpoint gives the attacker direct read access to the full user database.

#### Chain 2 — Admin Takeover

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    B0(["Internet Attacker"]):::crit --> B1["T-003 Hardcoded RSA key"]:::crit
    B1 --> B2["Forge admin JWT"]:::crit --> B3(["Full admin access"]):::crit
```

**Key takeaway:** A single fix does not break the chain — parameterized queries plus secret rotation must both land simultaneously.

### 3.2 SQL Injection Authentication Bypass

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant API as /rest/user/login
    ATK->>API: email=admin'--&password=x
    API-->>ATK: 200 OK (admin JWT)
```
