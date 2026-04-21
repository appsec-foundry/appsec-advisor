## 3. Attack Walkthroughs

### 3.1 Attack Chain Overview

The diagram below shows how Critical findings combine into two attacker workflows.

```mermaid
graph TD
    ATTACKER["Internet Attacker"]:::person

    subgraph CHAIN1["Chain 1 — DB Compromise"]
        A1["POST /rest/user/login"]:::risk
        A2["SQL Injection"]:::risk
    end

    subgraph CHAIN2["Chain 2 — Admin Takeover"]
        B1["git clone repo"]:::system
        B2["Extract RSA key"]:::risk
    end

    ATTACKER -->|"T-001"| A1
    A1 --> A2
    ATTACKER -->|"T-003"| B1
    B1 --> B2

    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#1168BD,stroke:#0E5CA8,color:#fff
    classDef risk fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
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
