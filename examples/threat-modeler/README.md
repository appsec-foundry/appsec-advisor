# Example Reports

Three reports produced by [`/appsec-advisor:create-threat-model`](../../docs/threat-model-skill.md) against publicly available training apps.

### [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)

Deliberately vulnerable Node.js / Angular web shop — OWASP flagship project for Top-10 training. Broad feature set: auth, B2B orders, file upload, admin panel.

| Report | Mode | Components | Findings |
|---|---|---:|---|
| [`threat-model-juice-shop-thorough.md`](threat-model-juice-shop-thorough.md) | `--assessment-depth thorough --full --verbose` | 8 | **35** — 🔴 12 · 🟠 19 · 🟡 3 · 🟢 1 |
| [`threat-model-juice-shop-standard.md`](threat-model-juice-shop-standard.md) | `--verbose` (standard) | 6 | **50** — 🔴 10 · 🟠 25 · 🟡 15 |

### [SasanLabs VulnerableApp](https://github.com/SasanLabs/VulnerableApp)

Java / Spring Boot learning platform implementing OWASP-catalog vulnerabilities on purpose (JWT attacks, SQLi, SSRF, …).

| Report | Mode | Components | Findings |
|---|---|---:|---|
| [`threat-model-vulnerable-app-standard.md`](threat-model-vulnerable-app-standard.md) | `--verbose` (standard) | 5 | **24** — 🔴 8 · 🟠 11 · 🟡 5 |

Severity: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low.
