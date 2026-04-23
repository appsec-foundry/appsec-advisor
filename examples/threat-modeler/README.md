# Example Reports

Three reports produced by [`/appsec-advisor:create-threat-model`](../../docs/threat-model-skill.md) against publicly available training apps.

### [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)

Deliberately vulnerable Node.js / Angular web shop — OWASP flagship project for Top-10 training. Broad feature set: auth, B2B orders, file upload, admin panel.

| Report | Mode | Components | Findings |
|---|---|---:|---|
| [`threat-model-juice-shop-thorough.md`](threat-model-juice-shop-thorough.md) | `--assessment-depth thorough --full --verbose` | 8 | **35** — 12 Critical · 19 High · 3 Medium · 1 Low |
| [`threat-model-juice-shop-standard.md`](threat-model-juice-shop-standard.md) | `--verbose` (standard) | 6 | **50** — 10 Critical · 25 High · 15 Medium |

### [SasanLabs VulnerableApp](https://github.com/SasanLabs/VulnerableApp)

Java / Spring Boot learning platform implementing OWASP-catalog vulnerabilities on purpose (JWT attacks, SQLi, SSRF, …).

| Report | Mode | Components | Findings |
|---|---|---:|---|
| [`threat-model-vulnerable-app-standard.md`](threat-model-vulnerable-app-standard.md) | `--verbose` (standard) | 5 | **24** — 8 Critical · 11 High · 5 Medium |
