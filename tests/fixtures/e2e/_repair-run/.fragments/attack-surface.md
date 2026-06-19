## 5. Attack Surface

Network-reachable entry points classified by authentication requirement. Each row links to the threat(s) referenced in its **Notes** column. The **Risk** column reflects the highest-severity linked finding. Entry points with no linked finding are still listed when they sit on a sensitive surface (authentication, registration, management) or look like a missing-auth/authz suspect — marked **⚑ Review** in Notes.

### 5.1 Unauthenticated Entry Points (56)

| Method | Route | Risk | Notes |
|-------|------------------------|---------|--------------------------------------------|
| POST | `/file-upload` | 🔴 Critical | [F-010](#f-010)<br/>[F-057](#f-057)<br/>[F-018](#f-018)<br/>handler: server.ts:309 |
| POST | `/profile` | 🔴 Critical | [F-012](#f-012)<br/>[F-039](#f-039)<br/>handler: server.ts:664 |
| GET | `/ftp/` | 🔴 Critical | [F-014](#f-014)<br/>[F-038](#f-038)<br/>Directory listing enabled via serve-index — unauthenticated; exposes legal, acquisition, and other internal documents |
| GET | `/profile` | 🔴 Critical | [F-012](#f-012)<br/>[F-039](#f-039)<br/>handler: server.ts:663 |
| GET | `/rest/products/search` | 🔴 Critical | [F-008](#f-008)<br/>SQL injection via criteria param — unauthenticated; UNION-based data exfiltration possible |
| POST | `/rest/user/login` | 🔴 Critical | [F-003](#f-003)<br/>[F-043](#f-043)<br/>[F-045](#f-045)<br/>SQL injection entry point — unauthenticated; raw string interpolation into SELECT query |
| POST | `/profile/image/file` | 🟠 High | [F-039](#f-039)<br/>[F-057](#f-057)<br/>handler: server.ts:310 |
| POST | `/profile/image/url` | 🟠 High | [F-039](#f-039)<br/>handler: server.ts:311 |
| GET | `/​rest/​admin/​application-​configuration` | 🟠 High | [F-052](#f-052)<br/>Management surface; handler: server.ts:605 |
| GET | `/​rest/​admin/​application-​version` | 🟠 High | [F-052](#f-052)<br/>Management surface; handler: server.ts:604 |
| POST | `/rest/user/data-export` | 🟠 High | [F-036](#f-036)<br/>handler: server.ts:618 |
| POST | `/rest/user/reset-password` | 🟠 High | [F-016](#f-016)<br/>[F-045](#f-045)<br/>[F-037](#f-037)<br/>handler: server.ts:596 |
| GET | `/encryptionkeys/:file` | 🟠 High | [F-035](#f-035)<br/>[F-038](#f-038)<br/>Serves RSA public key and premium.key — unauthenticated; path traversal mitigated by slash check only |
| GET | `/rest/user/security-question` | 🟠 High | [F-016](#f-016)<br/>handler: server.ts:597 |
| GET | `/​this/​page/​is/​hidden/​behind/​an/​incredibly/​high/​paywall/​that/​could/​only/​be/​unlocked/​by/​sending/​1btc/​to/​us` | 🟠 High | [F-019](#f-019)<br/>[F-023](#f-023)<br/>[F-031](#f-031)<br/>handler: server.ts:649 |
| ? | `WSS Socket.IO /` | 🟠 High | [F-019](#f-019)<br/>[F-047](#f-047)<br/>[F-062](#f-062)<br/>Real-time chat channel — persistent WebSocket connection; no per-message authentication validation |
| GET | `/redirect` | 🟡 Medium | [F-062](#f-062)<br/>handler: server.ts:656 |
| POST | `/` | — | handler: routes/dataErasure.ts:54<br/>_⚑ Review: no auth guard detected_ |
| POST | `/api/Feedbacks` | — | handler: server.ts:401<br/>_⚑ Review: no auth guard detected_ |
| GET | `/metrics` | — | Prometheus metrics — unauthenticated; exposes internal application topology and request patterns<br/>_⚑ Review: no auth guard detected_ |
| PUT | `/​rest/​continue-​code-​findIt/​apply/​:​continueCode` | — | handler: server.ts:610<br/>_⚑ Review: no auth guard detected_ |
| PUT | `/​rest/​continue-​code-​fixIt/​apply/​:​continueCode` | — | handler: server.ts:611<br/>_⚑ Review: no auth guard detected_ |
| PUT | `/​rest/​continue-​code/​apply/​:​continueCode` | — | handler: server.ts:612<br/>_⚑ Review: no auth guard detected_ |
| POST | `/rest/memories` | — | handler: server.ts:312<br/>_⚑ Review: no auth guard detected_ |
| PUT | `/​rest/​order-​history/​:​id/​delivery-​status` | — | handler: server.ts:623<br/>_⚑ Review: no auth guard detected_ |
| PUT | `/rest/wallet/balance` | — | handler: server.ts:625<br/>_⚑ Review: no auth guard detected_ |
| POST | `/​rest/​web3/​walletExploitAddress` | — | handler: server.ts:642<br/>_⚑ Review: no auth guard detected_ |
| POST | `/rest/web3/walletNFTVerify` | — | handler: server.ts:641<br/>_⚑ Review: no auth guard detected_ |
| POST | `/snippets/fixes` | — | handler: server.ts:670<br/>_⚑ Review: no auth guard detected_ |
| POST | `/snippets/verdict` | — | handler: server.ts:668<br/>_⚑ Review: no auth guard detected_ |

_26 further entry point(s) in this category carry no linked finding and no elevated review signal, and are not listed individually (56 total). The complete route inventory is available in `.route-inventory.json` and, when exported, `pentest-tasks.yaml`._

### 5.2 Authenticated Entry Points (53)

| Method | Route | Risk | Notes |
|-------|------------------------|---------|--------------------------------------------|
| GET | `/api/Users` | 🔴 Critical | [F-009](#f-009)<br/>[F-013](#f-013)<br/>handler: server.ts:362 |
| POST | `/api/Users` | 🔴 Critical | [F-009](#f-009)<br/>[F-013](#f-013)<br/>handler: server.ts:407 |
| PUT | `/api/Products/:id` | 🟠 High | [F-020](#f-020)<br/>handler: server.ts:369 |
| DELETE | `/api/Products/:id` | 🟠 High | [F-020](#f-020)<br/>handler: server.ts:370 |
| POST | `/api/Products` | 🟠 High | [F-020](#f-020)<br/>handler: server.ts:368 |
| POST | `/b2b/v2/orders` | 🟠 High | [F-044](#f-044)<br/>B2B order endpoint — JWT required but key is hardcoded; vm.runInContext sandbox escape RCE possible |
| POST | `/rest/chatbot/respond` | 🟠 High | [F-052](#f-052)<br/>handler: server.ts:630 |
| GET | `/rest/chatbot/status` | 🟠 High | [F-052](#f-052)<br/>handler: server.ts:629 |
| GET | `/​rest/​user/​authentication-​details` | 🟠 High | [F-050](#f-050)<br/>[F-035](#f-035)<br/>handler: server.ts:599 |
| POST | `/rest/web3/submitKey` | 🟠 High | [F-028](#f-028)<br/>handler: server.ts:638 |
| PUT | `/api/Addresss/:id` | — | handler: server.ts:449<br/>_⚑ Review: no authz guard detected_ |
| DELETE | `/api/Addresss/:id` | — | handler: server.ts:450<br/>_⚑ Review: no authz guard detected_ |
| PUT | `/api/BasketItems/:id` | — | handler: server.ts:425<br/>_⚑ Review: no authz guard detected_ |
| PUT | `/api/Cards/:id` | — | handler: server.ts:439<br/>_⚑ Review: no authz guard detected_ |
| DELETE | `/api/Cards/:id` | — | handler: server.ts:440<br/>_⚑ Review: no authz guard detected_ |
| GET | `/api/Cards/:id` | — | handler: server.ts:441<br/>_⚑ Review: no authz guard detected_ |
| PUT | `/api/Feedbacks/:id` | — | handler: server.ts:432<br/>_⚑ Review: no authz guard detected_ |
| DELETE | `/api/Quantitys/:id` | — | handler: server.ts:428<br/>_⚑ Review: no authz guard detected_ |
| GET | `/api/Recycles/:id` | — | handler: server.ts:387<br/>_⚑ Review: no authz guard detected_ |
| PUT | `/api/Recycles/:id` | — | handler: server.ts:388<br/>_⚑ Review: no authz guard detected_ |
| DELETE | `/api/Recycles/:id` | — | handler: server.ts:389<br/>_⚑ Review: no authz guard detected_ |
| POST | `/rest/2fa/disable` | — | handler: server.ts:470<br/>_⚑ Review: auth/token endpoint_ |
| POST | `/rest/2fa/setup` | — | handler: server.ts:464<br/>_⚑ Review: auth/token endpoint_ |
| GET | `/rest/2fa/status` | — | handler: server.ts:462<br/>_⚑ Review: auth/token endpoint_ |
| POST | `/rest/2fa/verify` | — | handler: server.ts:457<br/>_⚑ Review: auth/token endpoint_ |
| GET | `/rest/basket/:id` | — | handler: server.ts:601<br/>_⚑ Review: no authz guard detected_ |
| POST | `/rest/basket/:id/checkout` | — | handler: server.ts:602<br/>_⚑ Review: no authz guard detected_ |
| PUT | `/​rest/​basket/​:​id/​coupon/​:​coupon` | — | handler: server.ts:603<br/>_⚑ Review: no authz guard detected_ |
| GET | `/rest/products/:id/reviews` | — | handler: server.ts:632<br/>_⚑ Review: no authz guard detected_ |
| PUT | `/rest/products/:id/reviews` | — | handler: server.ts:633<br/>_⚑ Review: no authz guard detected_ |

_23 further entry point(s) in this category carry no linked finding and no elevated review signal, and are not listed individually (53 total). The complete route inventory is available in `.route-inventory.json` and, when exported, `pentest-tasks.yaml`._
