## 5. Attack Surface

Network-reachable entry points classified by authentication requirement. Each row links to the threat(s) referenced in its **Notes** column. The **Risk** column reflects the highest-severity linked finding. Entry points with no linked finding are still listed when they sit on a sensitive surface (authentication, registration, management) or look like a missing-auth/authz suspect — marked **⚑ Review** in Notes.

### 5.1 Unauthenticated Entry Points (69)

| Method | Route | Risk | Notes |
|-------|------------------------|---------|--------------------------------------------|
| POST | `/rest/user/data-export` | 🔴 Critical | [F-008](#f-008)<br/>[F-063](#f-063)<br/>[F-087](#f-087) |
| POST | `/rest/user/login` | 🔴 Critical | [F-012](#f-012)<br/>Public by design |
| GET | `/rest/products/search` | 🔴 Critical | [F-006](#f-006) |
| POST | `/api/Users` | 🟠 High | [F-043](#f-043) |
| POST | `/file-upload` | 🟠 High | [F-023](#f-023)<br/>[F-033](#f-033)<br/>[F-039](#f-039) |
| POST | `/rest/2fa/verify` | 🟠 High | [F-043](#f-043)<br/>Public by design |
| POST | `/rest/chat` | 🟠 High | [F-014](#f-014)<br/>[F-042](#f-042)<br/>[F-083](#f-083) |
| POST | `/rest/user/reset-password` | 🟠 High | [F-019](#f-019)<br/>[F-050](#f-050)<br/>[F-081](#f-081)<br/>Public by design |
| PUT | `/rest/wallet/balance` | 🟠 High | [F-021](#f-021) |
| ALL | `/encryptionkeys/:file` | 🟠 High | [F-032](#f-032) |
| GET | `/rest/track-order/:id` | 🟠 High | [F-029](#f-029) |
| GET | `/rest/wallet/balance` | 🟠 High | [F-021](#f-021) |
| GET | `/metrics` | 🟡 Medium | [F-071](#f-071)<br/>Management surface |
| POST | `/rest/deluxe-membership` | 🟡 Medium | [F-088](#f-088) |
| POST | `/rest/memories` | 🟡 Medium | [F-068](#f-068)<br/>[F-084](#f-084) |
| POST | `/​rest/​web3/​walletExploitAddress` | 🟡 Medium | [F-085](#f-085) |
| GET | `/rest/captcha` | 🟡 Medium | [F-069](#f-069)<br/>Public by design |
| GET | `/rest/deluxe-membership` | 🟡 Medium | [F-088](#f-088) |
| GET | `/rest/image-captcha` | 🟡 Medium | [F-067](#f-067)<br/>[F-087](#f-087) |
| GET | `/rest/memories` | 🟡 Medium | [F-068](#f-068)<br/>[F-084](#f-084) |
| GET | `/rest/saveLoginIp` | 🟡 Medium | [F-065](#f-065) |
| GET | `/rest/user/change-password` | 🟡 Medium | [F-045](#f-045)<br/>[F-078](#f-078) |
| GET | `/rest/user/security-question` | 🟡 Medium | [F-070](#f-070) |
| ALL | `/support/logs/:file` | 🟡 Medium | [F-073](#f-073)<br/>[F-074](#f-074) |
| POST | `/api/Addresss` | — | _⚑ Review: no auth guard detected_ |
| PUT | `/api/Addresss/:id` | — | _⚑ Review: no auth guard detected_ |
| DELETE | `/api/Addresss/:id` | — | _⚑ Review: no auth guard detected_ |
| POST | `/api/Cards` | — | _⚑ Review: no auth guard detected_ |
| DELETE | `/api/Cards/:id` | — | _⚑ Review: no auth guard detected_ |
| POST | `/api/Feedbacks` | — | _⚑ Review: no auth guard detected_ |
| GET | `/​rest/​admin/​application-​configuration` | — | Management surface<br/>_⚑ Review: no auth guard detected_ |
| GET | `/​rest/​admin/​application-​version` | — | Management surface<br/>_⚑ Review: no auth guard detected_ |
| PUT | `/​rest/​continue-​code-​findIt/​apply/​:​continueCode` | — | _⚑ Review: no auth guard detected_ |
| PUT | `/​rest/​continue-​code-​fixIt/​apply/​:​continueCode` | — | _⚑ Review: no auth guard detected_ |
| PUT | `/​rest/​continue-​code/​apply/​:​continueCode` | — | _⚑ Review: no auth guard detected_ |
| PUT | `/rest/products/:id/reviews` | — | _⚑ Review: no auth guard detected_ |
| POST | `/rest/web3/submitKey` | — | _⚑ Review: no auth guard detected_ |
| POST | `/rest/web3/walletNFTVerify` | — | _⚑ Review: no auth guard detected_ |
| POST | `/snippets/fixes` | — | _⚑ Review: no auth guard detected_ |
| POST | `/snippets/verdict` | — | _⚑ Review: no auth guard detected_ |

_29 further entry point(s) in this category carry no linked finding and no elevated review signal, and are not listed individually (69 total). The complete route inventory is available in `.route-inventory.json` and, when exported, `pentest-tasks.yaml`._

### 5.2 Authenticated Entry Points (40)

| Method | Route | Risk | Notes |
|-------|------------------------|---------|--------------------------------------------|
| PUT | `/api/BasketItems/:id` | 🟠 High | [F-024](#f-024)<br/>[F-038](#f-038)<br/>Authorization not confirmed (review) |
| DELETE | `/api/Products/:id` | 🟠 High | [F-004](#f-004)<br/>Authorization not confirmed (review) |
| PUT | `/api/Products/:id` | 🟠 High | [F-004](#f-004)<br/>Authorization not confirmed (review) |
| GET | `/rest/basket/:id` | 🟠 High | [F-003](#f-003) |
| POST | `/rest/basket/:id/checkout` | 🟠 High | [F-003](#f-003)<br/>Authorization not confirmed (review) |
| PUT | `/​rest/​basket/​:​id/​coupon/​:​coupon` | 🟠 High | [F-003](#f-003)<br/>Authorization not confirmed (review) |
| POST | `/api/BasketItems` | 🟠 High | [F-024](#f-024)<br/>[F-038](#f-038)<br/>Authorization not confirmed (review) |
| POST | `/api/Products` | 🟠 High | [F-004](#f-004)<br/>Authorization not confirmed (review) |
| GET | `/api/Users` | 🟠 High | [F-043](#f-043) |
| GET | `/profile` | 🟠 High | [F-034](#f-034)<br/>[F-037](#f-037)<br/>[F-082](#f-082) |
| POST | `/profile` | 🟠 High | [F-034](#f-034)<br/>[F-037](#f-037)<br/>[F-082](#f-082)<br/>Authorization not confirmed (review) |
| POST | `/profile/image/file` | 🟠 High | [F-034](#f-034)<br/>[F-082](#f-082)<br/>Authorization not confirmed (review) |
| POST | `/profile/image/url` | 🟠 High | [F-034](#f-034)<br/>[F-082](#f-082)<br/>Authorization not confirmed (review) |
| GET | `/​rest/​user/​authentication-​details` | 🟡 Medium | [F-091](#f-091) |
| PUT | `/api/Cards/:id` | — | Authorization not confirmed (review)<br/>_⚑ Review: no authz guard detected_ |
| PUT | `/api/Feedbacks/:id` | — | Authorization not confirmed (review)<br/>_⚑ Review: no authz guard detected_ |
| DELETE | `/api/Quantitys/:id` | — | Authorization not confirmed (review)<br/>_⚑ Review: no authz guard detected_ |
| PUT | `/api/Recycles/:id` | — | Authorization not confirmed (review)<br/>_⚑ Review: no authz guard detected_ |
| DELETE | `/api/Recycles/:id` | — | Authorization not confirmed (review)<br/>_⚑ Review: no authz guard detected_ |
| POST | `/rest/2fa/disable` | — | Public by design<br/>_⚑ Review: auth/token endpoint_ |
| POST | `/rest/2fa/setup` | — | Public by design<br/>_⚑ Review: auth/token endpoint_ |
| GET | `/rest/2fa/status` | — | Public by design<br/>_⚑ Review: auth/token endpoint_ |
| PUT | `/​rest/​order-​history/​:​id/​delivery-​status` | — | Authorization not confirmed (review)<br/>_⚑ Review: no authz guard detected_ |

_17 further entry point(s) in this category carry no linked finding and no elevated review signal, and are not listed individually (40 total). The complete route inventory is available in `.route-inventory.json` and, when exported, `pentest-tasks.yaml`._
