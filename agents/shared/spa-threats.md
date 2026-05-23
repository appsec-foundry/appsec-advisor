# Client-side / SPA threat lens

Applied by `appsec-stride-analyzer` when `COMPONENT_ID` is `frontend`, `spa`, `web-app`, `client`, or when `COMPONENT_DESCRIPTION` indicates a browser-based application. In addition to standard STRIDE, systematically check these client-side vectors. Same quality bar as standard STRIDE threats.

| Threat vector | What to check | STRIDE category |
|--------------|--------------|-----------------|
| **DOM-based XSS** | Do user-controlled values from URL (`location.hash`, `URLSearchParams`, `useParams`) reach DOM sinks (`innerHTML`, `document.write`, `v-html`, `dangerouslySetInnerHTML`)? Check source→sink data flow. | Tampering |
| **Framework sanitizer bypass** | Is the framework's built-in XSS protection disabled? (`bypassSecurityTrustHtml` in Angular, `dangerouslySetInnerHTML` in React, `v-html` in Vue, `{@html}` in Svelte) | Tampering |
| **Client-side storage abuse** | Are tokens, PII, or session data stored in `localStorage`/`sessionStorage`? XSS can exfiltrate these. | Information Disclosure |
| **Missing CSP** | Is Content-Security-Policy set? Does it allow `unsafe-inline` or `unsafe-eval`? No CSP = any XSS can load external scripts. | Tampering |
| **CORS misconfiguration** | Does the server allow `Access-Control-Allow-Origin: *` with credentials? Overly broad origins? | Information Disclosure |
| **postMessage without origin check** | Do `message` event listeners validate `event.origin` before processing? | Spoofing |
| **WebSocket auth** | Are WebSocket connections authenticated? Is origin validated on the server? Is `wss://` enforced? | Spoofing |
| **Client-only auth guards** | Are route guards (`canActivate`, `beforeEach`, `PrivateRoute`) backed by server-side authorization, or can they be bypassed by direct API calls? | Elevation of Privilege |
| **Client-side secrets** | Are API keys, Firebase configs, or other sensitive values exposed in frontend bundles that should be server-side only? | Information Disclosure |
| **Third-party script injection** | Are external scripts loaded without SRI (Subresource Integrity) attributes? Could a compromised CDN inject malicious code? | Tampering |
| **Clickjacking** | Is `X-Frame-Options` or CSP `frame-ancestors` set? Can the app be framed by an attacker? | Spoofing |

Do not generate a threat if the vector is not applicable (e.g. no WebSockets found = skip WebSocket auth). Confirm presence/absence with grep when in doubt.
