# Darstellung von Maßnahmenprioritäten

## Variante A: portable Füllstandsskala

Diese Variante verwendet ausschließlich Unicode und benötigt kein CSS.

| Priorität | Darstellung |
|---|---|
| P1 | ● P1 · [M-001](#m-001) — Kritische Maßnahme sofort umsetzen |
| P2 | ◕ P2 · [M-002](#m-002) — Maßnahme kurzfristig umsetzen |
| P3 | ◑ P3 · [M-003](#m-003) — Maßnahme regulär einplanen |
| P4 | ○ P4 · [M-004](#m-004) — Maßnahme für den Backlog |

## Variante B: Zahl im Kreis mit Graustufen

Diese Variante behält die Prioritätszahl im Kreis. Die Abstufung verwendet
Inline-HTML und kann von Markdown-Renderern, die Farbstile entfernen, ignoriert
werden.

| Priorität | Darstellung |
|---|---|
| P1 | <span style="color:#111111">❶</span> [M-001](#m-001) — Kritische Maßnahme sofort umsetzen |
| P2 | <span style="color:#555555">❷</span> [M-002](#m-002) — Maßnahme kurzfristig umsetzen |
| P3 | <span style="color:#888888">❸</span> [M-003](#m-003) — Maßnahme regulär einplanen |
| P4 | <span style="color:#bbbbbb">❹</span> [M-004](#m-004) — Maßnahme für den Backlog |

## Vergleich als Liste

- ● P1 · [M-001](#m-001) — portable Füllstandsskala
- ◕ P2 · [M-002](#m-002) — portable Füllstandsskala
- ◑ P3 · [M-003](#m-003) — portable Füllstandsskala
- ○ P4 · [M-004](#m-004) — portable Füllstandsskala

- <span style="color:#111111">❶</span> [M-001](#m-001) — Kreiszahl in Schwarz
- <span style="color:#555555">❷</span> [M-002](#m-002) — Kreiszahl in Dunkelgrau
- <span style="color:#888888">❸</span> [M-003](#m-003) — Kreiszahl in Mittelgrau
- <span style="color:#bbbbbb">❹</span> [M-004](#m-004) — Kreiszahl in Hellgrau

<a id="m-001"></a>
<a id="m-002"></a>
<a id="m-003"></a>
<a id="m-004"></a>
