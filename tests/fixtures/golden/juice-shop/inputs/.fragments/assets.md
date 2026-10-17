## 4. Assets

Information assets and the classification level that drives the Confidentiality / Integrity / Availability targets used in [§8 Findings Register](#8-findings-register) risk scoring.

| Asset | Classification | Description | Linked Threats |
|----------------------|-------------|-------------------------------------------|----------------------|
| Alchemy API key | Restricted | Credential read from ALCHEMY_API_KEY for the blockchain RPC endpoint. | [F-001](#f-001) · [F-005](#f-005) · [F-006](#f-006) · [F-012](#f-012) · [F-035](#f-035) · [F-050](#f-050) · [F-063](#f-063) · [F-064](#f-064) · [F-065](#f-065) |
| LLM provider API key | Restricted | Credential read from LLM_API_KEY for the chatbot provider. | [F-001](#f-001) · [F-005](#f-005) · [F-006](#f-006) · [F-012](#f-012) · [F-035](#f-035) · [F-050](#f-050) · [F-063](#f-063) · [F-064](#f-064) · [F-065](#f-065) |
| Application relational data | Confidential | Sequelize-managed SQLite data (users, baskets, cards, addresses, etc.). | [F-003](#f-003) · [F-004](#f-004) · [F-006](#f-006) · [F-008](#f-008) · [F-012](#f-012) · [F-024](#f-024) · [F-038](#f-038) · [F-039](#f-039) · [F-041](#f-041) · [F-043](#f-043) · [F-091](#f-091) |
| Reviews and orders collections | Confidential | MarsDB collections for product reviews and orders. | — |
