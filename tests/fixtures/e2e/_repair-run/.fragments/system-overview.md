## 1. System Overview

**Repository:** https://github.com/juice-shop/juice-shop

### Scope

This threat model covers 8 components of juice-shop: **Angular SPA Frontend**, **Express.js REST API Backend**, **File Upload & Processing Service**, **B2B Order Processing API**, **Data Layer (SQLite + MarsDB)**, **Authentication & Session Surface**, **CI/CD Pipeline**, **Real-time WebSocket Channel**.

All 8 modeled components received full STRIDE threat analysis.

**Out of scope:** third-party hosted dependencies, browser runtime, operating-system kernel, and the underlying network infrastructure.
