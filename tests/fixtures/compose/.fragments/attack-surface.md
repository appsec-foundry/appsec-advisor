## 5. Attack Surface

### 5.1 Unauthenticated Entry Points

| Entry Point | Protocol | Notes |
|-------------|----------|-------|
| POST /rest/user/login | HTTP | SQLi |

### 5.2 Authenticated Entry Points

| Entry Point | Protocol | Notes |
|-------------|----------|-------|
| GET /api/Users | HTTP | Broken access |
