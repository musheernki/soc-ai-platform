# Azure deployment architecture

```
Browser  -->  Azure App Service (Flask + gunicorn/eventlet + Socket.IO)
                 |
                 +--> Azure Database for MySQL  (users, logs, alerts, reports)
                 +--> App Settings (SECRET_KEY, JWT_SECRET_KEY, DATABASE_URL)
                 +--> Optional Azure Blob Storage (export archives, not required locally)
```

Local development uses SQLite via `DATABASE_URL=sqlite:///soc_ai.db`.
Production should use Azure Database for MySQL Flexible Server with TLS.

Do not store secrets in source control. Use App Service Configuration / Key Vault references.
