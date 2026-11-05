<<<<<<< HEAD
# AI-Based Cloud Security Threat Detection and Prevention System

Professional SOC-style web application that records login activity, scores it with an Isolation Forest model plus explicit security rules, and surfaces alerts to administrators.

This repository is a **working local application**. Isolation Forest is trained on a **synthetic** sample dataset. Do not treat scores as measured real-world attacker detection accuracy.

## Architecture

```
Browser (Bootstrap 5 + Chart.js + Socket.IO)
    |
Flask (pages + REST JSON APIs + Flask-SocketIO)
    |
    +-- JWT cookies/headers, bcrypt passwords, RBAC on every admin route
    +-- SQLAlchemy  ->  SQLite (local) or Azure Database for MySQL
    +-- ai_engine   ->  Isolation Forest (+ optional Random Forest helper)
    +-- services    ->  logging, risk scoring, alert fan-out
```

### Roles (enforced in the API)

- **admin**: users, all logs, alerts, simulation, reports, dashboards
- **user**: own dashboard, own login history, profile, logout

Hiding sidebar links is not the access control. Admin blueprints use `role_required("admin")`.

## Folder structure

```
soc-ai-platform/
  app.py                 Application factory, seed data
  config.py              Environment-driven settings
  wsgi.py                Azure / gunicorn entry
  extensions.py
  models/                SQLAlchemy entities
  routes/                Auth, admin, dashboard, security, reports, pages
  ai_engine/             Preprocess, train, detect
  services/              Alerts, logging, risk, RBAC
  templates/  static/
  dataset/               Synthetic feature CSV + notes
  tests/
  azure/                 Startup command and architecture notes
```

## Database schema

Tables from the specification, plus operational tables:

| Table | Purpose |
| --- | --- |
| `users` | Identity, `password_hash`, `role`, `account_status` |
| `login_logs` | Each attempt: IP, UA, status, AI fields |
| `activity_logs` | In-app actions |
| `threat_alerts` | Scored incidents, status New / Investigating / Resolved |
| `security_reports` | Generated report JSON |
| `token_blocklist` | Logout / JWT invalidation |
| `password_reset_tokens` | Hashed one-time reset tokens |

MySQL is supported via `DATABASE_URL`. Local default is SQLite in `instance/`.

## Risk scoring (implemented)

1. **Features** (see `ai_engine/preprocess.py`): failed counts, hour, weekend flag, unique IPs, new IP flag, burst rate, recency, activity volume, fail ratio.
2. **Isolation Forest** `score_samples` mapped to `ml_risk` 0–100. Lower sample score = higher risk.
3. **Rules** (capped boost +50): failed-login bursts, 10-minute frequency spikes, off-hours **combined with** other signals, many distinct IPs, restricted-resource probes.
4. **A new IP by itself is informational only** (small boost). It is never labelled malicious on that signal alone.
5. **Severity**: LOW 0–24, MEDIUM 25–49, HIGH 50–74, CRITICAL 75–100.
6. Alerts are stored when prediction is anomalous or risk ≥ 40, then pushed on Socket.IO.

## Sample accounts (created on first run)

| Email | Password | Role |
| --- | --- | --- |
| `admin@soc.local` | `Admin@123` | admin |
| `user@soc.local` | `User@123` | user |

## Local setup (Windows PowerShell)

```powershell
cd $env:USERPROFILE\Projects\soc-ai-platform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m ai_engine.train_model
python app.py
```

Open http://127.0.0.1:5000

Optional MySQL instead of SQLite: set `DATABASE_URL=mysql+pymysql://USER:PASSWORD@HOST:3306/soc_ai` in `.env`. SQLAlchemy creates tables on startup.

### Train the model only

```powershell
python -m ai_engine.train_model
```

If `dataset/security_logs.csv` is missing, training writes a larger synthetic CSV. Classification reports printed during training compare the unsupervised model to **synthetic** labels only.

### Tests

```powershell
pytest -q
```

Covered: registration, login, bad password, lockout after repeated failures, JWT `/me`, user forbidden on admin APIs, token revoke, normal vs anomalous scoring, simulated alert creation, dashboard KPIs.

### Safe test-mode events

Admin page **Threat Detection** or:

```http
POST /api/security/simulate
Authorization: Bearer <admin token>
{ "mode": "anomalous", "email": "user@soc.local", "repeats": 6 }
```

This only inserts rows in the app database. It does not scan networks or attack hosts.

## Azure App Service

1. Create Azure Database for MySQL Flexible Server and a database `soc_ai`.
2. Create a Web App (Python 3.11+ Linux).
3. Configure Application Settings:
   - `FLASK_ENV=production`
   - `SECRET_KEY` (random)
   - `JWT_SECRET_KEY` (random)
   - `JWT_COOKIE_SECURE=true`
   - `EXPOSE_RESET_TOKEN=false`
   - `DATABASE_URL=mysql+pymysql://USER:PASSWORD@HOST:3306/soc_ai`
4. Startup command (also in `azure/startup.txt`):

```
gunicorn --bind 0.0.0.0:8000 --worker-class eventlet -w 1 wsgi:app
```

5. Deploy the repo (Local Git, GitHub Actions, or `az webapp up`).
6. Optional: Azure Blob connection string for future log archival. Core monitoring does not require Blob Storage.

Use TLS to MySQL (`ssl_ca` query parameter) in production. Rotate secrets in App Settings / Key Vault. The app will not work as a real Azure Sentinel replacement; it monitors **this application's** auth telemetry.

## Implementation status

Implemented and wired to the database/API:

- Registration, bcrypt, JWT (header + cookie), logout blocklist, password reset (dev token exposure flag), lockout
- Admin/user RBAC on backend
- Isolation Forest + rule overlay, persisted alerts, Socket.IO notify
- Admin KPI dashboard and Chart.js from `/api/dashboard/admin`
- Monitoring with search/filter/pagination
- CSV and PDF reports
- Azure-ready config (no hardcoded secrets)

Not claimed: live Microsoft 365/Azure AD tenant ingestion, guaranteed detection of real attackers, or production email delivery of reset tokens (set `EXPOSE_RESET_TOKEN=false` and add your own mailer).
=======
# AI-Based Cloud Security Threat Detection and Prevention System

Professional SOC-style web application that records login activity, scores it with an Isolation Forest model plus explicit security rules, and surfaces alerts to administrators.

This repository is a **working local application**. Isolation Forest is trained on a **synthetic** sample dataset. Do not treat scores as measured real-world attacker detection accuracy.

## Architecture

```
Browser (Bootstrap 5 + Chart.js + Socket.IO)
    |
Flask (pages + REST JSON APIs + Flask-SocketIO)
    |
    +-- JWT cookies/headers, bcrypt passwords, RBAC on every admin route
    +-- SQLAlchemy  ->  SQLite (local) or Azure Database for MySQL
    +-- ai_engine   ->  Isolation Forest (+ optional Random Forest helper)
    +-- services    ->  logging, risk scoring, alert fan-out
```

### Roles (enforced in the API)

- **admin**: users, all logs, alerts, simulation, reports, dashboards
- **user**: own dashboard, own login history, profile, logout

Hiding sidebar links is not the access control. Admin blueprints use `role_required("admin")`.

## Folder structure

```
soc-ai-platform/
  app.py                 Application factory, seed data
  config.py              Environment-driven settings
  wsgi.py                Azure / gunicorn entry
  extensions.py
  models/                SQLAlchemy entities
  routes/                Auth, admin, dashboard, security, reports, pages
  ai_engine/             Preprocess, train, detect
  services/              Alerts, logging, risk, RBAC
  templates/  static/
  dataset/               Synthetic feature CSV + notes
  tests/
  azure/                 Startup command and architecture notes
```

## Database schema

Tables from the specification, plus operational tables:

| Table | Purpose |
| --- | --- |
| `users` | Identity, `password_hash`, `role`, `account_status` |
| `login_logs` | Each attempt: IP, UA, status, AI fields |
| `activity_logs` | In-app actions |
| `threat_alerts` | Scored incidents, status New / Investigating / Resolved |
| `security_reports` | Generated report JSON |
| `token_blocklist` | Logout / JWT invalidation |
| `password_reset_tokens` | Hashed one-time reset tokens |

MySQL is supported via `DATABASE_URL`. Local default is SQLite in `instance/`.

## Risk scoring (implemented)

1. **Features** (see `ai_engine/preprocess.py`): failed counts, hour, weekend flag, unique IPs, new IP flag, burst rate, recency, activity volume, fail ratio.
2. **Isolation Forest** `score_samples` mapped to `ml_risk` 0–100. Lower sample score = higher risk.
3. **Rules** (capped boost +50): failed-login bursts, 10-minute frequency spikes, off-hours **combined with** other signals, many distinct IPs, restricted-resource probes.
4. **A new IP by itself is informational only** (small boost). It is never labelled malicious on that signal alone.
5. **Severity**: LOW 0–24, MEDIUM 25–49, HIGH 50–74, CRITICAL 75–100.
6. Alerts are stored when prediction is anomalous or risk ≥ 40, then pushed on Socket.IO.

## Sample accounts (created on first run)

| Email | Password | Role |
| --- | --- | --- |
| `admin@soc.local` | `Admin@123` | admin |
| `user@soc.local` | `User@123` | user |

## Local setup (Windows PowerShell)

```powershell
cd $env:USERPROFILE\Projects\soc-ai-platform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m ai_engine.train_model
python app.py
```

Open http://127.0.0.1:5000

Optional MySQL instead of SQLite: set `DATABASE_URL=mysql+pymysql://USER:PASSWORD@HOST:3306/soc_ai` in `.env`. SQLAlchemy creates tables on startup.

### Train the model only

```powershell
python -m ai_engine.train_model
```

If `dataset/security_logs.csv` is missing, training writes a larger synthetic CSV. Classification reports printed during training compare the unsupervised model to **synthetic** labels only.

### Tests

```powershell
pytest -q
```

Covered: registration, login, bad password, lockout after repeated failures, JWT `/me`, user forbidden on admin APIs, token revoke, normal vs anomalous scoring, simulated alert creation, dashboard KPIs.

### Safe test-mode events

Admin page **Threat Detection** or:

```http
POST /api/security/simulate
Authorization: Bearer <admin token>
{ "mode": "anomalous", "email": "user@soc.local", "repeats": 6 }
```

This only inserts rows in the app database. It does not scan networks or attack hosts.

## Azure App Service

1. Create Azure Database for MySQL Flexible Server and a database `soc_ai`.
2. Create a Web App (Python 3.11+ Linux).
3. Configure Application Settings:
   - `FLASK_ENV=production`
   - `SECRET_KEY` (random)
   - `JWT_SECRET_KEY` (random)
   - `JWT_COOKIE_SECURE=true`
   - `EXPOSE_RESET_TOKEN=false`
   - `DATABASE_URL=mysql+pymysql://USER:PASSWORD@HOST:3306/soc_ai`
4. Startup command (also in `azure/startup.txt`):

```
gunicorn --bind 0.0.0.0:8000 --worker-class eventlet -w 1 wsgi:app
```

5. Deploy the repo (Local Git, GitHub Actions, or `az webapp up`).
6. Optional: Azure Blob connection string for future log archival. Core monitoring does not require Blob Storage.

Use TLS to MySQL (`ssl_ca` query parameter) in production. Rotate secrets in App Settings / Key Vault. The app will not work as a real Azure Sentinel replacement; it monitors **this application's** auth telemetry.

## Implementation status

Implemented and wired to the database/API:

- Registration, bcrypt, JWT (header + cookie), logout blocklist, password reset (dev token exposure flag), lockout
- Admin/user RBAC on backend
- Isolation Forest + rule overlay, persisted alerts, Socket.IO notify
- Admin KPI dashboard and Chart.js from `/api/dashboard/admin`
- Monitoring with search/filter/pagination
- CSV and PDF reports
- Azure-ready config (no hardcoded secrets)

Not claimed: live Microsoft 365/Azure AD tenant ingestion, guaranteed detection of real attackers, or production email delivery of reset tokens (set `EXPOSE_RESET_TOKEN=false` and add your own mailer).
>>>>>>> 5aeceaef23432e326a4511ac1320d8e8a6060045
