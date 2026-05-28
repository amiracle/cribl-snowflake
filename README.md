# Cribl Pack for Snowflake (v1.1.0)

Cribl Stream collector pack that gathers security and audit data from Snowflake via the SQL REST API (`/api/v2/statements`).

## Quick Start with Snowflake Notebook

A Jupyter notebook (`snowflake_workspace.ipynb`) is included to help you set up the Snowflake environment for this pack. Import it into your Snowflake SQL Worksheet or run it locally to:

1. Create the OAuth security integration
2. Test the SQL queries used by each collector
3. Set up the JWT key pair authentication (optional)
4. Validate the `CRIBL_COLLECTOR` user and RSA key assignment
5. Verify your account and organization identifiers

To use it in Snowflake:
1. Open **Projects > Notebooks** in Snowsight
2. Click **Import .ipynb file**
3. Select `snowflake_workspace.ipynb`
4. Follow the steps in order for your chosen authentication method

## Data Collected

| Collector | View | Schedule | Sourcetype |
|-----------|------|----------|------------|
| Login History | `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY` | Every 5 min | `snowflake:login` |
| Query History | `SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY` | Every 5 min | `snowflake:query` |
| Access History | `SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY` | Every 15 min | `snowflake:access` |
| Sessions | `SNOWFLAKE.ACCOUNT_USAGE.SESSIONS` | Every 15 min | `snowflake:session` |

## Prerequisites

- Cribl Stream 4.17.0 or later
- Snowflake account with `ACCOUNT_USAGE` access
- One of the supported authentication methods configured (see below)

## Authentication Methods

This pack supports two authentication methods for the Snowflake SQL REST API:

| Method | Best For | Token Lifetime | Requires External Process |
|--------|----------|---------------|--------------------------|
| **OAuth2 Refresh Token** | Production deployments | Long-lived (refresh token persists) | One-time browser auth |
| **Key Pair JWT** | Fully automated / no browser | 60 min max | Yes (cron to regenerate JWT) |

---

## Method 1: OAuth2 Refresh Token (Recommended)

This is the recommended approach for Cribl REST collection. After a one-time interactive authorization, the collector uses a long-lived refresh token to automatically obtain fresh access tokens on every run.

### Step 1: Create Security Integration

```sql
USE ROLE ACCOUNTADMIN;

CREATE SECURITY INTEGRATION cribl_oauth
  TYPE = OAUTH
  ENABLED = TRUE
  OAUTH_CLIENT = CUSTOM
  OAUTH_CLIENT_TYPE = 'CONFIDENTIAL'
  OAUTH_REDIRECT_URI = 'https://localhost'
  OAUTH_ISSUE_REFRESH_TOKENS = TRUE
  OAUTH_ENFORCE_PKCE = FALSE;

-- Unblock roles for use with this integration
ALTER SECURITY INTEGRATION cribl_oauth SET BLOCKED_ROLES_LIST = ();
```

### Step 2: Get Client Credentials

```sql
SELECT SYSTEM$SHOW_OAUTH_CLIENT_SECRETS('CRIBL_OAUTH');
```

This returns `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET`.

### Step 3: Create a Dedicated Role

```sql
CREATE ROLE IF NOT EXISTS CRIBL_COLLECTOR_ROLE;
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE CRIBL_COLLECTOR_ROLE;
GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE CRIBL_COLLECTOR_ROLE;
GRANT ROLE CRIBL_COLLECTOR_ROLE TO USER <your_user>;
```

### Step 4: Authorize via Browser (One-Time)

Open this URL in your browser (replace `<client_id>` with your URL-encoded client ID):

```
https://<account_identifier>.snowflakecomputing.com/oauth/authorize?response_type=code&client_id=<client_id>&redirect_uri=https%3A%2F%2Flocalhost&scope=session%3Arole%3ACRIBL_COLLECTOR_ROLE
```

After login, you'll be redirected to `https://localhost?code=<AUTH_CODE>`. Copy the `code` value.

### Step 5: Exchange Code for Tokens

```bash
curl -X POST \
  'https://<account_identifier>.snowflakecomputing.com/oauth/token-request' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&code=<AUTH_CODE>&client_id=<url_encoded_client_id>&client_secret=<url_encoded_client_secret>&redirect_uri=https%3A%2F%2Flocalhost'
```

Save the `refresh_token` from the response (include the `ver:2:` prefix — it's part of the token).

### Step 6: Configure Pack Variables

| Variable | Value |
|----------|-------|
| `snowflake_account_identifier` | Your account identifier (e.g., `zgjymzt-nec65309`) |
| `snowflake_client_id` | OAuth Client ID from Step 2 |
| `snowflake_client_secret` | OAuth Client Secret from Step 2 |
| `snowflake_refresh_token` | Refresh token from Step 5 |
| `snowflake_warehouse` | Warehouse name (e.g., `COMPUTE_WH`) |
| `snowflake_role` | Role name (e.g., `CRIBL_COLLECTOR_ROLE`) |

### How It Works

1. On each collection run, Cribl posts the refresh token to `/oauth/token-request` with `grant_type=refresh_token`
2. Snowflake returns a fresh `access_token`
3. Cribl uses the access token with `Authorization: Bearer <token>` and `X-Snowflake-Authorization-Token-Type: OAUTH` headers
4. The SQL query is sent as a POST body to `/api/v2/statements`

---

## Method 2: Key Pair JWT

Use this method for fully automated deployments where no interactive browser login is possible. Requires an external process to regenerate the JWT before it expires (max 60 minutes).

### Step 1: Generate RSA Key Pair

```bash
# Generate private key
openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt

# Generate public key
openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
```

### Step 2: Assign Public Key to Snowflake User

```sql
USE ROLE ACCOUNTADMIN;

CREATE USER IF NOT EXISTS cribl_collector
  TYPE = SERVICE
  DEFAULT_ROLE = CRIBL_COLLECTOR_ROLE
  DEFAULT_WAREHOUSE = COMPUTE_WH;

-- Assign the public key (paste contents without BEGIN/END header/footer)
ALTER USER cribl_collector SET RSA_PUBLIC_KEY='MIIBIjANBgkqh...your_key_here...';

-- Grant access
CREATE ROLE IF NOT EXISTS CRIBL_COLLECTOR_ROLE;
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE CRIBL_COLLECTOR_ROLE;
GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE CRIBL_COLLECTOR_ROLE;
GRANT ROLE CRIBL_COLLECTOR_ROLE TO USER cribl_collector;
```

### Step 3: Generate JWT Token

```python
#!/usr/bin/env python3
"""Generate a Snowflake JWT for key pair authentication."""
import hashlib
import base64
import time
import jwt  # pip install PyJWT cryptography
from cryptography.hazmat.primitives import serialization

# Configuration
ACCOUNT = "MYORG-MYACCOUNT"  # Uppercase account identifier
USER = "CRIBL_COLLECTOR"      # Uppercase username
PRIVATE_KEY_PATH = "rsa_key.p8"

# Load private key
with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Get public key fingerprint
public_key_bytes = private_key.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo
)
sha256_hash = hashlib.sha256(public_key_bytes).digest()
fingerprint = "SHA256:" + base64.b64encode(sha256_hash).decode()

# Build JWT
now = int(time.time())
payload = {
    "iss": f"{ACCOUNT}.{USER}.{fingerprint}",
    "sub": f"{ACCOUNT}.{USER}",
    "iat": now,
    "exp": now + 3600,  # 60 minutes
}

token = jwt.encode(payload, private_key, algorithm="RS256")
print(token)
```

### Step 4: Configure Pack Variables and UI Settings

1. Set `snowflake_auth_method` to `jwt`
2. Paste the generated JWT into `snowflake_refresh_token`
3. **Important:** In the Cribl UI, change the **Authentication** dropdown from `Login` to `None` on each collector. The JWT is passed directly as a Bearer token — no token exchange is needed.

The `Authorization` header is automatically set to `Bearer <JWT>` and `X-Snowflake-Authorization-Token-Type` is set to `KEYPAIR_JWT` when `snowflake_auth_method` = `jwt`.

### JWT Token Renewal

The JWT expires after 60 minutes maximum. Automate renewal with a cron job:

```bash
# Example cron job (every 50 minutes)
*/50 * * * * /path/to/generate_jwt.py | curl -s -X PATCH \
  "https://your-cribl-leader:9000/api/v1/m/default/packs/cribl-snowflake-rest-io/vars/snowflake_refresh_token" \
  -H "Authorization: Bearer <cribl_api_token>" \
  -H "Content-Type: application/json" \
  -d "{\"value\": \"$(cat)\"}"
```

---

## Installation

1. Download the `.crbl` pack file or clone this repository
2. In Cribl Stream, navigate to **Processing > Packs**
3. Click **Add Pack** > **Import from File**
4. Upload the pack and configure the required variables

## Configuration Variables

### Required

| Variable | Description |
|----------|-------------|
| `snowflake_account_identifier` | Account identifier for URLs (e.g., `zgjymzt-nec65309` or `lsc79078.us-east-1`) |
| `snowflake_client_id` | OAuth2 Client ID |
| `snowflake_client_secret` | OAuth2 Client Secret (stored encrypted) |
| `snowflake_refresh_token` | Refresh token or JWT (stored encrypted) |
| `snowflake_warehouse` | Warehouse for query execution |
| `snowflake_role` | Role with ACCOUNT_USAGE access |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `default_splunk_index` | `snowflake` | Default destination index |
| `default_splunk_sourcetype` | `snowflake:audit` | Default sourcetype |

## API Details

Each collector issues a POST (with body) to `/api/v2/statements` with a JSON body containing:
- `statement` — SQL query with `DATEADD(day, -7, CURRENT_TIMESTAMP())` time window
- `database` — `SNOWFLAKE`
- `schema` — `ACCOUNT_USAGE`
- `warehouse` — Configured warehouse
- `role` — Configured role

Responses contain a `data` array with row results and `resultSetMetaData` with column definitions.

## Rate Limiting & Retries

- Exponential backoff: 1s initial, 2x multiplier, 20s max
- Retries on HTTP 429 (Too Many Requests) and 503 (Service Unavailable)
- Max 5 retry attempts per request
- Respects `Retry-After` header

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| `invalid_client` | Wrong client_id/secret; ensure special chars are URL-encoded |
| `invalid_grant` | Refresh token expired/revoked, or wrong grant_type for integration type |
| 400 empty body | Ensure `collectMethod` is `post_with_body` (not `post`) |
| 400 from SQL API | Check JSON body format; verify warehouse and role exist |
| 401 Unauthorized | Access token expired; check refresh token is valid |
| 403 Forbidden | Role lacks `IMPORTED PRIVILEGES` on SNOWFLAKE database |
| Parse Error JS Exception | Verify breaker rulesets are empty or match response format |
| Empty results | Check warehouse is running and not suspended |
| Timeout | Increase warehouse size or reduce LIMIT; check `jobTimeout` |

## Important Notes

- Use `collectMethod: post_with_body` (not `post`) — only `post_with_body` sends the request body
- The YAML key for the request body is `collectBody` (not `collectRequestBody`)
- Special characters in client_id/secret (`+`, `/`, `=`) must be URL-encoded using `encodeURIComponent()`
- Snowflake's `OAUTH_CLIENT = CUSTOM` integrations do NOT support `grant_type=client_credentials` — use refresh token or JWT bearer instead

## License

Apache 2.0
