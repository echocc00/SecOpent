# Injection Analysis Deliverable

## Overview

Shannon white-box analysis of injection attack surface.

## Findings

### SQL Injection in Login Endpoint - HIGH

Target: http://host.docker.internal:3000/api/login

Severity: HIGH

CWE-89: SQL Injection

The login endpoint concatenates user-supplied `username` directly into a SQL
query without parameterization. An attacker can bypass authentication or
extract database contents via standard UNION-based techniques.

```sql
SELECT * FROM users WHERE username = '$input' AND password = '$hash'
```

### Information Disclosure in Error Messages - LOW

Target: http://host.docker.internal:3000/api/status

Severity: LOW

Verbose error responses expose internal stack traces and database driver
version strings. While not directly exploitable, this aids reconnaissance.
