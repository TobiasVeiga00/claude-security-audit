---
name: cloud
description: Cloud and infrastructure-as-code security — IAM least privilege, public exposure, encryption, logging, and CIS-benchmark posture across AWS, Azure and GCP, plus Terraform, CloudFormation, Kubernetes and container configuration. Use for "audit my AWS", "check my Terraform", "cloud misconfiguration", "is my S3 bucket public", "Kubernetes security".
argument-hint: "[path or --provider aws|azure|gcp]"
allowed-tools: Read, Glob, Grep, Write, Bash(node:*), Bash(git:*), Bash(checkov:*), Bash(trivy:*), Bash(kics:*), Bash(prowler:*), Bash(kubescape:*), Bash(hadolint:*)
---

# Cloud and infrastructure security

Two modes. **Static** review of infrastructure-as-code needs no authorization —
it is reading files. **Live** posture assessment queries a real account and does.
Know which one you are doing before you run anything.

Tooling:
!`node "${CLAUDE_PLUGIN_ROOT}/scripts/tools.mjs" --domain iac,container,cloud --missing 2>&1 | head -14`

---

## Static: infrastructure as code

Run what is present; parse through the importer so raw output never enters the
conversation:

```bash
checkov -d . -o json > .security-audit/checkov.json 2>/dev/null
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" import --tool checkov --file .security-audit/checkov.json

trivy config . --format json -o .security-audit/trivy-iac.json 2>/dev/null
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" import --tool trivy --file .security-audit/trivy-iac.json
```

`trivy config` is the successor to `tfsec`, which is now folded into Trivy. Do
not reach for `tfsec` or `terrascan` — both are retired.

The surface mapper already flags the high-signal Terraform, Kubernetes,
Dockerfile and GitHub Actions patterns with line numbers, so start from those
hotspots and confirm each in context.

### What matters most

- **Public exposure.** `0.0.0.0/0` ingress, `public-read` buckets,
  `publicly_accessible = true` databases, security groups open to the world.
  This is where real breaches begin.
- **IAM over-permission.** `"Action": "*"`, `"Resource": "*"`, `"Principal":
  "*"`, wildcard Kubernetes RBAC. Least privilege is the whole game.
- **Encryption off.** `encrypted = false`, missing KMS keys, disabled key
  rotation, unencrypted storage or transit.
- **Instance metadata (IMDS) hardening.** On AWS, an instance whose
  `metadata_options` has `http_tokens = "optional"` (or none set) leaves IMDSv1
  reachable — the SSRF-to-credential pivot behind the Capital One breach.
  Require IMDSv2 (`http_tokens = "required"`) and a low
  `http_put_response_hop_limit` (1). The parallel elsewhere: legacy metadata
  endpoints on GCP, and unrestricted IMDS reachable from a compromised app on
  Azure.
- **Logging off.** No CloudTrail, no flow logs, no audit logging — this is what
  makes an incident un-investigable (OWASP A09:2025).
- **Secrets in IaC.** Credentials as literals in Terraform, or a Dockerfile
  `ENV`/`ARG` — route those to `/security-audit:secrets`.

### Containers and CI

- **Dockerfile:** no `USER` (runs as root), unpinned base image, remote fetch
  without integrity, `curl | sh`, secrets baked into layers.
- **Kubernetes:** `privileged: true`, `hostNetwork`/`hostPID`/`hostIPC`,
  dangerous capabilities (`SYS_ADMIN`, `NET_ADMIN`), `runAsUser: 0`, wildcard
  RBAC, automounted service-account tokens.
- **GitHub Actions:** the highest-value CI finding is `pull_request_target`
  checking out and running untrusted PR code, and untrusted `github.event.*`
  values interpolated into a `run:` script (script injection). Also unpinned
  actions (a tag can be moved) and `permissions: write-all`. Maps to the OWASP
  CI/CD Top 10, CICD-SEC-4.

## Live: cloud posture

Requires an authenticated session and rules of engagement:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/scope.mjs" check "prowler aws"
prowler aws -M json-ocsf -o .security-audit/prowler 2>/dev/null
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" import --tool prowler --file .security-audit/prowler/<output>.ocsf.json
```

Prowler is the primary multi-cloud posture tool (AWS, Azure, GCP, Kubernetes,
M365) with CIS, PCI, NIST and ISO mappings built in. Its output is large, so the
`prowler` importer parses the OCSF file into the ledger (keeping only the FAILs)
rather than letting the raw report into the conversation. Then rank by the
criteria below; never paste the whole report.

Ranking for live findings: internet-reachable before internal · data-bearing
before empty · identity and key management before everything else · a finding
that defeats logging (so you would not see the next attack) is worse than it
first looks.

## Recording

`domain: "iac"` for code, `"container"` for image and Kubernetes, `"cloud"` for
live-account findings. Put the resource in `location.resource` and the region in
`location.region`. Map to CIS benchmark items where the tool provides them, and
remediation must name the exact setting to change.
