# Container Registry Security Lab

A defensive security-engineering project that assesses container registry posture using synthetic artifact metadata. The project demonstrates how to evaluate software-supply-chain integrity, vulnerability governance, registry exposure, artifact lifecycle hygiene, and remediation validation without interacting with live registries.

## Problem statement

Container registries often become a weak point in the software delivery chain when teams allow mutable tags, unsigned images, unsupported base images, missing SBOMs, excessive public exposure, stale artifacts, or unresolved critical vulnerabilities. These conditions increase the likelihood that vulnerable or untrusted artifacts reach runtime environments.

This lab turns those conditions into deterministic, evidence-preserving findings that can be prioritized and revalidated.

## What this project demonstrates

- defensive container registry security assessment
- immutable, validated security domain models
- fail-closed input validation and duplicate detection
- explainable control evaluation
- severity-weighted posture scoring
- software-supply-chain risk analysis
- vulnerability and base-image governance
- SBOM and image-signing controls
- public exposure and ownership checks
- stale artifact detection
- Markdown reporting
- synthetic test fixtures
- unit testing and CI/CD security quality gates
- remediation and validation workflow design

## Architecture

```text
Synthetic JSON inventory
        |
        v
src/io.py
  ingestion
        |
        v
src/models.py
  validation + identity controls
        |
        v
src/assessment.py
  deterministic defensive controls
        |
        +--> severity / evidence / ATT&CK context
        |
        v
src/io.py
  Markdown reporting
        |
        v
Assessment report
```

See [`docs/architecture.md`](docs/architecture.md) for the full methodology and control design.

## Implemented controls

| ID | Control | Risk focus |
|---|---|---|
| REG-001 | Public artifact exposure | unintended registry access |
| REG-002 | Missing trusted image signature | software supply-chain integrity |
| REG-003 | Missing SBOM | component transparency |
| REG-004 | Mutable release tags | artifact integrity and drift |
| REG-005 | Critical vulnerabilities | severe exploitable exposure |
| REG-006 | High-vulnerability concentration | remediation backlog risk |
| REG-007 | Unsupported base image | lifecycle and patchability |
| REG-008 | Missing artifact ownership | accountability and remediation routing |
| REG-009 | Stale image age | lifecycle hygiene |

## MITRE ATT&CK context

- **T1195.002 – Compromise Software Supply Chain**: relevant to unsigned or mutable artifacts and weak provenance controls.
- **T1190 – Exploit Public-Facing Application**: relevant where vulnerable containerized workloads could later be externally exposed.

These mappings provide defensive threat context only. A control failure is not evidence that compromise occurred.

## Repository structure

```text
.github/workflows/security-quality.yml
 data/synthetic_registry_inventory.json
 docs/architecture.md
 reports/example-assessment.md
 src/models.py
 src/assessment.py
 src/io.py
 src/cli.py
 tests/test_assessment.py
```

## Usage

Python 3.11+ is sufficient; there are no third-party runtime dependencies.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_registry_inventory.json --output reports/generated-assessment.md
```

The CLI prints a compact summary and writes a detailed Markdown assessment.

## Design principles

### Evidence before conclusion
Every finding preserves the condition that triggered it. The engine does not infer compromise from exposure.

### Deterministic scoring
The posture score is intentionally simple and explainable. It is an engineering prioritization aid, not a predictive breach model.

### Fail-closed inventory handling
Malformed timestamps, invalid digests, negative vulnerability counts, and duplicate artifact identities are rejected rather than silently normalized into potentially misleading findings.

### Remediation must be revalidated
Findings should be closed only after the affected digest or registry control is changed and the updated metadata passes reassessment.

## Example remediation workflow

1. assign the finding to the accountable service owner
2. rebuild using a supported minimal base image
3. remediate package vulnerabilities
4. generate an SBOM bound to the exact digest
5. sign the rebuilt image
6. enforce signature verification
7. enable immutable release tags
8. restrict unnecessary public access
9. rescan and reassess the new digest
10. retain validation evidence before closure

## CI/CD security checks

The GitHub Actions workflow uses least-privilege `contents: read` permissions and performs:

- Python source compilation
- unit-test execution
- synthetic assessment smoke test
- report-generation validation

## Synthetic data

All inventory data in this repository is synthetic and intentionally uses example domains and non-production metadata. No employer, client, or production environment information is included.

## Limitations

This project does not connect to AWS ECR, Azure Container Registry, Google Artifact Registry, Docker Hub, Kubernetes clusters, admission controllers, or commercial vulnerability scanners. It performs no image extraction, exploitation, secret harvesting, credential collection, or runtime attack simulation.

The scoring model is deliberately transparent and compact. Production programs would normally integrate richer threat intelligence, exploitability data, business criticality, policy exceptions, deployment context, and scanner confidence.

## Skills demonstrated

- container and cloud security engineering
- software supply-chain security
- vulnerability management
- security-control design
- Python security automation
- defensive risk scoring
- secure data validation
- security reporting
- remediation governance
- CI/CD security engineering
- MITRE ATT&CK contextual mapping

## Roadmap

Future safe extensions may include:

- registry-provider adapters using exported metadata rather than live credentials
- policy-as-code controls for admission decisions
- SBOM component-risk correlation
- signature-policy simulation
- remediation SLA tracking
- approved exception workflows
- trend metrics across synthetic assessment snapshots
- SARIF or machine-readable report export

## Safety statement

This repository is intentionally defensive. It contains no live credentials, production targeting, exploit payloads, credential-theft logic, malware, persistence mechanisms, or unsafe offensive automation.
