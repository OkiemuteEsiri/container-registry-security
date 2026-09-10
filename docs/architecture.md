# Architecture and Methodology

## Objective

This project models a defensive container-registry security review using synthetic inventory only. It is designed to demonstrate how a security engineer can normalize artifact metadata, evaluate preventive and detective controls, prioritize findings, and produce auditable remediation guidance without interacting with live registries.

## Data flow

1. JSON inventory is loaded through `src/io.py`.
2. `ImageRecord` validates identity, timestamps, digests, and vulnerability counts.
3. `validate_unique_images` rejects duplicate registry/repository/digest identities.
4. `src/assessment.py` applies deterministic security controls.
5. Findings preserve evidence, severity, remediation, and ATT&CK context.
6. `render_markdown` creates a portable assessment report.

## Control methodology

The implemented control set covers four security domains:

- **Artifact integrity:** trusted signatures, immutable tags, digest-oriented deployment.
- **Software supply chain transparency:** SBOM availability and supported base images.
- **Exposure reduction:** public repository visibility and stale artifact governance.
- **Vulnerability governance:** critical/high vulnerability concentration and accountable ownership.

The assessment deliberately separates security posture from evidence of compromise. A vulnerable, unsigned, or public image is an exposure condition; it is not proof that exploitation occurred.

## Risk model

Each finding is assigned a deterministic severity. A bounded posture score is derived from severity weights to provide an executive summary while preserving individual evidence for engineering remediation. The score is intentionally simple and explainable rather than a predictive model.

## MITRE ATT&CK context

- **T1195.002 – Compromise Software Supply Chain: Compromise Software Supply Chain**: contextual relevance for unsigned or mutable artifacts.
- **T1190 – Exploit Public-Facing Application**: contextual relevance where vulnerable containerized services may be externally exposed after deployment.

Mappings indicate plausible defensive relevance only and do not imply adversary activity.

## Remediation and validation workflow

1. Assign the finding to the accountable service owner.
2. Rebuild the image from a supported base and remediated dependencies where required.
3. Generate an SBOM for the exact digest.
4. Sign the artifact and verify trust policy enforcement.
5. Enforce immutable release tags and deploy by digest.
6. Restrict registry visibility to intended principals.
7. Rescan the rebuilt artifact.
8. Re-run this assessment against updated metadata.
9. Close only when the failing condition is no longer present and evidence is retained.

## Limitations

This lab does not connect to AWS ECR, Azure Container Registry, Google Artifact Registry, Docker Hub, Kubernetes clusters, admission controllers, or production scanners. It does not perform image extraction, exploit testing, secret harvesting, or runtime compromise validation.
