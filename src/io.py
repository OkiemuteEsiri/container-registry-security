from __future__ import annotations

import json
from pathlib import Path
from .models import ImageRecord


def load_images(path: str | Path) -> list[ImageRecord]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("inventory must be a JSON list")
    return [ImageRecord(**item) for item in payload]


def render_markdown(result: dict) -> str:
    lines = [
        "# Container Registry Security Assessment",
        "",
        f"- Images assessed: {result['images_assessed']}",
        f"- Findings: {result['finding_count']}",
        f"- Posture score: {result['posture_score']}/100",
        "",
        "## Findings",
    ]
    for f in result["findings"]:
        lines.extend([
            f"### {f.control_id} — {f.title}",
            f"- Severity: **{f.severity.upper()}**",
            f"- Resource: `{f.resource}`",
            f"- Evidence: {f.evidence}",
            f"- Remediation: {f.remediation}",
            f"- ATT&CK context: {', '.join(f.attack_techniques) if f.attack_techniques else 'N/A'}",
            "",
        ])
    return "\n".join(lines)
