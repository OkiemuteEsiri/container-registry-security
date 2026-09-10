from __future__ import annotations

import argparse
from pathlib import Path
from .assessment import assess
from .io import load_images, render_markdown


def main() -> None:
    parser = argparse.ArgumentParser(description="Assess synthetic container registry inventory against defensive controls.")
    parser.add_argument("inventory")
    parser.add_argument("--output", default="reports/generated-assessment.md")
    args = parser.parse_args()
    result = assess(load_images(args.inventory))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(result), encoding="utf-8")
    print(f"assessed={result['images_assessed']} findings={result['finding_count']} posture={result['posture_score']}")


if __name__ == "__main__":
    main()
