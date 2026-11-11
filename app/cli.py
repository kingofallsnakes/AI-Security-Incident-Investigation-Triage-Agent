import json
import sys
from pathlib import Path

from .models import AlertInput
from .pipeline import InvestigationService


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("examples/sample_alert.json")
    alert = AlertInput.model_validate_json(path.read_text(encoding="utf-8"))
    report = InvestigationService().investigate(alert)
    print(report.model_dump_json(indent=2))
    print("\n" + report.markdown_summary)


if __name__ == "__main__":
    main()
