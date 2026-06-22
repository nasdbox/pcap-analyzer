"""
reporters/json_reporter.py - JSON export
"""

import json
import sys
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger(__name__)


class JSONReporter:
    def __init__(self, results: dict):
        self.results = results

    def render(self, output_file: str = None):
        output = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "tool": "PacketLens v1.0.0",
            **self.results,
        }
        serialized = json.dumps(output, indent=2, default=str)

        if output_file:
            with open(output_file, "w") as f:
                f.write(serialized)
            print(f"JSON report saved to: {output_file}")
        else:
            print(serialized)
