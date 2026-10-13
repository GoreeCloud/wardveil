#!/usr/bin/env python3
"""Fail-closed regression tests for Wardveil Seal gate validation."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import validate_seal_readiness as validator


class SealReadinessNegativeTests(unittest.TestCase):
    def check_bad_record(self, path, mutate, expected):
        actual_read = Path.read_text
        record = json.loads(path.read_text())
        mutate(record)

        def substitute(target, *args, **kwargs):
            if target == path:
                return json.dumps(record)
            return actual_read(target, *args, **kwargs)

        with patch.object(Path, "read_text", substitute):
            with self.assertRaisesRegex(SystemExit, expected):
                validator.main()

    def test_duplicate_gate_rejected(self):
        self.check_bad_record(
            validator.RECORD,
            lambda r: r["gates"].append(r["gates"][0].copy()),
            "gate inventory drifted",
        )

    def test_missing_evidence_rejected(self):
        self.check_bad_record(
            validator.RECORD,
            lambda r: r["gates"][0].update(evidence=["docs/NOT_A_FILE.md"]),
            "evidence path missing or outside repository",
        )

    def test_invalid_source_tree_rejected(self):
        self.check_bad_record(
            validator.CANDIDATE,
            lambda r: r.update(source_tree="invalid"),
            "candidate source_tree must be an exact SHA",
        )


if __name__ == "__main__":
    unittest.main()
