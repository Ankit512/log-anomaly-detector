#!/usr/bin/env python3
"""
test_intake.py — the safe-intake flow is network-free, redacted by default,
and honest about empty/unrecognized input.

    python3 tests/test_intake.py

Network-free is enforced, not assumed: urllib.request.urlopen is replaced for
every test, so ANY attempted HTTP call fails the test outright. Fixtures are
the eval suite's own case files — real inputs with known behavior.
"""

import hashlib
import io
import sys
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import intake  # noqa: E402

CASES = ROOT / "tests" / "eval" / "cases"
BRUTE_LOG = CASES / "fmt_bruteforce_canonical.log"      # 6 failures: rule fires
UNRECOGNIZED_LOG = CASES / "neg_unrecognized_format.log"
EMPTY_LOG = CASES / "neg_empty.log"

# Values that appear verbatim in the brute-force fixture and must NOT appear
# in anything marked safe-to-share.
RAW_IP = "198.51.100.20"
RAW_USER = "'admin'"
RAW_HOST = "server-01"

FROZEN_DETECTOR_SHA = "43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05"


def _no_network(*args, **kwargs):
    raise AssertionError("network call attempted during intake — flow must be local-only")


def _run(log_path, out_dir):
    with redirect_stdout(io.StringIO()):
        return intake.run_intake(str(log_path), str(out_dir))


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self._urlopen = urllib.request.urlopen
        urllib.request.urlopen = _no_network
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name)

    def tearDown(self):
        urllib.request.urlopen = self._urlopen
        self._tmp.cleanup()

    def test_redacted_by_default(self):
        """The shareable outputs carry placeholders, never the raw IP/user/host."""
        result = _run(BRUTE_LOG, self.out)
        md = result["paths"]["redacted_md"].read_text()
        html = result["paths"]["redacted_html"].read_text()
        # The console template carries fictional built-in demo data ('admin',
        # server-01, 203.0.113.44) that standalone mode never renders; the run's
        # actual content is the injected CONSOLE_DATA payload — assert on that.
        payload = next(line for line in html.splitlines()
                       if line.startswith("window.CONSOLE_DATA"))

        for artifact, name in ((md, "markdown"), (payload, "html payload")):
            self.assertNotIn(RAW_IP, artifact, f"raw IP leaked into redacted {name}")
            self.assertNotIn(RAW_USER, artifact, f"raw username leaked into redacted {name}")
            self.assertNotIn(RAW_HOST, artifact, f"raw hostname leaked into redacted {name}")

        self.assertIn("[IP-", md, "expected an IP placeholder in the findings report")
        self.assertIn("[USER-", md, "expected a username placeholder in the findings report")
        self.assertGreater(result["counts"]["IP"], 0)
        self.assertGreater(result["counts"]["USER"], 0)
        self.assertGreater(result["counts"]["HOST"], 0)

        # The run found something real: the fixture's brute-force rule fires.
        self.assertGreater(len(result["state"]["findings"]), 0)
        # And the local (unredacted) report still exists for the log owner.
        self.assertIn(RAW_IP, result["paths"]["local_json"].read_text())

    def test_unrecognized_format_is_honest(self):
        """0 lines parsed -> the report says so; no findings are fabricated."""
        result = _run(UNRECOGNIZED_LOG, self.out)
        md = result["paths"]["redacted_md"].read_text()

        self.assertTrue(result["state"]["unrecognized"])
        self.assertIn("FORMAT NOT RECOGNIZED", md)
        self.assertIn("NOT an all-clear", md)
        self.assertEqual(result["state"]["linesParsed"], 0)
        self.assertEqual(len(result["state"]["findings"]), 0,
                         "no rule ran, so no finding may exist")
        self.assertIn("**Findings:** 0", md)

    def test_empty_input_is_honest(self):
        """An empty file -> 'EMPTY INPUT', not a clean bill of health."""
        result = _run(EMPTY_LOG, self.out)
        md = result["paths"]["redacted_md"].read_text()

        self.assertTrue(result["state"]["emptyInput"])
        self.assertIn("EMPTY INPUT", md)
        self.assertIn("NOT an all-clear", md)
        self.assertEqual(len(result["state"]["findings"]), 0)

    def test_detector_is_frozen(self):
        """Guardrail: the intake path never touches the frozen detector."""
        sha = hashlib.sha256((ROOT / "anomaly_detector.py").read_bytes()).hexdigest()
        self.assertEqual(sha, FROZEN_DETECTOR_SHA)


if __name__ == "__main__":
    unittest.main(verbosity=2)
