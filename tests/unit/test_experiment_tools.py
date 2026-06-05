#!/usr/bin/env python3
import csv
import io
import unittest

from scripts import analyze_experiment
from scripts import run_experiment


class ExperimentToolTests(unittest.TestCase):
    def test_build_matrix_has_requested_cases(self):
        names = [case["name"] for case in run_experiment.build_matrix()]

        self.assertIn("local_veth_xdp_encrypt_64", names)
        self.assertIn("local_veth_tc_encrypt_64", names)
        self.assertIn("local_veth_tc_encrypt_decrypt", names)
        self.assertIn("local_veth_tc_encrypt_decrypt_1200", names)

    def test_summarize_parses_metrics_and_cpu_metadata(self):
        data = {
            "results": [
                {
                    "name": "xdp_encrypt",
                    "payload_bytes": 64,
                    "returncode": 0,
                    "duration_sec": 5.2,
                    "stdout": (
                        "seen=10 passed=1 crypto_ok=9 crypto_fail=0 malformed=2\n"
                        "benchmark smoke sent=300 duration=3s pps=100\n"
                    ),
                    "metadata": {"cpu_count": 8, "kernel": "test-kernel"},
                },
                {
                    "name": "xdp_encrypt",
                    "payload_bytes": 64,
                    "returncode": 0,
                    "duration_sec": 5.1,
                    "stdout": (
                        "seen=20 passed=1 crypto_ok=19 crypto_fail=0 malformed=0\n"
                        "benchmark smoke sent=600 duration=3s pps=200\n"
                    ),
                    "metadata": {"cpu_count": 8, "kernel": "test-kernel"},
                },
                {
                    "name": "tc_encrypt_decrypt",
                    "returncode": 0,
                    "duration_sec": 2.5,
                    "stdout": (
                        "1714914\n"
                        '{"type":"packet","action":"encrypt"}\n'
                        '{"type":"packet","action":"decrypt"}\n'
                        "tc udp chat crypto passed\n"
                    ),
                    "metadata": {"cpu_count": 8, "kernel": "test-kernel"},
                },
            ]
        }

        rows = analyze_experiment.summarize(data)

        xdp = next(row for row in rows if row["name"] == "xdp_encrypt")
        self.assertEqual(xdp["pps_min"], 100)
        self.assertEqual(xdp["pps_median"], 150)
        self.assertEqual(xdp["pps_max"], 200)
        self.assertEqual(xdp["crypto_ok"], 28)
        self.assertEqual(xdp["malformed"], 2)
        self.assertEqual(xdp["cpu_count"], 8)
        self.assertEqual(xdp["kernel"], "test-kernel")
        self.assertEqual(xdp["payload_bytes"], 64)

        chat = next(row for row in rows if row["name"] == "tc_encrypt_decrypt")
        self.assertEqual(chat["passed"], True)
        self.assertEqual(chat["samples"], 1)
        self.assertEqual(chat["crypto_ok"], 2)

    def test_write_csv_outputs_presentation_table(self):
        rows = [
            {
                "name": "xdp_encrypt",
                "hook": "xdp",
                "mode": "encrypt",
                "samples": 2,
                "passed": True,
                "pps_min": 100,
                "pps_median": 150,
                "pps_max": 200,
                "crypto_ok": 28,
                "malformed": 2,
                "duration_sec": 10.3,
                "cpu_count": 8,
                "kernel": "test-kernel",
                "payload_bytes": 64,
            }
        ]
        out = io.StringIO()

        analyze_experiment.write_csv(rows, out)

        table = list(csv.DictReader(io.StringIO(out.getvalue())))
        self.assertEqual(table[0]["name"], "xdp_encrypt")
        self.assertEqual(table[0]["pps_median"], "150")
        self.assertEqual(table[0]["crypto_ok"], "28")
        self.assertEqual(table[0]["payload_bytes"], "64")


if __name__ == "__main__":
    unittest.main()
