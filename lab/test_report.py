#!/usr/bin/env python3
"""Unit tests for lab/report.py (run by ctest, or: python3 lab/test_report.py)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402


class Wilson(unittest.TestCase):
    def test_known_values(self):
        # 87/100 worked by hand: centre = (0.87 + z²/200) / (1 + z²/100) = 0.8563,
        # half-width = z·sqrt(0.87·0.13/100 + z²/40000) / (1 + z²/100) = 0.0661.
        lo, hi = report.wilson(87, 100)
        self.assertAlmostEqual(lo, 0.7902, places=4)
        self.assertAlmostEqual(hi, 0.9224, places=4)

    def test_edges_stay_in_range(self):
        lo, hi = report.wilson(100, 100)
        self.assertAlmostEqual(hi, 1.0)
        self.assertAlmostEqual(lo, 0.9630, places=4)
        lo, hi = report.wilson(0, 100)
        self.assertAlmostEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.0370, places=4)


class Percentile(unittest.TestCase):
    def test_nearest_rank(self):
        values = list(range(1, 101))
        self.assertEqual(report.percentile(values, 50), 50)
        self.assertEqual(report.percentile(values, 95), 95)
        self.assertEqual(report.percentile([7.0], 95), 7.0)


class EndToEnd(unittest.TestCase):
    def write(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False)
        f.write(text)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_tables_and_splice(self):
        rows = ["natA,natB,attempt,success,time_to_connect_ms,probes_sent,path"]
        rows += [f"full,symmetric-random,{i},{int(i <= 87)},{i if i <= 87 else ''},9,direct"
                 for i in range(1, 101)]
        cells, has_time = report.load([self.write("\n".join(rows) + "\n")], "time_to_connect_ms")
        self.assertTrue(has_time)
        body = report.render(cells, has_time, "Time to connect")
        self.assertIn("| full | — | — | — | 87% [79–92] | — |", body)
        self.assertIn("| full | — | — | — | 44 / 83 | — |", body)
        self.assertIn("n = 100", body)

        readme = "a\n<!-- report:x:start -->\nold\n<!-- report:x:end -->\nb\n"
        out = report.splice(readme, "x", "new")
        self.assertEqual(out, "a\n<!-- report:x:start -->\nnew\n<!-- report:x:end -->\nb\n")

    def test_relay_table_only_when_relayed(self):
        rows = ["natA,natB,attempt,success,time_to_connect_ms,probes_sent,path"]
        rows += [f"full,full,{i},1,40,4,direct" for i in range(1, 11)]
        plain = report.render(*report.load([self.write("\n".join(rows) + "\n")],
                                           "time_to_connect_ms"), "Time to connect")
        self.assertNotIn("Relay usage", plain)
        rows += [f"symmetric-random,symmetric-random,{i},0,3100,300,relay" for i in range(1, 11)]
        body = report.render(*report.load([self.write("\n".join(rows) + "\n")],
                                          "time_to_connect_ms"), "Time to connect")
        self.assertIn("Relay usage", body)
        self.assertIn("| symmetric-random | — | — | — | 100% [72–100] | — |",
                      body.split("Relay usage")[1])

    def test_pivot_by_column(self):
        rows = ["natA,natB,delay_ms,attempt,success,time_to_connect_ms,probes_sent,path"]
        for d in ("200", "0", "50"):
            rows += [f"full,full,{d},{i},1,{10 + i},4,direct" for i in range(1, 11)]
        rows += [f"port-restricted,symmetric-random,0,{i},0,,150,none" for i in range(1, 11)]
        cells, has_time = report.load([self.write("\n".join(rows) + "\n")],
                                      "time_to_connect_ms", by="delay_ms")
        body = report.render(cells, has_time, "Time to connect", by="delay_ms")
        # Columns sorted numerically (0, 50, 200), not as text.
        self.assertIn("| NAT A × NAT B | delay_ms = 0 | delay_ms = 50 | delay_ms = 200 |", body)
        self.assertIn("| full × full | 100% [72–100] | 100% [72–100] | 100% [72–100] |", body)
        self.assertIn("| port-restricted × symmetric-random | 0% [0–28] | — | — |", body)


if __name__ == "__main__":
    unittest.main()
