#!/usr/bin/env python3
"""Unit tests for lab/report.py (run by ctest, or: python3 lab/test_report.py)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ci_check  # noqa: E402
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

    def test_upgrade_table(self):
        rows = ["natA,natB,attempt,initial_path,upgrade_ms"]
        rows += ["symmetric-random,port-restricted,1,direct,",
                 "symmetric-random,port-restricted,2,relay,5100",
                 "symmetric-random,port-restricted,3,relay,10200",
                 "symmetric-random,port-restricted,4,relay,"]
        body = report.render_upgrade([self.write("\n".join(rows) + "\n")])
        # 3 started on the relay, 2 upgraded; median of [5100, 10200] by nearest rank is 5100.
        self.assertIn("| symmetric-random × port-restricted | 3 | 67% [21–94] | 5100 / 10200 |", body)

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


class CiCheck(unittest.TestCase):
    def write(self, rows):
        f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False)
        f.write("natA,natB,attempt,success,time_to_connect_ms,probes_sent,path\n")
        f.write("\n".join(rows) + "\n")
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def rows(self, a, b, ok, n, fail_path="relay"):
        return [f"{a},{b},{i},{int(i <= ok)},,1,{'direct' if i <= ok else fail_path}"
                for i in range(1, n + 1)]

    def test_binom_cdf(self):
        self.assertAlmostEqual(ci_check.binom_cdf(10, 10, 0.3), 1.0)
        self.assertAlmostEqual(ci_check.binom_cdf(0, 2, 0.5), 0.25)

    def test_tolerates_noise_fails_on_regression(self):
        ref = self.write(self.rows("full", "full", 100, 100) +
                         self.rows("symmetric-random", "port-restricted", 64, 100))
        # 8/10 against 100/100 passes, 7/10 fails; 3/10 against 64/100 passes, 1/10 fails.
        self.assertEqual(ci_check.check(ref, self.write(self.rows("full", "full", 8, 10))), [])
        self.assertEqual(len(ci_check.check(ref, self.write(self.rows("full", "full", 7, 10)))), 1)
        self.assertEqual(ci_check.check(
            ref, self.write(self.rows("symmetric-random", "port-restricted", 3, 10))), [])
        self.assertEqual(len(ci_check.check(
            ref, self.write(self.rows("symmetric-random", "port-restricted", 1, 10)))), 1)

    def test_lost_relay_fallback_fails(self):
        ref = self.write(self.rows("symmetric-random", "symmetric-random", 0, 100))
        run = self.write(self.rows("symmetric-random", "symmetric-random", 0, 10, fail_path="none"))
        self.assertEqual(len(ci_check.check(ref, run)), 1)


if __name__ == "__main__":
    unittest.main()
