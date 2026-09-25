import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from harness import profile as P  # noqa: E402
from harness.report import metric_meta  # noqa: E402

TRACE = """
 Summary of events:

 tokio-rt-worker (101), 40 events, 50.0%

   syscall            calls  errors  total       min       avg       max       stddev
                                     (msec)    (msec)    (msec)    (msec)        (%)
   --------------- --------  ------ -------- --------- --------- ---------     ------
   openat                10      0     1.000     0.050     0.100     0.200      5.00%

 tokio-rt-worker (102), 40 events, 50.0%

   syscall            calls  errors  total       min       avg       max       stddev
                                     (msec)    (msec)    (msec)    (msec)        (%)
   --------------- --------  ------ -------- --------- --------- ---------     ------
   openat                10      0     1.000     0.050     0.100     0.200      5.00%
"""


def summ(roci, zot, key="storm.images_per_s"):
    return {"metrics": {key: {"roci": {"median": roci}, "zot": {"median": zot}}}}


class Stacks(unittest.TestCase):
    def setUp(self):
        self.s = P.parse_folded("main;roci_core::x;sha2::compress 7\nmain;tokio::park 3")

    def test_categorize(self):
        self.assertEqual(P.categorize(self.s), {"hashing": 70.0, "runtime": 30.0})

    def test_self_top(self):
        self.assertEqual(P.self_top(self.s)[0], ("sha2::compress", 7, 70.0))

    def test_inclusive_top(self):
        self.assertEqual(P.inclusive_top(self.s), [("roci_core::x", 7, 70.0)])

    def test_kernel_leaf_wins_first(self):
        self.assertEqual(P.categorize(P.parse_folded("main;roci_x;do_syscall_64_[k] 1")), {"kernel": 100.0})


class Instrumentation(unittest.TestCase):
    def test_strips_profiler_leaves(self):
        kept, pct = P.strip_instrumentation(P.parse_folded("w;roci_x;perf_tp_event_[k] 3\nw;roci_x;memcpy 1"))
        self.assertEqual((kept, pct), ([(["w", "roci_x", "memcpy"], 1)], 75.0))


class Syscalls(unittest.TestCase):
    def test_perf_trace_sums_threads(self):
        self.assertEqual(P.parse_perf_trace_summary(TRACE)["openat"], {"calls": 20, "total_ms": 2.0})

    def test_strace(self):
        txt = ("% time     seconds  usecs/call     calls    errors syscall\n"
               "------ ----------- ----------- --------- --------- ----------------\n"
               " 60.00    0.003000          30       100           fsync\n"
               " 40.00    0.002000          10       200        50 openat\n"
               "100.00    0.005000                   300        50 total\n")
        s = P.parse_strace_summary(txt)
        self.assertEqual(s["fsync"], {"calls": 100, "total_ms": 3.0})
        self.assertEqual(s["openat"]["calls"], 200)
        self.assertNotIn("total", s)


class Metrics(unittest.TestCase):
    def test_delta(self):
        n = "http_server_request_duration_seconds"
        before = f'{n}_sum{{r="a"}} 1\n{n}_count{{r="a"}} 10\n{n}_sum{{r="b"}} 5\n{n}_count{{r="b"}} 3\n'
        after = f'{n}_sum{{r="a"}} 2\n{n}_count{{r="a"}} 20\n{n}_sum{{r="b"}} 5\n{n}_count{{r="b"}} 3\n'
        rows = P.metrics_delta(before, after)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 10)
        self.assertAlmostEqual(rows[0]["mean_ms"], 100.0)
        self.assertEqual(rows[0]["labels"], '{r="a"}')


class Findings(unittest.TestCase):
    def test_kernel_only(self):
        self.assertEqual(P.findings({"storm": {"categories": {"kernel": 60}}}),
                         ["storm: >50% CPU in kernel — syscall/IO-bound; see syscall table"])

    def test_gap_higher_better(self):
        rows = P.gaps(summ(1000, 2000), metric_meta)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["phase"], rows[0]["competitor"]), ("storm", "zot"))
        self.assertTrue(P.findings({}, rows)[0].startswith("gap: `storm.images_per_s`"))

    def test_gap_within_threshold(self):
        self.assertEqual(P.gaps(summ(1000, 1050), metric_meta), [])

    def test_gap_lower_better_direction(self):
        self.assertEqual(P.gaps(summ(10, 20, "storm.p99_ms"), metric_meta), [])
        self.assertEqual(P.gaps(summ(20, 10, "storm.p99_ms"), metric_meta)[0]["phase"], "storm")

    def test_transport_overhead(self):
        d = {"hot": {"vegeta_p50_ms": {"manifest_get": 5.0},
                     "routes": [{"labels": '{http_route="/v2/{name}/manifests/{reference}"}', "mean_ms": 1.0}]}}
        self.assertIn("overhead is in connection/transport", P.findings(d)[0])


if __name__ == "__main__":
    unittest.main()


class CgroupRestart(unittest.TestCase):
    def test_cpu_counter_stays_monotonic_across_restart(self):
        import tempfile
        from harness import cgroup
        d = tempfile.mkdtemp()
        def write(usage):
            open(os.path.join(d, "memory.stat"), "w").write("anon 1\nfile 2\n")
            open(os.path.join(d, "cpu.stat"), "w").write(f"usage_usec {usage}\n")
        write(500)
        s = cgroup.Sampler(d, interval=3600)
        s.stop()
        write(900); s.sample()
        write(100); s.sample()  # container restarted: counter reset
        usages = [x[3] for x in s.samples]
        self.assertEqual(usages[-2:], [900, 1000])
        self.assertEqual(usages, sorted(usages))
