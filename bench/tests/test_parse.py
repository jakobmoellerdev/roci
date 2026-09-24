import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from harness.parse import parse_go_duration, parse_vegeta, parse_zb  # noqa: E402

# Verbatim zb v2.1.21 tabwriter output shape (README + printStats TTFB lines).
ZB = """Registry URL:      http://localhost:9000
Concurrency Level: 1
Total requests:    100
Working dir:       /tmp/zb

============
Test name:            Push Monolith 1MB
Time taken for tests: 952.336383ms
Requests per second:  105.00491
Complete requests:    100
Failed requests:      0

2xx responses: 100

min: 11.125673ms
max: 26.375356ms
p50: 18.917253ms
p75: 21.753441ms
p90: 24.02137ms
p99: 26.375356ms

============
Test name:            Pull 1MB
Time taken for tests: 1.001s
Requests per second:  99.9
Complete requests:    100
Failed requests:      0

2xx responses: 100

min: 1.1ms
max: 9ms
p50: 2.5ms
p75: 3ms
p90: 4ms
p99: 8.5ms

Manifest HEAD TTFB p50: 402µs
Manifest HEAD TTFB p75: 500µs
Manifest HEAD TTFB p90: 600µs
Manifest HEAD TTFB p99: 900µs

Manifest GET TTFB p50:  855.045µs
Manifest GET TTFB p99:  1.2ms

"""


class GoDuration(unittest.TestCase):
    def test_values(self):
        for s, ms in [("855.045µs", 0.855045), ("1m2.5s", 62500.0), ("3.295887ms", 3.295887),
                      ("5.170570733s", 5170.570733), ("402ns", 0.000402)]:
            self.assertAlmostEqual(parse_go_duration(s), ms, places=9, msg=s)

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            parse_go_duration("12 parsecs")


class Zb(unittest.TestCase):
    def test_two_blocks(self):
        recs = parse_zb(ZB)
        self.assertEqual([r["name"] for r in recs], ["Push Monolith 1MB", "Pull 1MB"])
        self.assertAlmostEqual(recs[0]["rps"], 105.00491)
        self.assertAlmostEqual(recs[0]["p99_ms"], 26.375356)
        self.assertEqual(recs[0]["failed"], 0)
        self.assertNotIn("manifest_get_ttfb_p50", recs[0])
        self.assertAlmostEqual(recs[1]["manifest_get_ttfb_p50"], 0.855045)
        self.assertAlmostEqual(recs[1]["manifest_head_ttfb_p99"], 0.9)


class Vegeta(unittest.TestCase):
    def test_ns_to_ms(self):
        r = parse_vegeta('{"requests":10,"rate":10.0,"throughput":9.9,"status_codes":{"404":10},'
                         '"latencies":{"50th":500000,"90th":900000,"99th":1500000,"max":2000000}}')
        self.assertEqual(r["p99_ms"], 1.5)
        self.assertEqual(r["status_codes"], {"404": 10})
        self.assertEqual(r["requests"], 10)


if __name__ == "__main__":
    unittest.main()
