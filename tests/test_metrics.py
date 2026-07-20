import unittest

from cver.benchmark.metrics import set_metrics


class MetricsTest(unittest.TestCase):
    def test_set_metrics(self):
        m = set_metrics(["a", "b"], ["b", "c"])
        self.assertEqual(m["tp"], 1)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["fn"], 1)


if __name__ == "__main__":
    unittest.main()
