"""The shared firewall cases (tests/vectors/waf.json): PHP, JavaScript and Python must agree."""
import json
import pathlib
import unittest

from draco_insomnis.waf import flatten, inspect

VECTORS = json.loads((pathlib.Path(__file__).resolve().parents[2] / "tests" / "vectors" / "waf.json").read_text())


def run(req):
    return inspect(req.get("path", ""), req.get("query", ""), req.get("params", []), req.get("userAgent", ""))


class WafVectors(unittest.TestCase):
    def test_attacks_are_recognised_with_the_same_rule(self):
        for case in VECTORS["attacks"]:
            with self.subTest(case["name"]):
                self.assertEqual(run(case["request"]), case["rule"])

    def test_ordinary_requests_pass(self):
        for case in VECTORS["ordinary"]:
            with self.subTest(case["name"]):
                self.assertIsNone(run(case["request"]))

    def test_flatten_reads_keys_and_nested_values(self):
        self.assertEqual(flatten({"a": {"b": ["x", 2, True, False]}, "": "v"}), ["a", "b", "x", "2", "1", "", "v"])


if __name__ == "__main__":
    unittest.main()
