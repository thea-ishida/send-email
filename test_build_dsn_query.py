"""
Tests for build_dns_query() in solution.py.

Put this file next to solution.py and run:
    python3 test_build_dns_query.py

Format from the spec:  ID (1 byte) + QNAME + QTYPE (1 byte)
QNAME = [len (1 byte) + ASCII label] for each label, then 0x00. No dots sent.
"""

import unittest

from solution import build_dns_query


class TestBuildDnsQuery(unittest.TestCase):

    # ---------- exact byte layouts ----------

    def test_spec_qname_example(self):
        # Spec: QNAME for utoronto.ca = 08 75 74 6f 72 6f 6e 74 6f 02 63 61 00
        q = build_dns_query(18, "utoronto.ca", 15)
        expected_qname = bytes([0x08, 0x75, 0x74, 0x6f, 0x72, 0x6f, 0x6e, 0x74,
                                0x6f, 0x02, 0x63, 0x61, 0x00])
        self.assertEqual(q[1:-1], expected_qname)

    def test_full_mx_query_as_main_sends_it(self):
        # main(): build_dns_query(18, domain, 15)
        q = build_dns_query(18, "utoronto.ca", 15)
        self.assertEqual(q, b"\x12" + b"\x08utoronto\x02ca\x00" + b"\x0f")

    def test_full_a_query_as_main_sends_it(self):
        # main(): build_dns_query(19, mx_host, 1)
        q = build_dns_query(19, "smtp.utoronto.ca", 1)
        self.assertEqual(q, b"\x13" + b"\x04smtp\x08utoronto\x02ca\x00" + b"\x01")

    def test_lakeheadu_example(self):
        q = build_dns_query(18, "lakeheadu.ca", 15)
        self.assertEqual(q, b"\x12\x09lakeheadu\x02ca\x00\x0f")

    def test_single_label(self):
        q = build_dns_query(1, "localhost", 1)
        self.assertEqual(q, b"\x01\x09localhost\x00\x01")

    def test_many_labels(self):
        q = build_dns_query(7, "a.bb.ccc.dddd", 15)
        self.assertEqual(q, b"\x07\x01a\x02bb\x03ccc\x04dddd\x00\x0f")

    # ---------- individual fields ----------

    def test_returns_bytes(self):
        self.assertIsInstance(build_dns_query(18, "uwo.ca", 15), bytes)

    def test_id_is_first_byte(self):
        for i in (0, 1, 18, 19, 127, 255):
            self.assertEqual(build_dns_query(i, "uwo.ca", 15)[0], i)

    def test_qtype_is_last_byte(self):
        self.assertEqual(build_dns_query(18, "uwo.ca", 15)[-1], 15)
        self.assertEqual(build_dns_query(18, "uwo.ca", 1)[-1], 1)

    def test_qname_ends_with_null_before_qtype(self):
        q = build_dns_query(18, "uwo.ca", 15)
        self.assertEqual(q[-2], 0x00)

    def test_no_dots_sent(self):
        q = build_dns_query(18, "smtp.utoronto.ca", 1)
        self.assertNotIn(b".", q)

    def test_total_length(self):
        # 1 (ID) + sum(1 + len(label)) + 1 (0x00) + 1 (QTYPE)
        domain = "smtp.utoronto.ca"
        expected_len = 1 + sum(1 + len(l) for l in domain.split(".")) + 1 + 1
        self.assertEqual(len(build_dns_query(19, domain, 1)), expected_len)

    def test_same_input_same_output(self):
        self.assertEqual(build_dns_query(18, "uwo.ca", 15),
                         build_dns_query(18, "uwo.ca", 15))


class OptionalRobustness(unittest.TestCase):
    """
    NOT required by the spec. These only matter if the autograder ever
    passes odd domains. A failure here is not a spec violation.
    """

    def test_trailing_dot_is_ignored(self):
        # "uwo.ca." is a valid fully-qualified name in real DNS.
        # Without handling it, you get an extra empty label (0x00 0x00).
        self.assertEqual(build_dns_query(18, "uwo.ca.", 15),
                         build_dns_query(18, "uwo.ca", 15))


if __name__ == "__main__":
    unittest.main(verbosity=2)