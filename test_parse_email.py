"""
Tests for parse_email() in solution.py.

Put this file in the same folder as solution.py and run:
    python3 test_parse_email.py

Keep it OUT of solution.py: the autograder runs your main block, and you
only submit solution.py anyway.
"""

import os
import tempfile
import unittest

from solution import parse_email


def write_email(contents, newline="\n"):
    """Write contents to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", newline=newline) as f:
        f.write(contents)
    return path


class TestParseEmail(unittest.TestCase):

    def setUp(self):
        self.paths = []

    def tearDown(self):
        for p in self.paths:
            if os.path.exists(p):
                os.remove(p)

    def make(self, contents, newline="\n"):
        path = write_email(contents, newline)
        self.paths.append(path)
        return path

    # ---------- valid inputs ----------

    def test_spec_example(self):
        path = self.make(
            "From: alice@uwo.ca\n"
            "To: bob@utoronto.ca\n"
            "Subject: Test Email\n"
            "\n"
            "This is the body.\n"
            "With multiple lines.\n"
        )
        sender, recipient, subject, body = parse_email(path)
        self.assertEqual(sender, "alice@uwo.ca")
        self.assertEqual(recipient, "bob@utoronto.ca")
        self.assertEqual(subject, "Test Email")
        self.assertEqual(body, "This is the body.\nWith multiple lines.")

    def test_returns_tuple_of_strings(self):
        path = self.make("From: a@x.ca\nTo: b@y.ca\nSubject: Hi\n\nBody\n")
        result = parse_email(path)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 4)
        for item in result:
            self.assertIsInstance(item, str)

    def test_windows_line_endings(self):
        # Same email saved with \r\n endings
        path = self.make(
            "From: alice@uwo.ca\nTo: bob@lakeheadu.ca\nSubject: CRLF\n\nLine one.\nLine two.\n",
            newline="\r\n",
        )
        sender, recipient, subject, body = parse_email(path)
        self.assertEqual(sender, "alice@uwo.ca")
        self.assertEqual(recipient, "bob@lakeheadu.ca")
        self.assertEqual(subject, "CRLF")
        self.assertNotIn("\r", body)
        self.assertEqual(body, "Line one.\nLine two.")

    def test_headers_in_different_order(self):
        path = self.make("Subject: Reordered\nTo: bob@y.ca\nFrom: alice@x.ca\n\nBody\n")
        sender, recipient, subject, body = parse_email(path)
        self.assertEqual(sender, "alice@x.ca")
        self.assertEqual(recipient, "bob@y.ca")
        self.assertEqual(subject, "Reordered")

    def test_extra_whitespace_after_colon(self):
        path = self.make("From:    alice@x.ca\nTo:   bob@y.ca  \nSubject:   Spaced  \n\nBody\n")
        sender, recipient, subject, _ = parse_email(path)
        self.assertEqual(sender, "alice@x.ca")
        self.assertEqual(recipient, "bob@y.ca")
        self.assertEqual(subject, "Spaced")

    def test_body_keeps_inner_blank_lines(self):
        # Only the FIRST blank line separates headers from body
        path = self.make("From: a@x.ca\nTo: b@y.ca\nSubject: S\n\nPara one.\n\nPara two.\n")
        _, _, _, body = parse_email(path)
        self.assertEqual(body, "Para one.\n\nPara two.")

    def test_subject_containing_colon(self):
        path = self.make("From: a@x.ca\nTo: b@y.ca\nSubject: Re: meeting at 3:00\n\nBody\n")
        _, _, subject, _ = parse_email(path)
        self.assertEqual(subject, "Re: meeting at 3:00")

    # ---------- invalid inputs: must exit with code 1 ----------

    def assert_exits_1(self, path):
        with self.assertRaises(SystemExit) as ctx:
            parse_email(path)
        self.assertEqual(ctx.exception.code, 1)

    def test_missing_file(self):
        self.assert_exits_1("/definitely/not/a/real/file.txt")

    def test_sender_without_at(self):
        self.assert_exits_1(self.make("From: alice.uwo.ca\nTo: b@y.ca\nSubject: S\n\nBody\n"))

    def test_recipient_without_at(self):
        self.assert_exits_1(self.make("From: a@x.ca\nTo: bob\nSubject: S\n\nBody\n"))

    def test_empty_domain(self):
        self.assert_exits_1(self.make("From: a@x.ca\nTo: bob@\nSubject: S\n\nBody\n"))

    def test_empty_user(self):
        self.assert_exits_1(self.make("From: @x.ca\nTo: b@y.ca\nSubject: S\n\nBody\n"))

    def test_missing_from(self):
        self.assert_exits_1(self.make("To: b@y.ca\nSubject: S\n\nBody\n"))

    def test_missing_to(self):
        self.assert_exits_1(self.make("From: a@x.ca\nSubject: S\n\nBody\n"))

    def test_empty_file(self):
        self.assert_exits_1(self.make(""))


if __name__ == "__main__":
    unittest.main(verbosity=2)