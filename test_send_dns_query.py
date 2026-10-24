"""
Tests for send_dns_query() in solution.py.

Runs a fake DNS server on 127.0.0.1:1053 in a background thread, so you
don't need the real course server. Put this file next to solution.py and run:
    python3 test_send_dns_query.py

Note: the timeout tests take about 3 seconds each (your timeout value).
If you see "Address already in use", something else is on port 1053:
stop it and rerun.
"""

import socket
import threading
import time
import unittest

from solution import send_dns_query

HOST = "127.0.0.1"
PORT = 1053


class FakeDnsServer:
    """
    UDP server on port 1053. Behaviour is set per test:
      mode = "reply"  -> send back self.reply_bytes
      mode = "silent" -> receive the query but never answer (forces a timeout)
    Every query received is stored in self.received.
    """

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, PORT))
        self.sock.settimeout(0.2)
        self.mode = "reply"
        self.reply_bytes = b""
        self.received = []
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            self.received.append(data)
            if self.mode == "reply":
                self.sock.sendto(self.reply_bytes, addr)

    def stop(self):
        self.running = False
        self.thread.join(timeout=1)
        self.sock.close()


# A valid MX response for "utoronto.ca" (ID 18), built by hand from the spec:
# ID + QNAME echo + QCODE(0) + ANSWER_LEN + "smtp.utoronto.ca" label-encoded
MX_QUERY = b"\x12\x08utoronto\x02ca\x00\x0f"
MX_ANSWER = b"\x04smtp\x08utoronto\x02ca\x00"
MX_RESPONSE = b"\x12" + b"\x08utoronto\x02ca\x00" + b"\x00" + bytes([len(MX_ANSWER)]) + MX_ANSWER

# A valid A response for "smtp.utoronto.ca" (ID 19) -> 127.0.0.1
A_QUERY = b"\x13\x04smtp\x08utoronto\x02ca\x00\x01"
A_RESPONSE = b"\x13" + b"\x04smtp\x08utoronto\x02ca\x00" + b"\x00\x04" + b"\x7f\x00\x00\x01"


class TestSendDnsQuery(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = FakeDnsServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.server.mode = "reply"
        self.server.received.clear()

    # ---------- normal replies ----------

    def test_returns_server_reply_exactly(self):
        self.server.reply_bytes = MX_RESPONSE
        self.assertEqual(send_dns_query(HOST, MX_QUERY), MX_RESPONSE)

    def test_returns_bytes(self):
        self.server.reply_bytes = A_RESPONSE
        self.assertIsInstance(send_dns_query(HOST, A_QUERY), bytes)

    def test_server_receives_query_unchanged(self):
        self.server.reply_bytes = MX_RESPONSE
        send_dns_query(HOST, MX_QUERY)
        time.sleep(0.05)
        self.assertEqual(self.server.received, [MX_QUERY])

    def test_sends_exactly_one_packet(self):
        self.server.reply_bytes = A_RESPONSE
        send_dns_query(HOST, A_QUERY)
        time.sleep(0.05)
        self.assertEqual(len(self.server.received), 1)

    def test_error_response_is_still_returned(self):
        # QCODE=1 responses are parse_dns_response's job to reject,
        # send_dns_query should just hand the bytes back.
        msg = b"domain not found"
        err = b"\x12" + b"\x08utoronto\x02ca\x00" + b"\x01" + bytes([len(msg)]) + msg
        self.server.reply_bytes = err
        self.assertEqual(send_dns_query(HOST, MX_QUERY), err)

    def test_two_queries_in_a_row(self):
        # main() sends the MX query, then the A query
        self.server.reply_bytes = MX_RESPONSE
        self.assertEqual(send_dns_query(HOST, MX_QUERY), MX_RESPONSE)
        self.server.reply_bytes = A_RESPONSE
        self.assertEqual(send_dns_query(HOST, A_QUERY), A_RESPONSE)

    # ---------- errors: must exit with code 1 ----------

    def assert_exits_1(self, *args):
        with self.assertRaises(SystemExit) as ctx:
            send_dns_query(*args)
        self.assertEqual(ctx.exception.code, 1)

    def test_timeout_when_server_never_answers(self):
        self.server.mode = "silent"
        start = time.time()
        self.assert_exits_1(HOST, MX_QUERY)
        elapsed = time.time() - start
        # Should give up after your timeout, not hang forever
        self.assertLess(elapsed, 10, "took too long: is a timeout set?")

    def test_invalid_ip_string(self):
        self.assert_exits_1("999.999.999.999", MX_QUERY)

    def test_garbage_hostname(self):
        self.assert_exits_1("not a real host!!", MX_QUERY)


if __name__ == "__main__":
    unittest.main(verbosity=2)