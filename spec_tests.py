"""
Spec checker for the SMTP sender assignment.

Usage:
    python3 spec_tests.py                  # tests ./solution.py
    python3 spec_tests.py path/to/solution.py

Runs two kinds of tests:
  1. Unit tests that import each function and check it against the spec.
  2. End-to-end tests that run `python3 solution.py <email_file>` as a subprocess
     against built-in mock DNS (UDP 1053) and SMTP (TCP 1025) servers.

Ports 1025 and 1053 must be free (stop any other mock server first).
"""
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

SOLUTION = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "solution.py")
TMP = tempfile.mkdtemp()

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))


def exits_1(fn, *args):
    """True if fn(*args) raises SystemExit with code 1."""
    try:
        fn(*args)
    except SystemExit as e:
        return e.code == 1
    except Exception:
        return False
    return False


def write(name, text):
    path = os.path.join(TMP, name)
    with open(path, "w", newline="") as f:
        f.write(text)
    return path


GOOD_EMAIL = (
    "From: alice@uwo.ca\nTo: bob@utoronto.ca\nSubject: Test Email\n\n"
    "This is the body.\nWith multiple lines.\n"
)

# ---------------------------------------------------------------- mock servers
STATE = {"dns_mode": "ok", "smtp_mode": "ok", "dns_log": [], "smtp_log": []}


def enc(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 1053))
    while True:
        data, addr = s.recvfrom(4096)
        STATE["dns_log"].append(data)
        i = 1
        labels = []
        while data[i]:
            labels.append(data[i + 1:i + 1 + data[i]].decode())
            i += 1 + data[i]
        qn, qt, qid = data[1:i + 1], data[i + 1], data[0]
        mode = STATE["dns_mode"]
        if mode == "silent":
            continue
        if mode == "error":
            code, ans = 1, b"Domain not found"
        elif qt == 15:
            code, ans = 0, enc("smtp." + ".".join(labels))
        else:
            code, ans = 0, bytes([127, 0, 0, 1])
        if mode == "badid":
            qid = (qid + 1) % 256
        if mode == "shortA" and qt == 1:
            ans = bytes([127, 0, 0])
        s.sendto(bytes([qid]) + qn + bytes([code, len(ans)]) + ans, addr)


def smtp_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 1025))
    s.listen()
    while True:
        conn, _ = s.accept()
        log = STATE["smtp_log"]
        try:
            with conn, conn.makefile("rw", newline="\n") as f:
                conn.settimeout(3)

                def out(x):
                    f.write(x + "\n")
                    f.flush()

                def inp():
                    line = f.readline()
                    log.append(line)
                    return line.rstrip("\n")

                out("220 utoronto.ca")
                inp()
                out("250 Hello")
                inp()
                out("250 Sender ok")
                inp()
                if STATE["smtp_mode"] == "reject":
                    out("550 No such user")
                    continue
                out("250 Recipient ok")
                inp()
                out("354 Enter mail")
                while inp() not in (".", ""):
                    pass
                out("250 Message accepted for delivery")
                inp()
                out("221 utoronto.ca closing connection")
        except OSError:
            pass


def run(args, dns_mode="ok", smtp_mode="ok"):
    STATE.update(dns_mode=dns_mode, smtp_mode=smtp_mode, dns_log=[], smtp_log=[])
    p = subprocess.run(
        [sys.executable, SOLUTION] + args, capture_output=True, text=True, timeout=20
    )
    time.sleep(0.2)
    return p


# ---------------------------------------------------------------- unit tests
def unit_tests(m):
    # parse_email
    path = write("good.txt", GOOD_EMAIL)
    try:
        r = m.parse_email(path)
        check("parse_email returns 4-tuple of str",
              isinstance(r, tuple) and len(r) == 4 and all(isinstance(x, str) for x in r), repr(r))
        check("parse_email extracts sender/recipient/subject",
              r[:3] == ("alice@uwo.ca", "bob@utoronto.ca", "Test Email"), repr(r[:3]))
        check("parse_email body contains both body lines",
              "This is the body." in r[3] and "With multiple lines." in r[3], repr(r[3]))
    except BaseException as e:
        check("parse_email on valid file", False, repr(e))

    bad_cases = {
        "missing file": os.path.join(TMP, "does_not_exist.txt"),
        "sender without @": write("b1.txt", GOOD_EMAIL.replace("alice@uwo.ca", "alice")),
        "recipient 'bob@'": write("b2.txt", GOOD_EMAIL.replace("bob@utoronto.ca", "bob@")),
        "sender '@uwo.ca'": write("b3.txt", GOOD_EMAIL.replace("alice@uwo.ca", "@uwo.ca")),
        "two @ signs": write("b4.txt", GOOD_EMAIL.replace("alice@uwo.ca", "a@b@uwo.ca")),
        "missing To header": write("b5.txt", GOOD_EMAIL.replace("To: bob@utoronto.ca\n", "")),
        "missing Subject header": write("b6.txt", GOOD_EMAIL.replace("Subject: Test Email\n", "")),
        "no blank line before body": write("b7.txt", GOOD_EMAIL.replace("\n\n", "\n")),
    }
    for label, p in bad_cases.items():
        check(f"parse_email exits 1: {label}", exits_1(m.parse_email, p))

    # build_dns_query (spec example bytes)
    try:
        q = m.build_dns_query(18, "utoronto.ca", 15)
        expected = bytes([18]) + bytes.fromhex("08 75 74 6f 72 6f 6e 74 6f 02 63 61 00") + bytes([15])
        check("build_dns_query matches spec bytes (MX)", q == expected, q.hex(" "))
        q = m.build_dns_query(19, "smtp.utoronto.ca", 1)
        check("build_dns_query matches spec bytes (A)",
              q == bytes([19]) + enc("smtp.utoronto.ca") + bytes([1]), q.hex(" "))
        check("build_dns_query returns bytes", isinstance(q, bytes))
    except BaseException as e:
        check("build_dns_query on valid input", False, repr(e))

    # parse_dns_response
    qn = enc("utoronto.ca")
    mx_ans = enc("smtp.utoronto.ca")
    mx_ok = bytes([18]) + qn + bytes([0, len(mx_ans)]) + mx_ans
    a_ok = bytes([19]) + enc("smtp.utoronto.ca") + bytes([0, 4, 127, 0, 0, 1])
    try:
        check("parse_dns_response MX -> 'smtp.utoronto.ca'",
              m.parse_dns_response(mx_ok, 18, 15) == "smtp.utoronto.ca")
        check("parse_dns_response A -> '127.0.0.1'",
              m.parse_dns_response(a_ok, 19, 1) == "127.0.0.1")
    except BaseException as e:
        check("parse_dns_response on valid input", False, repr(e))

    err = b"Domain not found"
    dns_bad = {
        "wrong ID": (mx_ok, 99, 15),
        "QCODE=1 error": (bytes([18]) + qn + bytes([1, len(err)]) + err, 18, 15),
        "truncated packet": (mx_ok[:-5], 18, 15),
        "empty response": (b"", 18, 15),
        "A answer only 3 bytes": (bytes([19]) + qn + bytes([0, 3, 127, 0, 0]), 19, 1),
    }
    for label, args in dns_bad.items():
        check(f"parse_dns_response exits 1: {label}", exits_1(m.parse_dns_response, *args))

    # send_dns_query with nothing listening on the port
    STATE["dns_mode"] = "silent"
    t = time.time()
    check("send_dns_query exits 1 on timeout",
          exits_1(m.send_dns_query, "127.0.0.1", b"\x01\x00\x01"))
    check("send_dns_query timeout is finite (<10s)", time.time() - t < 10)
    STATE["dns_mode"] = "ok"


# ---------------------------------------------------------------- end-to-end
def e2e_tests():
    good = write("e2e.txt", GOOD_EMAIL)

    p = run([good])
    check("e2e: exit code 0 on success", p.returncode == 0, p.stderr.strip()[-300:])
    queries = STATE["dns_log"]
    check("e2e: sends MX query (QTYPE 15) for recipient domain",
          any(q[1:] == enc("utoronto.ca") + b"\x0f" for q in queries),
          f"{len(queries)} DNS queries seen")
    check("e2e: sends A query (QTYPE 1) for MX host",
          any(q[1:] == enc("smtp.utoronto.ca") + b"\x01" for q in queries))
    expected = [
        "HELO uwo.ca\n", "MAIL FROM: alice@uwo.ca\n", "RCPT TO: bob@utoronto.ca\n",
        "DATA\n", "This is the body.\n", "With multiple lines.\n", ".\n", "QUIT\n",
    ]
    got = STATE["smtp_log"]
    check("e2e: SMTP dialog matches spec exactly (\\n endings)", got == expected,
          "got: " + repr(got))
    check("e2e: no \\r\\n line endings", not any("\r" in l for l in got))

    p = run([good, "127.0.0.1"])
    check("e2e: optional <dns_ip> argument works", p.returncode == 0, p.stderr.strip()[-300:])

    error_cases = [
        ("no arguments", [], "ok", "ok"),
        ("too many arguments", [good, "127.0.0.1", "x"], "ok", "ok"),
        ("missing email file", [os.path.join(TMP, "nope.txt")], "ok", "ok"),
        ("DNS returns QCODE=1", [good], "error", "ok"),
        ("DNS reply has wrong ID", [good], "badid", "ok"),
        ("DNS A answer truncated", [good], "shortA", "ok"),
        ("DNS server silent (timeout)", [good], "silent", "ok"),
        ("SMTP rejects recipient (550)", [good], "ok", "reject"),
    ]
    for label, args, dm, sm in error_cases:
        p = run(args, dm, sm)
        tb = "Traceback" in p.stderr
        check(f"e2e exits 1: {label}", p.returncode == 1 and not tb,
              f"exit={p.returncode}" + (" (traceback printed)" if tb else ""))


# ---------------------------------------------------------------- static checks
def static_checks():
    src = open(SOLUTION).read()
    allowed = {"socket", "sys", "time", "os"}
    imports = set()
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("import "):
            imports.update(x.strip().split(" ")[0] for x in s[7:].split(","))
        elif s.startswith("from "):
            imports.add(s.split()[1].split(".")[0])
    check("only allowed modules imported (socket, sys, time, os)",
          imports <= allowed, f"extra: {sorted(imports - allowed)}")
    check("file is named solution.py", os.path.basename(SOLUTION) == "solution.py")
    check("no leftover NotImplementedError", "NotImplementedError" not in src)
    check("no SystemExit with a code other than 1",
          all(c in ("1", "") for c in __import__("re").findall(r"SystemExit\((\w*)\)", src)))


# ---------------------------------------------------------------- main
if __name__ == "__main__":
    threading.Thread(target=dns_server, daemon=True).start()
    threading.Thread(target=smtp_server, daemon=True).start()
    time.sleep(0.3)

    spec = importlib.util.spec_from_file_location("solution", SOLUTION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    static_checks()
    unit_tests(mod)
    e2e_tests()

    failed = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n        {detail}" if not ok and detail else ""))
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)