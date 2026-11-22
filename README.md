# DIR868L-MACF-RCE — D-Link DIR-868L B1 HNAP SetMACFilters2 MacAddress root RCE

Public advisory and PoC for a zero-credential OS command injection in the
HNAP `SetMACFilters2` handler of the D-Link DIR-868L B1 (firmware 2.03b01).

| | |
|---|---|
| Vendor | D-Link |
| Product | DIR-868L, hardware revision B1 |
| Firmware | 2.03b01 (`DIR868LB1_FW203b01.bin`, SHA-256 `9af5829b628d6274f4a7fe8f3926aaa7cc51760579aa4fa117c384f96b44a2c5`) |
| Component | HNAP `SetMACFilters2` → `/acl/macctrl/entry:N/mac` → `service MACCTRL restart` → `/var/servd/IPTMACCTRL_start.sh` (root) |
| Sink | `etc/services/IPTMACCTRL.php` unquoted `iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> -j LOG/DROP` |
| Class | CWE-78; zero-credential HNAP access |
| CVSS 3.1 | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Attack | HTTP/80 `/HNAP1/`, no credentials |
| Impact | Arbitrary command execution as **root**, output read-back over TCP/49152 |
| Vendor status | End-of-life (D-Link SAP10397); no fix expected |
| CVE | pending (VulDB request prepared, 2026-11-22) |
| PoC ID | `DIR868L-MACF-RCE` |

## Summary

`etc/templates/hnap/SetMACFilters2.php` copies the request-body
`MACList/MACInfo/MacAddress` value verbatim into
`/acl/macctrl/entry:N/mac` (line 72) and runs `service MACCTRL restart`
(line 84). The MAC validator in `htdocs/phplib/fatlady/MACCTRL.php`
(`PHYINF_validmacaddr`, lines 68-79) is only used by the legacy
`postxml`/`hedwig` path; the HNAP template does not call it.

`servd`/`svchlper` renders `etc/services/IPTMACCTRL.php` into
`/var/servd/IPTMACCTRL_start.sh` and executes it as root. With
`Enabled=true` and `IsAllowList=false` the policy is `DROP`, selecting the
branch that emits:

```
iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> -j LOG ...
iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> -j DROP
```

A `MacAddress` value of the form

```
00:11:22:33:44:55;<command>;#
```

terminates the `--mac-source` argument at the semicolon and executes
`<command>` as root; the trailing `#` comments out the rest of the iptables
line. Command output is written into `/var/htdocs/upnp/LAN-1/` (ramfs) and
served by the UPnP LAN vhost on **TCP/49152**.

### Zero-credential HNAP access

Any `Cookie: uid=<value>` creates a HNAP session with an **empty
PrivateKey** (only the `Login` action writes it). The server accepts:

```
HNAP_AUTH = upper(HMAC_MD5(key="", ts + quoted raw SOAPAction)) + " " + ts
```

No login, password, captcha or prior session is required.

## Quick start

```bash
# read the current MAC filter baseline (zero credentials)
python3 poc/poc_DIR868L_MACF_RCE.py --192.168.0.1 --check

# execute a command as root and print the output
python3 poc/poc_DIR868L_MACF_RCE.py --192.168.0.1 \
    'cat /proc/self/status; uname -a; cat /etc/passwd; cat /etc/shadow'

# keep the device-side evidence file and save the fetched bytes locally
python3 poc/poc_DIR868L_MACF_RCE.py --192.168.0.1 --out r09_full.gif \
    'cat /etc/passwd; cat /etc/shadow'
```

The PoC snapshots `GetMACFilters2` (including the raw `<MACInfo>` blocks),
injects, fetches the output, and **always restores the exact baseline** in a
`finally` block, then verifies it with `GetMACFilters2`. It does not reboot,
factory-reset, flash, or create persistent accounts. The device has no
busybox `id` applet; use `cat /proc/self/status` for `Uid/Gid 0 0 0 0` and
`CapEff`.

## Verification

- **Physical unit** (FW 2.03b01, LAN side): MAC `E4:6F:13:3E:AE:04`,
  HTTP `Date: Sat, 21 Nov 2026 ... GMT`, HNAP `FirmwareVersion=2.03`,
  `HardwareVersion=B1`.
  `SetMACFilters2` with the injected `MacAddress` returned
  `SetMACFilters2Result=OK`; the 1008-byte evidence file contained
  `Uid/Gid 0 0 0 0`, `CapEff ffffffffffffffff`,
  `uname 2.6.36.4brcmarm+`, `/etc/passwd` and `/etc/shadow`.
  Baseline before/after: `Enabled=true / IsAllowList=true / empty MACList`;
  restored and read back.
- **Second physical run** (`i278`, 2026-11-21 10:13): baseline
  `Enabled=false / IsAllowList=false`; root output verified and baseline
  restored.
- **PoC validation**: the wrapper was validated against a local mock HNAP
  server for the full `GetMACFilters2 → inject → fetch → restore → verify`
  sequence; it reuses the exact `SetMACFilters2` body from the physical
  evidence. A final end-to-end wrapper run on the unit is pending because the
  unit was unreachable at the end of the session; the raw physical
  request/response evidence is included under `evidence/`.

> **Public evidence**: this repository intentionally includes the full
> physical evidence and hashes **without redaction**, as requested by the
> researcher. The `/etc/shadow` samples are from the researcher's own
> end-of-life test unit.

## Files

| Path | Content |
|---|---|
| `ADVISORY.md` | full advisory (root cause, impact, evidence, remediation) |
| `poc/poc_DIR868L_MACF_RCE.py` | one-shot PoC (zero-cred HNAP + 49152 read-back + restore) |
| `analysis/root_cause.md` | technical deep dive |
| `analysis/code_SetMACFilters2.php.txt` | vulnerable template (line-numbered) |
| `analysis/code_IPTMACCTRL.php.txt` | unquoted iptables sink (line-numbered) |
| `analysis/code_MACCTRL_fatlady.php.txt` | validator bypassed on the HNAP path |
| `evidence/` | full physical requests/responses, root output and hashes |
| `evidence/raw_hnap_request.txt` | exact verified zero-credential request |

## Related vulnerabilities (not duplicates for this build)

| CVE | Relation |
|---|---|
| **CVE-2024-48630** | D-Link **DIR-882_FW130B06** / **DIR-878_FW130B08** — command injection via the `MacAddress` parameter in `SetMACFilters2`. **Same function/parameter**, different products/builds; closest prior art. This repo is the DIR-868L **B1 2.03b01** build. |
| CVE-2018-19987 | DIR-868L Rev.B 2.05B02 — HNAP `SetAccessPointMode`. Different handler/version. |
| CVE-2018-19988 | DIR-868L Rev.B 2.05B02 — HNAP `SetClientInfoDemo`. Different handler/version. |
| CVE-2026-110536 | DIR-868L 2.01b05 — HNAP `SOAPACTION`. Different version/handler. |
| CVE-2018-6530 | DIR-868L A1 112b04 — `soap.cgi`. Different handler. |
| CVE-2026-1506 | DIR-615 4.10 — `/adv_mac_filter.php` `mac`. Same concept, other product. |

Prior-art check: NVD API 2.0 on 2026-11-22; `SetMACFilters2` returns 1 record
(CVE-2024-48630, DIR-882/DIR-878), `MACFilters2` 0, `IPTMACCTRL` 0,
`DIR-868L MAC` 0. No exact public CVE for the DIR-868L B1 2.03b01 build;
duplicate risk is medium-high because the sink is already public on other
D-Link models.

## Remediation

1. Validate `MacAddress` with `PHYINF_validmacaddr()` on the HNAP path.
2. Do not build shell command lines from configuration values; use an argv
   array for `iptables` or quote/escape `$mac` in `IPTMACCTRL.php`.
3. Do not auto-create authenticated HNAP sessions with an empty PrivateKey;
   require a real Login challenge/key.
4. Restrict `/HNAP1/` and the web UI to the LAN; disable WAN management.
5. The DIR-868L is EOL — replace the device.

## Disclosure

| Date | Event |
|---|---|
| 2026-11-21 | Physical-unit zero-credential verification and baseline restore |
| 2026-11-22 | Final PoC, NVD duplicate check, advisory and request prepared |
| TBD | VulDB request / public advisory publication (this repository) |

## Disclaimer

This material is provided for vulnerability verification on **owned devices**
and coordinated disclosure only. Do not use it against devices you do not own
or are not authorized to test. The PoC always restores the MAC filter
baseline; the evidence file remains in `/var/htdocs/upnp/LAN-1` (ramfs)
unless `--clean` is used.

## Credit

Discovered and researched by **Walnut1337** (`walnut1337@163.com`), 2026-11.
