# Security Advisory — D-Link DIR-868L B1 HNAP SetMACFilters2 MacAddress command injection

| Field | Value |
|---|---|
| Title | Zero-credential OS command injection in the D-Link DIR-868L B1 HNAP `SetMACFilters2` handler (`MacAddress`) leads to root code execution |
| PoC ID | `DIR868L-MACF-RCE` |
| Vendor | D-Link |
| Product | DIR-868L, hardware revision **B1** |
| Firmware | **v2.03b01** (`DIR868LB1_FW203b01.bin`, SHA-256 `9af5829b628d6274f4a7fe8f3926aaa7cc51760579aa4fa117c384f96b44a2c5`) — dynamically verified on a physical unit |
| Vulnerable files | `etc/templates/hnap/SetMACFilters2.php` (`5f1ffc09…f8a1`), `etc/services/IPTMACCTRL.php` (`93a6dd74…d627`), `htdocs/cgibin` (`70c1f4c8…03ee`); the fatlady validator `htdocs/phplib/fatlady/MACCTRL.php` (`3cf13db5…bd43`) is bypassed on the HNAP path |
| Weakness | CWE-78 (primary); zero-credential HNAP access (empty PrivateKey session) |
| CVSS 3.1 | **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Attack vector | HTTP/80 `/HNAP1/`, `SetMACFilters2`, no credentials; root command execution with output read-back over TCP/49152 |
| CVE | pending (VulDB request prepared, 2026-11-22) |
| Related prior art | **CVE-2024-48630** — DIR-882 / DIR-878, command injection via `MacAddress` in `SetMACFilters2` (different products); CVE-2018-19987/19988 (DIR-868L Rev.B 2.05B02, different HNAP handlers); CVE-2026-110536 (DIR-868L 2.01b05, HNAP SOAPACTION) |

## 1. Summary

The DIR-868L B1 HNAP `SetMACFilters2` action stores the request-body
`<MacAddress>` value **verbatim** into `/acl/macctrl/entry:N/mac`
(`SetMACFilters2.php` line 72) and then runs `service MACCTRL restart`
(line 84). `servd`/`svchlper` renders `/etc/services/IPTMACCTRL.php` into
`/var/servd/IPTMACCTRL_start.sh` and executes it as **root**; the script
writes, without quoting:

```
iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> -j LOG ...
iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> -j DROP
```

(`IPTMACCTRL.php` lines 51-52). The MAC syntax validator in
`htdocs/phplib/fatlady/MACCTRL.php` (`PHYINF_validmacaddr`, lines 68-79) is
only used by the legacy `postxml`/`hedwig` path; the HNAP template path does
not call it. With

```
MacAddress = 00:11:22:33:44:55;<command>;#
```

the `;` terminates the `--mac-source` argument and `<command>` is executed
as root; `#` comments out the rest of the generated iptables line. The DROP
branch is selected with `Enabled=true` and `IsAllowList=false`
(`SetMACFilters2.php` lines 49-52).

The action is reachable with **zero credentials**: any `Cookie: uid=<value>`
creates a HNAP session whose `PrivateKey` is empty, and
`HNAP_AUTH = upper(HMAC_MD5(key="", ts + quoted raw SOAPAction))` is accepted by the
server. No login, password or prior session is required.

The command output is redirected into the writable ramfs directory
`/var/htdocs/upnp/LAN-1/` and fetched over the UPnP LAN vhost on **TCP/49152**.

## 2. Affected entry point

| Interface | Value |
|---|---|
| Protocol | HTTP/1.1 |
| Endpoint | `POST /HNAP1/` |
| SOAPAction | `"http://purenetworks.com/HNAP1/SetMACFilters2"` |
| Body fields | `Enabled=true`, `IsAllowList=false`, `MACList/MACInfo/MacAddress` |
| Auth | zero credentials: `Cookie: uid=<any>`, `HNAP_AUTH=upper(HMAC_MD5(key="", ts+quoted SOAPAction))` |
| Trigger | `service MACCTRL restart` in `SetMACFilters2.php` → servd/svchlper → root shell |
| Output | `http://TARGET:49152/<mark>.gif` (docroot `/var/htdocs/upnp/LAN-1`) |

## 3. Root cause

1. **No validation on the HNAP path.** `SetMACFilters2.php` reads
   `$nodebase = /runtime/hnap/SetMACFilters2/` and copies
   `MACList/MACInfo:N/MacAddress` into `/acl/macctrl/entry:N/mac` without
   syntax checks. `fatlady/MACCTRL.php` performs `PHYINF_validmacaddr()` but
   is only invoked by the legacy `postxml`/`hedwig` configuration path, not by
   the HNAP template.
2. **Policy selection.** `Enabled=true` + `IsAllowList=false` sets
   `/acl/macctrl/policy = DROP`.
3. **Root script generation.** `SetMACFilters2.php` writes
   `service MACCTRL restart > /dev/console`; servd/svchlper renders
   `IPTMACCTRL.php` to `/var/servd/IPTMACCTRL_start.sh` and runs it as root.
4. **Unquoted shell argument.** `IPTMACCTRL.php` concatenates the stored MAC
   into `iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> ...` without
   quoting. A `;` in `MacAddress` starts a new shell command; `#` comments the
   remaining `-j LOG/DROP`.
5. **Zero-credential HNAP session.** `cgibin sub_19CE4` creates a session for
   any `Cookie: uid=`; only the HNAP `Login` action writes the PrivateKey, so
   the automatically created session has an empty PrivateKey. The server
   accepts `HNAP_AUTH` computed with `key=""`.

## 4. Impact

Zero-credential remote code execution as **root** from the LAN (WAN if the
web UI/HNAP is exposed):

- read `/etc/passwd`, `/etc/shadow`, configuration and NVRAM;
- modify device state, add accounts, persist;
- pivot into the LAN; take over the router;
- output read-back via TCP/49152.

The DIR-868L is end-of-life (D-Link SAP10397); no firmware fix is expected.

## 5. Verification

### 5.1 Physical unit (FW 2.03b01)

| Check | Result |
|---|---|
| Identity | MAC `E4:6F:13:3E:AE:04`; HTTP `Date: Sat, 21 Nov 2026 ... GMT`; HNAP `FirmwareVersion=2.03`, `HardwareVersion=B1` |
| Baseline | `GetMACFilters2` → `Enabled=true`, `IsAllowList=true`, empty `MACList` (the 2026-11-21 09:37 run); restored after the test |
| Injection | `SetMACFilters2` with `Enabled=true`, `IsAllowList=false`, `MacAddress=00:11:22:33:44:55;id>/var/htdocs/upnp/LAN-1/i253r09.gif;uname -a>>...;cat /etc/passwd>>...;cat /etc/shadow>>...;cat /proc/self/status>>...;#` → `SetMACFilters2Result=OK` |
| Evidence | 1008-byte file fetched from `http://192.168.0.1:49152/i253r09.gif` (`r09_full_20261121.gif`) |
| Root proof | `Uid/Gid 0 0 0 0`, `CapEff ffffffffffffffff`, `uname Linux dlinkrouter 2.6.36.4brcmarm+ ... armv7l`, `/etc/passwd`, `/etc/shadow` |
| Restore | `SetMACFilters2` with the original `Enabled=true / IsAllowList=true / empty` → `OK`; `GetMACFilters2` read-back matches the baseline |
| No auth | No login, password or session; only `Cookie: uid=i253r09` and a locally computed empty-key `HNAP_AUTH` |

A second physical run (`i278`, 2026-11-21 10:13-10:14) observed a different
baseline (`Enabled=false / IsAllowList=false`) and again confirmed root
execution and restoration. The packaged PoC snapshots and restores whichever
baseline is present.

### 5.2 PoC

```bash
# read the current MAC filter configuration (zero credentials)
python3 poc_DIR868L_MACF_RCE.py --192.168.0.1 --check

# execute a command as root and print the output
python3 poc_DIR868L_MACF_RCE.py --192.168.0.1 \
    'cat /proc/self/status; uname -a; cat /etc/passwd; cat /etc/shadow'
```

The PoC:
1. reads `GetMACFilters2` and saves the exact baseline (including raw
   `<MACInfo>` blocks);
2. injects the command with `Enabled=true / IsAllowList=false`;
3. polls `http://TARGET:49152/<mark>.gif` for the output;
4. always restores the saved baseline and verifies it via `GetMACFilters2`.

The device has no busybox `id` applet; use `cat /proc/self/status` for
`Uid/Gid 0 0 0 0` and `CapEff`.

## 6. Related vulnerabilities (not duplicates for this build)

| CVE / report | Relation |
|---|---|
| **CVE-2024-48630** | D-Link **DIR-882_FW130B06** and **DIR-878_FW130B08** — command injection via the `MacAddress` parameter in `SetMACFilters2`. **Same function and parameter**, different products/builds. This is the closest prior art and the main duplicate risk. |
| CVE-2018-19987 | DIR-868L Rev.B 2.05B02 — HNAP `SetAccessPointMode` `IsAccessPoint`. Same model, different handler/version. |
| CVE-2018-19988 | DIR-868L Rev.B 2.05B02 — HNAP `SetClientInfoDemo` `AudioMute`/`AudioEnable`. Same model, different handler/version. |
| CVE-2026-110536 | DIR-868L 2.01b05 — HNAP `SOAPACTION` command injection. Same model, different version/handler. |
| CVE-2018-6530 | DIR-868L A1 112b04 — `soap.cgi` command injection. Different handler. |
| CVE-2026-1506 | DIR-615 4.10 — `/adv_mac_filter.php` `mac` command injection. Same concept, different product. |
| CVE-2025-14659 / CVE-2025-55583 | DIR-868L B1 DHCP hostname / fileaccess. Different daemons/components. |

## 7. Duplicate-check conclusion

NVD API 2.0 (2026-11-22):

- `keywordSearch=SetMACFilters2`: **1** record — CVE-2024-48630 (DIR-882 /
  DIR-878, `MacAddress`, command injection).
- `keywordSearch=MACFilters2`: 0 records.
- `keywordSearch=IPTMACCTRL`: 0 records.
- `keywordSearch=DIR-868L MAC`: 0 records.
- `keywordSearch=MAC filter D-Link`: 6 records, all unrelated (CSRF/access
  control/other products).

**Conclusion:** no exact public CVE for the **DIR-868L B1 2.03b01** HNAP
`SetMACFilters2` `MacAddress` injection. The closest is **CVE-2024-48630**
(same `SetMACFilters2`/`MacAddress` sink, but DIR-882/DIR-878). A new CVE can
be submitted for the DIR-868L B1 2.03b01 affected model/version, citing
CVE-2024-48630 as related prior art; duplicate risk is **medium-high**
because the underlying sink is already public on other D-Link models. The
DIR-868L-specific zero-credential chain (empty PrivateKey), `IPTMACCTRL.php`
script and physical-unit verification are the differentiators.

## 8. Remediation

1. Validate `MacAddress` with `PHYINF_validmacaddr()` on the HNAP path
   (the same validator used by `fatlady/MACCTRL.php`).
2. Do not build shell command lines from configuration values; use an argv
   array for `iptables` or quote/escape `$mac` in `IPTMACCTRL.php`.
3. Do not auto-create authenticated HNAP sessions with an empty PrivateKey;
   require a real Login challenge/key.
4. Restrict `/HNAP1/` and the web UI to the LAN; disable WAN management.
5. The DIR-868L is EOL — replace the device.

## 9. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-21 | Physical-unit verification (zero-credential SetMACFilters2 → root; baseline restored) |
| 2026-11-22 | Final PoC, NVD duplicate check, advisory and CVE package prepared |
| TBD | VulDB request / public GitHub advisory |

## 10. Credit

Discovered and researched by **Walnut1337** (`walnut1337@163.com`), 2026-11.
