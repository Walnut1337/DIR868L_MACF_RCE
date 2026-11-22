# Root cause — DIR868L-MACF-RCE

## 1. Component

- Product: D-Link DIR-868L hardware revision B1
- Firmware: 2.03b01 (`DIR868LB1_FW203b01.bin`, SHA-256
  `9af5829b628d6274f4a7fe8f3926aaa7cc51760579aa4fa117c384f96b44a2c5`)
- Entry: HTTP/80 `POST /HNAP1/`, SOAPAction
  `http://purenetworks.com/HNAP1/SetMACFilters2`
- Template: `etc/templates/hnap/SetMACFilters2.php`, SHA-256
  `5f1ffc092862aeabc91d0c972bcf50449b652869387085db5a87f1f91e21f8a1`
- Root script generator: `etc/services/IPTMACCTRL.php`, SHA-256
  `93a6dd74e631393f56b7bdc2c9346d4e1f835228b42abe0cdd09da9edbe2d627`
- Bypassed validator: `htdocs/phplib/fatlady/MACCTRL.php`, SHA-256
  `3cf13db5e1f0960d9ae0b0378496cafbf978157c4d50363f9fb5c58de42fbd43`
- CGI: `htdocs/cgibin`, SHA-256
  `70c1f4c8e9b5a80d5cc504e465eb879f29de1db636c961f370a0805dc53603ee`

## 2. Data flow

```
HTTP POST /HNAP1/ (SOAPAction SetMACFilters2, Cookie uid=, empty-key HNAP_AUTH)
  -> cgibin HNAP dispatcher
  -> /etc/templates/hnap/SetMACFilters2.php
       /runtime/hnap/SetMACFilters2/{Enabled,IsAllowList,MACList}
       set("/acl/macctrl/entry:N/mac",
           query(".../MACInfo:N/MacAddress"))        # line 72, no validation
       set("/acl/macctrl/policy", "DROP")            # lines 49-52
       fwrite("service MACCTRL restart > /dev/console") # line 84
  -> servd / svchlper
       xmldbc -P /etc/services/IPTMACCTRL.php -V START=/var/servd/IPTMACCTRL_start.sh
       sh /var/servd/IPTMACCTRL_start.sh             # root
  -> IPTMACCTRL.php
       iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> -j LOG ...  # line 51
       iptables -A MACF.LAN-x -m mac --mac-source <MacAddress> -j DROP     # line 52
```

## 3. Why the HNAP path bypasses the MAC validator

`htdocs/phplib/fatlady/MACCTRL.php` performs:

```php
$mac = query("mac");
if (PHYINF_validmacaddr($mac) != 1)
{
    $ret = set_result("FAILED", $entry."/mac", i18n("Invalid MAC address value."));
    break;
}
```

but this file is part of the legacy `postxml`/`hedwig` configuration
validation path. The HNAP template `SetMACFilters2.php` writes directly to
`/acl/macctrl` and never invokes it.

## 4. Why the shell command executes

`IPTMACCTRL.php` writes the stored MAC value into a shell script without
quoting:

```php
fwrite("a", $START, "iptables -A ".$CHAIN." -m mac --mac-source ".$mac." -j LOG ... \n");
fwrite("a", $START, "iptables -A ".$CHAIN." -m mac --mac-source ".$mac." -j DROP \n");
```

With `$mac = 00:11:22:33:44:55;<command>;#`, the generated line becomes:

```
iptables -A MACF.LAN-1 -m mac --mac-source 00:11:22:33:44:55;<command>;# -j LOG ...
```

The `;` terminates the iptables command and starts `<command>`; `#` comments
out the rest. The script is executed by `servd`/`svchlper` as root.

## 5. Zero-credential HNAP access

`cgibin sub_19CE4` creates `/var/session/<slot>` for any `Cookie: uid=`.
Only the HNAP `Login` action writes the PrivateKey, so the automatically
created session has an empty PrivateKey. The server accepts:

```
HNAP_AUTH = upper(HMAC_MD5(key="", ts + raw SOAPAction)) + " " + ts
```

No login/password/captcha is required. The `GetMACFilters2` action can be
used to read the baseline; `SetMACFilters2` performs the injection.

## 6. Device-specific notes

- `Enabled=true` + `IsAllowList=false` selects policy `DROP` and the branch
  that emits `iptables ... --mac-source <MacAddress>`.
- The vendor rootfs is a read-only squashfs, but `/var/htdocs/upnp/LAN-1`
  is a writable ramfs served on TCP/49152. Use `.gif` for evidence (`.txt`
  is handled by phpcgi and returns 500).
- The device has no busybox `id` applet; use `cat /proc/self/status`,
  `uname -a`, `cat /etc/passwd`, `cat /etc/shadow`, `ls`, `netstat`, `wget`,
  `printf`.
- The service restart is asynchronous; poll the evidence file.
- Always snapshot and restore the exact MAC filter baseline, including the
  raw `<MACInfo>` fields (ScheduleName/Status).

## 7. Fix guidance

1. Validate `MacAddress` with `PHYINF_validmacaddr()` on the HNAP path.
2. Use an argv array for `iptables` or quote/escape `$mac` in
   `IPTMACCTRL.php`.
3. Do not auto-create authenticated HNAP sessions with an empty PrivateKey;
   require a real Login challenge/key.
4. Restrict `/HNAP1/` and the web UI to the LAN; disable WAN management.
5. DIR-868L is EOL (SAP10397); replace the device.
