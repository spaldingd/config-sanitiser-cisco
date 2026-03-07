# cisco_sanitise.py

A single-file Python script that sanitises Cisco IOS, IOS XE, and IOS XR
configuration files for safe sharing — with engineers, vendors, or support teams —
without exposing credentials, internal addressing, or network topology.

---

## Features

- **Credentials redacted** — enable secrets, username passwords, line passwords,
  OSPF/IS-IS/EIGRP auth keys, key-chain key-strings, TACACS+/RADIUS keys (block,
  flat, and `server-private` inside `aaa group server` blocks), BGP neighbour
  passwords, IKE pre-shared keys, NTP auth keys, PKI certificate blocks,
  PKI `enrollment url` and `subject-name`
- **IPv4 addresses tokenised** — host addresses replaced with consistent `IPv4-xxxx`
  tokens; subnet masks, wildcard masks (including non-standard octets such as
  `0.15.255.255`), and CIDR prefixes are left unchanged
- **IPv6 addresses tokenised** — host addresses replaced with consistent `IPv6-xxxx`
  tokens; link-local (`fe80::/10`), loopback (`::1`), multicast (`ff00::/8`), and
  unspecified (`::`) addresses are preserved; CIDR prefix lengths are left unchanged
- **AS numbers tokenised** — BGP process, `remote-as`, VRF `rd`, `route-target`,
  community value lines, `bgp confederation identifier`, `bgp confederation peers`,
  and `bgp local-as` all replaced with consistent `AS-xxxx` tokens
- **SNMP community strings tokenised** — not just redacted, so `snmp-server community`
  definitions and `snmp-server host` references carry the same `snmp-xxxx` token;
  `snmp-server location` and `snmp-server contact` are redacted
- **Banner body redacted** — `banner motd`, `banner login`, and `banner exec` body
  text replaced with `<REMOVED>` while preserving the delimiter structure
- **Call-home fields redacted** — `contact-email-addr`, `street-address`, `site-id`,
  `customer-id`, `phone-number`, and `contract-id` all replaced with `<REMOVED>`
- **Named objects tokenised** — hostnames, usernames, domain names, VRFs,
  route-maps/policies, policy-maps, class-maps, named ACLs, prefix-lists/sets,
  community-lists/sets, peer-groups, neighbor-groups, keychains, crypto maps,
  transform sets, PKI trustpoints, object-groups, IP SLA IDs, track IDs, BGP
  templates, TACACS/RADIUS server block names, and `aaa group server` block names
  (with references in `aaa authentication` / `aaa authorization` / `aaa accounting`
  lines)
- **Descriptions anonymised** — all `description` text replaced with `desc-xxxx`
  tokens, including inline descriptions on `neighbor` and `prefix-list` lines
- **Deterministic** — the same seed always produces the same tokens, so outputs are
  reproducible and comparable across runs
- **Traceable** — every substitution is recorded; an optional JSON mapping file maps
  every original value back to its token

---

## Requirements

- Python 3.10 or later
- No third-party dependencies — standard library only (`re`, `hashlib`, `argparse`,
  `ipaddress`, `json`, `pathlib`)

---

## Installation

No installation required. Copy `cisco_sanitise.py` to any convenient location and
run it directly with Python.

```bash
# Optional: make it executable
chmod +x cisco_sanitise.py
```

---

## Usage

```
python cisco_sanitise.py -i INPUT [-o OUTPUT] [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-i`, `--input` | Input file or directory (required) |
| `-o`, `--output` | Output file or directory. Defaults to `<input>_sanitised` alongside the source |
| `--seed TEXT` | Determinism seed. Same seed = same tokens every run. Default: `cisco-sanitise` |
| `--no-ips` | Skip IPv4 address anonymisation |
| `--no-descriptions` | Skip description line anonymisation |
| `--dump-map FILE` | Write the full `original → token` mapping to a JSON file |
| `--dry-run` | Print sanitised output to stdout; do not write any files |
| `--extensions` | Comma-separated file extensions to process. Default: `.cfg,.txt,.conf,.log` |

### Examples

```bash
# Sanitise a directory of configs with a project-specific seed
python cisco_sanitise.py -i ./configs/ -o ./sanitised/ --seed myproject

# Sanitise a single file and save the token mapping for reference
python cisco_sanitise.py -i router.cfg -o router_clean.cfg --dump-map map.json

# Preview sanitised output without writing any files
python cisco_sanitise.py -i router.cfg --dry-run --seed myproject

# Sanitise named objects only — keep real IPs and descriptions
python cisco_sanitise.py -i ./configs/ -o ./sanitised/ --no-ips --no-descriptions
```

---

## How It Works

The script runs six sequential passes over each config file:

1. **Credentials** — pattern-matches credential lines for all IOS/XE/XR variants
   and replaces values with `<REMOVED>`; also covers PKI enrollment URLs,
   `server-private` keys, banner body text, and call-home sensitive fields
2. **SNMP** — tokenises community strings; redacts location and contact strings
3. **AS numbers** — replaces BGP AS numbers and community values with `AS-xxxx` tokens,
   including confederation and local-as
4. **Named objects** — replaces all named configuration objects with deterministic
   `prefix-xxxx` tokens (see Token Reference below)
5. **Descriptions** — replaces all description text with `desc-xxxx` tokens
6. **IPv4 addresses** — replaces host addresses with `IPv4-xxxx` tokens
7. **IPv6 addresses** — replaces host addresses with `IPv6-xxxx` tokens;
   link-local, loopback, multicast, and unspecified addresses are preserved;
   no skip-span logic is needed as IPv6 uses CIDR notation rather than
   separate wildcard address fields

Each token is derived from a SHA-256 hash of `seed:category:original_value`, so the
same value always maps to the same token within a run, and across runs using the same
seed. This means a VRF name referenced in ten places will carry the same `vrf-xxxx`
token in all ten places in the output.

---

## Token Reference

| What | Token format | Example |
|------|-------------|---------|
| Hostname | `host-xxxx` | `host-3a7f` |
| Username | `user-xxxx` | `user-d120` |
| Domain name | `dom-xxxx` | `dom-9c2e` |
| VRF name | `vrf-xxxx` | `vrf-a48e` |
| Route-map / route-policy | `rmap-xxxx` | `rmap-5791` |
| Policy-map | `pmap-xxxx` | `pmap-1b4c` |
| Class-map | `cmap-xxxx` | `cmap-ff01` |
| Named ACL | `acl-xxxx` | `acl-ad94` |
| Prefix-list / prefix-set | `pfx-xxxx` | `pfx-64c6` |
| Community-list / community-set | `cmty-xxxx` | `cmty-3fc3` |
| SNMP community string | `snmp-xxxx` | `snmp-1595` |
| BGP peer-group | `pg-xxxx` | `pg-c0b4` |
| BGP neighbor-group (XR) | `ng-xxxx` | `ng-77c9` |
| TACACS / RADIUS server name | `srv-xxxx` | `srv-ebad` |
| AAA group server name | `aaag-xxxx` | `aaag-6afb` |
| Crypto map | `cmap-xxxx` | `cmap-7d11` |
| Keychain | `kc-xxxx` | `kc-2a55` |
| Track object | `trk-xxxx` | `trk-0e3f` |
| Object-group | `og-xxxx` | `og-b912` |
| IP SLA | `sla-xxxx` | `sla-4401` |
| BGP template | `tmpl-xxxx` | `tmpl-cc8a` |
| Description text | `desc-xxxx` | `desc-9dee` |
| AS number | `AS-xxxx` | `AS-2b08` |
| IPv4 host address | `IPv4-xxxx` | `IPv4-b766` |
| IPv6 host address | `IPv6-xxxx` | `IPv6-3a7f` |
| Credentials / sensitive strings | `<REMOVED>` | — |

---

## What Is Never Modified

- Subnet masks — `255.255.255.0`, `255.255.0.0`, etc.
- Wildcard masks — any value in the second address position of an ACE line,
  regardless of octet values
- CIDR prefix lengths — `/24`, `/32`, etc.
- **Loopback range** — the entire `127.0.0.0/8` range; note that a routable IP
  assigned to a Loopback *interface* (e.g. `10.0.0.1`) is **not** preserved —
  the script has no awareness of interface names, only address values
- **Special addresses** — `0.0.0.0` and `255.255.255.255` exactly
- Numeric ACL IDs in SNMP community lines — `RO 10` is left as `RO 10`
- Keychain lifetime lines — `accept-lifetime`, `send-lifetime`
- Cisco syntax keywords — `permit`, `deny`, `any`, `default`, `encrypted`, etc.
- Comment lines (`!`, `!!`) and all config structure

---

## Output Example

**Before:**
```
hostname CORE-ROUTER-LON-01
!
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
 ipv6 address 2001:db8:1:100::1/128
 description Management Loopback
!
router bgp 65001
 bgp confederation identifier 65000
 bgp local-as 65100 no-prepend replace-as
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.2 password 7 060506324F41584B56
 neighbor 2001:db8:1:3::1 remote-as 65002
 neighbor 2001:db8:1:3::1 password 7 060506324F41584B56
!
snmp-server contact "noc@acmecorp.com"
!
call-home
 contact-email-addr noc@acmecorp.com
 site-id SITE-LON-CORE-01
```

**After** (`--seed myproject`):
```
hostname host-7882
!
interface Loopback0
 ip address IPv4-93fc 255.255.255.255
 ipv6 address IPv6-4190/128
 description desc-a19c
!
router bgp AS-d55c
 bgp confederation identifier AS-9f01
 bgp local-as AS-4e7a no-prepend replace-as
 neighbor IPv4-d8e3 remote-as AS-50cc
 neighbor IPv4-d8e3 password 7 <REMOVED>
 neighbor IPv6-78db remote-as AS-50cc
 neighbor IPv6-78db password 7 <REMOVED>
!
snmp-server contact <REMOVED>
!
call-home
 contact-email-addr <REMOVED>
 site-id <REMOVED>
```

---

## Mapping File

When `--dump-map` is used, a JSON file is written containing every substitution made,
grouped by category. Use this to reverse-look up any token in the sanitised output.

```json
{
  "hostname":      { "CORE-ROUTER-LON-01": "host-7882" },
  "as_number":     { "65001": "AS-d55c", "65002": "AS-50cc", "65000": "AS-9f01", "65100": "AS-4e7a" },
  "ip_address":    { "10.0.0.1": "IPv4-93fc", "10.0.0.2": "IPv4-d8e3" },
  "ipv6_address":  { "2001:db8:1:100::1": "IPv6-4190", "2001:db8:1:3::1": "IPv6-78db" },
  "vrf":           { "CUSTOMER-ACME": "vrf-a48e" },
  "aaa_group":     { "TACACS-GROUP": "aaag-6afb" }
}
```

---

## Platform Coverage

| Feature area | IOS | IOS XE | IOS XR |
|-------------|:---:|:------:|:------:|
| Credentials (all types) | ✓ | ✓ | ✓ |
| server-private keys (aaa group server) | ✓ | ✓ | ✓ |
| PKI enrollment url / subject-name | — | ✓ | — |
| Banner body text | ✓ | ✓ | ✓ |
| Call-home sensitive fields | ✓ | ✓ | ✓ |
| SNMP community + host refs | ✓ | ✓ | ✓ |
| SNMP location + contact | ✓ | ✓ | ✓ |
| AS numbers + community values | ✓ | ✓ | ✓ |
| BGP confederation identifier / peers | ✓ | ✓ | ✓ |
| BGP local-as | ✓ | ✓ | ✓ |
| Hostname / domain / usernames | ✓ | ✓ | ✓ |
| VRF (all syntax variants) | ✓ | ✓ | ✓ |
| Route-maps (IOS/XE syntax) | ✓ | ✓ | — |
| Route-policies (XR syntax) | — | — | ✓ |
| Policy-maps / class-maps | — | ✓ | ✓ |
| Named ACLs (all ref types) | ✓ | ✓ | ✓ |
| Prefix-lists (IOS/XE) | ✓ | ✓ | — |
| Prefix-sets (XR) | — | — | ✓ |
| Community-lists (IOS/XE) | ✓ | ✓ | — |
| Community-sets (XR) | — | — | ✓ |
| BGP peer-groups | ✓ | ✓ | — |
| BGP neighbor-groups (XR) | — | — | ✓ |
| BGP templates | — | ✓ | — |
| Keychains | ✓ | ✓ | ✓ |
| Crypto maps / IKE PSK | ✓ | ✓ | — |
| Transform sets | ✓ | ✓ | — |
| PKI trustpoints | — | ✓ | — |
| Object-groups / IP SLA / Track | ✓ | ✓ | — |
| TACACS/RADIUS server block names | — | ✓ | — |
| AAA group server block names + refs | ✓ | ✓ | ✓ |
| Descriptions (all positions) | ✓ | ✓ | ✓ |
| IPv4 host addresses | ✓ | ✓ | ✓ |
| IPv6 host addresses | ✓ | ✓ | ✓ |

---

## Known Limitations

The following items are **not currently sanitised**.

| Item | Detail |
|------|--------|
| **`snmp-server contact` on IOS XR** | XR uses an identical syntax and is handled, but the XR `snmp-server contact` is inside a block context in some versions. Verify against your XR release. |
| **Hostnames in `description` lines** | If a hostname (e.g. `CORE-ROUTER-LON-01`) appears literally inside a description string, the description token replaces the whole string but the original is visible in the mapping file. |
| **`archive path` naming conventions** | The TFTP/FTP server IP is anonymised by the IP pass, but the path template (e.g. `/configs/$h-$t`) reveals the naming convention. |
| **IOS XR `snmp-server contact` block syntax** | Some XR versions nest `contact` inside an `snmp-server` block. The current pattern matches the flat `snmp-server contact` form only. |

---

## Testing

Three sample configs are included in `test_configs/` covering all three platforms
and exercising all sanitisation rules including IPv6. See `test_configs/TEST_REFERENCE.md`
for the full rule coverage matrix and verification checklist.

```bash
python cisco_sanitise.py \
  -i ./test_configs/ \
  -o ./test_configs_sanitised/ \
  --seed test-run-2024 \
  --dump-map test_mapping.json
```

---

## License

MIT