# cisco_sanitise.py

A single-file Python script that sanitises Cisco IOS, IOS XE, and IOS XR
configuration files for safe sharing — with engineers, vendors, or support teams —
without exposing credentials, internal addressing, or network topology.

---

## Features

- **Credentials redacted** — enable secrets, username passwords, line passwords,
  OSPF/IS-IS/EIGRP auth keys, key-chain key-strings, TACACS+/RADIUS keys, BGP
  neighbour passwords, IKE pre-shared keys, NTP auth keys, PKI certificate blocks
- **IPv4 addresses tokenised** — host addresses replaced with consistent `IP-xxxx`
  tokens; subnet masks, wildcard masks (including non-standard octets such as
  `0.15.255.255`), and CIDR prefixes are left unchanged
- **AS numbers tokenised** — BGP process, `remote-as`, VRF `rd`, `route-target`,
  and community value lines all replaced with consistent `AS-xxxx` tokens
- **SNMP community strings tokenised** — not just redacted, so `snmp-server community`
  definitions and `snmp-server host` references carry the same `snmp-xxxx` token
- **Named objects tokenised** — hostnames, usernames, domain names, VRFs,
  route-maps/policies, policy-maps, class-maps, named ACLs, prefix-lists/sets,
  community-lists/sets, peer-groups, neighbor-groups, keychains, crypto maps,
  object-groups, IP SLA IDs, track IDs, BGP templates, and AAA server block names
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
   and replaces values with `<REMOVED>`
2. **SNMP** — tokenises community strings and redacts the location string
3. **AS numbers** — replaces BGP AS numbers and community values with `AS-xxxx` tokens
4. **Named objects** — replaces all named configuration objects with deterministic
   `prefix-xxxx` tokens (see Token Reference below)
5. **Descriptions** — replaces all description text with `desc-xxxx` tokens
6. **IPv4 addresses** — replaces host addresses with `IP-xxxx` tokens as a final pass,
   after all structural patterns have been matched

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
| Crypto map | `cmap-xxxx` | `cmap-7d11` |
| Keychain | `kc-xxxx` | `kc-2a55` |
| Track object | `trk-xxxx` | `trk-0e3f` |
| Object-group | `og-xxxx` | `og-b912` |
| IP SLA | `sla-xxxx` | `sla-4401` |
| BGP template | `tmpl-xxxx` | `tmpl-cc8a` |
| Description text | `desc-xxxx` | `desc-9dee` |
| AS number | `AS-xxxx` | `AS-2b08` |
| IPv4 host address | `IP-xxxx` | `IP-b766` |
| Credentials | `<REMOVED>` | — |

---

## What Is Never Modified

- Subnet masks — `255.255.255.0`, `255.255.0.0`, etc.
- Wildcard masks — any value in the second address position of an ACE line,
  regardless of octet values
- CIDR prefix lengths — `/24`, `/32`, etc.
- Loopback and special addresses — `127.x.x.x`, `0.0.0.0`, `255.255.255.255`
- Numeric ACL IDs in SNMP community lines — `RO 10` is left as `RO 10`
- Keychain lifetime lines — `accept-lifetime`, `send-lifetime`
- Cisco syntax keywords — `permit`, `deny`, `any`, `default`, `encrypted`, etc.
- Comment lines (`!`) and all config structure

---

## Output Example

**Before:**
```
hostname CORE-ROUTER-LON-01
!
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
 description Management Loopback
!
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.2 password 7 060506324F41584B56
```

**After** (`--seed myproject`):
```
hostname host-4c2a
!
interface Loopback0
 ip address 127.0.0.1 255.255.255.255
 description desc-7f3e
!
router bgp AS-2b08
 neighbor IP-b766 remote-as AS-9d1c
 neighbor IP-b766 password 7 <REMOVED>
```

---

## Mapping File

When `--dump-map` is used, a JSON file is written containing every substitution made,
grouped by category. Use this to reverse-look up any token in the sanitised output.

```json
{
  "hostname": { "CORE-ROUTER-LON-01": "host-4c2a" },
  "as_number": { "65001": "AS-2b08", "65002": "AS-9d1c" },
  "ip_address": { "10.0.0.2": "IP-b766" },
  "vrf":        { "CUSTOMER-ACME": "vrf-a48e" }
}
```

---

## Platform Coverage

| Feature area | IOS | IOS XE | IOS XR |
|-------------|:---:|:------:|:------:|
| Credentials (all types) | ✓ | ✓ | ✓ |
| SNMP community + host refs | ✓ | ✓ | ✓ |
| AS numbers + community values | ✓ | ✓ | ✓ |
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
| Object-groups / IP SLA / Track | ✓ | ✓ | — |
| TACACS/RADIUS server names | — | ✓ | — |
| Descriptions (all positions) | ✓ | ✓ | ✓ |
| IPv4 host addresses | ✓ | ✓ | ✓ |

---

## Limitations

- **IPv6 addresses** are not anonymised
- **Hostnames in banners** (`banner motd`, `banner login`) are not anonymised
- **SNMP contact** (`snmp-server contact`) is not anonymised
- **No IOS XR AAA server names** — XR uses a different AAA model not covered
- Configs must be readable UTF-8 text; binary or encrypted exports are not supported

---

## Testing

Three sample configs are included in `test_configs/` to verify coverage across all
three platforms. See `test_configs/TEST_REFERENCE.md` for the full rule coverage
matrix and verification checklist.

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