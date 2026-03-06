# Cisco Sanitisation Pipeline — Test Config Reference

Three sample configs are provided to test the full sanitisation pipeline.
Each file is designed to exercise specific sanitisation rules.

---

## Files

| File | Platform | Role |
|------|----------|------|
| `sample_iosxe.cfg` | IOS XE | Core/edge router — full feature set |
| `sample_iosxr.cfg` | IOS XR | Core router — XR syntax variants |
| `sample_ios.cfg`   | IOS 15.x | Access/distribution — classic syntax |

---

## Test Coverage Matrix

### Step 1 — cisco_sanitise.py (Credentials, IPs, SNMP, BGP keys)

| Item | IOS XE | IOS XR | IOS |
|------|--------|--------|-----|
| `enable secret 5 <hash>` | ✓ | — | ✓ |
| `enable password 7 <hash>` | — | — | ✓ |
| `username … secret 5 <hash>` | ✓ | ✓ | ✓ |
| `username … secret 0 <plain>` | ✓ | ✓ | — |
| `username … password 7 <hash>` | ✓ | ✓ | ✓ |
| `password 7 <hash>` (line) | ✓ | — | ✓ |
| TACACS `key 7 <hash>` | ✓ | ✓ | ✓ |
| TACACS `key 0 <plain>` | ✓ | ✓ | ✓ |
| RADIUS `key 7 <hash>` | — | — | ✓ |
| OSPF `message-digest-key … md5 0 <key>` | ✓ | — | — |
| `key-string 0 <plain>` (keychain) | ✓ | ✓ | ✓ |
| `key-string 7 <hash>` (keychain) | ✓ | ✓ | ✓ |
| `crypto isakmp key <key>` | ✓ | — | ✓ |
| BGP `neighbor … password 7 <hash>` | ✓ | — | ✓ |
| BGP `neighbor … password 0 <plain>` | ✓ | ✓ | ✓ |
| BGP `password encrypted <hash>` (XR) | — | ✓ | — |
| BGP `template … password` | ✓ | — | — |
| `snmp-server community <string> RO` | ✓ | ✓ | ✓ |
| `snmp-server community <string> RW` | ✓ | ✓ | ✓ |
| NTP `authentication-key … md5 <key>` | ✓ | ✓ | ✓ |
| PKI `certificate self-signed` block | ✓ | — | — |
| IPv4 addresses (all) | ✓ | ✓ | ✓ |

### Step 2 — cisco_name_anonymise.py (Named objects)

| Named Object | IOS XE | IOS XR | IOS |
|-------------|--------|--------|-----|
| `hostname` | ✓ | ✓ | ✓ |
| `ip domain-name` / `domain name` | ✓ | ✓ | ✓ |
| VRF names (`vrf definition`, `ip vrf`, `vrf`) | ✓ | ✓ | ✓ |
| VRF references (`vrf forwarding`, `vrf member`) | ✓ | ✓ | ✓ |
| Route-map names (`route-map`, references in BGP) | ✓ | ✓ | ✓ |
| Route-policy names (XR `route-policy`) | — | ✓ | — |
| Policy-map names | ✓ | ✓ | — |
| Class-map names + `class` references | ✓ | ✓ | — |
| Named ACL names | ✓ | — | ✓ |
| Prefix-list names | ✓ | ✓ | ✓ |
| Community-list names | ✓ | — | ✓ |
| BGP peer-group names | ✓ | — | ✓ |
| BGP neighbor-group names (XR) | — | ✓ | — |
| Keychain names | ✓ | ✓ | ✓ |
| Crypto map names | ✓ | — | ✓ |
| Object-group names | ✓ | — | ✓ |
| Track IDs | ✓ | — | ✓ |
| IP SLA IDs | ✓ | — | ✓ |
| BGP template names | ✓ | — | — |
| Interface `description` text | ✓ | ✓ | ✓ |
| Object/policy `description` text | ✓ | ✓ | ✓ |

---

## How to Run

```bash
# Full pipeline against all three test configs
python cisco_sanitise_pipeline.py \
  -i ./test_configs/ \
  -o ./test_configs_sanitised/ \
  --seed test-run-2024 \
  --dump-map test_mapping.json

# Dry run — preview without writing files (single file)
python cisco_sanitise_pipeline.py \
  -i ./test_configs/sample_iosxe.cfg \
  --dry-run \
  --seed test-run-2024
```

## What to Verify After Running

1. **Credentials removed**: Search output for `$1$`, `password 7`, `community`,
   `key 0`, `key 7` — none should have real values.
2. **IPs anonymised**: All `x.x.x.x` addresses replaced; loopbacks (127.x, 0.0.0.0)
   preserved; same IP maps to same anonymised IP across files.
3. **Names consistent**: `RMAP-ACME-IN` in the route-map definition and all BGP
   neighbor references should all show the same token (e.g. `rmap-4a2f`).
4. **Cross-file consistency**: `CUSTOMER-ACME` VRF should map to the same `vrf-xxxx`
   token in all three files (shared seed ensures this).
5. **Descriptions replaced**: All `description` lines should show `desc-xxxx` tokens.
6. **Config structure intact**: File should still be parseable — `!` comments, 
   indentation, and keyword structure preserved.
7. **Mapping file**: `test_mapping.json` lists every original→token substitution
   for traceability.
