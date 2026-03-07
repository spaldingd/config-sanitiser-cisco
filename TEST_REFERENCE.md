# Cisco Configuration Sanitiser — Test Reference

`cisco_sanitise.py` is a single unified script supporting IOS, IOS XE, and IOS XR.
Three sample configs exercise its sanitisation rules across all three platforms.
Each config also includes IPv6 configuration to demonstrate the current IPv6
limitation (addresses pass through unsanitised).

---

## Test Files

| File | Platform | Role |
|------|----------|------|
| `sample_ios.cfg` | IOS 15.x | Access/distribution — classic flat syntax |
| `sample_iosxe.cfg` | IOS XE | Core/edge router — full modern feature set |
| `sample_iosxr.cfg` | IOS XR | Core router — XR block syntax and policy language |

---

## Token Scheme

Every anonymised value is replaced with a deterministic `prefix-xxxx` token derived
from a SHA-256 hash of `seed:category:original_value`. The same original value always
produces the same token for a given seed, making substitutions traceable via the
mapping file.

| Category | Token prefix | Example |
|----------|-------------|---------|
| Hostname | `host` | `host-3a7f` |
| Username | `user` | `user-d120` |
| Domain name | `dom` | `dom-9c2e` |
| VRF name | `vrf` | `vrf-a48e` |
| Route-map / route-policy | `rmap` | `rmap-5791` |
| Policy-map | `pmap` | `pmap-1b4c` |
| Class-map | `cmap` | `cmap-ff01` |
| Named ACL | `acl` | `acl-ad94` |
| Prefix-list / prefix-set | `pfx` | `pfx-64c6` |
| Community-list / community-set | `cmty` | `cmty-3fc3` |
| SNMP community string | `snmp` | `snmp-1595` |
| BGP peer-group | `pg` | `pg-c0b4` |
| BGP neighbor-group (XR) | `ng` | `ng-77c9` |
| TACACS / RADIUS server block name | `srv` | `srv-ebad` |
| AAA group server block name | `aaag` | `aaag-6afb` |
| Crypto map | `cmap` | `cmap-7d11` |
| Keychain name | `kc` | `kc-2a55` |
| Track object | `trk` | `trk-0e3f` |
| Object-group | `og` | `og-b912` |
| IP SLA | `sla` | `sla-4401` |
| BGP template | `tmpl` | `tmpl-cc8a` |
| Description text | `desc` | `desc-9dee` |
| AS number | `AS` | `AS-2b08` |
| IPv4 host address | `IP` | `IP-b766` |

Credentials and sensitive free-text values are replaced with the literal `<REMOVED>`
rather than a token, as they carry no structural meaning that needs to remain
traceable.

---

## What Is Preserved

The following values are never anonymised regardless of context:

- **Loopback range** — the entire `127.0.0.0/8` range (`addr.is_loopback`)
- **Special addresses** — `0.0.0.0` and `255.255.255.255` exactly
- Note: routable IPs assigned to Loopback *interfaces* (e.g. `10.0.0.1/32`) are
  anonymised — the script operates on address values only, not interface names
- **Subnet masks** — any quad matching standard mask octets
  (255/254/252/248/240/224/192/128/0)
- **Wildcard masks** — the second address on any ACE (`permit`/`deny`) line is
  identified by position, not by octet value, so non-standard wildcards such as
  `0.15.255.255` are correctly left in place
- **CIDR prefix lengths** — `/24`, `/32`, etc.
- **Numeric ACL IDs** in SNMP community lines — `RO 10` left as-is
- **Keychain lifetime lines** — `accept-lifetime`, `send-lifetime`
- **Cisco syntax keywords** — `permit`, `deny`, `any`, `default`, `encrypted`, etc.
- **Comment lines** (`!`, `!!`) and config structure (indentation, blank lines)

---

## Sanitisation Passes (in execution order)

The script runs six sequential passes. Each pass operates on the output of the
previous one. All patterns prevent newline-crossing by using `[^\S\n]+` rather than
`\s+` between tokens within a single config line.

---

### Pass 1 — Credentials

All credential values and sensitive literal strings are replaced with `<REMOVED>`.

#### Authentication credentials

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| enable secret/password | `enable secret 5 $1$...` | ✓ | ✓ | — |
| username secret/password | `username NAME secret 5 $1$...` | ✓ | ✓ | ✓ |
| XR username secret block | ` secret 5 $1$...` (indented) | — | — | ✓ |
| XR username password block | ` password 7 <hash>` (indented) | — | ✓ | ✓ |
| Line password | ` password 7 <hash>` (line vty/con) | ✓ | ✓ | ✓ |
| OSPF message-digest-key | ` ip ospf message-digest-key 1 md5 0 <key>` | — | ✓ | — |
| Keychain key-string (IOS/XE) | ` key-string 0 <plain>` / ` key-string 7 <hash>` | ✓ | ✓ | — |
| Keychain key-string (XR) | ` key-string password 0 <plain>` | — | — | ✓ |
| NTP authentication-key (IOS/XE) | `ntp authentication-key 1 md5 <key>` | ✓ | ✓ | — |
| authentication-key md5 encrypted (XR) | ` authentication-key 1 md5 encrypted <hash>` | — | — | ✓ |
| authentication-key (generic) | ` authentication-key 0 <key>` | ✓ | ✓ | — |
| AAA server key (block) | ` key 7 <hash>` (inside tacacs/radius server block) | — | ✓ | ✓ |
| AAA server-private key | ` server-private <ip> [port N] key [N] <val>` (inside aaa group server block) | ✓ | ✓ | ✓ |
| tacacs-server key (IOS flat) | `tacacs-server host <ip> key 7 <hash>` | ✓ | — | — |
| radius-server key (IOS flat) | `radius-server host <ip> key 7 <hash>` | ✓ | — | — |
| BGP neighbor password | ` neighbor <x> password 7 <hash>` | ✓ | ✓ | — |
| XR BGP password (neighbor block) | ` password encrypted <hash>` / ` password 0 <plain>` | — | — | ✓ |
| IKE pre-shared-key | ` pre-shared-key address <ip> <key>` | — | ✓ | — |
| crypto isakmp key | `crypto isakmp key <key> address <ip>` | ✓ | ✓ | — |
| tunnel key | ` tunnel key <value>` | — | ✓ | — |
| PKI certificate block | `certificate self-signed … quit` (multiline) | — | ✓ | — |

#### PKI identity

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| PKI enrollment url | ` enrollment url http://pki.internal.example.com` | — | ✓ | — |
| PKI subject-name | ` subject-name CN=router.example.com,OU=Network,O=Corp` | — | ✓ | — |

#### Banner body

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| banner body | `banner motd ^C … ^C` — body replaced with `<REMOVED>`; delimiter lines preserved | ✓ | ✓ | ✓ |

Covers `banner motd`, `banner login`, `banner exec`, and `banner incoming`.

#### Call-home block

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| contact-email-addr | ` contact-email-addr noc@example.com` | ✓ | ✓ | ✓ |
| street-address | ` street-address 123 Main Street, London` | ✓ | ✓ | ✓ |
| site-id | ` site-id SITE-LON-CORE-01` | ✓ | ✓ | ✓ |
| customer-id | ` customer-id ACME-CORP-UK-12345` | ✓ | ✓ | ✓ |
| phone-number | ` phone-number +442079460000` | ✓ | ✓ | ✓ |
| contract-id | ` contract-id CON-98765432` | ✓ | ✓ | ✓ |

---

### Pass 2 — SNMP

SNMP community strings are **tokenised** (not redacted) so that the same community
name appearing in both a `snmp-server community` definition and a `snmp-server host`
reference maps to the same `snmp-xxxx` token, preserving traceability.

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| SNMP community def | `snmp-server community <n> RO\|RW` | ✓ | ✓ | ✓ |
| SNMP community ACL ref | `snmp-server community <n> RO NAMED-ACL` (named ACLs only) | ✓ | ✓ | ✓ |
| SNMP community host ref | `snmp-server host <ip> version 2c <community>` | ✓ | ✓ | ✓ |
| XR SNMP ACL ref | `RO IPv4 <acl>` / `RW IPv4 <acl>` (inside XR community block) | — | — | ✓ |
| SNMP location | `snmp-server location <free text>` → `<REMOVED>` | ✓ | ✓ | ✓ |
| SNMP contact | `snmp-server contact <free text>` → `<REMOVED>` | ✓ | ✓ | ✓ |

---

### Pass 3 — AS Numbers

BGP AS numbers and community values are tokenised to `AS-xxxx` tokens. The same AS
number maps to the same token across all contexts.

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| router bgp AS | `router bgp 65001` | ✓ | ✓ | ✓ |
| bgp confederation identifier | `bgp confederation identifier 65000` | ✓ | ✓ | ✓ |
| bgp confederation peers | `bgp confederation peers 65002 65003` (each AS tokenised) | ✓ | ✓ | ✓ |
| bgp local-as | `bgp local-as 65100 no-prepend replace-as` | ✓ | ✓ | ✓ |
| remote-as | `remote-as 65001` | ✓ | ✓ | ✓ |
| VRF rd | `rd 65001:100` | ✓ | ✓ | ✓ |
| route-target | `route-target export 65001:100` | ✓ | ✓ | — |
| XR route-target value | `   65001:100` (3+ space-indented bare value line) | — | — | ✓ |
| XR community-set value | `  65001:1000` (2+ space-indented bare value line) | — | — | ✓ |
| community permit AS:tag | `permit 65001:1000` (in community-list) | ✓ | ✓ | — |
| community deny AS:tag | `deny 65001:1000` (in community-list) | — | — | — |
| set community AS:tag | `set community 65001:1000` (in route-map) | — | ✓ | — |

---

### Pass 4 — Named Objects

All named configuration objects are replaced with deterministic tokens. Definitions
and all references share the same token category so names stay consistent throughout
the sanitised output.

#### Hostname and Domain

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| hostname | `hostname ROUTER-NAME` | ✓ | ✓ | ✓ |
| ip domain-name (IOS/XE) | `ip domain-name corp.internal` | ✓ | ✓ | — |
| domain name (XR) | `domain name corp.internal` | — | — | ✓ |

#### Usernames

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| username | `username admin privilege 15 ...` — name field only | ✓ | ✓ | ✓ |

The username field is anonymised to `user-xxxx`. The credential value is separately
removed by Pass 1.

#### AAA Server Block Names

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| tacacs server name | `tacacs server TACACS-PRIMARY` | — | ✓ | — |
| radius server name | `radius server RADIUS-SRV-01` | — | ✓ | — |

#### AAA Group Server Block Names

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| aaa group server name | `aaa group server tacacs+ TACACS-GROUP` | ✓ | ✓ | ✓ |
| aaa group ref | `aaa authentication login default group TACACS-GROUP local` | ✓ | ✓ | ✓ |

The same `aaag-xxxx` token appears on the group definition line and all
`aaa authentication` / `aaa authorization` / `aaa accounting` reference lines.
Built-in protocol keywords (`tacacs+`, `radius`, `ldap`, `local`) are never
captured as group names.

#### VRF Names

Anonymised to `vrf-xxxx`. All definition and reference syntaxes are covered:

| Rule | Syntax | IOS | XE | XR |
|------|--------|:---:|:---:|:---:|
| `vrf definition NAME` | IOS XE definition | — | ✓ | — |
| `ip vrf NAME` | IOS definition | ✓ | — | — |
| `vrf NAME` (top-level) | XR definition | — | — | ✓ |
| `vrf forwarding NAME` | IOS XE interface reference | — | ✓ | — |
| `ip vrf forwarding NAME` | IOS interface reference | ✓ | — | — |
| `vrf NAME` (indented) | XR interface / sub-interface reference | — | — | ✓ |
| `address-family … vrf NAME` | BGP / routing AF reference | ✓ | ✓ | ✓ |
| Trailing `vrf NAME` | IP SLA and other trailing references | ✓ | ✓ | ✓ |

#### Routing Policy

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| route-map def | `route-map RMAP-NAME permit 10` | ✓ | ✓ | — |
| route-map ref | `neighbor x route-map RMAP-NAME in` | ✓ | ✓ | — |
| route-policy def (XR) | `route-policy POLICY-NAME` | — | — | ✓ |
| route-policy ref (XR) | `route-policy POLICY-NAME in` | — | — | ✓ |

#### QoS

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| policy-map def | `policy-map PM-NAME` | — | ✓ | ✓ |
| service-policy ref | `service-policy output PM-NAME` | — | ✓ | ✓ |
| class-map def | `class-map match-all CM-NAME` | — | ✓ | ✓ |
| class ref | `class CM-NAME` (inside policy-map) | — | ✓ | ✓ |

#### ACLs

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| ip access-list def | `ip access-list extended ACL-NAME` | ✓ | ✓ | — |
| access-group ref | `ip access-group ACL-NAME in` | ✓ | ✓ | — |
| access-class ref | `access-class ACL-NAME in` (line vty) | ✓ | ✓ | — |
| match ip address ref | `match ip address ACL-NAME` (route-map) | — | ✓ | — |
| match address ref | `match address ACL-NAME` (route-map) | ✓ | ✓ | — |
| match access-group name | `match access-group name ACL-NAME` | — | ✓ | — |
| XR SNMP ACL ref | `RO IPv4 ACL-NAME` / `RW IPv4 ACL-NAME` | — | — | ✓ |
| SNMP community ACL ref | `snmp-server community snmp-xxxx RO ACL-NAME` | ✓ | ✓ | ✓ |

#### Prefix Lists and Prefix Sets

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| prefix-list def | `ip prefix-list PFX-NAME` / `ipv6 prefix-list PFX-NAME` | ✓ | ✓ | — |
| prefix-list ref | `prefix-list PFX-NAME in` (BGP) | ✓ | ✓ | ✓ |
| prefix-set def (XR) | `prefix-set PFX-SET-NAME` | — | — | ✓ |
| XR destination in ref | `destination in PFX-SET-NAME` | — | — | ✓ |

Note: `ipv6 prefix-list` names are tokenised but the IPv6 prefix *values* inside
entries are not anonymised (see Known Limitations).

#### Community Lists and Community Sets

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| community-list def | `ip community-list standard COMM-NAME permit ...` | ✓ | ✓ | — |
| community-list ref | `community-list COMM-NAME` (in route-map match) | ✓ | ✓ | — |
| community-set def (XR) | `community-set COMM-SET-NAME` | — | — | ✓ |
| XR set community ref | `set community COMM-SET-NAME` (named set ref) | — | ✓ | ✓ |

#### BGP Peer-Groups and Neighbor-Groups

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| peer-group declaration | `neighbor PG-NAME peer-group` | ✓ | ✓ | — |
| peer-group assignment | `neighbor <ip> peer-group PG-NAME` | ✓ | ✓ | — |
| peer-group usage | `neighbor PG-NAME route-map / prefix-list / ...` | ✓ | ✓ | — |
| neighbor-group def (XR) | `neighbor-group NG-NAME` | — | — | ✓ |
| use neighbor-group (XR) | `use neighbor-group NG-NAME` | — | — | ✓ |

#### Keychains

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| key chain def | `key chain KC-NAME` | ✓ | ✓ | ✓ |
| EIGRP key-chain ref | `ip authentication key-chain eigrp 1 KC-NAME` | ✓ | — | — |
| key-chain ref (generic) | `key-chain KC-NAME` (OSPF / IS-IS) | ✓ | ✓ | — |

#### Other Objects

| Rule | Syntax matched | IOS | XE | XR |
|------|---------------|:---:|:---:|:---:|
| crypto map | `crypto map CM-NAME 10 ipsec-isakmp` | ✓ | ✓ | — |
| object-group def | `object-group network OG-NAME` | ✓ | ✓ | — |
| group-object ref | `group-object OG-NAME` (nested object-group) | ✓ | ✓ | — |
| ip sla def | `ip sla 10` | ✓ | ✓ | — |
| ip sla schedule | `ip sla schedule 10 ...` | ✓ | ✓ | — |
| ip sla ref | `track 1 ip sla 10` | ✓ | ✓ | — |
| track def | `track 1 ip sla ...` | ✓ | ✓ | — |
| track ref | `track 1` inline references | ✓ | ✓ | — |
| BGP template def | `template peer-session TMPL-NAME` | — | ✓ | — |
| BGP template ref | `inherit peer-session TMPL-NAME` | — | ✓ | — |

---

### Pass 5 — Descriptions

Description text is anonymised to `desc-xxxx` tokens.

| Rule | Syntax matched | Notes |
|------|---------------|-------|
| Standalone description lines | `description <text>` (any indentation) | Interface, VRF, route-map, object descriptions |
| Inline description text | `… description <text>` (mid-line) | e.g. `ip prefix-list NAME description <text>`, `neighbor X description <text>` |

The same description text maps to the same `desc-xxxx` token wherever it appears.

---

### Pass 6 — IPv4 Addresses

IPv4 host addresses are anonymised last, after all named-object and credential passes.

- **Token format** — `IP-xxxx` (4 hex chars), e.g. `IP-b766`
- **Deterministic** — same source IP → same `IP-xxxx` token for the same seed
- **Loopbacks preserved** — `127.0.0.0/8` range only; routable IPs on Loopback
  interfaces are anonymised
- **Special addresses preserved** — `0.0.0.0` and `255.255.255.255` exactly
- **Subnet masks preserved** — standard mask octets (255/254/252/248/240/224/192/128/0)
- **Wildcard masks preserved** — second address on ACE lines preserved by position

---

## Per-File Coverage Summary

| Rule group | `sample_ios` | `sample_iosxe` | `sample_iosxr` |
|-----------|:---:|:---:|:---:|
| enable secret/password | ✓ | ✓ | — |
| username credentials | ✓ | ✓ | ✓ |
| Line password | ✓ | ✓ | ✓ |
| OSPF message-digest-key | — | ✓ | — |
| Keychain key-string (IOS/XE) | ✓ | ✓ | — |
| Keychain key-string password (XR) | — | — | ✓ |
| NTP authentication-key (IOS/XE) | ✓ | ✓ | — |
| NTP/OSPF auth-key encrypted (XR) | — | — | ✓ |
| TACACS/RADIUS block keys | — | ✓ | ✓ |
| TACACS/RADIUS flat keys (IOS) | ✓ | — | — |
| AAA server-private keys | ✓ | ✓ | ✓ |
| BGP neighbor password | ✓ | ✓ | — |
| XR BGP password (neighbor block) | ✓ | ✓ | ✓ |
| IKE pre-shared-key | — | ✓ | — |
| crypto isakmp key | ✓ | ✓ | — |
| tunnel key | — | ✓ | — |
| PKI certificate block | — | ✓ | — |
| PKI enrollment url | — | ✓ | — |
| PKI subject-name | — | ✓ | — |
| Banner body | ✓ | ✓ | ✓ |
| Call-home fields (all 6) | ✓ | ✓ | ✓ |
| SNMP community (def + host ref + ACL) | ✓ | ✓ | ✓ |
| SNMP location | ✓ | ✓ | ✓ |
| SNMP contact | ✓ | ✓ | ✓ |
| AS numbers (BGP / rd / rt) | ✓ | ✓ | ✓ |
| BGP confederation identifier / peers | ✓ | ✓ | ✓ |
| BGP local-as | ✓ | ✓ | ✓ |
| Community AS:tag values | ✓ | ✓ | ✓ |
| set community AS:tag (route-map) | — | ✓ | — |
| Hostname | ✓ | ✓ | ✓ |
| Domain name | ✓ | ✓ | ✓ |
| Usernames | ✓ | ✓ | ✓ |
| TACACS/RADIUS server block names | — | ✓ | — |
| AAA group server block names + refs | ✓ | ✓ | ✓ |
| VRF (all syntax variants) | ✓ | ✓ | ✓ |
| Route-maps (IOS/XE) | ✓ | ✓ | — |
| Route-policies (XR) | — | — | ✓ |
| Policy-maps / class-maps | — | ✓ | ✓ |
| Named ACLs (all ref types) | ✓ | ✓ | ✓ |
| Wildcard masks (non-standard octets) | — | ✓ | — |
| Prefix-lists (IOS/XE) | ✓ | ✓ | — |
| Prefix-sets (XR) | — | — | ✓ |
| Community-lists (IOS/XE) | ✓ | ✓ | — |
| Community-sets (XR) | — | — | ✓ |
| BGP peer-groups | ✓ | ✓ | — |
| BGP neighbor-groups (XR) | — | — | ✓ |
| Keychains | ✓ | ✓ | ✓ |
| Crypto maps | ✓ | ✓ | — |
| Object-groups | ✓ | ✓ | — |
| IP SLA | ✓ | ✓ | — |
| Track objects | ✓ | ✓ | — |
| BGP templates | — | ✓ | — |
| Descriptions (standalone + inline) | ✓ | ✓ | ✓ |
| IPv4 host addresses | ✓ | ✓ | ✓ |
| IPv6 addresses (NOT sanitised) | ✗ | ✗ | ✗ |

---

## Known Limitations

The following items are not currently sanitised. The test configs include examples
of each so that future fixes can be verified by re-running the test suite.

| Item | Detail | Test config |
|------|--------|-------------|
| **IPv6 host addresses** | All IPv6 addresses pass through unchanged — `2001:db8:...`, `FE80::`, `::` etc. BGP neighbour *passwords* on IPv6 sessions are correctly removed; only the addresses are not tokenised. Highest-priority outstanding item for dual-stack deployments. | All three |
| **IPv6 ACL entries** | `deny ipv6 2001:db8:bad::/48 any` — IPv6 prefixes in ACL entries not anonymised | `sample_ios`, `sample_iosxe` |
| **IPv6 prefix-list / prefix-set values** | Prefix *names* are tokenised; the IPv6 prefix values inside entries are not | All three |
| **IPv6 static route next-hops** | `ipv6 route ::/0 2001:db8::1` — next-hop address not anonymised | `sample_ios`, `sample_iosxe` |
| **IPv6 BGP neighbour addresses** | `neighbor 2001:db8::1 remote-as ...` — address not anonymised (password is removed) | All three |
| **`archive path` naming convention** | Server IP is anonymised by the IP pass; the path template (e.g. `/configs/$h-$t`) reveals the device naming convention | — |
| **Hostnames embedded in descriptions** | If a real hostname appears inside a description string, the whole description is tokenised (good) but the mapping file retains the original, which contains the hostname | — |

---

## Rules Defined but Not Exercised by Current Test Configs

| Rule | Syntax | Notes |
|------|--------|-------|
| `authentication-key` (generic) | ` authentication-key 0 <key>` (no md5) | No plain-text IS-IS / OSPF auth in test configs |
| `community deny AS:tag` | `deny 65001:1000` in community-list | All test community entries use `permit` |
| `group-object ref` | `group-object OG-NAME` | Object-group nesting not present |
| `track ref` | Inline `track N` references | Track objects defined but not referenced inline |

---

## How to Run

```bash
# Sanitise all three test configs with a reproducible seed
python cisco_sanitise.py \
  -i ./test_configs/ \
  -o ./test_configs_sanitised/ \
  --seed test-run-2024 \
  --dump-map test_mapping.json

# Dry-run preview of a single file (stdout only, no files written)
python cisco_sanitise.py \
  -i ./test_configs/sample_iosxe.cfg \
  --dry-run \
  --seed test-run-2024

# Skip IP anonymisation (useful for isolating named-object changes)
python cisco_sanitise.py \
  -i ./test_configs/ \
  -o ./test_configs_sanitised/ \
  --seed test-run-2024 \
  --no-ips
```

---

## What to Verify After Running

**Credentials removed**
Search the output for `$1$`, `$5$`, `password 7`, `key 7`, `key 0`, `secret`.
None should retain a real value — all should show `<REMOVED>`.

**Server-private keys removed**
Check `aaa group server` blocks — `server-private <ip> key 7 <hash>` lines should
show `<REMOVED>` for the key value.

**PKI identity removed**
`enrollment url` and `subject-name` lines should show `<REMOVED>`.

**Banner body removed**
`banner motd` blocks should retain their delimiter lines (`^C`) with `<REMOVED>`
replacing the body text between them.

**Call-home fields removed**
All six call-home sensitive fields should show `<REMOVED>`.

**SNMP contact removed**
`snmp-server contact` should show `<REMOVED>`.

**SNMP community consistent**
The same community string should produce the same `snmp-xxxx` token on both the
definition line and any `snmp-server host` reference line.

**AS numbers tokenised**
`65001` should map to the same `AS-xxxx` token in `router bgp`, `remote-as`, `rd`,
`route-target`, `confederation identifier`, `confederation peers`, and `local-as`.

**AAA group names consistent**
`TACACS-GROUP` should carry the same `aaag-xxxx` token on the `aaa group server`
definition line and all `aaa authentication` / `aaa authorization` reference lines.

**IP addresses tokenised**
All non-loopback host addresses replaced with `IP-xxxx` tokens. Subnet masks and
wildcard masks untouched.

**IPv6 addresses NOT tokenised** (expected)
All `2001:db8:...`, `FE80::`, `::` addresses should pass through unchanged. This
confirms the known limitation is correctly documented and demonstrated.

**Names consistent**
A named object (e.g. `RMAP-ACME-IN`) should carry the same `rmap-xxxx` token on
its definition line and every reference.

**Config structure intact**
The sanitised file should remain syntactically valid — correct indentation, `!`
comment lines, `end` terminator, and block structure all preserved.

**Mapping file**
`test_mapping.json` lists every `original → token` substitution grouped by category.
Use this to trace any token back to its source value.