# Security Notice — Test Configuration Credentials

## Summary

The test configuration files in this repository contain credentials, password hashes,
and network addresses that appear sensitive. **Every single value is entirely fabricated.**
No credential, address, AS number, hostname, or organisation name in any test file has
ever been used on a real device or network. This document explains what is present,
why it is present, and why it does not represent a security risk.

---

## All Data Is Fictional

The three test configurations (`sample_ios.cfg`, `sample_iosxe.cfg`, `sample_iosxr.cfg`)
are synthetic. They were written from scratch to exercise the sanitiser's rule coverage
and contain no information derived from any real network, organisation, or device. In
particular:

- **Hostnames** such as `CORE-ROUTER-LON-01` and `BRANCH-ROUTER-MAN-01` are invented.
  They do not correspond to any real device.
- **Organisation names** such as `acmecorp.com`, `ACME-CORP`, and `NOC` are placeholder
  names with no relation to any real entity.
- **Network addresses** are drawn exclusively from RFC-reserved ranges that can never
  appear on the public internet:
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — RFC 1918 private ranges
  - `198.51.100.0/24`, `203.0.113.0/24` — RFC 5737 documentation ranges (TEST-NET-2/3)
  - `2001:db8::/32` — RFC 3849 IPv6 documentation range
- **AS numbers** such as `65000`–`65200` are in the IANA-reserved private AS range
  (64512–65534) and are not assigned to any real organisation.
- **PKI certificate data** in `sample_iosxe.cfg` is a hex blob that does not represent
  a real certificate issued by any CA.
- **Contact details**, street addresses, and email addresses (e.g. `noc@acmecorp.com`,
  `1 Data Centre Way`) are entirely made up.

---

## Why Plaintext Passwords Are Present

Cisco IOS, IOS XE, and IOS XR each support several credential encoding levels. A core
purpose of this tool is to detect and redact **all** of them. To test that coverage
comprehensively, the test configs must contain one or more examples of every encoding
type that appears in real-world configurations.

| Cisco type | Encoding | Example in test configs |
|-----------|----------|------------------------|
| Type 0 | Cleartext — stored verbatim in the config | `key 0 T@cacs$ecretKey99` |
| Type 5 | MD5-based hash (IOS `enable secret`) | `secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0` |
| Type 7 | Vigenère obfuscation — trivially reversible, not real encryption | `password 7 060506324F41584B56` |
| `encrypted` keyword (XR) | XR equivalent of type 7 | `password encrypted 060506324F41584B56` |

**Type 7 / `encrypted` values are not passwords.** The Cisco type-7 algorithm is a
well-documented, reversible obfuscation scheme. The hex strings `060506324F41584B56`,
`110A1016141D5A5E57`, `045802150C2E1D1C5A`, and similar values in these files are
fabricated sequences that do not encode any real credential. They are present solely
because the sanitiser must recognise and redact the `password 7 <hash>` pattern on
every line type where it appears.

**Type 5 hashes are also fabricated.** The strings beginning `$1$` are MD5 crypt
hashes. The values in the test configs (`$1$K2xP$mT9nL3vKpQ8rWzXy7sUoI3`,
`$1$mERr$hx5rVt7rPNoS4wqbXKX7m0`, etc.) were generated with random salts and do
not correspond to any known or used passphrase.

### Plaintext sensitive values used

The following cleartext values appear across the test configs. They are listed here
in full to make clear that they are obviously contrived test strings, not operational
secrets. The table covers two categories: **credentials** (keys, passwords, secrets)
and **device identity data** (hardware identifiers that are not credentials but are
still sensitive and must be redacted).

#### Credentials

| Value | Where used |
|-------|-----------|
| `T@cacs$ecretIOS!` | TACACS+ server key (IOS flat / XE server-private) |
| `T@cacs$ecretKey99` | TACACS+ server key (IOS XE / XR server-private) |
| `T@cacs$ecretKeyXR!` | TACACS+ server key (XR server-private) |
| `R@dius$ecret2024` | RADIUS server key |
| `OspfK3y$ecret!` | OSPF MD5 authentication key |
| `K3yStr!ng$ecret2024` | Key chain key-string (IOS/XE and XR) |
| `NtpAuth$ecret!` | NTP authentication key |
| `BranchV@nK3y!` | IKE pre-shared key (crypto isakmp) |
| `BranchIOS$ecret!` | IKE pre-shared key (crypto isakmp) |
| `Backup$iteKey` | IKE pre-shared key (crypto isakmp) |
| `iBGP$essionKey!` | BGP neighbour MD5 password |
| `iBGP$essionTemplate!` | BGP session-template password |
| `Cust0m3r$ecret!` | BGP neighbour MD5 password (customer peer) |
| `Cust0m3r@ccess!` | BGP neighbour MD5 password (customer peer) |
| `Cust0m3r$ecretMAN!` | BGP neighbour MD5 password (Manchester peer) |
| `NetOps$ecret2024!` | Username secret (netops account) |
| `M0nit0r$ecret!` | Username password (monitor account) |

None of these strings have ever been used as a credential on any real system. The
deliberate use of `$ecret`, `@ccess`, and similar leet-speak substitutions is
intentional — it makes them visually distinct from real operational credentials while
still exercising every code path in the sanitiser that handles cleartext values.

#### Device identity data

Device identity fields are not credentials, but they uniquely identify physical
hardware and must be redacted. They are fabricated values that follow the correct
format for their field type but do not correspond to any real device.

| Value | Field | Where used |
|-------|-------|-----------|
| `ISR4351/K9` | Product ID (PID) | `license udi` line in `sample_ios.cfg` |
| `FDO2213A0GL` | Serial number (SN) | `license udi` line in `sample_ios.cfg` |
| `C9500-16X` | Product ID (PID) | `license udi` line in `sample_iosxe.cfg` |
| `FCW2233A5ZV` | Serial number (SN) | `license udi` line in `sample_iosxe.cfg` |

These values are present solely to exercise the `license udi pid <PID> sn <SN>`
redaction rule. They have never been assigned to any real Cisco device.

---

## Why Credentials Must Be Kept in the Test Configs

The sanitiser operates on raw configuration text. To verify that a rule works
correctly, the input file must contain a real example of the pattern the rule
targets. There is no way to test redaction of a cleartext TACACS+ key without a
cleartext TACACS+ key being present in the file.

Specifically, the test suite depends on these credential examples to verify:

1. **Pattern coverage** — every credential-bearing line type that exists in
   IOS / IOS XE / IOS XR must appear in at least one test config so that the
   corresponding regex can be confirmed to match.

2. **Pass ordering** — credentials are redacted in pass 1, before any other
   substitution. Test configs with interleaved credential types (e.g. a type-0 key
   on one line and a type-7 hash on the next) confirm that the pass-ordering logic
   does not cause one form to be missed or double-processed.

3. **False-positive detection** — the IPv6 regex must not match type-7 hex strings.
   The only reliable way to confirm this is to run the sanitiser against a config
   that contains both IPv6 addresses and type-7 hashes on nearby lines.

4. **Dry-run verification** — the `--dry-run` flag prints the sanitised output
   without writing files. Reviewers comparing before/after output need recognisable
   credential strings in the input to confirm that `<REMOVED>` appears in the
   correct positions in the output.

Removing or replacing credentials with inert placeholder text (e.g. `key 0 REDACTED`)
would make the test configs unable to serve their purpose: the sanitiser would have
nothing meaningful to redact, and the test would prove nothing.

---

## What the Sanitiser Does to These Values

When `cisco_sanitise.py` is run against the test configs, every credential listed
above is replaced with `<REMOVED>` in the output. The mapping file produced by
`--dump-map` records the substitution but does not expose the original value — it
records only that a credential was present on that line. After sanitisation, no
credential value appears in any output file.

The test configs exist as *inputs* to demonstrate the tool works. They are never
intended to be, and should never be treated as, outputs.

---

## Checklist for New Contributors

If you are adding new test configuration content to this project, please follow
these rules:

- [ ] All IP addresses must be drawn from RFC 1918 (`10/8`, `172.16/12`,
      `192.168/16`) or RFC 5737/3849 documentation ranges
      (`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`)
- [ ] All AS numbers must be in the IANA private range (64512–65534)
- [ ] All hostnames, domain names, and organisation names must be clearly fictional
- [ ] Cleartext credential values must be obviously contrived strings
      (e.g. use `$ecret`, `@ccess` conventions, or similar) — never use any string
      that resembles a real password policy format
- [ ] Type-5 hashes must be generated fresh with a random salt and must not
      encode any real or guessable passphrase
- [ ] If adding a `license udi` line, use a clearly fictitious PID and serial number
      (e.g. `ISR4351/K9 sn FDO2213A0GL` — format correct, values fabricated)
- [ ] Any new credential pattern added for test coverage must be accompanied by a
      corresponding entry in `test_configs/TEST_REFERENCE.md`
- [ ] Run `cisco_sanitise.py --dry-run` against your new config and confirm that
      every credential you added appears as `<REMOVED>` in the output

---

## Questions

If you have concerns about any specific value in the test configs, open an issue.
Please quote the file name, line number, and the specific string you are querying.