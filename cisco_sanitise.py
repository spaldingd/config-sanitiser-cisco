#!/usr/bin/env python3
"""
Cisco Configuration Sanitiser
Supports IOS, IOS XE, and IOS XR
Sanitises: passwords/secrets, IP addresses, SNMP community strings, BGP keys & peer info
"""

import re
import os
import sys
import ipaddress
import argparse
import hashlib
from pathlib import Path


# ─────────────────────────────────────────────
#  IP ADDRESS ANONYMISATION
#  Consistent mapping: same input IP → same output IP
# ─────────────────────────────────────────────

class IPAnonymiser:
    def __init__(self, seed="cisco-sanitiser"):
        self.seed = seed
        self._map = {}
        # Reserve pools per class to keep addresses realistic
        self._pools = {
            "loopback":  {"prefix": "192.0.2.",    "counter": 1},
            "private10": {"prefix": "10.",          "counter": None},
            "private172":{"prefix": "172.16.",      "counter": None},
            "private192":{"prefix": "192.168.",     "counter": None},
            "public":    {"prefix": "100.64.",      "counter": 1},
            "mgmt":      {"prefix": "198.51.100.",  "counter": 1},
        }
        self._pool_counters = {k: 1 for k in self._pools}

    def _deterministic_ip(self, original_ip: str) -> str:
        """Return a consistent anonymised IP for the given original."""
        if original_ip in self._map:
            return self._map[original_ip]

        try:
            addr = ipaddress.ip_address(original_ip)
        except ValueError:
            return original_ip

        # Preserve special addresses
        if addr.is_loopback or str(addr) in ("0.0.0.0", "255.255.255.255"):
            self._map[original_ip] = original_ip
            return original_ip

        # Determine pool
        if addr.is_private:
            first_octet = int(str(addr).split(".")[0])
            if first_octet == 10:
                pool_key = "private10"
            elif first_octet == 172:
                pool_key = "private172"
            else:
                pool_key = "private192"
        else:
            pool_key = "public"

        # Use a hash for deterministic but opaque mapping
        h = int(hashlib.md5(f"{self.seed}:{original_ip}".encode()).hexdigest(), 16)
        
        if pool_key == "private10":
            a = (h >> 16) & 0xFF
            b = (h >> 8)  & 0xFF
            c = h & 0xFE  # avoid .0 and .255 at last octet would need more logic
            new_ip = f"10.{a}.{b}.{max(1, c)}"
        elif pool_key == "private172":
            a = 16 + (h & 0x0F)  # 172.16–31
            b = (h >> 4) & 0xFF
            c = max(1, (h >> 12) & 0xFE)
            new_ip = f"172.{a}.{b}.{c}"
        elif pool_key == "private192":
            a = (h >> 8) & 0xFF
            b = max(1, h & 0xFE)
            new_ip = f"192.168.{a}.{b}"
        else:
            # Use 100.64.x.x (IANA shared address space — safe for docs)
            a = (h >> 8) & 0x3F  # 0-63
            b = max(1, h & 0xFE)
            new_ip = f"100.64.{a}.{b}"

        self._map[original_ip] = new_ip
        return new_ip

    def anonymise(self, text: str) -> str:
        """Replace all IPv4 addresses in text with anonymised equivalents."""
        ip_pattern = re.compile(
            r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        )
        return ip_pattern.sub(lambda m: self._deterministic_ip(m.group(0)), text)


# ─────────────────────────────────────────────
#  SANITISATION RULES
# ─────────────────────────────────────────────

# Each rule: (compiled_regex, replacement_string_or_callable)
# Replacement may reference groups via \1, \2 etc. or be a lambda

def build_rules(sanitise_ips: bool):
    rules = []

    # ── Passwords & Secrets ──────────────────────────────────────────────

    # enable secret / enable password
    rules.append((
        re.compile(r'^(enable\s+(?:secret|password)\s+(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # username … password / secret (IOS / IOS XE / IOS XR)
    rules.append((
        re.compile(r'^(username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # service password-encryption hashed passwords (type 7)
    rules.append((
        re.compile(r'^(password\s+7\s+)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))
    rules.append((
        re.compile(r'^(\s+password\s+7\s+)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # Plain passwords on lines (e.g. under line vty/con)
    rules.append((
        re.compile(r'^(\s+password\s+)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # secret 0/5/8/9 anywhere
    rules.append((
        re.compile(r'(\bsecret\s+[0-9]\s+)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # IOS XR: secret hashed value
    rules.append((
        re.compile(r'(secret\s+)\$[^\s]+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # Crypto pre-shared keys (IKE/IPsec)
    rules.append((
        re.compile(r'^(\s*pre-shared-key\s+(?:address\s+\S+\s+|local\s+|remote\s+)?(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # Tunnel keys
    rules.append((
        re.compile(r'^(\s*tunnel\s+key\s+)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # ── SNMP Community Strings ───────────────────────────────────────────

    # snmp-server community <string> [RO|RW] ...
    rules.append((
        re.compile(r'^(snmp-server\s+community\s+)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # IOS XR: snmp-server community-map / community
    rules.append((
        re.compile(r'^(\s*community\s+)\S+(\s+(?:RO|RW|ro|rw))', re.MULTILINE),
        r'\1<REMOVED>\2'
    ))

    # ── BGP Keys & Peer Info ─────────────────────────────────────────────

    # neighbor … password
    rules.append((
        re.compile(r'^(\s*neighbor\s+\S+\s+password\s+(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # IOS XR: password under neighbor block
    rules.append((
        re.compile(r'^(\s*password\s+(?:encrypted\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # BGP neighbor remote-as (replace AS number)
    rules.append((
        re.compile(r'^(\s*neighbor\s+)(\S+)(\s+remote-as\s+)(\d+)', re.MULTILINE),
        r'\1\2\3<AS-REMOVED>'
    ))

    # router bgp <AS>
    rules.append((
        re.compile(r'^(router\s+bgp\s+)\d+', re.MULTILINE),
        r'\1<AS-REMOVED>'
    ))

    # bgp router-id
    # (handled by IP anonymiser if IPs enabled, otherwise redact)
    if not sanitise_ips:
        rules.append((
            re.compile(r'^(\s*bgp\s+router-id\s+)\S+', re.MULTILINE),
            r'\1<REMOVED>'
        ))

    # ── Routing Protocol Auth Keys ───────────────────────────────────────

    # OSPF / EIGRP / IS-IS authentication keys
    rules.append((
        re.compile(r'^(\s*(?:ip\s+)?(?:ospf|eigrp)\s+(?:authentication-key|message-digest-key\s+\d+\s+\S+)\s+(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))
    rules.append((
        re.compile(r'^(\s*authentication-key\s+(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))
    rules.append((
        re.compile(r'^(\s*key-string\s+(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # ── TACACS+ / RADIUS Keys ────────────────────────────────────────────

    rules.append((
        re.compile(r'^(tacacs-server\s+key\s+(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))
    rules.append((
        re.compile(r'^(radius-server\s+key\s+(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))
    rules.append((
        re.compile(r'^(\s*key\s+(?:\d+\s+)?)\S+', re.MULTILINE),
        r'\1<REMOVED>'
    ))

    # ── Crypto / PKI Certificates ────────────────────────────────────────

    # Strip certificate blocks
    rules.append((
        re.compile(
            r'^\s*certificate\s+(?:self-signed\s+)?\S+\n.*?^\s*quit',
            re.MULTILINE | re.DOTALL
        ),
        ' certificate <REMOVED>\n  quit'
    ))

    return rules


# ─────────────────────────────────────────────
#  CORE SANITISE FUNCTION
# ─────────────────────────────────────────────

def sanitise(text: str, rules, ip_anonymiser=None) -> tuple[str, list]:
    """Apply all sanitisation rules; return sanitised text and change log."""
    log = []
    result = text

    for pattern, replacement in rules:
        new_result, count = pattern.subn(replacement, result)
        if count:
            log.append(f"  [{count:>3}x] {pattern.pattern[:70]}")
        result = new_result

    if ip_anonymiser:
        # Count IP changes by diffing before/after
        before_ips = set(re.findall(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
            result
        ))
        result = ip_anonymiser.anonymise(result)
        after_ips = set(re.findall(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
            result
        ))
        if before_ips:
            log.append(f"  [{len(before_ips):>3}x] IP addresses anonymised")

    return result, log


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Sanitise Cisco IOS / IOS XE / IOS XR configuration files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sanitise a single file
  python cisco_sanitise.py -i router1.cfg -o router1_sanitised.cfg

  # Sanitise all .cfg / .txt files in a directory
  python cisco_sanitise.py -i ./configs/ -o ./sanitised/

  # Skip IP anonymisation
  python cisco_sanitise.py -i ./configs/ -o ./sanitised/ --no-anonymize-ips

  # Dry run (print to stdout, no files written)
  python cisco_sanitise.py -i router1.cfg --dry-run
        """
    )
    parser.add_argument("-i", "--input",  required=True,  help="Input file or directory")
    parser.add_argument("-o", "--output", required=False, help="Output file or directory")
    parser.add_argument("--no-anonymize-ips", action="store_true",
                        help="Skip IP address anonymisation")
    parser.add_argument("--ip-seed", default="cisco-sanitiser",
                        help="Seed for deterministic IP mapping (default: cisco-sanitiser)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print sanitised output to stdout; do not write files")
    parser.add_argument("--extensions", default=".cfg,.txt,.conf,.log",
                        help="Comma-separated file extensions to process (default: .cfg,.txt,.conf,.log)")
    return parser.parse_args()


def process_file(input_path: Path, output_path: Path, rules, ip_anonymiser, dry_run: bool):
    print(f"\n{'─'*60}")
    print(f"  Input : {input_path}")

    try:
        text = input_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  ERROR reading file: {e}")
        return False

    sanitised, log = sanitise(text, rules, ip_anonymiser)

    if log:
        print("  Changes made:")
        for entry in log:
            print(entry)
    else:
        print("  No sensitive patterns found.")

    if dry_run:
        print(f"\n{'═'*60}  DRY RUN OUTPUT  {'═'*60}")
        print(sanitised)
        print(f"{'═'*60}")
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(sanitised, encoding="utf-8")
        print(f"  Output: {output_path}")

    return True


def main():
    args = parse_args()

    sanitise_ips = not args.no_anonymize_ips
    rules = build_rules(sanitise_ips)
    ip_anonymiser = IPAnonymiser(seed=args.ip_seed) if sanitise_ips else None

    input_path  = Path(args.input)
    output_path = Path(args.output) if args.output else None
    extensions  = tuple(args.extensions.split(","))

    print("╔══════════════════════════════════════════════════╗")
    print("║       Cisco Configuration Sanitiser              ║")
    print("║  IOS / IOS XE / IOS XR                           ║")
    print("╚══════════════════════════════════════════════════╝")
    print(f"  Anonymise IPs : {'Yes' if sanitise_ips else 'No'}")
    print(f"  IP seed       : {args.ip_seed}")
    print(f"  Dry run       : {'Yes' if args.dry_run else 'No'}")

    success = 0
    failure = 0

    if input_path.is_file():
        # Single file
        if output_path is None and not args.dry_run:
            output_path = input_path.parent / (input_path.stem + "_sanitised" + input_path.suffix)
        ok = process_file(input_path, output_path, rules, ip_anonymiser, args.dry_run)
        success += int(ok)
        failure += int(not ok)

    elif input_path.is_dir():
        # Directory — find all matching files
        files = [f for f in input_path.rglob("*") if f.is_file() and f.suffix.lower() in extensions]
        if not files:
            print(f"\n  No files matching {extensions} found in {input_path}")
            sys.exit(1)

        if output_path is None and not args.dry_run:
            output_path = input_path.parent / (input_path.name + "_sanitised")

        for f in sorted(files):
            if args.dry_run:
                dest = None
            else:
                dest = output_path / f.relative_to(input_path)
            ok = process_file(f, dest, rules, ip_anonymiser, args.dry_run)
            success += int(ok)
            failure += int(not ok)
    else:
        print(f"\n  ERROR: '{input_path}' is not a valid file or directory.")
        sys.exit(1)

    print(f"\n{'─'*60}")
    print(f"  Done. {success} file(s) sanitised, {failure} error(s).")

    # Print IP mapping summary if IPs were anonymised
    if sanitise_ips and ip_anonymiser and ip_anonymiser._map:
        print(f"\n  IP mapping ({len(ip_anonymiser._map)} addresses):")
        for orig, anon in sorted(ip_anonymiser._map.items()):
            if orig != anon:
                print(f"    {orig:>18}  →  {anon}")


if __name__ == "__main__":
    main()
