#!/usr/bin/env python3
"""
Cisco Named-Object Anonymiser
Extension module for cisco_sanitise.py

Discovers and consistently renames all "named things" across Cisco
IOS / IOS XE / IOS XR configurations:
  - Interface descriptions
  - Route-map names
  - VRF names
  - Policy-map / class-map names
  - ACL names
  - Prefix-list names
  - Community-list names
  - BGP peer-group names
  - Crypto map / keychain names
  - Track names
  - Object-group names
  - SLA names
  - Hostnames / domain names

Names are replaced consistently: the same name always maps to the
same anonymised token, so cross-references in the config remain valid.

Usage (standalone):
    python cisco_name_anonymise.py -i ./configs/ -o ./anon/ [--seed myseed]

Usage (as a library, e.g. after cisco_sanitise.py):
    from cisco_name_anonymise import NameAnonymiser
    anon = NameAnonymiser(seed="myseed")
    sanitised_text = anon.process(sanitised_text)
    print(anon.mapping_report())
"""

import re
import os
import sys
import hashlib
import argparse
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
#  TOKEN GENERATOR
#  Produces short, deterministic, human-readable tokens like "obj-4a2f", 
#  "vrf-c913", "rmap-77b1" so that references are traceable but opaque.
# ─────────────────────────────────────────────────────────────────────────────

class TokenGenerator:
    def __init__(self, seed: str = "cisco-anon"):
        self.seed = seed
        # Maps: category -> {original_name -> token}
        self._maps: dict[str, dict[str, str]] = {}

    def get(self, category: str, original: str) -> str:
        """Return a stable anonymised token for (category, original)."""
        if category not in self._maps:
            self._maps[category] = {}
        if original not in self._maps[category]:
            h = hashlib.sha256(f"{self.seed}:{category}:{original}".encode()).hexdigest()
            short = h[:4]  # 4 hex chars = 65536 possibilities per category
            prefix = CATEGORY_PREFIXES.get(category, "obj")
            token = f"{prefix}-{short}"
            # Handle collisions (rare but possible)
            existing_tokens = set(self._maps[category].values())
            offset = 4
            while token in existing_tokens:
                token = f"{prefix}-{h[offset:offset+4]}"
                offset += 1
            self._maps[category][original] = token
        return self._maps[category][original]

    def all_mappings(self) -> dict[str, dict[str, str]]:
        return {k: dict(v) for k, v in self._maps.items()}

    def total_replacements(self) -> int:
        return sum(len(v) for v in self._maps.values())


# Short prefixes per category — keeps tokens readable in-context
CATEGORY_PREFIXES = {
    "hostname":        "host",
    "domain":          "domain",
    "vrf":             "vrf",
    "route_map":       "rmap",
    "policy_map":      "pmap",
    "class_map":       "cmap",
    "acl":             "acl",
    "prefix_list":     "pfx",
    "community_list":  "cmty",
    "peer_group":      "pg",
    "crypto_map":      "cmap",
    "keychain":        "kc",
    "track":           "trk",
    "object_group":    "og",
    "ip_sla":          "sla",
    "description":     "desc",
    "interface_name":  "intf",  # for named subinterfaces / tunnels with names
    "template":        "tmpl",
    "service_policy":  "sp",
}


# ─────────────────────────────────────────────────────────────────────────────
#  NAMED OBJECT PATTERNS
#  Each entry: (category, regex_with_named_group "name", optional_flags)
#  The regex MUST contain a named group (?P<name>...) for the token to replace.
#
#  Strategy:
#   - DEFINE patterns capture the first declaration of a name.
#   - REFERENCE patterns capture subsequent uses of the same name.
#   Both are processed identically (same category → same token).
# ─────────────────────────────────────────────────────────────────────────────

# Patterns are tried in order; earlier = higher priority
NAME_PATTERNS = [

    # ── Hostname ─────────────────────────────────────────────────────────
    ("hostname", re.compile(
        r'^(hostname\s+)(?P<name>\S+)', re.MULTILINE
    )),
    ("domain", re.compile(
        r'^((?:ip\s+)?domain(?:-name|name)\s+)(?P<name>\S+)', re.MULTILINE
    )),

    # ── VRF ──────────────────────────────────────────────────────────────
    # IOS / IOS XE
    ("vrf", re.compile(
        r'^((?:ip\s+)?vrf\s+(?:definition\s+|forwarding\s+)?)(?P<name>\S+)', re.MULTILINE
    )),
    # IOS XR
    ("vrf", re.compile(
        r'^(vrd\s+)(?P<name>\S+)', re.MULTILINE
    )),
    # VRF references inside interface blocks
    ("vrf", re.compile(
        r'^(\s+vrf(?:\s+forwarding|\s+member)?\s+)(?P<name>\S+)', re.MULTILINE
    )),
    # neighbor activate under address-family with vrf
    ("vrf", re.compile(
        r'(address-family\s+\S+\s+vrf\s+)(?P<name>\S+)', re.MULTILINE
    )),

    # ── Route Maps ───────────────────────────────────────────────────────
    ("route_map", re.compile(
        r'^(route-map\s+)(?P<name>\S+)', re.MULTILINE
    )),
    # References: redistribute … route-map, neighbor … route-map
    ("route_map", re.compile(
        r'(\broute-map\s+)(?P<name>\S+)(?=\s+(?:in|out|permit|deny|\d))', re.MULTILINE
    )),

    # ── Policy Maps (QoS) ────────────────────────────────────────────────
    ("policy_map", re.compile(
        r'^(policy-map\s+)(?P<name>\S+)', re.MULTILINE
    )),
    ("policy_map", re.compile(
        r'(\bservice-policy\s+(?:input|output)\s+)(?P<name>\S+)', re.MULTILINE
    )),

    # ── Class Maps (QoS) ─────────────────────────────────────────────────
    ("class_map", re.compile(
        r'^(class-map\s+(?:match-(?:all|any|not)\s+)?)(?P<name>\S+)', re.MULTILINE
    )),
    ("class_map", re.compile(
        r'^(\s+class\s+)(?P<name>(?!default)\S+)', re.MULTILINE
    )),

    # ── Named ACLs ───────────────────────────────────────────────────────
    ("acl", re.compile(
        r'^(ip(?:v6)?\s+access-list\s+(?:extended|standard|named)?\s*)(?P<name>[A-Za-z]\S*)',
        re.MULTILINE
    )),
    # ACL references
    ("acl", re.compile(
        r'(\bip(?:v6)?\s+access-group\s+)(?P<name>[A-Za-z]\S*)', re.MULTILINE
    )),
    ("acl", re.compile(
        r'(\baccess-class\s+)(?P<name>[A-Za-z]\S*)', re.MULTILINE
    )),

    # ── Prefix Lists ─────────────────────────────────────────────────────
    ("prefix_list", re.compile(
        r'^(ip(?:v6)?\s+prefix-list\s+)(?P<name>\S+)', re.MULTILINE
    )),
    ("prefix_list", re.compile(
        r'(\bprefix-list\s+)(?P<name>\S+)', re.MULTILINE
    )),

    # ── Community Lists ──────────────────────────────────────────────────
    ("community_list", re.compile(
        r'^(ip\s+community-list\s+(?:expanded|standard\s+)?)(?P<name>\S+)', re.MULTILINE
    )),
    ("community_list", re.compile(
        r'(\bcommunity-list\s+)(?P<name>\S+)', re.MULTILINE
    )),

    # ── BGP Peer Groups ──────────────────────────────────────────────────
    ("peer_group", re.compile(
        r'^(\s+neighbor\s+)(?P<name>[A-Za-z]\S*)(\s+peer-group(?:\s+$|\s+(?!remote-as|update-source)))',
        re.MULTILINE
    )),
    # peer-group references
    ("peer_group", re.compile(
        r'^(\s+neighbor\s+\S+\s+peer-group\s+)(?P<name>\S+)', re.MULTILINE
    )),

    # ── Crypto Maps & Keychains ──────────────────────────────────────────
    ("crypto_map", re.compile(
        r'^(crypto\s+map\s+)(?P<name>\S+)', re.MULTILINE
    )),
    ("keychain", re.compile(
        r'^(key\s+chain\s+)(?P<name>\S+)', re.MULTILINE
    )),
    ("keychain", re.compile(
        r'(\bkey-chain\s+)(?P<name>\S+)', re.MULTILINE
    )),

    # ── Track Objects ────────────────────────────────────────────────────
    ("track", re.compile(
        r'^(track\s+)(?P<name>\d+)', re.MULTILINE
    )),
    ("track", re.compile(
        r'(\btrack\s+)(?P<name>\d+)', re.MULTILINE
    )),

    # ── Object Groups ────────────────────────────────────────────────────
    ("object_group", re.compile(
        r'^(object-group\s+(?:network|service)\s+)(?P<name>\S+)', re.MULTILINE
    )),
    ("object_group", re.compile(
        r'(\bgroup-object\s+)(?P<name>\S+)', re.MULTILINE
    )),

    # ── IP SLA ───────────────────────────────────────────────────────────
    ("ip_sla", re.compile(
        r'^(ip\s+sla\s+)(?P<name>\d+)', re.MULTILINE
    )),

    # ── Templates ────────────────────────────────────────────────────────
    ("template", re.compile(
        r'^(template\s+)(?P<name>\S+)', re.MULTILINE
    )),
    ("template", re.compile(
        r'(\binherit\s+peer-(?:session|policy)\s+)(?P<name>\S+)', re.MULTILINE
    )),
]


# ─────────────────────────────────────────────────────────────────────────────
#  INTERFACE DESCRIPTION ANONYMISER
#  Replaces free-text descriptions with opaque tokens while keeping
#  the description keyword so the config remains parseable.
# ─────────────────────────────────────────────────────────────────────────────

DESCRIPTION_RE = re.compile(
    r'^(\s*description\s+)(.+)$', re.MULTILINE
)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class NameAnonymiser:
    def __init__(self, seed: str = "cisco-anon", anonymise_descriptions: bool = True):
        self.tokens = TokenGenerator(seed=seed)
        self.anonymise_descriptions = anonymise_descriptions

    def process(self, text: str) -> str:
        """Apply all name-anonymisation passes to text."""
        result = text

        # Pass 1: Named objects
        for category, pattern in NAME_PATTERNS:
            result = pattern.sub(
                lambda m, cat=category: self._replace_name(m, cat),
                result
            )

        # Pass 2: Interface descriptions
        if self.anonymise_descriptions:
            result = DESCRIPTION_RE.sub(self._replace_description, result)

        return result

    def _replace_name(self, match: re.Match, category: str) -> str:
        """Substitute the named group with an anonymised token."""
        original_name = match.group("name")

        # Skip reserved/keyword values that aren't real names
        if original_name.lower() in RESERVED_KEYWORDS:
            return match.group(0)

        token = self.tokens.get(category, original_name)
        # Reconstruct: everything before the name + token + everything after
        start = match.start("name") - match.start()
        end   = match.end("name")   - match.start()
        full  = match.group(0)
        return full[:start] + token + full[end:]

    def _replace_description(self, match: re.Match) -> str:
        """Replace a description value with an opaque token."""
        prefix = match.group(1)   # e.g. "  description "
        desc   = match.group(2)   # the free-text value
        token  = self.tokens.get("description", desc)
        return prefix + token

    def mapping_report(self, as_json: bool = False) -> str:
        """Return a human-readable (or JSON) mapping of original → anonymised names."""
        mappings = self.tokens.all_mappings()
        if not mappings:
            return "  No named objects found."

        if as_json:
            return json.dumps(mappings, indent=2)

        lines = []
        for category, m in sorted(mappings.items()):
            if not m:
                continue
            lines.append(f"\n  [{category}]")
            for orig, token in sorted(m.items()):
                lines.append(f"    {orig:<40} →  {token}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  RESERVED KEYWORDS  (never anonymise these — they're Cisco syntax, not names)
# ─────────────────────────────────────────────────────────────────────────────

RESERVED_KEYWORDS = {
    "default", "any", "all", "none", "permit", "deny", "in", "out",
    "input", "output", "both", "true", "false", "enable", "disable",
    "active", "passive", "static", "dynamic", "extended", "standard",
    "match-all", "match-any", "match-not", "internet", "local",
    "management", "global", "null", "null0", "loopback",
    "ipv4", "ipv6", "vpnv4", "vpnv6", "l2vpn", "evpn", "flowspec",
}


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Anonymise named objects in Cisco IOS/IOS XE/IOS XR configs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Anonymise a single file
  python cisco_name_anonymise.py -i router1.cfg -o router1_anon.cfg

  # Anonymise a directory, dump name mapping to JSON
  python cisco_name_anonymise.py -i ./configs/ -o ./anon/ --dump-map mapping.json

  # Skip description anonymisation
  python cisco_name_anonymise.py -i ./configs/ -o ./anon/ --no-descriptions

  # Use a fixed seed (same seed = same tokens every run)
  python cisco_name_anonymise.py -i ./configs/ -o ./anon/ --seed my-project-2024

  # Dry run — print to stdout
  python cisco_name_anonymise.py -i router1.cfg --dry-run
        """
    )
    parser.add_argument("-i", "--input",    required=True)
    parser.add_argument("-o", "--output",   required=False)
    parser.add_argument("--seed",           default="cisco-anon",
                        help="Determinism seed (same seed = same tokens). Default: cisco-anon")
    parser.add_argument("--no-descriptions", action="store_true",
                        help="Skip anonymising interface/object descriptions")
    parser.add_argument("--dump-map",       metavar="FILE",
                        help="Write name→token mapping to a JSON file")
    parser.add_argument("--dry-run",        action="store_true",
                        help="Print to stdout; do not write files")
    parser.add_argument("--extensions",     default=".cfg,.txt,.conf",
                        help="File extensions to process")
    return parser.parse_args()


def process_file(input_path: Path, output_path: Path, anonymiser: NameAnonymiser,
                 dry_run: bool) -> bool:
    print(f"\n{'─'*60}")
    print(f"  Input : {input_path}")
    try:
        text = input_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  ERROR: {e}")
        return False

    result = anonymiser.process(text)

    if dry_run:
        print(f"\n{'═'*60}  DRY RUN OUTPUT  {'═'*60}")
        print(result)
        print(f"{'═'*60}")
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result, encoding="utf-8")
        print(f"  Output: {output_path}")

    return True


def main():
    args   = parse_args()
    anon   = NameAnonymiser(
        seed=args.seed,
        anonymise_descriptions=not args.no_descriptions
    )
    exts   = tuple(args.extensions.split(","))
    inp    = Path(args.input)
    out    = Path(args.output) if args.output else None

    print("╔══════════════════════════════════════════════════╗")
    print("║     Cisco Named-Object Anonymiser                ║")
    print("║  IOS / IOS XE / IOS XR                           ║")
    print("╚══════════════════════════════════════════════════╝")
    print(f"  Seed              : {args.seed}")
    print(f"  Anonymise descs   : {'No' if args.no_descriptions else 'Yes'}")
    print(f"  Dry run           : {'Yes' if args.dry_run else 'No'}")

    success = failure = 0

    if inp.is_file():
        dest = out or (inp.parent / (inp.stem + "_anon" + inp.suffix)) if not args.dry_run else None
        ok = process_file(inp, dest, anon, args.dry_run)
        success += int(ok); failure += int(not ok)

    elif inp.is_dir():
        files = [f for f in inp.rglob("*") if f.is_file() and f.suffix.lower() in exts]
        if not files:
            print(f"\n  No matching files found in {inp}")
            sys.exit(1)
        base_out = out or inp.parent / (inp.name + "_anon") if not args.dry_run else None
        for f in sorted(files):
            dest = (base_out / f.relative_to(inp)) if not args.dry_run else None
            ok = process_file(f, dest, anon, args.dry_run)
            success += int(ok); failure += int(not ok)
    else:
        print(f"\n  ERROR: '{inp}' is not a valid file or directory.")
        sys.exit(1)

    # Summary
    print(f"\n{'─'*60}")
    print(f"  Done. {success} file(s) processed, {failure} error(s).")
    print(f"  Total unique names anonymised: {anon.tokens.total_replacements()}")
    print("\n  Name mapping:")
    print(anon.mapping_report())

    # Dump JSON map
    if args.dump_map:
        map_path = Path(args.dump_map)
        map_path.write_text(anon.mapping_report(as_json=True), encoding="utf-8")
        print(f"\n  Mapping saved to: {map_path}")


if __name__ == "__main__":
    main()
