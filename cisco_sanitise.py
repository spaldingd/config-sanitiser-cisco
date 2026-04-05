#!/usr/bin/env python3
"""
cisco_sanitise.py  —  Cisco Configuration Sanitiser  (unified, single-pass)
Supports IOS, IOS XE, IOS XR

What it sanitises
─────────────────
Credentials    : enable secret/password, username secrets, type-5/7 hashes,
                 line passwords, OSPF/EIGRP/IS-IS auth keys, key-chain
                 key-strings, TACACS+/RADIUS keys (block and flat style,
                 including server-private keys in aaa group server blocks),
                 IKE pre-shared-keys, BGP neighbour passwords, NTP auth keys,
                 PKI cert blocks, PKI enrollment URL and subject-name,
                 Smart Licensing UDI (product ID and serial number)
IP addresses   : all IPv4 host addresses → consistent IPv4-xxxx tokens,
                 all IPv6 host addresses → consistent IPv6-xxxx tokens,
                 subnet masks / wildcard masks / CIDR prefixes left unchanged;
                 link-local, loopback, multicast, and unspecified IPv6
                 addresses are preserved
AS numbers     : router bgp, neighbor remote-as, VRF rd / route-targets,
                 community-list value lines, bgp confederation identifier/peers,
                 bgp local-as — consistent AS-xxxx tokens
SNMP           : community strings → consistent tokens (traceable across config),
                 snmp-server host community references, SNMP location,
                 snmp-server contact
Banners        : banner motd / login / exec body text → <REMOVED>
Call-home      : contact-email-addr, street-address, site-id, customer-id,
                 phone-number, contract-id — all → <REMOVED>
Named objects  : hostnames, domain names, usernames, VRFs, route-maps/policies,
                 policy-maps, class-maps, named ACLs, prefix-lists/sets,
                 community-lists/sets, peer-groups/neighbor-groups, keychains,
                 crypto maps, transform sets, PKI trustpoints, object-groups,
                 IP SLA IDs, track IDs, BGP templates, TACACS/RADIUS server
                 block names, aaa group server block names
Descriptions   : all free-text description lines including inline descriptions
                 on neighbor, prefix-list, and object definition lines

Usage
─────
  python cisco_sanitise.py -i ./configs/ -o ./clean/ --seed myproject
  python cisco_sanitise.py -i router.cfg -o router_clean.cfg --dump-map map.json
  python cisco_sanitise.py -i router.cfg --dry-run
  python cisco_sanitise.py -i ./configs/ -o ./clean/ --no-ips --no-descriptions
"""

import re
import sys
import json
import hashlib
import argparse
import ipaddress
from datetime import datetime, timezone
from pathlib import Path


# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

RESERVED_KEYWORDS = {
    # Cisco syntax keywords that must never be treated as object names
    "default", "any", "all", "none", "permit", "deny", "in", "out",
    "input", "output", "both", "true", "false", "enable", "disable",
    "active", "passive", "static", "dynamic", "extended", "standard",
    "named", "match-all", "match-any", "match-not", "internet", "local",
    "management", "global", "null", "null0", "loopback", "definition",
    "forwarding", "member", "unicast", "multicast",
    "ipv4", "ipv6", "vpnv4", "vpnv6", "l2vpn", "evpn", "flowspec",
    "encrypted", "clear", "class-default", "infinite", "host",
}

CATEGORY_PREFIXES = {
    "hostname":       "host",
    "username":       "user",
    "domain":         "dom",
    "vrf":            "vrf",
    "route_map":      "rmap",
    "policy_map":     "pmap",
    "class_map":      "cmap",
    "acl":            "acl",
    "prefix_list":    "pfx",
    "community_list": "cmty",
    "snmp_community": "snmp",
    "peer_group":     "pg",
    "neighbor_group": "ng",
    "aaa_server":     "srv",
    "aaa_group":      "aaag",
    "crypto_map":     "cmap",
    "transform_set":  "tset",
    "trustpoint":     "tp",
    "keychain":       "kc",
    "track":          "trk",
    "object_group":   "og",
    "ip_sla":         "sla",
    "template":       "tmpl",
    "description":    "desc",
    "as_number":      "AS",
    "ip_address":     "IPv4",
    "ipv6_address":   "IPv6",
}

# Standard subnet masks (255.x.x.x or 0.x.x.x patterns with only valid mask octets)
_SUBNET_MASK_RE = re.compile(
    r'\b(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)\b'
)

# ACL wildcard masks: the second IPv4 address on any ACE line (permit/deny)
_IP_RE = re.compile(
    r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_ACE_LINE_RE = re.compile(
    r'^\s*(?:\d+\s+)?(?:permit|deny)\s+\S+\s+.*$', re.M
)

# OSPF/EIGRP network statements — wildcard is the second address on the line.
# e.g. " network 10.3.0.0 0.0.0.3 area 0" — preserve 0.0.0.3
# Also matches bare EIGRP statements with no wildcard: " network 172.16.0.0"
# NOTE: trailing group uses [ \t]+ (horizontal whitespace only) — \s+ would span
# newlines and merge consecutive network lines, causing the second line's address
# to be wrongly treated as a wildcard and skipped.
_NETWORK_STMT_RE = re.compile(
    r'^\s+network\s+\S+(?:[ \t]+.*)?$', re.M
)

# IPv6 address regex — union of all RFC 5952 compressed forms.
# Bounded by negative lookbehind/lookahead so it stops at '/' (prefix length),
# whitespace, and other delimiters.  Each candidate is validated with
# ipaddress.ip_address() to eliminate false positives (e.g. MAC addresses,
# type-7 credential hashes).
_IPV6_RE = re.compile(r"""(?<![:\w./])(
    (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}             |
    (?:[0-9a-fA-F]{1,4}:){1,7}:                           |
    (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}          |
    (?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2} |
    (?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3} |
    (?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4} |
    (?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5} |
    [0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}          |
    ::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}         |
    ::
)(?![:\w])""", re.X | re.I)


def _collect_skip_spans(text: str) -> set[tuple[int, int]]:
    """Return spans of all IP-like values that must NOT be anonymised."""
    skip: set[tuple[int, int]] = set()

    # 1. Standard subnet/wildcard masks (well-formed mask octets)
    for m in _SUBNET_MASK_RE.finditer(text):
        skip.add(m.span())

    # 2. Wildcard masks in ACE lines (permit/deny)
    #    e.g. "permit ip 10.0.0.0 0.255.255.255 any" — preserve 0.255.255.255
    #    e.g. "deny ip 172.16.0.0 0.15.255.255 any"  — preserve 0.15.255.255
    for ace in _ACE_LINE_RE.finditer(text):
        ips_in_ace = list(_IP_RE.finditer(text, ace.start(), ace.end()))
        i = 1
        while i < len(ips_in_ace):
            skip.add(ips_in_ace[i].span())
            i += 2

    # 3. Wildcard masks in OSPF/EIGRP network statements
    #    e.g. " network 10.3.0.0 0.0.0.3 area 0" — preserve 0.0.0.3
    for stmt in _NETWORK_STMT_RE.finditer(text):
        ips_in_stmt = list(_IP_RE.finditer(text, stmt.start(), stmt.end()))
        if len(ips_in_stmt) >= 2:
            skip.add(ips_in_stmt[1].span())

    return skip


# ══════════════════════════════════════════════════════════════════════════════
#  SANITISER CONFIGURATION  —  item / pass / group selection
# ══════════════════════════════════════════════════════════════════════════════

# ── Hierarchy definition ──────────────────────────────────────────────────────
#
# Three-level tree: GROUP → PASS → ITEM
# Items are the atomic units checked inside pass methods via cfg.enabled(item).
# Passes are named collections of items.
# Groups are named collections of passes.
#
# Key:  group_id  →  { pass_id  →  [item_id, ...] }

SANITISE_HIERARCHY: dict[str, dict[str, list[str]]] = {
    "credentials": {
        "local-auth": [
            "enable-secret",
            "username-secrets",
            "line-passwords",
        ],
        "routing-auth": [
            "ospf-keys",
            "keychain-keys",
            "ntp-keys",
            "bgp-passwords",
        ],
        "aaa-keys": [
            "tacacs-keys",
            "radius-keys",
            "server-private-keys",
        ],
        "vpn-keys": [
            "isakmp-keys",
            "tunnel-keys",
            "ike-psk",
        ],
        "pki": [
            "pki-cert-blocks",
            "pki-enrollment",
            "pki-subject-name",
        ],
        "device-identity": [
            "license-udi",
        ],
        "informational": [
            "banner-body",
            "call-home-fields",
        ],
    },
    "snmp": {
        "snmp": [
            "snmp-communities",
            "snmp-location",
            "snmp-contact",
        ],
    },
    "bgp-topology": {
        "as-numbers": [
            "bgp-asn",
            "vrf-rd-rt",
            "community-values",
            "bgp-confederation",
        ],
    },
    "named-objects": {
        "identity": [
            "hostname",
            "domain-name",
            "usernames",
        ],
        "routing-policy": [
            "route-maps",
            "route-policies",
            "policy-maps",
            "class-maps",
            "prefix-lists",
            "prefix-sets",
            "community-lists",
            "community-sets",
        ],
        "bgp-peers": [
            "peer-groups",
            "neighbor-groups",
            "bgp-templates",
        ],
        "network-objects": [
            "vrfs",
            "acls",
            "object-groups",
            "ip-sla",
            "track-objects",
        ],
        "aaa-objects": [
            "aaa-server-names",
            "aaa-group-names",
        ],
        "crypto-objects": [
            "crypto-maps",
            "transform-sets",
            "pki-trustpoints",
            "keychains",
        ],
    },
    "addressing": {
        "ipv4": [
            "ipv4-addresses",
        ],
        "ipv6": [
            "ipv6-addresses",
        ],
    },
    "descriptions": {
        "descriptions": [
            "standalone-descriptions",
            "inline-descriptions",
        ],
    },
}

# Convenience flat lookups built once at import time
_ALL_ITEMS:  frozenset[str] = frozenset(
    item
    for passes in SANITISE_HIERARCHY.values()
    for items in passes.values()
    for item in items
)
_ALL_PASSES: frozenset[str] = frozenset(
    pass_id
    for passes in SANITISE_HIERARCHY.values()
    for pass_id in passes
)
_ALL_GROUPS: frozenset[str] = frozenset(SANITISE_HIERARCHY)

# Maps pass_id → frozenset of item_ids within it
_PASS_TO_ITEMS: dict[str, frozenset[str]] = {
    pass_id: frozenset(items)
    for passes in SANITISE_HIERARCHY.values()
    for pass_id, items in passes.items()
}

# Maps group_id → frozenset of item_ids within it
_GROUP_TO_ITEMS: dict[str, frozenset[str]] = {
    group_id: frozenset(
        item
        for pass_items in passes.values()
        for item in pass_items
    )
    for group_id, passes in SANITISE_HIERARCHY.items()
}

# Maps item_id → (group_id, pass_id) for membership queries
_ITEM_TO_PATH: dict[str, tuple[str, str]] = {
    item: (group_id, pass_id)
    for group_id, passes in SANITISE_HIERARCHY.items()
    for pass_id, items in passes.items()
    for item in items
}


class SanitiserConfig:
    """
    Resolves CLI selection flags into a frozenset of enabled item IDs.

    Precedence (highest wins):  item  >  pass  >  group

    Resolution order applied to the full item set:
      1. Start with all items enabled
      2. Apply --skip-group  (disable all items in named groups)
      3. Apply --only-group  (disable items NOT in named groups)
      4. Apply --skip-pass   (disable all items in named passes)
      5. Apply --only-pass   (disable items NOT in named passes)
      6. Apply --skip        (disable named items individually)
      7. Apply --only        (disable all items not explicitly named)

    --skip and --only are mutually exclusive at each level.
    """

    def __init__(
        self,
        skip_groups:  list[str] | None = None,
        only_groups:  list[str] | None = None,
        skip_passes:  list[str] | None = None,
        only_passes:  list[str] | None = None,
        skip_items:   list[str] | None = None,
        only_items:   list[str] | None = None,
    ) -> None:
        enabled = set(_ALL_ITEMS)

        for g in (skip_groups or []):        # step 2
            enabled -= _GROUP_TO_ITEMS.get(g, frozenset())

        if only_groups:                      # step 3
            keep = frozenset().union(*(_GROUP_TO_ITEMS.get(g, frozenset())
                                       for g in only_groups))
            enabled &= keep

        for p in (skip_passes or []):        # step 4
            enabled -= _PASS_TO_ITEMS.get(p, frozenset())

        if only_passes:                      # step 5
            keep = frozenset().union(*(_PASS_TO_ITEMS.get(p, frozenset())
                                       for p in only_passes))
            enabled &= keep

        for i in (skip_items or []):         # step 6
            enabled.discard(i)

        if only_items:                       # step 7
            enabled &= frozenset(only_items)

        self._enabled: frozenset[str] = frozenset(enabled)

    # ── Querying ──────────────────────────────────────────────────────────

    def enabled(self, item_id: str) -> bool:
        """Return True if the named item is active."""
        return item_id in self._enabled

    def pass_has_any(self, pass_id: str) -> bool:
        """Return True if at least one item in the pass is enabled."""
        return bool(_PASS_TO_ITEMS.get(pass_id, frozenset()) & self._enabled)

    def group_has_any(self, group_id: str) -> bool:
        """Return True if at least one item in the group is enabled."""
        return bool(_GROUP_TO_ITEMS.get(group_id, frozenset()) & self._enabled)

    # ── Introspection (used by banner and startup summary) ────────────────

    def disabled_items(self) -> frozenset[str]:
        return _ALL_ITEMS - self._enabled

    def disabled_passes(self) -> frozenset[str]:
        """Passes where ALL items are disabled."""
        return frozenset(
            p for p in _ALL_PASSES
            if not (_PASS_TO_ITEMS[p] & self._enabled)
        )

    def disabled_groups(self) -> frozenset[str]:
        """Groups where ALL items are disabled."""
        return frozenset(
            g for g in _ALL_GROUPS
            if not (_GROUP_TO_ITEMS[g] & self._enabled)
        )

    def summary_lines(self) -> list[str]:
        """
        Human-readable summary of what is disabled, used in the startup
        header. Reports at the coarsest granularity possible: whole groups
        first, then whole passes, then individual items.
        """
        lines = []
        reported_items: set[str] = set()

        for g in sorted(self.disabled_groups()):
            lines.append(f"  Skipped group  : {g}")
            reported_items |= _GROUP_TO_ITEMS[g]

        for p in sorted(self.disabled_passes()):
            if _PASS_TO_ITEMS[p] <= reported_items:
                continue   # already covered by a group
            lines.append(f"  Skipped pass   : {p}")
            reported_items |= _PASS_TO_ITEMS[p]

        for i in sorted(self.disabled_items()):
            if i not in reported_items:
                lines.append(f"  Skipped item   : {i}")

        return lines

    # ── Validation ────────────────────────────────────────────────────────

    @staticmethod
    def validate(
        skip_groups:  list[str],
        only_groups:  list[str],
        skip_passes:  list[str],
        only_passes:  list[str],
        skip_items:   list[str],
        only_items:   list[str],
    ) -> list[str]:
        """Return a list of error strings (empty = valid)."""
        errors: list[str] = []
        for name in skip_groups + only_groups:
            if name not in _ALL_GROUPS:
                errors.append(
                    f"Unknown group '{name}'. "
                    f"Valid: {', '.join(sorted(_ALL_GROUPS))}")
        for name in skip_passes + only_passes:
            if name not in _ALL_PASSES:
                errors.append(
                    f"Unknown pass '{name}'. "
                    f"Valid: {', '.join(sorted(_ALL_PASSES))}")
        for name in skip_items + only_items:
            if name not in _ALL_ITEMS:
                errors.append(
                    f"Unknown item '{name}'. "
                    f"Valid: {', '.join(sorted(_ALL_ITEMS))}")
        if skip_groups and only_groups:
            errors.append("--skip-group and --only-group cannot be combined.")
        if skip_passes and only_passes:
            errors.append("--skip-pass and --only-pass cannot be combined.")
        if skip_items and only_items:
            errors.append("--skip and --only cannot be combined.")
        return errors

    @classmethod
    def default(cls) -> "SanitiserConfig":
        """All items enabled — equivalent to running with no selection flags."""
        return cls()

    @classmethod
    def from_args(cls, args: "argparse.Namespace") -> "SanitiserConfig":
        """
        Construct from parsed CLI args, handling legacy flag aliases.
        --no-ips          →  --skip-group addressing
        --no-descriptions →  --skip-pass  descriptions
        """
        skip_groups = list(args.skip_group)
        only_groups = list(args.only_group)
        skip_passes = list(args.skip_pass)
        only_passes = list(args.only_pass)
        skip_items  = list(args.skip)
        only_items  = list(args.only)

        if getattr(args, "no_ips", False):
            skip_groups.append("addressing")
        if getattr(args, "no_descriptions", False):
            skip_passes.append("descriptions")

        errors = cls.validate(
            skip_groups, only_groups,
            skip_passes, only_passes,
            skip_items,  only_items,
        )
        if errors:
            for e in errors:
                print(f"  ERROR: {e}", file=sys.stderr)
            sys.exit(2)

        return cls(
            skip_groups=skip_groups,
            only_groups=only_groups,
            skip_passes=skip_passes,
            only_passes=only_passes,
            skip_items=skip_items,
            only_items=only_items,
        )


# ══════════════════════════════════════════════════════════════════════════════
#  TOKEN GENERATOR  —  deterministic, collision-safe, double-anonymisation-safe
# ══════════════════════════════════════════════════════════════════════════════

class TokenGenerator:
    def __init__(self, seed: str = "cisco-sanitise"):
        self.seed = seed
        self._maps: dict[str, dict[str, str]] = {}
        # Reverse maps: category → set of output tokens (for already_token check)
        self._reverse: dict[str, set[str]] = {}

    def get(self, category: str, original: str) -> str:
        """Return a stable anonymised token for (category, original)."""
        cat_map = self._maps.setdefault(category, {})
        rev_set = self._reverse.setdefault(category, set())
        if original in cat_map:
            return cat_map[original]
        h = hashlib.sha256(
            f"{self.seed}:{category}:{original}".encode()
        ).hexdigest()
        prefix = CATEGORY_PREFIXES.get(category, "obj")
        token = f"{prefix}-{h[:4]}"
        offset = 4
        while token in rev_set:
            token = f"{prefix}-{h[offset:offset + 4]}"
            offset += 1
        cat_map[original] = token
        rev_set.add(token)
        return token

    def already_token(self, category: str, value: str) -> bool:
        """True if value is already an output token for this category."""
        return value in self._reverse.get(category, set())

    def all_mappings(self) -> dict[str, dict[str, str]]:
        return {k: dict(v) for k, v in self._maps.items()}

    def total(self) -> int:
        return sum(len(v) for v in self._maps.values())


# ══════════════════════════════════════════════════════════════════════════════
#  IP ANONYMISER  —  IPv4-xxxx / IPv6-xxxx token scheme, masks/CIDR preserved
# ══════════════════════════════════════════════════════════════════════════════

class IPAnonymiser:
    # IPv4 addresses always kept verbatim
    PRESERVE_V4 = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}

    def __init__(self, tokens: TokenGenerator):
        self.tokens = tokens

    # ── IPv4 ──────────────────────────────────────────────────────────────────

    def _anon_v4(self, original: str) -> str:
        """Return consistent IPv4-xxxx token for a host address."""
        try:
            addr = ipaddress.ip_address(original)
        except ValueError:
            return original
        if addr.is_loopback or original in self.PRESERVE_V4:
            return original
        return self.tokens.get("ip_address", original)

    def anonymise(self, text: str) -> str:
        """Replace IPv4 host addresses with IPv4-xxxx tokens; leave masks and CIDR alone."""
        skip_spans = _collect_skip_spans(text)

        ip_re = re.compile(
            r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        )
        parts: list[str] = []
        prev = 0
        for m in ip_re.finditer(text):
            if m.span() in skip_spans:
                parts.append(text[prev:m.end()])
            else:
                parts.append(text[prev:m.start()])
                parts.append(self._anon_v4(m.group(0)))
            prev = m.end()
        parts.append(text[prev:])
        return "".join(parts)

    # ── IPv6 ──────────────────────────────────────────────────────────────────

    def _anon_v6(self, original: str) -> str:
        """Return consistent IPv6-xxxx token for a host address."""
        try:
            addr = ipaddress.ip_address(original)
        except ValueError:
            return original
        # Preserve protocol-reserved addresses — carry no topology information
        if (addr.is_loopback or addr.is_unspecified
                or addr.is_link_local or addr.is_multicast):
            return original
        return self.tokens.get("ipv6_address", original)

    def anonymise_v6(self, text: str) -> str:
        """Replace IPv6 host addresses with IPv6-xxxx tokens.

        IPv6 ACLs and prefix statements use CIDR notation exclusively — there
        are no separate wildcard address fields — so no skip-span logic is
        needed.  The negative lookbehind on '/' in _IPV6_RE ensures prefix
        lengths (/64, /128, etc.) are never matched as part of an address.
        Each regex candidate is validated with ipaddress.ip_address() to
        eliminate false positives such as MAC addresses.
        """
        parts: list[str] = []
        prev = 0
        for m in _IPV6_RE.finditer(text):
            candidate = m.group(1)
            replacement = self._anon_v6(candidate)
            parts.append(text[prev:m.start(1)])
            parts.append(replacement)
            prev = m.end(1)
        parts.append(text[prev:])
        return "".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
#  UNIFIED SANITISER
# ══════════════════════════════════════════════════════════════════════════════

class CiscoSanitiser:
    def __init__(self, seed: str = "cisco-sanitise",
                 cfg: SanitiserConfig | None = None):
        self.tokens = TokenGenerator(seed=seed)
        self._cfg   = cfg if cfg is not None else SanitiserConfig.default()
        self.ip_anon = (
            IPAnonymiser(self.tokens)
            if self._cfg.group_has_any("addressing") else None
        )
        self._log: list[str] = []

    # Convenience properties for backward-compatible external access
    @property
    def anonymise_descriptions(self) -> bool:
        return self._cfg.pass_has_any("descriptions")

    # ─────────────────────────────────────────── public ──────────────────

    def process(self, text: str) -> str:
        self._log = []
        text = self._pass_credentials(text)
        if self._cfg.pass_has_any("snmp"):
            text = self._pass_snmp(text)
        if self._cfg.pass_has_any("as-numbers"):
            text = self._pass_as_numbers(text)
        if self._cfg.group_has_any("named-objects"):
            text = self._pass_named_objects(text)
        if self._cfg.pass_has_any("descriptions"):
            text = self._pass_descriptions(text)
        if self.ip_anon:
            if self._cfg.enabled("ipv4-addresses"):
                text = self.ip_anon.anonymise(text)
                self._log.append("  [IP]  IPv4 host addresses anonymised")
            if self._cfg.enabled("ipv6-addresses"):
                text = self.ip_anon.anonymise_v6(text)
                self._log.append("  [IP]  IPv6 host addresses anonymised")
        return text

    @property
    def log(self) -> list[str]:
        return list(self._log)

    # ─────────────────────────────────────────── helpers ─────────────────

    def _sub(self, pattern: re.Pattern, repl, text: str, label: str) -> str:
        result, n = pattern.subn(repl, text)
        if n:
            self._log.append(f"  [{n:>3}x] {label}")
        return result

    def _name(self, category: str, original: str) -> str:
        """Return token; pass through reserved keywords and existing tokens."""
        if original.lower() in RESERVED_KEYWORDS:
            return original
        if self.tokens.already_token(category, original):
            return original   # prevents double-anonymisation
        return self.tokens.get(category, original)

    def _repl(self, m: re.Match, category: str) -> str:
        """Generic replacement handler for patterns with named group 'n'."""
        original = m.group("n")
        token = self._name(category, original)
        s = m.start("n") - m.start()
        e = m.end("n") - m.start()
        full = m.group(0)
        return full[:s] + token + full[e:]

    def _sub_name(self, pattern: re.Pattern, category: str,
                  label: str, text: str) -> str:
        return self._sub(
            pattern,
            lambda m, cat=category: self._repl(m, cat),
            text, label
        )

    # ──────────────────────────────── pass 1: credentials ────────────────

    def _pass_credentials(self, text: str) -> str:
        S = self._sub
        cfg = self._cfg

        # ── local-auth ────────────────────────────────────────────────────
        if cfg.enabled("enable-secret"):
            text = S(re.compile(
                r'^(enable\s+(?:secret|password)\s+(?:\d+\s+)?)\S+', re.M),
                r'\1<REMOVED>', text, "enable secret/password")

        if cfg.enabled("username-secrets"):
            text = S(re.compile(
                r'^(username\s+\S+(?:\s+privilege\s+\d+)?'
                r'\s+(?:secret|password)\s+(?:\d+\s+)?)\S+', re.M),
                r'\1<REMOVED>', text, "username secret/password")

            # IOS XR username block: " secret [N] <hash>"
            text = S(re.compile(r'^(\s+secret[^\S\n]+(?:[0-9][^\S\n]+)?)\S+', re.M),
                r'\1<REMOVED>', text, "XR username secret block")

            # IOS XR username block: " password N <val>"
            text = S(re.compile(r'^(\s+password[^\S\n]+\d+[^\S\n]+)\S+', re.M),
                r'\1<REMOVED>', text, "XR username password block")

        if cfg.enabled("line-passwords"):
            # line vty/con password  (catch-all for remaining password lines)
            # Negative lookahead prevents matching "password encrypted ..." lines
            text = S(re.compile(
                r'^(\s+password[^\S\n]+(?:\d+[^\S\n]+)?)(?!encrypted\b)\S+', re.M),
                r'\1<REMOVED>', text, "line password")

        # ── routing-auth ──────────────────────────────────────────────────
        if cfg.enabled("ospf-keys"):
            text = S(re.compile(
                r'^(\s+ip\s+ospf\s+message-digest-key[^\S\n]+\d+[^\S\n]+md5[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
                r'\1<REMOVED>', text, "OSPF message-digest-key")

        if cfg.enabled("keychain-keys"):
            # IOS/XE keychain: "key-string [N] <val>"  — NOT "key-string password …"
            text = S(re.compile(
                r'^(\s+key-string[^\S\n]+)(?!password\b)(?:\d+[^\S\n]+)?\S+', re.M),
                r'\1<REMOVED>', text, "keychain key-string (IOS/XE)")
            # IOS XR keychain: "key-string password N <val>"
            text = S(re.compile(
                r'^(\s+key-string[^\S\n]+password[^\S\n]+\d+[^\S\n]+)\S+', re.M),
                r'\1<REMOVED>', text, "keychain key-string password (XR)")

        if cfg.enabled("ntp-keys"):
            # NTP authentication-key — must come BEFORE the generic rule
            text = S(re.compile(
                r'^(\s*(?:ntp\s+)?authentication-key\s+\d+\s+md5\s+)'
                r'(?!encrypted\b)(\S+)(\s+\d+)?$', re.M),
                lambda m: m.group(1) + '<REMOVED>' + (m.group(3) or ''),
                text, "NTP authentication-key (IOS/XE)")
            # IOS XR: "authentication-key N md5 encrypted <val>"
            text = S(re.compile(
                r'^(\s*(?:ntp\s+)?authentication-key\s+\d+\s+md5\s+encrypted\s+)\S+', re.M),
                r'\1<REMOVED>', text, "authentication-key md5 encrypted (XR)")
            # Generic OSPF/IS-IS authentication-key (indented, no md5 qualifier)
            text = S(re.compile(
                r'^(\s+authentication-key\s+\d+\s+)(?!md5\b)\S+', re.M),
                r'\1<REMOVED>', text, "authentication-key (generic)")

        if cfg.enabled("bgp-passwords"):
            # BGP neighbor password (IOS/XE inline)
            text = S(re.compile(
                r'^(\s+neighbor\s+\S+[^\S\n]+password[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
                r'\1<REMOVED>', text, "BGP neighbor password")
            # IOS XR BGP: "  password encrypted <val>" or "  password 0 <val>"
            text = S(re.compile(
                r'^(\s+password[^\S\n]+(?:encrypted[^\S\n]+|\d+[^\S\n]+))\S+', re.M),
                r'\1<REMOVED>', text, "XR BGP password (neighbor block)")

        # ── aaa-keys ──────────────────────────────────────────────────────
        if cfg.enabled("tacacs-keys") or cfg.enabled("radius-keys"):
            # Block-style AAA server key (inside tacacs server / radius server stanza)
            text = S(re.compile(r'^(\s+key[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
                r'\1<REMOVED>', text, "AAA server key (block)")

        if cfg.enabled("tacacs-keys"):
            text = S(re.compile(
                r'^(tacacs-server\s+(?:host\s+\S+\s+)?key[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
                r'\1<REMOVED>', text, "tacacs-server key")

        if cfg.enabled("radius-keys"):
            text = S(re.compile(
                r'^(radius-server\s+(?:host\s+\S+(?:\s+\S+)*?\s+)?key[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
                r'\1<REMOVED>', text, "radius-server key")

        if cfg.enabled("server-private-keys"):
            text = S(re.compile(
                r'^(\s+server-private\s+\S+(?:\s+(?:auth-port|acct-port|port|timeout)\s+\d+)*'
                r'\s+key[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
                r'\1<REMOVED>', text, "AAA server-private key")

        # ── vpn-keys ──────────────────────────────────────────────────────
        if cfg.enabled("ike-psk"):
            text = S(re.compile(
                r'^(\s*pre-shared-key\s+(?:address\s+\S+\s+|local\s+|remote\s+)?'
                r'(?:\d+[^\S\n]+)?)\S+', re.M),
                r'\1<REMOVED>', text, "IKE pre-shared-key")

        if cfg.enabled("isakmp-keys"):
            text = S(re.compile(r'^(crypto\s+isakmp\s+key\s+)\S+', re.M),
                r'\1<REMOVED>', text, "crypto isakmp key")

        if cfg.enabled("tunnel-keys"):
            text = S(re.compile(r'^(\s*tunnel\s+key\s+)\S+', re.M),
                r'\1<REMOVED>', text, "tunnel key")

        # ── pki ───────────────────────────────────────────────────────────
        if cfg.enabled("pki-cert-blocks"):
            text = S(re.compile(
                r'^\s*certificate\s+(?:self-signed\s+)?\S+\n.*?^\s*quit',
                re.M | re.DOTALL),
                ' certificate <REMOVED>\n  quit', text, "PKI certificate block")

        if cfg.enabled("pki-enrollment"):
            text = S(re.compile(r'^(\s*enrollment\s+url\s+)\S+', re.M),
                r'\1<REMOVED>', text, "PKI enrollment url")

        if cfg.enabled("pki-subject-name"):
            text = S(re.compile(r'^(\s*subject-name\s+).+$', re.M),
                r'\1<REMOVED>', text, "PKI subject-name")

        # ── informational ─────────────────────────────────────────────────
        if cfg.enabled("banner-body"):
            def _redact_banner(m: re.Match) -> str:
                return m.group(1) + '<REMOVED>' + m.group(4)
            text = S(re.compile(
                r'^(banner\s+\w+\s+(\S+)\n)(.*?)(\n\2\s*$)',
                re.M | re.DOTALL),
                _redact_banner, text, "banner body")

        if cfg.enabled("call-home-fields"):
            for kw in ('contact-email-addr', 'street-address', 'site-id',
                       'customer-id', 'phone-number', 'contract-id'):
                text = S(re.compile(
                    rf'^(\s*{re.escape(kw)}\s+).+$', re.M),
                    r'\1<REMOVED>', text, f"call-home {kw}")

        # ── device-identity ───────────────────────────────────────────────
        if cfg.enabled("license-udi"):
            text = S(re.compile(
                r'^(license\s+udi\s+pid\s+)\S+(\s+sn\s+)\S+', re.M),
                r'\1<REMOVED>\2<REMOVED>', text, "license udi (pid + sn)")

        return text

    # ──────────────────────────────── pass 2: SNMP ───────────────────────

    def _pass_snmp(self, text: str) -> str:
        """
        SNMP community strings are tokenised (not just redacted) so that
        references in 'snmp-server host' lines remain traceable.
        """
        N = self._sub_name
        S = self._sub
        cfg = self._cfg

        if cfg.enabled("snmp-communities"):
            text = N(re.compile(r'^(snmp-server\s+community\s+)(?P<n>\S+)', re.M),
                     "snmp_community", "SNMP community def (IOS/XE)", text)
            text = N(re.compile(r'^(snmp-server\s+community\s+)(?P<n>\S+)', re.M),
                     "snmp_community", "SNMP community def (XR)", text)
            text = N(re.compile(
                r'^(snmp-server\s+community\s+\S+\s+(?:RO|RW)\s+)(?P<n>[A-Za-z]\S*)', re.M),
                     "acl", "SNMP community ACL ref", text)
            text = N(re.compile(
                r'^(snmp-server\s+host\s+\S+\s+(?:version\s+\S+\s+)?)(?P<n>\S+)', re.M),
                     "snmp_community", "SNMP community host ref", text)

        if cfg.enabled("snmp-location"):
            text = S(re.compile(r'^(snmp-server\s+location\s+).+$', re.M),
                r'\1<REMOVED>', text, "SNMP location")

        if cfg.enabled("snmp-contact"):
            text = S(re.compile(r'^(snmp-server\s+contact\s+).+$', re.M),
                r'\1<REMOVED>', text, "SNMP contact")

        return text

    # ──────────────────────────────── pass 3: AS numbers ─────────────────

    def _pass_as_numbers(self, text: str) -> str:
        cfg = self._cfg

        def replace_as(m: re.Match) -> str:
            return m.group(1) + self.tokens.get("as_number", m.group(2))

        def replace_rt(m: re.Match) -> str:
            return (m.group(1)
                    + self.tokens.get("as_number", m.group(2))
                    + m.group(3))

        if cfg.enabled("bgp-asn"):
            text = self._sub(
                re.compile(r'^(router\s+bgp\s+)(\d+(?:\.\d+)?)', re.M),
                replace_as, text, "router bgp AS")
            text = self._sub(
                re.compile(r'^(\s*bgp\s+local-as\s+)(\d+(?:\.\d+)?)', re.M),
                replace_as, text, "bgp local-as")
            text = self._sub(
                re.compile(r'^(\s+(?:neighbor\s+\S+\s+)?remote-as\s+)(\d+(?:\.\d+)?)', re.M),
                replace_as, text, "remote-as")

        if cfg.enabled("bgp-confederation"):
            text = self._sub(
                re.compile(r'^(\s*bgp\s+confederation\s+identifier\s+)(\d+(?:\.\d+)?)', re.M),
                replace_as, text, "bgp confederation identifier")
            def replace_confederation_peers(m: re.Match) -> str:
                prefix = m.group(1)
                peers = re.sub(
                    r'\d+(?:\.\d+)?',
                    lambda a: self.tokens.get("as_number", a.group(0)),
                    m.group(2))
                return prefix + peers
            text = self._sub(
                re.compile(r'^(\s*bgp\s+confederation\s+peers\s+)(.+)$', re.M),
                replace_confederation_peers, text, "bgp confederation peers")

        if cfg.enabled("vrf-rd-rt"):
            text = self._sub(
                re.compile(r'(\brd\s+)(\d+(?:\.\d+)?)(\s*:\s*\d+)', re.M),
                replace_rt, text, "VRF rd")
            text = self._sub(
                re.compile(
                    r'(\broute-target\s+(?:export|import)\s+)(\d+(?:\.\d+)?)(\s*:\s*\d+)', re.M),
                replace_rt, text, "route-target")
            text = self._sub(
                re.compile(r'^(\s{3,})(\d+(?:\.\d+)?)(:\d+\s*$)', re.M),
                replace_rt, text, "XR route-target value")

        if cfg.enabled("community-values"):
            text = self._sub(
                re.compile(r'^(\s{2,})(\d+(?:\.\d+)?)(:\d+),?\s*$', re.M),
                replace_rt, text, "XR community-set value")
            text = self._sub(
                re.compile(r'(\bpermit\s+)(\d+(?:\.\d+)?)(:\d+)', re.M),
                replace_rt, text, "community permit AS:tag")
            text = self._sub(
                re.compile(r'(\bdeny\s+)(\d+(?:\.\d+)?)(:\d+)', re.M),
                replace_rt, text, "community deny AS:tag")
            text = self._sub(
                re.compile(r'(\bset\s+community\s+)(\d+(?:\.\d+)?)(:\d+)', re.M),
                replace_rt, text, "set community AS:tag")

        return text

    # ──────────────────────────────── pass 4: named objects ──────────────

    def _pass_named_objects(self, text: str) -> str:
        N = self._sub_name
        cfg = self._cfg

        # ── identity ──────────────────────────────────────────────────────
        if cfg.enabled("hostname"):
            text = N(re.compile(r'^(hostname\s+)(?P<n>\S+)', re.M),
                     "hostname", "hostname", text)

        if cfg.enabled("domain-name"):
            text = N(re.compile(r'^(ip\s+domain[- ]name\s+)(?P<n>\S+)', re.M),
                     "domain", "ip domain-name (IOS/XE)", text)
            text = N(re.compile(r'^(domain\s+name\s+)(?P<n>\S+)', re.M),
                     "domain", "domain name (XR)", text)

        if cfg.enabled("usernames"):
            text = N(re.compile(r'^(username\s+)(?P<n>\S+)', re.M),
                     "username", "username (IOS/XE)", text)
            text = N(re.compile(r'^(username\s+)(?P<n>\S+)', re.M),
                     "username", "username (XR)", text)

        # ── aaa-objects ───────────────────────────────────────────────────
        if cfg.enabled("aaa-server-names"):
            text = N(re.compile(r'^(tacacs\s+server\s+)(?P<n>\S+)', re.M),
                     "aaa_server", "tacacs server name", text)
            text = N(re.compile(r'^(radius\s+server\s+)(?P<n>\S+)', re.M),
                     "aaa_server", "radius server name", text)

        if cfg.enabled("aaa-group-names"):
            text = N(re.compile(
                r'^(aaa\s+group\s+server\s+\S+\s+)(?P<n>\S+)', re.M),
                     "aaa_group", "aaa group server name", text)
            text = N(re.compile(
                r'(\baaa\s+(?:authentication|authorization|accounting)\s+\S+\s+\S+\s+group\s+)'
                r'(?P<n>(?!tacacs\+?\b|radius\b|ldap\b|local\b)\S+)', re.M),
                     "aaa_group", "aaa group ref", text)

        # ── network-objects / vrfs ────────────────────────────────────────
        if cfg.enabled("vrfs"):
            text = N(re.compile(r'^(vrf\s+definition\s+)(?P<n>\S+)', re.M),
                     "vrf", "vrf definition (XE)", text)
            text = N(re.compile(r'^(ip\s+vrf\s+)(?P<n>\S+)', re.M),
                     "vrf", "ip vrf (IOS)", text)
            text = N(re.compile(
                r'^(vrf\s+)(?P<n>(?!definition\b|forwarding\b|member\b)\S+)', re.M),
                     "vrf", "vrf (XR top-level)", text)
            text = N(re.compile(r'^(\s+vrf\s+forwarding\s+)(?P<n>\S+)', re.M),
                     "vrf", "vrf forwarding (XE)", text)
            text = N(re.compile(r'^(\s+ip\s+vrf\s+forwarding\s+)(?P<n>\S+)', re.M),
                     "vrf", "ip vrf forwarding (IOS)", text)
            text = N(re.compile(
                r'^(\s+vrf\s+)(?P<n>(?!forwarding\b|member\b)\S+)', re.M),
                     "vrf", "vrf ref (XR interface)", text)
            text = N(re.compile(
                r'(\baddress-family\s+\S+(?:\s+\S+)?\s+vrf\s+)(?P<n>\S+)', re.M),
                     "vrf", "address-family vrf", text)
            text = N(re.compile(r'(\s+vrf\s+)(?P<n>\S+)(?=\s*$)', re.M),
                     "vrf", "trailing vrf ref", text)

        # ── routing-policy ────────────────────────────────────────────────
        if cfg.enabled("route-maps"):
            text = N(re.compile(r'^(route-map\s+)(?P<n>\S+)', re.M),
                     "route_map", "route-map def", text)
            text = N(re.compile(
                r'(\broute-map\s+)(?P<n>\S+)(?=\s+(?:in|out|permit|deny|\d))', re.M),
                     "route_map", "route-map ref", text)

        if cfg.enabled("route-policies"):
            text = N(re.compile(r'^(route-policy\s+)(?P<n>\S+)', re.M),
                     "route_map", "route-policy def (XR)", text)
            text = N(re.compile(r'(\broute-policy\s+)(?P<n>\S+)', re.M),
                     "route_map", "route-policy ref (XR)", text)

        if cfg.enabled("policy-maps"):
            text = N(re.compile(r'^(policy-map\s+)(?P<n>\S+)', re.M),
                     "policy_map", "policy-map def", text)
            text = N(re.compile(
                r'(\bservice-policy\s+(?:input|output)\s+)(?P<n>\S+)', re.M),
                     "policy_map", "service-policy ref", text)

        if cfg.enabled("class-maps"):
            text = N(re.compile(
                r'^(class-map\s+(?:match-(?:all|any|not)\s+)?)(?P<n>\S+)', re.M),
                     "class_map", "class-map def", text)
            text = N(re.compile(r'^(\s+class\s+)(?P<n>(?!default\b)\S+)', re.M),
                     "class_map", "class ref", text)

        # ── network-objects / acls ────────────────────────────────────────
        if cfg.enabled("acls"):
            text = N(re.compile(
                r'^(ip(?:v6)?\s+access-list\s+(?:extended|standard|named)?\s*)'
                r'(?P<n>[A-Za-z]\S*)', re.M),
                     "acl", "ip access-list def", text)
            text = N(re.compile(
                r'(\bip(?:v6)?\s+access-group\s+)(?P<n>[A-Za-z]\S*)', re.M),
                     "acl", "access-group ref", text)
            text = N(re.compile(r'(\baccess-class\s+)(?P<n>[A-Za-z]\S*)', re.M),
                     "acl", "access-class ref", text)
            text = N(re.compile(
                r'(\bmatch\s+ip\s+address\s+(?:acl\s+)?)'
                r'(?P<n>(?!prefix-list\b)[A-Za-z]\S*)', re.M),
                     "acl", "match ip address ref", text)
            text = N(re.compile(
                r'(\bmatch\s+address\s+(?:acl\s+)?)(?P<n>[A-Za-z]\S*)', re.M),
                     "acl", "match address ref", text)
            text = N(re.compile(
                r'(\bmatch\s+access-group\s+name\s+)(?P<n>\S+)', re.M),
                     "acl", "match access-group name", text)
            text = N(re.compile(r'(\b(?:RO|RW)\s+IPv[46]\s+)(?P<n>\S+)', re.M),
                     "acl", "XR SNMP ACL ref", text)

        if cfg.enabled("prefix-lists"):
            text = N(re.compile(r'^(ip(?:v6)?\s+prefix-list\s+)(?P<n>\S+)', re.M),
                     "prefix_list", "prefix-list def", text)
            text = N(re.compile(r'(\bprefix-list\s+)(?P<n>\S+)', re.M),
                     "prefix_list", "prefix-list ref", text)

        if cfg.enabled("prefix-sets"):
            text = N(re.compile(r'^(prefix-set\s+)(?P<n>\S+)', re.M),
                     "prefix_list", "prefix-set def (XR)", text)
            text = N(re.compile(r'(\bdestination\s+in\s+)(?P<n>\S+)', re.M),
                     "prefix_list", "XR destination in ref", text)

        if cfg.enabled("community-lists"):
            text = N(re.compile(
                r'^(ip\s+community-list\s+(?:standard|expanded)\s+)'
                r'(?P<n>(?!standard\b|expanded\b)\S+)', re.M),
                     "community_list", "community-list def", text)
            text = N(re.compile(
                r'(\bcommunity-list\s+)(?P<n>(?!standard\b|expanded\b)\S+)', re.M),
                     "community_list", "community-list ref", text)

        if cfg.enabled("community-sets"):
            text = N(re.compile(r'^(community-set\s+)(?P<n>\S+)', re.M),
                     "community_list", "community-set def (XR)", text)
            text = N(re.compile(r'(\bset\s+community\s+)(?P<n>[A-Za-z]\S*)', re.M),
                     "community_list", "XR set community ref", text)

        # ── bgp-peers ─────────────────────────────────────────────────────
        if cfg.enabled("peer-groups"):
            text = N(re.compile(
                r'^(\s+neighbor\s+)(?P<n>(?!neighbor\b)[A-Za-z]\S*)(\s+peer-group\s*$)', re.M),
                     "peer_group", "peer-group declaration", text)
            text = N(re.compile(
                r'^(\s+neighbor\s+\S+[^\S\n]+peer-group[^\S\n]+)(?P<n>[A-Za-z]\S+)', re.M),
                     "peer_group", "peer-group assignment", text)
            text = N(re.compile(
                r'^(\s+neighbor\s+)(?P<n>(?!neighbor\b)[A-Za-z][A-Za-z0-9_-]+)'
                r'(?=\s+(?:description|password|update-source|remote-as'
                r'|route-map|prefix-list|send-community|activate))', re.M),
                     "peer_group", "peer-group usage", text)

        if cfg.enabled("neighbor-groups"):
            text = N(re.compile(r'^(\s*neighbor-group\s+)(?P<n>\S+)', re.M),
                     "neighbor_group", "neighbor-group def (XR)", text)
            text = N(re.compile(r'^(\s+use\s+neighbor-group\s+)(?P<n>\S+)', re.M),
                     "neighbor_group", "use neighbor-group (XR)", text)

        if cfg.enabled("bgp-templates"):
            text = N(re.compile(
                r'^(template\s+peer-(?:session|policy)\s+)(?P<n>\S+)', re.M),
                     "template", "template def", text)
            text = N(re.compile(
                r'(\binherit\s+peer-(?:session|policy)\s+)(?P<n>\S+)', re.M),
                     "template", "template ref", text)

        # ── crypto-objects ────────────────────────────────────────────────
        if cfg.enabled("keychains"):
            text = N(re.compile(r'^(key\s+chain\s+)(?P<n>\S+)', re.M),
                     "keychain", "key chain def", text)
            text = N(re.compile(
                r'(\bip\s+authentication\s+key-chain\s+eigrp\s+\d+\s+)(?P<n>\S+)', re.M),
                     "keychain", "EIGRP key-chain ref", text)
            text = N(re.compile(
                r'(\bkey-chain\s+)(?P<n>(?!eigrp\b)\S+)', re.M),
                     "keychain", "key-chain ref", text)

        if cfg.enabled("crypto-maps"):
            text = N(re.compile(r'^(crypto\s+map\s+)(?P<n>\S+)', re.M),
                     "crypto_map", "crypto map", text)

        if cfg.enabled("transform-sets"):
            text = N(re.compile(
                r'^(crypto\s+ipsec\s+transform-set\s+)(?P<n>\S+)', re.M),
                     "transform_set", "transform-set def", text)
            text = N(re.compile(r'(\bset\s+transform-set\s+)(?P<n>\S+)', re.M),
                     "transform_set", "transform-set ref", text)

        if cfg.enabled("pki-trustpoints"):
            text = N(re.compile(
                r'^(crypto\s+pki\s+trustpoint\s+)(?P<n>\S+)', re.M),
                     "trustpoint", "pki trustpoint def", text)
            text = N(re.compile(
                r'^(crypto\s+pki\s+certificate\s+chain\s+)(?P<n>\S+)', re.M),
                     "trustpoint", "pki certificate chain ref", text)

        # ── network-objects (remaining) ───────────────────────────────────
        if cfg.enabled("object-groups"):
            text = N(re.compile(
                r'^(object-group\s+(?:network|service)\s+)(?P<n>\S+)', re.M),
                     "object_group", "object-group def", text)
            text = N(re.compile(r'(\bgroup-object\s+)(?P<n>\S+)', re.M),
                     "object_group", "group-object ref", text)

        if cfg.enabled("ip-sla"):
            text = N(re.compile(r'^(ip\s+sla\s+schedule\s+)(?P<n>\d+)', re.M),
                     "ip_sla", "ip sla schedule", text)
            text = N(re.compile(r'^(ip\s+sla\s+)(?P<n>\d+)', re.M),
                     "ip_sla", "ip sla def", text)
            text = N(re.compile(r'(\bip\s+sla\s+)(?P<n>\d+)', re.M),
                     "ip_sla", "ip sla ref", text)

        if cfg.enabled("track-objects"):
            text = N(re.compile(r'^(track\s+)(?P<n>\d+)', re.M),
                     "track", "track def", text)
            text = N(re.compile(r'(\btrack\s+)(?P<n>\d+)', re.M),
                     "track", "track ref", text)

        return text

    # ──────────────────────────────── pass 5: descriptions ───────────────

    def _pass_descriptions(self, text: str) -> str:
        """
        Anonymise description text in three forms:
          1. Standalone description lines:
               description <text>
                 description <text>
          2. Inline descriptions on object definition lines:
               ip prefix-list NAME description <text>
               neighbor <x> description <text>
          3. Inline descriptions on route-map / object-group / etc. lines
        """
        cfg = self._cfg

        def repl(m: re.Match) -> str:
            prefix = m.group(1)
            desc = m.group(2)
            if self.tokens.already_token("description", desc):
                return m.group(0)
            return prefix + self.tokens.get("description", desc)

        if cfg.enabled("standalone-descriptions"):
            text = self._sub(
                re.compile(r'^(\s*description\s+)(.+)$', re.M),
                repl, text, "standalone description lines")

        if cfg.enabled("inline-descriptions"):
            text = self._sub(
                re.compile(r'(\s+description\s+)(.+)$', re.M),
                repl, text, "inline description text")

        return text

    # ──────────────────────────────── mapping report ─────────────────────

    def mapping_report(self, as_json: bool = False) -> str:
        mappings = self.tokens.all_mappings()
        if not mappings:
            return "  Nothing was anonymised."
        if as_json:
            return json.dumps(mappings, indent=2)
        lines = []
        for category, m in sorted(mappings.items()):
            if not m:
                continue
            lines.append(f"\n  [{category}]")
            for orig, token in sorted(m.items()):
                lines.append(f"    {orig:<50} →  {token}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sanitise Cisco IOS / IOS XE / IOS XR configuration files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Selection flags (can be combined; item > pass > group precedence):
  --skip-group credentials      skip the entire credentials group
  --only-group named-objects    run only the named-objects group
  --skip-pass  vpn-keys         skip the vpn-keys pass
  --only-pass  routing-auth     run only the routing-auth pass
  --skip       banner-body,ntp-keys   skip specific items
  --only       hostname,ipv4-addresses  run only these items

Available groups : credentials, snmp, bgp-topology, named-objects,
                   addressing, descriptions
Available passes : local-auth, routing-auth, aaa-keys, vpn-keys, pki,
                   device-identity, informational, snmp, as-numbers,
                   identity, routing-policy, bgp-peers, network-objects,
                   aaa-objects, crypto-objects, ipv4, ipv6, descriptions
Run with --list-items to see all available item IDs.

Legacy flags (still supported):
  --no-ips          equivalent to --skip-group addressing
  --no-descriptions equivalent to --skip-pass  descriptions

Examples:
  python cisco_sanitise.py -i ./configs/ -o ./clean/ --seed myproject
  python cisco_sanitise.py -i router.cfg --dry-run
  python cisco_sanitise.py -i router.cfg --skip-group addressing,descriptions
  python cisco_sanitise.py -i router.cfg --only-group credentials,snmp
  python cisco_sanitise.py -i router.cfg --skip banner-body,call-home-fields
        """
    )
    p.add_argument("-i", "--input",       required=False,
                   help="Input file or directory")
    p.add_argument("-o", "--output",      required=False,
                   help="Output file or directory")
    p.add_argument("--seed",              default="cisco-sanitise",
                   help="Determinism seed — same seed = same tokens every run")
    p.add_argument("--dump-map",          metavar="FILE",
                   help="Write full original→token mapping to a JSON file")
    p.add_argument("--dry-run",           action="store_true",
                   help="Print sanitised output to stdout; do not write files")
    p.add_argument("--extensions",        default=".cfg,.txt,.conf,.log",
                   help="Comma-separated file extensions to process when input is a directory")
    p.add_argument("--list-items",        action="store_true",
                   help="Print all valid group / pass / item IDs and exit")

    # Selection flags
    sel = p.add_argument_group("selection (group level)")
    sel.add_argument("--skip-group", metavar="GROUP[,GROUP...]", default="",
                     help="Disable all items in the named group(s)")
    sel.add_argument("--only-group", metavar="GROUP[,GROUP...]", default="",
                     help="Enable only the named group(s); disable everything else")

    sel2 = p.add_argument_group("selection (pass level)")
    sel2.add_argument("--skip-pass", metavar="PASS[,PASS...]", default="",
                      help="Disable all items in the named pass(es)")
    sel2.add_argument("--only-pass", metavar="PASS[,PASS...]", default="",
                      help="Enable only the named pass(es); disable everything else")

    sel3 = p.add_argument_group("selection (item level)")
    sel3.add_argument("--skip", metavar="ITEM[,ITEM...]", default="",
                      help="Disable the named item(s)")
    sel3.add_argument("--only", metavar="ITEM[,ITEM...]", default="",
                      help="Enable only the named item(s); disable everything else")

    # Legacy aliases (kept for backward compatibility)
    leg = p.add_argument_group("legacy flags (deprecated aliases)")
    leg.add_argument("--no-ips",          action="store_true",
                     help="Skip IP address anonymisation (alias: --skip-group addressing)")
    leg.add_argument("--no-descriptions", action="store_true",
                     help="Skip description anonymisation (alias: --skip-pass descriptions)")

    args = p.parse_args()

    # --list-items: print hierarchy and exit
    if args.list_items:
        print("\nAvailable groups, passes, and items:\n")
        for group_id, passes in SANITISE_HIERARCHY.items():
            print(f"  GROUP: {group_id}")
            for pass_id, items in passes.items():
                print(f"    PASS: {pass_id}")
                for item in items:
                    print(f"      item: {item}")
        print()
        sys.exit(0)

    if not args.input:
        p.error("the following arguments are required: -i/--input")

    # Normalise comma-separated values to lists
    def _split(s: str) -> list[str]:
        return [x.strip() for x in s.split(",") if x.strip()]

    args.skip_group = _split(args.skip_group)
    args.only_group = _split(args.only_group)
    args.skip_pass  = _split(args.skip_pass)
    args.only_pass  = _split(args.only_pass)
    args.skip       = _split(args.skip)
    args.only       = _split(args.only)

    return args

# Repository URL — update this when the project is published.
# This value is embedded in the sanitised-configuration banner.
REPO_URL = "https://github.com/YOUR-ORG/YOUR-REPO"


def _seed_fingerprint(seed: str) -> str:
    """
    Return a 16-character hex fingerprint of the seed (first 64 bits of
    SHA-256). This is published in the sanitised-output banner so that two
    files can be verified as sharing the same seed (and therefore having
    consistent tokens) without exposing the seed itself.

    The seed is intentionally kept secret because, combined with the script,
    it enables forward-lookup against guessable values — most critically,
    IP addresses, where exhaustive enumeration of RFC 1918 space is trivial.
    A fingerprint preserves the diff-ability use-case while eliminating that
    risk.
    """
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def _sanitised_banner(seed: str, cfg: SanitiserConfig) -> str:
    """
    Return a comment block to prepend to every sanitised output file.
    Uses '!' as the comment character, which is valid on IOS, IOS XE, and IOS XR.
    The action list is derived from SanitiserConfig so it accurately reflects
    what was actually run.
    The seed fingerprint (not the seed itself) is included so that two sanitised
    files can be confirmed as sharing the same seed without exposing it.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    fingerprint = _seed_fingerprint(seed)

    # Build action lines at the most specific accurate level.
    # Each entry is (condition, label).
    action_map = [
        (cfg.group_has_any("credentials"),
         "credentials and keys replaced with <REMOVED>"),
        (cfg.enabled("license-udi"),
         "device identity data (Smart Licensing UDI) replaced with <REMOVED>"),
        (cfg.group_has_any("snmp"),
         "SNMP communities, location, and contact sanitised"),
        (cfg.group_has_any("bgp-topology"),
         "BGP AS numbers and community values replaced with opaque tokens"),
        (cfg.group_has_any("named-objects"),
         "named objects (hostnames, VRFs, ACLs, route-maps, etc.) replaced with"
         " opaque tokens"),
        (cfg.group_has_any("addressing"),
         "IP addresses (IPv4 and IPv6) replaced with opaque tokens"),
        (cfg.pass_has_any("descriptions"),
         "description text replaced with opaque tokens"),
    ]
    actions = [label for condition, label in action_map if condition]

    # Note any entirely-skipped groups so the reader knows what was NOT done
    skipped = sorted(cfg.disabled_groups())

    sep = "!" + "=" * 69
    out_lines = [
        sep,
        "! SANITISED CONFIGURATION",
        "! This file has been processed by cisco_sanitise.py.",
        "! Original sensitive data has been replaced as follows:",
        "!",
    ]
    for action in actions:
        out_lines.append(f"!   - {action}")
    if skipped:
        out_lines.append("!")
        out_lines.append("! The following sanitisation groups were skipped:")
        for g in skipped:
            out_lines.append(f"!   - {g}")
    out_lines += [
        "!",
        f"! Sanitised   : {now}",
        f"! Seed hash   : {fingerprint}  (SHA-256 fingerprint — not the seed itself)",
        f"! Script      : {REPO_URL}",
        sep,
        "",
    ]
    return "\n".join(out_lines) + "\n"

def process_file(path: Path, dest: "Path | None",
                 sanitiser: CiscoSanitiser, dry_run: bool) -> bool:
    print(f"\n{'─' * 60}")
    print(f"  Input : {path}")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  ERROR reading: {e}")
        return False

    result = sanitiser.process(text)
    result = _sanitised_banner(sanitiser.tokens.seed, sanitiser._cfg) + result
    for entry in sanitiser.log:
        print(entry)

    if dry_run:
        print(f"\n{'═' * 60}  DRY RUN  {'═' * 60}")
        print(result)
        print(f"{'═' * 60}")
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(result, encoding="utf-8")
        print(f"  Output: {dest}")
    return True


def main() -> None:
    args = parse_args()
    cfg = SanitiserConfig.from_args(args)
    sanitiser = CiscoSanitiser(seed=args.seed, cfg=cfg)
    exts = tuple(e if e.startswith(".") else f".{e}"
                 for e in args.extensions.split(","))
    inp = Path(args.input)
    out = Path(args.output) if args.output else None

    print("╔══════════════════════════════════════════════════════════╗")
    print("║       Cisco Configuration Sanitiser  (unified)          ║")
    print("║  IOS · IOS XE · IOS XR                                  ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Seed     : {args.seed}")
    print(f"  Dry run  : {'Yes' if args.dry_run else 'No'}")
    for line in cfg.summary_lines():
        print(line)
    if not cfg.summary_lines():
        print("  Selection: all items enabled (default)")

    success = failure = 0

    if inp.is_file():
        dest = (out or inp.parent / (inp.stem + "_sanitised" + inp.suffix)
                ) if not args.dry_run else None
        ok = process_file(inp, dest, sanitiser, args.dry_run)
        success += int(ok)
        failure += int(not ok)

    elif inp.is_dir():
        files = [f for f in inp.rglob("*")
                 if f.is_file() and f.suffix.lower() in exts]
        if not files:
            print(f"\n  No files matching {exts} found in {inp}")
            sys.exit(1)
        base_out = (out or inp.parent / (inp.name + "_sanitised")
                    ) if not args.dry_run else None
        for f in sorted(files):
            dest = (base_out / f.relative_to(inp)) if not args.dry_run else None
            ok = process_file(f, dest, sanitiser, args.dry_run)
            success += int(ok)
            failure += int(not ok)
    else:
        print(f"\n  ERROR: '{inp}' is not a valid file or directory.")
        sys.exit(1)

    print(f"\n{'═' * 60}")
    print(f"  Done. {success} file(s) sanitised, {failure} error(s).")
    print(f"  Unique objects anonymised: {sanitiser.tokens.total()}")
    print("\n  Full mapping:")
    print(sanitiser.mapping_report())

    if args.dump_map:
        map_path = Path(args.dump_map)
        map_path.write_text(sanitiser.mapping_report(as_json=True), encoding="utf-8")
        print(f"\n  Mapping saved to: {map_path}")

if __name__ == "__main__":
    main()