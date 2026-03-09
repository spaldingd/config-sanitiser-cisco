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
                 anonymise_ips: bool = True,
                 anonymise_descriptions: bool = True):
        self.tokens = TokenGenerator(seed=seed)
        self.ip_anon = IPAnonymiser(self.tokens) if anonymise_ips else None
        self.anonymise_descriptions = anonymise_descriptions
        self._log: list[str] = []

    # ─────────────────────────────────────────── public ──────────────────

    def process(self, text: str) -> str:
        self._log = []
        text = self._pass_credentials(text)
        text = self._pass_snmp(text)
        text = self._pass_as_numbers(text)
        text = self._pass_named_objects(text)
        if self.anonymise_descriptions:
            text = self._pass_descriptions(text)
        if self.ip_anon:
            text = self.ip_anon.anonymise(text)
            self._log.append("  [IP]  IPv4 host addresses anonymised")
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

        # enable secret / enable password
        text = S(re.compile(
            r'^(enable\s+(?:secret|password)\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "enable secret/password")

        # username … secret/password — credential value only, username preserved
        # for anonymisation in named-objects pass
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

        # line vty/con password  (catch-all for remaining password lines)
        # Negative lookahead prevents matching "password encrypted ..." lines
        # (those are handled by the XR BGP password rule later)
        text = S(re.compile(r'^(\s+password[^\S\n]+(?:\d+[^\S\n]+)?)(?!encrypted\b)\S+', re.M),
            r'\1<REMOVED>', text, "line password")

        # OSPF message-digest-key
        text = S(re.compile(
            r'^(\s+ip\s+ospf\s+message-digest-key[^\S\n]+\d+[^\S\n]+md5[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
            r'\1<REMOVED>', text, "OSPF message-digest-key")

        # IOS/XE keychain: "key-string [N] <val>"  — NOT "key-string password …"
        text = S(re.compile(
            r'^(\s+key-string[^\S\n]+)(?!password\b)(?:\d+[^\S\n]+)?\S+', re.M),
            r'\1<REMOVED>', text, "keychain key-string (IOS/XE)")

        # IOS XR keychain: "key-string password N <val>"
        text = S(re.compile(
            r'^(\s+key-string[^\S\n]+password[^\S\n]+\d+[^\S\n]+)\S+', re.M),
            r'\1<REMOVED>', text, "keychain key-string password (XR)")

        # NTP authentication-key — must come BEFORE the generic authentication-key
        # rule to handle the trailing type-digit correctly.
        # Handles both:
        #   ntp authentication-key 1 md5 <key>          (IOS/XE — no trailing digit)
        #   ntp authentication-key 1 md5 <key> 7        (IOS — trailing type digit)
        text = S(re.compile(
            r'^(\s*(?:ntp\s+)?authentication-key\s+\d+\s+md5\s+)'
            r'(?!encrypted\b)(\S+)(\s+\d+)?$', re.M),
            lambda m: m.group(1) + '<REMOVED>' + (m.group(3) or ''),
            text, "NTP authentication-key (IOS/XE)")

        # IOS XR: "authentication-key N md5 encrypted <val>"  — MUST be before generic rule
        text = S(re.compile(
            r'^(\s*(?:ntp\s+)?authentication-key\s+\d+\s+md5\s+encrypted\s+)\S+', re.M),
            r'\1<REMOVED>', text, "authentication-key md5 encrypted (XR)")

        # Generic OSPF/IS-IS authentication-key (indented, no md5 qualifier)
        # Requires a digit immediately after the keyword to avoid eating 'md5'
        text = S(re.compile(
            r'^(\s+authentication-key\s+\d+\s+)(?!md5\b)\S+', re.M),
            r'\1<REMOVED>', text, "authentication-key (generic)")

        # Block-style AAA server key (inside tacacs server / radius server stanza)
        # Use [^\S\n]+ to prevent the digit+whitespace from crossing a newline
        text = S(re.compile(r'^(\s+key[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
            r'\1<REMOVED>', text, "AAA server key (block)")

        # Flat-style tacacs-server key (IOS)
        text = S(re.compile(
            r'^(tacacs-server\s+(?:host\s+\S+\s+)?key[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
            r'\1<REMOVED>', text, "tacacs-server key")

        # Flat-style radius-server key (IOS)
        # host <ip> [<auth-port>] key ... — the port tokens are optional
        text = S(re.compile(
            r'^(radius-server\s+(?:host\s+\S+(?:\s+\S+)*?\s+)?key[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
            r'\1<REMOVED>', text, "radius-server key")

        # BGP neighbor password (IOS/XE inline)
        text = S(re.compile(
            r'^(\s+neighbor\s+\S+[^\S\n]+password[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
            r'\1<REMOVED>', text, "BGP neighbor password")

        # IOS XR BGP: "  password encrypted <val>" or "  password 0 <val>"
        # [^\S\n]+ prevents crossing newlines
        text = S(re.compile(
            r'^(\s+password[^\S\n]+(?:encrypted[^\S\n]+|\d+[^\S\n]+))\S+', re.M),
            r'\1<REMOVED>', text, "XR BGP password (neighbor block)")

        # IKE pre-shared-key
        text = S(re.compile(
            r'^(\s*pre-shared-key\s+(?:address\s+\S+\s+|local\s+|remote\s+)?'
            r'(?:\d+[^\S\n]+)?)\S+', re.M),
            r'\1<REMOVED>', text, "IKE pre-shared-key")

        # crypto isakmp key <key> address <ip>
        text = S(re.compile(r'^(crypto\s+isakmp\s+key\s+)\S+', re.M),
            r'\1<REMOVED>', text, "crypto isakmp key")

        # tunnel key
        text = S(re.compile(r'^(\s*tunnel\s+key\s+)\S+', re.M),
            r'\1<REMOVED>', text, "tunnel key")

        # PKI certificate blocks
        text = S(re.compile(
            r'^\s*certificate\s+(?:self-signed\s+)?\S+\n.*?^\s*quit',
            re.M | re.DOTALL),
            ' certificate <REMOVED>\n  quit', text, "PKI certificate block")

        # PKI trustpoint: enrollment url
        text = S(re.compile(r'^(\s*enrollment\s+url\s+)\S+', re.M),
            r'\1<REMOVED>', text, "PKI enrollment url")

        # PKI trustpoint: subject-name (free text, rest of line)
        text = S(re.compile(r'^(\s*subject-name\s+).+$', re.M),
            r'\1<REMOVED>', text, "PKI subject-name")

        # server-private key inside aaa group server blocks
        # e.g. " server-private 10.x.x.x [port N] key [N] <val>"
        text = S(re.compile(
            r'^(\s+server-private\s+\S+(?:\s+(?:auth-port|acct-port|port|timeout)\s+\d+)*'
            r'\s+key[^\S\n]+(?:\d+[^\S\n]+)?)\S+', re.M),
            r'\1<REMOVED>', text, "AAA server-private key")

        # banner body text (motd / login / exec / incoming)
        # Cisco banners: "banner WORD DELIM\n...body...\nDELIM"
        # The delimiter is the token immediately after the banner keyword (e.g. ^C, #, %)
        # Use a backreference to match the closing delimiter on its own line.
        def _redact_banner(m: re.Match) -> str:
            return m.group(1) + '<REMOVED>' + m.group(4)
        text = S(re.compile(
            r'^(banner\s+\w+\s+(\S+)\n)(.*?)(\n\2\s*$)',
            re.M | re.DOTALL),
            _redact_banner, text, "banner body")

        # call-home sensitive fields
        for kw in ('contact-email-addr', 'street-address', 'site-id',
                   'customer-id', 'phone-number', 'contract-id'):
            text = S(re.compile(
                rf'^(\s*{re.escape(kw)}\s+).+$', re.M),
                r'\1<REMOVED>', text, f"call-home {kw}")

        # Smart Licensing UDI — written to running-config by IOS/IOS XE.
        # Format: license udi pid <PRODUCT-ID> sn <SERIAL-NUMBER>
        # Both PID and serial number uniquely identify the physical device
        # and must be redacted. The keywords 'pid' and 'sn' are preserved
        # so the reader can see which field was in each position.
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

        # IOS/XE: "snmp-server community <name> RO|RW ..."
        # Tokenise the community name so host-line refs match
        text = N(re.compile(r'^(snmp-server\s+community\s+)(?P<n>\S+)', re.M),
                 "snmp_community", "SNMP community def (IOS/XE)", text)

        # IOS XR block: "snmp-server community <name>" (name on its own line)
        text = N(re.compile(r'^(snmp-server\s+community\s+)(?P<n>\S+)', re.M),
                 "snmp_community", "SNMP community def (XR)", text)

        # Named ACL after RO/RW on community line (community is already tokenised above)
        # e.g. "snmp-server community snmp-xxxx RO SNMP-ACCESS-LIST"
        # Only match alpha-starting names; numeric ACLs are left unchanged
        text = N(re.compile(
            r'^(snmp-server\s+community\s+\S+\s+(?:RO|RW)\s+)(?P<n>[A-Za-z]\S*)', re.M),
                 "acl", "SNMP community ACL ref", text)

        # snmp-server host <ip> version 2c <community>
        text = N(re.compile(
            r'^(snmp-server\s+host\s+\S+\s+(?:version\s+\S+\s+)?)(?P<n>\S+)', re.M),
                 "snmp_community", "SNMP community host ref", text)

        # SNMP location — redact free text
        text = S(re.compile(r'^(snmp-server\s+location\s+).+$', re.M),
            r'\1<REMOVED>', text, "SNMP location")

        # SNMP contact — redact free text (may be quoted)
        text = S(re.compile(r'^(snmp-server\s+contact\s+).+$', re.M),
            r'\1<REMOVED>', text, "SNMP contact")

        return text

    # ──────────────────────────────── pass 3: AS numbers ─────────────────

    def _pass_as_numbers(self, text: str) -> str:

        def replace_as(m: re.Match) -> str:
            return m.group(1) + self.tokens.get("as_number", m.group(2))

        def replace_rt(m: re.Match) -> str:
            return (m.group(1)
                    + self.tokens.get("as_number", m.group(2))
                    + m.group(3))

        # router bgp <AS>
        text = self._sub(
            re.compile(r'^(router\s+bgp\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "router bgp AS")

        # bgp confederation identifier <AS>
        text = self._sub(
            re.compile(r'^(\s*bgp\s+confederation\s+identifier\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "bgp confederation identifier")

        # bgp confederation peers <AS> [<AS> ...]  — replace each AS on the line
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

        # bgp local-as <AS> [no-prepend [replace-as [dual-as]]]
        text = self._sub(
            re.compile(r'^(\s*bgp\s+local-as\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "bgp local-as")

        # neighbor … remote-as <AS>
        text = self._sub(
            re.compile(r'^(\s+(?:neighbor\s+\S+\s+)?remote-as\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "remote-as")

        # VRF rd <AS>:<tag>
        text = self._sub(
            re.compile(r'(\brd\s+)(\d+(?:\.\d+)?)(\s*:\s*\d+)', re.M),
            replace_rt, text, "VRF rd")

        # route-target export/import <AS>:<tag>
        text = self._sub(
            re.compile(
                r'(\broute-target\s+(?:export|import)\s+)(\d+(?:\.\d+)?)(\s*:\s*\d+)', re.M),
            replace_rt, text, "route-target")

        # IOS XR bare route-target value lines, e.g. "   65001:100" (3+ spaces)
        text = self._sub(
            re.compile(r'^(\s{3,})(\d+(?:\.\d+)?)(:\d+\s*$)', re.M),
            replace_rt, text, "XR route-target value")

        # IOS XR community-set value lines, e.g. "  65001:1000" (2+ spaces, no keyword)
        text = self._sub(
            re.compile(r'^(\s{2,})(\d+(?:\.\d+)?)(:\d+),?\s*$', re.M),
            replace_rt, text, "XR community-set value")

        # community-list / community-set value lines, e.g. "permit 65001:1000"
        # or inline on definition line "ip community-list standard NAME permit 65001:1000"
        text = self._sub(
            re.compile(r'(\bpermit\s+)(\d+(?:\.\d+)?)(:\d+)', re.M),
            replace_rt, text, "community permit AS:tag")

        text = self._sub(
            re.compile(r'(\bdeny\s+)(\d+(?:\.\d+)?)(:\d+)', re.M),
            replace_rt, text, "community deny AS:tag")

        # route-map "set community AS:tag" (bare number:number, no permit/deny keyword)
        text = self._sub(
            re.compile(r'(\bset\s+community\s+)(\d+(?:\.\d+)?)(:\d+)', re.M),
            replace_rt, text, "set community AS:tag")

        return text

    # ──────────────────────────────── pass 4: named objects ──────────────

    def _pass_named_objects(self, text: str) -> str:
        N = self._sub_name

        # ── Hostname / domain ─────────────────────────────────────────────
        text = N(re.compile(r'^(hostname\s+)(?P<n>\S+)', re.M),
                 "hostname", "hostname", text)

        # IOS/XE: "ip domain-name" or "ip domain name"
        text = N(re.compile(r'^(ip\s+domain[- ]name\s+)(?P<n>\S+)', re.M),
                 "domain", "ip domain-name (IOS/XE)", text)

        # IOS XR: "domain name"
        text = N(re.compile(r'^(domain\s+name\s+)(?P<n>\S+)', re.M),
                 "domain", "domain name (XR)", text)

        # ── Usernames ─────────────────────────────────────────────────────
        # IOS/XE: "username NAME ..."
        text = N(re.compile(r'^(username\s+)(?P<n>\S+)', re.M),
                 "username", "username (IOS/XE)", text)

        # IOS XR: "username" block header
        text = N(re.compile(r'^(username\s+)(?P<n>\S+)', re.M),
                 "username", "username (XR)", text)

        # ── AAA server block names ────────────────────────────────────────
        # "tacacs server NAME" / "radius server NAME"
        text = N(re.compile(r'^(tacacs\s+server\s+)(?P<n>\S+)', re.M),
                 "aaa_server", "tacacs server name", text)

        text = N(re.compile(r'^(radius\s+server\s+)(?P<n>\S+)', re.M),
                 "aaa_server", "radius server name", text)

        # ── AAA group block names ──────────────────────────────────────────
        # "aaa group server tacacs+ NAME" / "aaa group server radius NAME"
        text = N(re.compile(
            r'^(aaa\s+group\s+server\s+\S+\s+)(?P<n>\S+)', re.M),
                 "aaa_group", "aaa group server name", text)

        # References in aaa authentication/authorization/accounting lines
        # e.g. "aaa authentication login default group NAME local"
        text = N(re.compile(
            r'(\baaa\s+(?:authentication|authorization|accounting)\s+\S+\s+\S+\s+group\s+)'
            r'(?P<n>(?!tacacs\+?\b|radius\b|ldap\b|local\b)\S+)', re.M),
                 "aaa_group", "aaa group ref", text)

        # ── VRF ───────────────────────────────────────────────────────────
        # Definitions — most specific first to avoid keyword capture
        text = N(re.compile(r'^(vrf\s+definition\s+)(?P<n>\S+)', re.M),
                 "vrf", "vrf definition (XE)", text)

        text = N(re.compile(r'^(ip\s+vrf\s+)(?P<n>\S+)', re.M),
                 "vrf", "ip vrf (IOS)", text)

        # IOS XR top-level: "vrf NAME" — negative lookahead for keywords
        text = N(re.compile(
            r'^(vrf\s+)(?P<n>(?!definition\b|forwarding\b|member\b)\S+)', re.M),
                 "vrf", "vrf (XR top-level)", text)

        # References
        text = N(re.compile(r'^(\s+vrf\s+forwarding\s+)(?P<n>\S+)', re.M),
                 "vrf", "vrf forwarding (XE)", text)

        text = N(re.compile(r'^(\s+ip\s+vrf\s+forwarding\s+)(?P<n>\S+)', re.M),
                 "vrf", "ip vrf forwarding (IOS)", text)

        # IOS XR interface: "vrf NAME" (indented)
        text = N(re.compile(
            r'^(\s+vrf\s+)(?P<n>(?!forwarding\b|member\b)\S+)', re.M),
                 "vrf", "vrf ref (XR interface)", text)

        # address-family … vrf NAME
        text = N(re.compile(
            r'(\baddress-family\s+\S+(?:\s+\S+)?\s+vrf\s+)(?P<n>\S+)', re.M),
                 "vrf", "address-family vrf", text)

        # Trailing vrf ref (ip sla, etc.)
        text = N(re.compile(r'(\s+vrf\s+)(?P<n>\S+)(?=\s*$)', re.M),
                 "vrf", "trailing vrf ref", text)

        # ── Route maps (IOS/XE) ───────────────────────────────────────────
        text = N(re.compile(r'^(route-map\s+)(?P<n>\S+)', re.M),
                 "route_map", "route-map def", text)

        text = N(re.compile(
            r'(\broute-map\s+)(?P<n>\S+)(?=\s+(?:in|out|permit|deny|\d))', re.M),
                 "route_map", "route-map ref", text)

        # ── Route policies (IOS XR) ───────────────────────────────────────
        text = N(re.compile(r'^(route-policy\s+)(?P<n>\S+)', re.M),
                 "route_map", "route-policy def (XR)", text)

        text = N(re.compile(r'(\broute-policy\s+)(?P<n>\S+)', re.M),
                 "route_map", "route-policy ref (XR)", text)

        # ── Policy maps ───────────────────────────────────────────────────
        text = N(re.compile(r'^(policy-map\s+)(?P<n>\S+)', re.M),
                 "policy_map", "policy-map def", text)

        text = N(re.compile(
            r'(\bservice-policy\s+(?:input|output)\s+)(?P<n>\S+)', re.M),
                 "policy_map", "service-policy ref", text)

        # ── Class maps ────────────────────────────────────────────────────
        text = N(re.compile(
            r'^(class-map\s+(?:match-(?:all|any|not)\s+)?)(?P<n>\S+)', re.M),
                 "class_map", "class-map def", text)

        text = N(re.compile(r'^(\s+class\s+)(?P<n>(?!default\b)\S+)', re.M),
                 "class_map", "class ref", text)

        # ── Named ACLs ────────────────────────────────────────────────────
        text = N(re.compile(
            r'^(ip(?:v6)?\s+access-list\s+(?:extended|standard|named)?\s*)'
            r'(?P<n>[A-Za-z]\S*)', re.M),
                 "acl", "ip access-list def", text)

        text = N(re.compile(
            r'(\bip(?:v6)?\s+access-group\s+)(?P<n>[A-Za-z]\S*)', re.M),
                 "acl", "access-group ref", text)

        text = N(re.compile(r'(\baccess-class\s+)(?P<n>[A-Za-z]\S*)', re.M),
                 "acl", "access-class ref", text)

        # "match ip address NAME" — exclude "prefix-list" keyword
        text = N(re.compile(
            r'(\bmatch\s+ip\s+address\s+(?:acl\s+)?)'
            r'(?P<n>(?!prefix-list\b)[A-Za-z]\S*)', re.M),
                 "acl", "match ip address ref", text)

        # "match address NAME" (IOS route-map style) — optional 'acl' keyword
        text = N(re.compile(r'(\bmatch\s+address\s+(?:acl\s+)?)(?P<n>[A-Za-z]\S*)', re.M),
                 "acl", "match address ref", text)

        # match access-group name NAME
        text = N(re.compile(
            r'(\bmatch\s+access-group\s+name\s+)(?P<n>\S+)', re.M),
                 "acl", "match access-group name", text)

        # IOS XR SNMP: RO/RW IPv4 <acl>
        text = N(re.compile(r'(\b(?:RO|RW)\s+IPv[46]\s+)(?P<n>\S+)', re.M),
                 "acl", "XR SNMP ACL ref", text)

        # ── Prefix lists (IOS/XE) ─────────────────────────────────────────
        text = N(re.compile(r'^(ip(?:v6)?\s+prefix-list\s+)(?P<n>\S+)', re.M),
                 "prefix_list", "prefix-list def", text)

        text = N(re.compile(r'(\bprefix-list\s+)(?P<n>\S+)', re.M),
                 "prefix_list", "prefix-list ref", text)

        # ── Prefix sets (IOS XR) ──────────────────────────────────────────
        text = N(re.compile(r'^(prefix-set\s+)(?P<n>\S+)', re.M),
                 "prefix_list", "prefix-set def (XR)", text)

        text = N(re.compile(r'(\bdestination\s+in\s+)(?P<n>\S+)', re.M),
                 "prefix_list", "XR destination in ref", text)

        # ── Community lists (IOS/XE) ──────────────────────────────────────
        # Negative lookahead prevents "standard" / "expanded" being captured
        text = N(re.compile(
            r'^(ip\s+community-list\s+(?:standard|expanded)\s+)'
            r'(?P<n>(?!standard\b|expanded\b)\S+)', re.M),
                 "community_list", "community-list def", text)

        text = N(re.compile(
            r'(\bcommunity-list\s+)(?P<n>(?!standard\b|expanded\b)\S+)', re.M),
                 "community_list", "community-list ref", text)

        # ── Community sets (IOS XR) ───────────────────────────────────────
        text = N(re.compile(r'^(community-set\s+)(?P<n>\S+)', re.M),
                 "community_list", "community-set def (XR)", text)

        text = N(re.compile(r'(\bset\s+community\s+)(?P<n>[A-Za-z]\S*)', re.M),
                 "community_list", "XR set community ref", text)

        # ── BGP peer-groups (IOS/XE) ──────────────────────────────────────
        # Declaration: "  neighbor NAME peer-group" (NAME is alpha, not an IP)
        text = N(re.compile(
            r'^(\s+neighbor\s+)(?P<n>(?!neighbor\b)[A-Za-z]\S*)(\s+peer-group\s*$)', re.M),
                 "peer_group", "peer-group declaration", text)

        # Assignment: "  neighbor <ip/token> peer-group NAME"
        # [^\S\n]+ prevents crossing line boundaries
        text = N(re.compile(
            r'^(\s+neighbor\s+\S+[^\S\n]+peer-group[^\S\n]+)(?P<n>[A-Za-z]\S+)', re.M),
                 "peer_group", "peer-group assignment", text)

        # Other peer-group-name config lines (description, password, etc.)
        text = N(re.compile(
            r'^(\s+neighbor\s+)(?P<n>(?!neighbor\b)[A-Za-z][A-Za-z0-9_-]+)'
            r'(?=\s+(?:description|password|update-source|remote-as'
            r'|route-map|prefix-list|send-community|activate))', re.M),
                 "peer_group", "peer-group usage", text)

        # ── Neighbor groups (IOS XR) ──────────────────────────────────────
        text = N(re.compile(r'^(\s*neighbor-group\s+)(?P<n>\S+)', re.M),
                 "neighbor_group", "neighbor-group def (XR)", text)

        text = N(re.compile(r'^(\s+use\s+neighbor-group\s+)(?P<n>\S+)', re.M),
                 "neighbor_group", "use neighbor-group (XR)", text)

        # ── Keychains ─────────────────────────────────────────────────────
        text = N(re.compile(r'^(key\s+chain\s+)(?P<n>\S+)', re.M),
                 "keychain", "key chain def", text)

        # EIGRP key-chain reference — must come before generic key-chain ref
        text = N(re.compile(
            r'(\bip\s+authentication\s+key-chain\s+eigrp\s+\d+\s+)(?P<n>\S+)', re.M),
                 "keychain", "EIGRP key-chain ref", text)

        # Generic key-chain ref — exclude the word "eigrp"
        text = N(re.compile(
            r'(\bkey-chain\s+)(?P<n>(?!eigrp\b)\S+)', re.M),
                 "keychain", "key-chain ref", text)

        # ── Crypto maps ───────────────────────────────────────────────────
        text = N(re.compile(r'^(crypto\s+map\s+)(?P<n>\S+)', re.M),
                 "crypto_map", "crypto map", text)

        # ── Transform sets ────────────────────────────────────────────────
        # Definition: crypto ipsec transform-set NAME ...
        text = N(re.compile(
            r'^(crypto\s+ipsec\s+transform-set\s+)(?P<n>\S+)', re.M),
                 "transform_set", "transform-set def", text)

        # Reference: set transform-set NAME (inside crypto map)
        text = N(re.compile(r'(\bset\s+transform-set\s+)(?P<n>\S+)', re.M),
                 "transform_set", "transform-set ref", text)

        # ── PKI trustpoints ───────────────────────────────────────────────
        # Definition: crypto pki trustpoint NAME
        text = N(re.compile(
            r'^(crypto\s+pki\s+trustpoint\s+)(?P<n>\S+)', re.M),
                 "trustpoint", "pki trustpoint def", text)

        # Reference: crypto pki certificate chain NAME
        text = N(re.compile(
            r'^(crypto\s+pki\s+certificate\s+chain\s+)(?P<n>\S+)', re.M),
                 "trustpoint", "pki certificate chain ref", text)

        # ── Object groups ─────────────────────────────────────────────────
        text = N(re.compile(
            r'^(object-group\s+(?:network|service)\s+)(?P<n>\S+)', re.M),
                 "object_group", "object-group def", text)

        text = N(re.compile(r'(\bgroup-object\s+)(?P<n>\S+)', re.M),
                 "object_group", "group-object ref", text)

        # ── IP SLA ────────────────────────────────────────────────────────
        # Schedule must come before def so the number is tokenised first
        text = N(re.compile(r'^(ip\s+sla\s+schedule\s+)(?P<n>\d+)', re.M),
                 "ip_sla", "ip sla schedule", text)

        text = N(re.compile(r'^(ip\s+sla\s+)(?P<n>\d+)', re.M),
                 "ip_sla", "ip sla def", text)

        text = N(re.compile(r'(\bip\s+sla\s+)(?P<n>\d+)', re.M),
                 "ip_sla", "ip sla ref", text)

        # ── Track objects ─────────────────────────────────────────────────
        text = N(re.compile(r'^(track\s+)(?P<n>\d+)', re.M),
                 "track", "track def", text)

        text = N(re.compile(r'(\btrack\s+)(?P<n>\d+)', re.M),
                 "track", "track ref", text)

        # ── BGP templates ─────────────────────────────────────────────────
        text = N(re.compile(
            r'^(template\s+peer-(?:session|policy)\s+)(?P<n>\S+)', re.M),
                 "template", "template def", text)

        text = N(re.compile(
            r'(\binherit\s+peer-(?:session|policy)\s+)(?P<n>\S+)', re.M),
                 "template", "template ref", text)

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
        def repl(m: re.Match) -> str:
            prefix = m.group(1)
            desc = m.group(2)
            if self.tokens.already_token("description", desc):
                return m.group(0)
            return prefix + self.tokens.get("description", desc)

        # Standalone description lines (leading whitespace optional)
        text = self._sub(
            re.compile(r'^(\s*description\s+)(.+)$', re.M),
            repl, text, "standalone description lines")

        # Inline: anything containing " description <text>" mid-line
        # e.g. "ip prefix-list NAME description text"
        #      " neighbor X description text"
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
Examples:
  python cisco_sanitise.py -i ./configs/ -o ./clean/ --seed myproject
  python cisco_sanitise.py -i router.cfg -o router_clean.cfg --dump-map map.json
  python cisco_sanitise.py -i router.cfg --dry-run
  python cisco_sanitise.py -i ./configs/ -o ./clean/ --no-ips --no-descriptions
        """
    )
    p.add_argument("-i", "--input",     required=True,
                   help="Input file or directory")
    p.add_argument("-o", "--output",    required=False,
                   help="Output file or directory")
    p.add_argument("--seed",            default="cisco-sanitise",
                   help="Determinism seed — same seed = same tokens every run")
    p.add_argument("--no-ips",          action="store_true",
                   help="Skip IP address anonymisation")
    p.add_argument("--no-descriptions", action="store_true",
                   help="Skip description line anonymisation")
    p.add_argument("--dump-map",        metavar="FILE",
                   help="Write full original→token mapping to a JSON file")
    p.add_argument("--dry-run",         action="store_true",
                   help="Print sanitised output to stdout; do not write files")
    p.add_argument("--extensions",      default=".cfg,.txt,.conf,.log",
                   help="Comma-separated file extensions to process")
    return p.parse_args()


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
    sanitiser = CiscoSanitiser(
        seed=args.seed,
        anonymise_ips=not args.no_ips,
        anonymise_descriptions=not args.no_descriptions,
    )
    exts = tuple(e if e.startswith(".") else f".{e}"
                 for e in args.extensions.split(","))
    inp = Path(args.input)
    out = Path(args.output) if args.output else None

    print("╔══════════════════════════════════════════════════════════╗")
    print("║       Cisco Configuration Sanitiser  (unified)          ║")
    print("║  IOS · IOS XE · IOS XR                                  ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Seed            : {args.seed}")
    print(f"  Anonymise IPs   : {'No' if args.no_ips else 'Yes (IPv4-xxxx / IPv6-xxxx tokens)'}")
    print(f"  Anonymise descs : {'No' if args.no_descriptions else 'Yes'}")
    print(f"  Dry run         : {'Yes' if args.dry_run else 'No'}")

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