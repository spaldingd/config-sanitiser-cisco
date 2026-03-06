#!/usr/bin/env python3
"""
cisco_sanitise.py  —  Cisco Configuration Sanitiser  (unified, single-pass)
Supports IOS, IOS XE, IOS XR

What it sanitises
─────────────────
Credentials    : enable secret/password, username secrets, type-5/7 hashes,
                 line passwords, OSPF/EIGRP/IS-IS auth keys, key-chain
                 key-strings, TACACS+/RADIUS keys, IKE pre-shared-keys,
                 BGP neighbour passwords, NTP auth keys, PKI cert blocks
IP addresses   : all IPv4 — deterministic mapping (same IP → same token),
                 subnet masks and wildcard masks preserved unchanged,
                 loopback/any/broadcast preserved
AS numbers     : router bgp, neighbor remote-as, VRF rd / route-targets —
                 consistent AS-xxxx tokens
SNMP           : community strings, SNMP location string
Named objects  : VRFs, route-maps/policies, policy-maps, class-maps,
                 named ACLs, prefix-lists/sets, community-lists/sets,
                 peer-groups/neighbor-groups, keychains, crypto maps,
                 object-groups, IP SLA IDs, track IDs, BGP templates
Descriptions   : all free-text description lines

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
    # Cisco syntax keywords that look like names but must never be anonymised
    "default", "any", "all", "none", "permit", "deny", "in", "out",
    "input", "output", "both", "true", "false", "enable", "disable",
    "active", "passive", "static", "dynamic", "extended", "standard",
    "named", "match-all", "match-any", "match-not", "internet", "local",
    "management", "global", "null", "null0", "loopback", "definition",
    "forwarding", "member", "unicast", "multicast",
    "ipv4", "ipv6", "vpnv4", "vpnv6", "l2vpn", "evpn", "flowspec",
    "encrypted", "clear", "class-default",
}

CATEGORY_PREFIXES = {
    "hostname":       "host",
    "domain":         "dom",
    "vrf":            "vrf",
    "route_map":      "rmap",
    "policy_map":     "pmap",
    "class_map":      "cmap",
    "acl":            "acl",
    "prefix_list":    "pfx",
    "community_list": "cmty",
    "peer_group":     "pg",
    "neighbor_group": "ng",
    "crypto_map":     "cmap",
    "keychain":       "kc",
    "track":          "trk",
    "object_group":   "og",
    "ip_sla":         "sla",
    "template":       "tmpl",
    "description":    "desc",
    "as_number":      "AS",
}

# Subnet masks and wildcard masks — never anonymise these
_MASK_RE = re.compile(
    r'\b(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)'
    r'\.(?:255|254|252|248|240|224|192|128|0)\b'
)


# ══════════════════════════════════════════════════════════════════════════════
#  TOKEN GENERATOR  —  deterministic, collision-safe, double-anonymisation-safe
# ══════════════════════════════════════════════════════════════════════════════

class TokenGenerator:
    def __init__(self, seed: str = "cisco-sanitise"):
        self.seed = seed
        self._maps: dict[str, dict[str, str]] = {}
        # Reverse maps for quick "is this already a token?" lookups
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
#  IP ANONYMISER
# ══════════════════════════════════════════════════════════════════════════════

class IPAnonymiser:
    PRESERVE = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}

    def __init__(self, seed: str = "cisco-sanitise"):
        self.seed = seed
        self._map: dict[str, str] = {}

    def _anon(self, original: str) -> str:
        if original in self._map:
            return self._map[original]
        try:
            addr = ipaddress.ip_address(original)
        except ValueError:
            return original
        if addr.is_loopback or original in self.PRESERVE:
            self._map[original] = original
            return original
        h = int(hashlib.md5(
            f"{self.seed}:ip:{original}".encode()
        ).hexdigest(), 16)
        if addr.is_private:
            first = int(str(addr).split(".")[0])
            if first == 10:
                new = f"10.{(h>>16)&0xFF}.{(h>>8)&0xFF}.{max(1,(h&0xFE))}"
            elif first == 172:
                new = f"172.{16+(h&0x0F)}.{(h>>4)&0xFF}.{max(1,(h>>12)&0xFE)}"
            else:
                new = f"192.168.{(h>>8)&0xFF}.{max(1,(h&0xFE))}"
        else:
            new = f"100.64.{(h>>8)&0x3F}.{max(1,(h&0xFE))}"
        self._map[original] = new
        return new

    def anonymise(self, text: str) -> str:
        """Replace host IPs; leave subnet/wildcard masks untouched."""
        mask_spans = {m.span() for m in _MASK_RE.finditer(text)}
        ip_re = re.compile(
            r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        )
        parts = []
        prev = 0
        for m in ip_re.finditer(text):
            if m.span() in mask_spans:
                parts.append(text[prev:m.end()])
            else:
                parts.append(text[prev:m.start()])
                parts.append(self._anon(m.group(0)))
            prev = m.end()
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
        self.ip_anon = IPAnonymiser(seed=seed) if anonymise_ips else None
        self.anonymise_descriptions = anonymise_descriptions
        self._log: list[str] = []

    # ─────────────────────────────── public ──────────────────────────────

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
        return text

    @property
    def log(self) -> list[str]:
        return list(self._log)

    # ─────────────────────────────── helpers ─────────────────────────────

    def _sub(self, pattern: re.Pattern, repl, text: str, label: str) -> str:
        result, n = pattern.subn(repl, text)
        if n:
            self._log.append(f"  [{n:>3}x] {label}")
        return result

    def _name(self, category: str, original: str) -> str:
        """Return token; skip reserved keywords and already-tokenised values."""
        if original.lower() in RESERVED_KEYWORDS:
            return original
        if self.tokens.already_token(category, original):
            return original          # ← KEY fix: prevents double-anonymisation
        return self.tokens.get(category, original)

    def _repl(self, m: re.Match, category: str) -> str:
        """Generic match handler for patterns with named group 'n'."""
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

    # ─────────────────────────── pass 1: credentials ─────────────────────

    def _pass_credentials(self, text: str) -> str:
        S = self._sub

        # enable secret / enable password
        text = S(re.compile(
            r'^(enable\s+(?:secret|password)\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "enable secret/password")

        # username … secret/password (all platforms)
        text = S(re.compile(
            r'^(username\s+\S+(?:\s+privilege\s+\d+)?'
            r'\s+(?:secret|password)\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "username secret/password")

        # IOS XR username block: " secret 5 <hash>" or " secret $..."
        text = S(re.compile(r'^(\s+secret\s+(?:[0-9]\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "XR username secret block")

        # IOS XR username block: " password N <val>"
        text = S(re.compile(r'^(\s+password\s+\d+\s+)\S+', re.M),
            r'\1<REMOVED>', text, "XR username password block")

        # line vty/con password (no type digit prefix — catch-all for remaining)
        text = S(re.compile(r'^(\s+password\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "line password")

        # OSPF message-digest-key
        text = S(re.compile(
            r'^(\s+ip\s+ospf\s+message-digest-key\s+\d+\s+md5\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "OSPF message-digest-key")

        # IOS/XE keychain: key-string [N] <val>  (NOT "key-string password …")
        text = S(re.compile(
            r'^(\s+key-string\s+)(?!password\b)(?:\d+\s+)?\S+', re.M),
            r'\1<REMOVED>', text, "keychain key-string (IOS/XE)")

        # IOS XR keychain: key-string password N <val>
        text = S(re.compile(
            r'^(\s+key-string\s+password\s+\d+\s+)\S+', re.M),
            r'\1<REMOVED>', text, "keychain key-string password (XR)")

        # authentication-key (OSPF/IS-IS)
        text = S(re.compile(
            r'^(\s+authentication-key\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "authentication-key")

        # Block-style server key (e.g. inside "tacacs server" / "radius server" stanza)
        text = S(re.compile(r'^(\s+key\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "server key (block style)")

        # Flat-style tacacs-server / radius-server key (IOS)
        text = S(re.compile(
            r'^(tacacs-server\s+(?:host\s+\S+\s+)?key\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "tacacs-server key")

        text = S(re.compile(
            r'^(radius-server\s+(?:host\s+\S+\s+\S+\s+)?key\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "radius-server key")

        # BGP neighbor password (IOS/XE inline)
        text = S(re.compile(
            r'^(\s+neighbor\s+\S+\s+password\s+(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "BGP neighbor password")

        # IOS XR BGP: "  password encrypted <val>" / "  password 0 <val>"
        # inside neighbor / neighbor-group block
        text = S(re.compile(
            r'^(\s+password\s+(?:encrypted\s+|\d+\s+))\S+', re.M),
            r'\1<REMOVED>', text, "XR BGP password (neighbor block)")

        # IKE pre-shared-key
        text = S(re.compile(
            r'^(\s*pre-shared-key\s+(?:address\s+\S+\s+|local\s+|remote\s+)?'
            r'(?:\d+\s+)?)\S+', re.M),
            r'\1<REMOVED>', text, "IKE pre-shared-key")

        # crypto isakmp key <key> address <ip>
        text = S(re.compile(
            r'^(crypto\s+isakmp\s+key\s+)\S+', re.M),
            r'\1<REMOVED>', text, "crypto isakmp key")

        # tunnel key
        text = S(re.compile(r'^(\s*tunnel\s+key\s+)\S+', re.M),
            r'\1<REMOVED>', text, "tunnel key")

        # NTP authentication-key N md5 <key>
        text = S(re.compile(
            r'^(\s*(?:ntp\s+)?authentication-key\s+\d+\s+md5\s+)\S+', re.M),
            r'\1<REMOVED>', text, "NTP authentication-key")

        # PKI certificate blocks
        text = S(re.compile(
            r'^\s*certificate\s+(?:self-signed\s+)?\S+\n.*?^\s*quit',
            re.M | re.DOTALL),
            ' certificate <REMOVED>\n  quit', text, "PKI certificate block")

        return text

    # ─────────────────────────────── pass 2: SNMP ────────────────────────

    def _pass_snmp(self, text: str) -> str:
        S = self._sub

        # IOS/XE: snmp-server community <string> RO|RW ...
        text = S(re.compile(r'^(snmp-server\s+community\s+)\S+', re.M),
            r'\1<REMOVED>', text, "SNMP community string")

        # IOS XR block style: snmp-server community <name>  (name on same line)
        text = S(re.compile(r'^(snmp-server\s+community\s+)\S+', re.M),
            r'\1<REMOVED>', text, "XR SNMP community")

        # IOS XR: " RO IPv4 <acl>" and " RW IPv4 <acl>" — ACL name handled in
        # named-objects pass; community name already removed above.

        # SNMP location free text
        text = S(re.compile(r'^(snmp-server\s+location\s+).+$', re.M),
            r'\1<REMOVED>', text, "SNMP location")

        return text

    # ─────────────────────────── pass 3: AS numbers ──────────────────────

    def _pass_as_numbers(self, text: str) -> str:

        def replace_as(m: re.Match) -> str:
            return m.group(1) + self.tokens.get("as_number", m.group(2))

        def replace_rt(m: re.Match) -> str:
            return m.group(1) + self.tokens.get("as_number", m.group(2)) + m.group(3)

        text = self._sub(
            re.compile(r'^(router\s+bgp\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "router bgp AS")

        text = self._sub(
            re.compile(r'^(\s+(?:neighbor\s+\S+\s+)?remote-as\s+)(\d+(?:\.\d+)?)', re.M),
            replace_as, text, "remote-as")

        text = self._sub(
            re.compile(r'(\brd\s+)(\d+(?:\.\d+)?)(\s*:\s*\d+)', re.M),
            replace_rt, text, "VRF rd")

        text = self._sub(
            re.compile(r'(\broute-target\s+(?:export|import)\s+)(\d+(?:\.\d+)?)(\s*:\s*\d+)', re.M),
            replace_rt, text, "route-target")

        # IOS XR bare route-target value lines (indented, e.g. "   65001:100")
        text = self._sub(
            re.compile(r'^(\s{3,})(\d+(?:\.\d+)?)(:\d+\s*$)', re.M),
            replace_rt, text, "XR route-target value")

        return text

    # ─────────────────────── pass 4: named objects ───────────────────────

    def _pass_named_objects(self, text: str) -> str:
        N = self._sub_name

        # ── Hostname / domain ─────────────────────────────────────────────
        text = N(re.compile(r'^(hostname\s+)(?P<n>\S+)', re.M),
                 "hostname", "hostname", text)

        text = N(re.compile(r'^(ip\s+domain[- ]name\s+)(?P<n>\S+)', re.M),
                 "domain", "ip domain-name (IOS/XE)", text)

        text = N(re.compile(r'^(domain\s+name\s+)(?P<n>\S+)', re.M),
                 "domain", "domain name (XR)", text)

        # ── VRF ───────────────────────────────────────────────────────────
        # Definitions — most specific first to avoid keyword capture
        text = N(re.compile(r'^(vrf\s+definition\s+)(?P<n>\S+)', re.M),
                 "vrf", "vrf definition (XE)", text)

        text = N(re.compile(r'^(ip\s+vrf\s+)(?P<n>\S+)', re.M),
                 "vrf", "ip vrf (IOS)", text)

        # IOS XR top-level: "vrf NAME" — exclude keywords after vrf
        text = N(re.compile(
            r'^(vrf\s+)(?P<n>(?!definition\b|forwarding\b|member\b)\S+)', re.M),
                 "vrf", "vrf (XR top-level)", text)

        # References
        text = N(re.compile(r'^(\s+vrf\s+forwarding\s+)(?P<n>\S+)', re.M),
                 "vrf", "vrf forwarding (XE)", text)

        text = N(re.compile(r'^(\s+ip\s+vrf\s+forwarding\s+)(?P<n>\S+)', re.M),
                 "vrf", "ip vrf forwarding (IOS)", text)

        # IOS XR interface: "vrf NAME" (indented, not forwarding/member)
        text = N(re.compile(
            r'^(\s+vrf\s+)(?P<n>(?!forwarding\b|member\b)\S+)', re.M),
                 "vrf", "vrf ref (XR interface)", text)

        text = N(re.compile(
            r'(\baddress-family\s+\S+(?:\s+\S+)?\s+vrf\s+)(?P<n>\S+)', re.M),
                 "vrf", "address-family vrf", text)

        # IOS XR ip sla vrf ref
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

        # match ip address NAME  — exclude "prefix-list" keyword from capture
        text = N(re.compile(
            r'(\bmatch\s+ip\s+address\s+(?:acl\s+)?)'
            r'(?P<n>(?!prefix-list\b)[A-Za-z]\S*)', re.M),
                 "acl", "match ip address ref", text)

        # match access-group name NAME
        text = N(re.compile(
            r'(\bmatch\s+access-group\s+name\s+)(?P<n>\S+)', re.M),
                 "acl", "match access-group name", text)

        # IOS XR SNMP: RO/RW IPv4 <acl>
        text = N(re.compile(
            r'(\b(?:RO|RW)\s+IPv[46]\s+)(?P<n>\S+)', re.M),
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
        # The keyword (standard|expanded) must be followed by a real name — add
        # it to RESERVED_KEYWORDS is not enough because it arrives as group 1.
        # Use a lookahead so we only capture after the keyword, not the keyword.
        text = N(re.compile(
            r'^(ip\s+community-list\s+(?:standard|expanded)\s+)(?P<n>(?!standard\b|expanded\b)\S+)', re.M),
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
        # Declaration: "  neighbor NAME peer-group" — NAME starts alpha, not keyword
        text = N(re.compile(
            r'^(\s+neighbor\s+)(?P<n>(?!neighbor\b)[A-Za-z]\S*)(\s+peer-group\s*$)', re.M),
                 "peer_group", "peer-group declaration", text)

        # Assignment: "  neighbor <ip> peer-group NAME"  — use [^\S\n] to block newline crossing
        text = N(re.compile(
            r'^(\s+neighbor\s+\S+[^\S\n]+peer-group[^\S\n]+)(?P<n>[A-Za-z]\S+)', re.M),
                 "peer_group", "peer-group assignment", text)

        # Other per-peer-group config lines (description, password, update-source …)
        # Exclude the word 'neighbor' as a peer-group name
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

        text = N(re.compile(
            r'(\bip\s+authentication\s+key-chain\s+eigrp\s+\d+\s+)(?P<n>\S+)', re.M),
                 "keychain", "EIGRP key-chain ref", text)

        # Generic key-chain ref — exclude keywords
        text = N(re.compile(
            r'(\bkey-chain\s+)(?P<n>(?!eigrp\b)\S+)', re.M),
                 "keychain", "key-chain ref", text)

        # ── Crypto maps ───────────────────────────────────────────────────
        text = N(re.compile(r'^(crypto\s+map\s+)(?P<n>\S+)', re.M),
                 "crypto_map", "crypto map", text)

        # ── Object groups ─────────────────────────────────────────────────
        text = N(re.compile(
            r'^(object-group\s+(?:network|service)\s+)(?P<n>\S+)', re.M),
                 "object_group", "object-group def", text)

        text = N(re.compile(r'(\bgroup-object\s+)(?P<n>\S+)', re.M),
                 "object_group", "group-object ref", text)

        # ── IP SLA ────────────────────────────────────────────────────────
        text = N(re.compile(r'^(ip\s+sla\s+schedule\s+)(?P<n>\d+)', re.M),
                 "ip_sla", "ip sla schedule", text)

        text = N(re.compile(r'^(ip\s+sla\s+)(?P<n>\d+)', re.M),
                 "ip_sla", "ip sla def", text)

        text = N(re.compile(r'(\bip\s+sla\s+)(?P<n>\d+)', re.M),
                 "ip_sla", "ip sla ref", text)

        # ── Track ─────────────────────────────────────────────────────────
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

    # ─────────────────────────── pass 5: descriptions ────────────────────

    def _pass_descriptions(self, text: str) -> str:
        def repl(m: re.Match) -> str:
            prefix = m.group(1)
            desc = m.group(2)
            # Don't re-anonymise a description that's already a token
            if self.tokens.already_token("description", desc):
                return m.group(0)
            return prefix + self.tokens.get("description", desc)

        return self._sub(
            re.compile(r'^(\s*description\s+)(.+)$', re.M),
            repl, text, "description lines")

    # ─────────────────────────── mapping report ──────────────────────────

    def mapping_report(self, as_json: bool = False) -> str:
        mappings = self.tokens.all_mappings()
        if self.ip_anon:
            ip_map = {k: v for k, v in self.ip_anon._map.items() if k != v}
            if ip_map:
                mappings["ip_addresses"] = ip_map
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
                lines.append(f"    {orig:<48} →  {token}")
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
    p.add_argument("-i", "--input",          required=True,
                   help="Input file or directory")
    p.add_argument("-o", "--output",         required=False,
                   help="Output file or directory")
    p.add_argument("--seed",                 default="cisco-sanitise",
                   help="Determinism seed — same seed = same tokens every run")
    p.add_argument("--no-ips",               action="store_true",
                   help="Skip IP address anonymisation")
    p.add_argument("--no-descriptions",      action="store_true",
                   help="Skip description line anonymisation")
    p.add_argument("--dump-map",             metavar="FILE",
                   help="Write full original→token mapping to a JSON file")
    p.add_argument("--dry-run",              action="store_true",
                   help="Print sanitised output to stdout; do not write files")
    p.add_argument("--extensions",           default=".cfg,.txt,.conf,.log",
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
    print(f"  Anonymise IPs   : {'No' if args.no_ips else 'Yes'}")
    print(f"  Anonymise descs : {'No' if args.no_descriptions else 'Yes'}")
    print(f"  Dry run         : {'Yes' if args.dry_run else 'No'}")

    success = failure = 0

    if inp.is_file():
        dest = (out or inp.parent / (inp.stem + "_sanitised" + inp.suffix)
                ) if not args.dry_run else None
        ok = process_file(inp, dest, sanitiser, args.dry_run)
        success += int(ok); failure += int(not ok)

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
            success += int(ok); failure += int(not ok)
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