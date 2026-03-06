#!/usr/bin/env python3
"""
Cisco Config Full Sanitisation Pipeline
Chains cisco_sanitise.py → cisco_name_anonymise.py in one command.

Step 1: Remove/replace passwords, IPs, SNMP strings, BGP keys
Step 2: Anonymise all named objects, VRFs, descriptions, policies etc.

Usage:
  python cisco_sanitise_pipeline.py -i ./configs/ -o ./sanitised/ --seed myproject
  python cisco_sanitise_pipeline.py -i router.cfg  -o router_clean.cfg --no-ips
  python cisco_sanitise_pipeline.py -i router.cfg  --dry-run
"""

import sys
import argparse
from pathlib import Path

# Import both modules (must be in same directory)
try:
    from cisco_sanitise import build_rules, sanitise, IPAnonymiser
    from cisco_name_anonymise import NameAnonymiser
except ImportError as e:
    print(f"ERROR: Could not import required modules: {e}")
    print("Ensure cisco_sanitise.py and cisco_name_anonymise.py are in the same directory.")
    sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Full Cisco config sanitisation pipeline (passwords + named objects).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full sanitisation of a directory
  python cisco_sanitise_pipeline.py -i ./configs/ -o ./clean/ --seed myproject-2024

  # Single file, dump name-map to JSON for traceability
  python cisco_sanitise_pipeline.py -i router.cfg -o router_clean.cfg --dump-map map.json

  # Preserve IPs (skip IP anonymisation)
  python cisco_sanitise_pipeline.py -i ./configs/ -o ./clean/ --no-ips

  # Preview without writing
  python cisco_sanitise_pipeline.py -i router.cfg --dry-run
        """
    )
    parser.add_argument("-i", "--input",         required=True)
    parser.add_argument("-o", "--output",        required=False)
    parser.add_argument("--seed",                default="cisco-pipeline",
                        help="Shared seed for deterministic anonymisation")
    parser.add_argument("--no-ips",              action="store_true",
                        help="Skip IP address anonymisation")
    parser.add_argument("--no-descriptions",     action="store_true",
                        help="Skip interface/object description anonymisation")
    parser.add_argument("--dump-map",            metavar="FILE",
                        help="Write name→token mapping to a JSON file")
    parser.add_argument("--dry-run",             action="store_true")
    parser.add_argument("--extensions",          default=".cfg,.txt,.conf",
                        help="File extensions to process")
    return parser.parse_args()


def process_file(input_path: Path, output_path: Path,
                 sanitise_rules, ip_anonymiser,
                 name_anonymiser: NameAnonymiser,
                 dry_run: bool) -> bool:

    print(f"\n{'─'*60}")
    print(f"  Input : {input_path}")

    try:
        text = input_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  ERROR reading: {e}")
        return False

    # ── Step 1: Credentials, IPs, SNMP, BGP keys ────────────────────────
    step1, log1 = sanitise(text, sanitise_rules, ip_anonymiser)
    if log1:
        print("  [Step 1 - Credentials/IPs]")
        for entry in log1:
            print(entry)

    # ── Step 2: Named objects & descriptions ────────────────────────────
    step2 = name_anonymiser.process(step1)
    print("  [Step 2 - Named objects] (see summary below)")

    if dry_run:
        print(f"\n{'═'*60}  DRY RUN OUTPUT  {'═'*60}")
        print(step2)
        print(f"{'═'*60}")
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(step2, encoding="utf-8")
        print(f"  Output: {output_path}")

    return True


def main():
    args = parse_args()

    # Build Step 1 components
    sanitise_ips  = not args.no_ips
    rules         = build_rules(sanitise_ips)
    ip_anonymiser = IPAnonymiser(seed=args.seed) if sanitise_ips else None

    # Build Step 2 component (shared across all files → consistent tokens)
    name_anonymiser = NameAnonymiser(
        seed=args.seed,
        anonymise_descriptions=not args.no_descriptions
    )

    exts = tuple(args.extensions.split(","))
    inp  = Path(args.input)
    out  = Path(args.output) if args.output else None

    print("╔══════════════════════════════════════════════════════════╗")
    print("║       Cisco Config Full Sanitisation Pipeline            ║")
    print("║  Step 1: Passwords · IPs · SNMP · BGP keys              ║")
    print("║  Step 2: Named objects · VRFs · Policies · Descriptions  ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Seed              : {args.seed}")
    print(f"  Anonymise IPs     : {'Yes' if sanitise_ips else 'No'}")
    print(f"  Anonymise descs   : {'No' if args.no_descriptions else 'Yes'}")

    success = failure = 0

    if inp.is_file():
        if not args.dry_run:
            dest = out or inp.parent / (inp.stem + "_sanitised" + inp.suffix)
        else:
            dest = None
        ok = process_file(inp, dest, rules, ip_anonymiser, name_anonymiser, args.dry_run)
        success += int(ok); failure += int(not ok)

    elif inp.is_dir():
        files = [f for f in inp.rglob("*") if f.is_file() and f.suffix.lower() in exts]
        if not files:
            print(f"\n  No matching files found in {inp}")
            sys.exit(1)
        if not args.dry_run:
            base_out = out or inp.parent / (inp.name + "_sanitised")
        for f in sorted(files):
            dest = (base_out / f.relative_to(inp)) if not args.dry_run else None
            ok = process_file(f, dest, rules, ip_anonymiser, name_anonymiser, args.dry_run)
            success += int(ok); failure += int(not ok)
    else:
        print(f"\n  ERROR: '{inp}' is not a valid file or directory.")
        sys.exit(1)

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"  Done. {success} file(s) sanitised, {failure} error(s).")
    print(f"  Total unique names anonymised: {name_anonymiser.tokens.total_replacements()}")

    if sanitise_ips and ip_anonymiser and ip_anonymiser._map:
        print(f"\n  IP address mapping ({len(ip_anonymiser._map)} addresses):")
        for orig, anon in sorted(ip_anonymiser._map.items()):
            if orig != anon:
                print(f"    {orig:>18}  →  {anon}")

    print("\n  Named object mapping:")
    print(name_anonymiser.mapping_report())

    if args.dump_map:
        import json
        combined_map = {
            "ips": {k: v for k, v in ip_anonymiser._map.items() if k != v} if ip_anonymiser else {},
            "names": name_anonymiser.tokens.all_mappings()
        }
        Path(args.dump_map).write_text(json.dumps(combined_map, indent=2), encoding="utf-8")
        print(f"\n  Full mapping saved to: {args.dump_map}")


if __name__ == "__main__":
    main()
