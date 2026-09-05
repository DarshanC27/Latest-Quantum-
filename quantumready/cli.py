"""Command line interface.

    quantumready scan acme.co.uk --org "Acme Ltd" --sector finance
    quantumready serve --port 8080
    quantumready algorithms
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import List, Optional

from .engine import quantum, remediation
from .model import SEVERITY_RANK, ScanTarget
from .report import html as html_report, serialise
from .scanner import ScanOptions, Scanner, normalise_domain

# Exit codes, so this can gate a pipeline.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_COLOURS = {
    "critical": "\033[97;41m", "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[96m", "info": "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _supports_colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


class Printer:
    def __init__(self, stream, quiet: bool = False):
        self.stream = stream
        self.colour = _supports_colour(stream)
        self.quiet = quiet

    def write(self, text: str = "") -> None:
        if not self.quiet:
            print(text, file=self.stream)

    def paint(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.colour else text

    def severity(self, name: str) -> str:
        return self.paint(f" {name.upper():8s} ", _COLOURS.get(name, ""))


def _progress_printer(printer: Printer):
    last = {"stage": None}

    def report(stage: str, message: str, data: dict) -> None:
        pct = data.get("progress")
        prefix = f"[{pct:3d}%]" if isinstance(pct, int) else "     "
        if stage != last["stage"]:
            printer.write(printer.paint(f"\n{prefix} {stage}", _BOLD))
            last["stage"] = stage
            printer.write(f"       {message}")
        else:
            printer.write(f"{prefix} {message}")

    return report


def cmd_scan(args: argparse.Namespace) -> int:
    printer = Printer(sys.stderr, quiet=args.quiet)
    domain = normalise_domain(args.domain)
    if not domain or "." not in domain:
        print(f"error: {args.domain!r} is not a usable domain", file=sys.stderr)
        return EXIT_ERROR

    shelf_life = args.shelf_life
    if shelf_life is None:
        shelf_life, reason = quantum.suggested_shelf_life(args.sector)
        printer.write(
            printer.paint(
                f"Using a {shelf_life}-year data shelf life for sector "
                f"'{args.sector}' ({reason}). Override with --shelf-life.",
                _DIM,
            )
        )

    target = ScanTarget(
        organisation=args.org or domain,
        domain=domain,
        data_shelf_life_years=shelf_life,
        migration_years=args.migration_years,
        sector=args.sector,
    )
    options = ScanOptions(
        max_hosts=args.max_hosts,
        timeout=args.timeout,
        deep_tls=not args.fast,
        probe_ciphers=not args.fast,
        use_ct=not args.no_ct,
        check_licences=not args.no_licences,
        check_dns=not args.no_dns,
        workers=args.workers,
        quantum_scenario=args.scenario,
        quantum_year=args.quantum_year,
    )

    printer.write(printer.paint(f"Quantum.Ready — scanning {domain}", _BOLD))
    scanner = Scanner(options, progress=_progress_printer(printer))
    try:
        result = scanner.run(target)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    _write_outputs(result, args, printer)
    if args.format == "text":
        _print_summary(result, printer)

    threshold = SEVERITY_RANK.get(args.fail_on, None)
    if threshold is not None:
        worst = min((f.rank for f in result.findings), default=99)
        if worst <= threshold:
            return EXIT_FINDINGS
    return EXIT_OK


def _write_outputs(result, args: argparse.Namespace, printer: Printer) -> None:
    outputs = {
        "json": (args.json_out, lambda: serialise.to_json(result)),
        "html": (args.html_out, lambda: html_report.render(result)),
        "markdown": (args.markdown_out, lambda: serialise.to_markdown(result)),
        "cbom": (args.cbom_out, lambda: serialise.to_cbom_json(result)),
    }
    for label, (path, produce) in outputs.items():
        if not path:
            continue
        try:
            destination = pathlib.Path(path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(produce(), encoding="utf-8")
            printer.write(printer.paint(f"  wrote {label}: {destination}", _DIM))
        except OSError as exc:
            print(f"error: could not write {label} to {path}: {exc}", file=sys.stderr)

    if args.format == "json":
        print(serialise.to_json(result))
    elif args.format == "markdown":
        print(serialise.to_markdown(result))
    elif args.format == "html":
        print(html_report.render(result))
    elif args.format == "cbom":
        print(serialise.to_cbom_json(result))


def _print_summary(result, printer: Printer) -> None:
    out = Printer(sys.stdout)
    counts = result.counts_by_severity()
    readiness = result.readiness
    mosca = result.mosca

    out.write("")
    out.write(out.paint("=" * 68, _DIM))
    out.write(out.paint(f" {result.target.organisation} — {result.target.domain}", _BOLD))
    out.write(out.paint("=" * 68, _DIM))
    out.write("")
    out.write(f"  Security score      {result.risk_score:g}/100  (grade {result.risk_grade})")
    if readiness:
        out.write(f"  Quantum readiness   {readiness.score:g}/100  (grade {readiness.grade})")
    out.write(
        "  Findings            "
        + "  ".join(
            f"{counts[name]} {name}"
            for name in ("critical", "high", "medium", "low")
            if counts[name]
        )
        or "  Findings            none"
    )
    out.write(f"  Hosts assessed      {len(result.discovered_hosts)}")
    out.write("")

    if mosca:
        colour = _COLOURS["critical"] if mosca.at_risk else "\033[92m"
        out.write(f"  {out.paint(' MOSCA: ' + mosca.verdict + ' ', colour)}  {mosca.formula}")
        out.write("")

    if readiness:
        out.write(out.paint("  Readiness breakdown", _BOLD))
        for name, value, maximum in readiness.rows():
            filled = int(round(value / maximum * 20)) if maximum else 0
            bar = "#" * filled + "." * (20 - filled)
            out.write(f"    {name:34s} {bar} {value:5.1f}/{maximum:g}")
        out.write("")

    findings = [f for f in result.sorted_findings() if f.severity != "info"]
    if findings:
        out.write(out.paint("  Findings", _BOLD))
        for finding in findings:
            tag = out.paint(" Q ", "\033[95m") if finding.quantum_relevant else "   "
            out.write(f"  {out.severity(finding.severity)}{tag} {finding.title}")
            out.write(f"           {out.paint(finding.target, _DIM)}")
        out.write("")

    if result.remediation:
        out.write(out.paint("  Do these first", _BOLD))
        for action in result.remediation[:5]:
            out.write(f"    {action.priority}. {action.title}")
            out.write(f"       {out.paint(action.effort + ' · ' + action.phase, _DIM)}")
        out.write("")

    if result.scan_notes or result.errors:
        out.write(out.paint("  Notes", _BOLD))
        for note in (result.scan_notes + result.errors)[:6]:
            out.write(f"    - {note}")
        out.write("")



def cmd_study(args: argparse.Namespace) -> int:
    """Run a cohort benchmark and write an aggregate report."""
    import datetime as _dt
    import json as _json

    from .data import cohorts as cohort_data
    from .report import study_html
    from .study import (
        StudyOptions, disclosure_annex, run_study, summarise,
    )

    printer = Printer(sys.stderr, quiet=args.quiet)

    if args.targets:
        try:
            subjects = cohort_data.load_csv(args.targets)
        except OSError as exc:
            print(f"error: could not read {args.targets}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        label = args.cohort or pathlib.Path(args.targets).stem
    elif args.domain:
        subjects = [cohort_data.Subject(d, d, args.sector) for d in args.domain]
        label = args.cohort or "ad-hoc cohort"
    else:
        names = args.preset or ["councils"]
        subjects = []
        for name in names:
            if name not in cohort_data.COHORTS:
                print(f"error: unknown cohort {name!r}. Available: "
                      f"{', '.join(sorted(cohort_data.COHORTS))}", file=sys.stderr)
                return EXIT_ERROR
            subjects.extend(cohort_data.COHORTS[name])
        label = args.cohort or (
            cohort_data.COHORT_LABELS[names[0]] if len(names) == 1
            else f"{len(names)} cohorts"
        )

    if not subjects:
        print("error: no subjects to scan", file=sys.stderr)
        return EXIT_ERROR

    if args.limit:
        subjects = subjects[: args.limit]

    options = StudyOptions(
        workers=args.workers, delay=args.delay, timeout=args.timeout,
        max_hosts=args.max_hosts, probe_ciphers=not args.fast,
        quantum_scenario=args.scenario, resume_path=args.resume,
    )

    printer.write(printer.paint(
        f"Quantum.Ready study — {label}: {len(subjects)} subject(s)", _BOLD))
    printer.write(printer.paint(
        f"  {options.workers} concurrent, {options.delay}s apart, apex + www only, "
        "no subdomain enumeration", _DIM))

    started = _dt.datetime.now(_dt.timezone.utc)

    def on_done(done: int, total: int, entry) -> None:
        if entry.ok:
            state = (f"{entry.readiness_grade or '?'} "
                     f"{entry.readiness_score if entry.readiness_score is not None else '?'}"
                     f" · {'PQC' if entry.pqc_ready else 'no PQC'}")
        else:
            state = f"failed ({entry.error})"
        printer.write(f"  [{done:3d}/{total}] {entry.subject.domain:38s} {state}")

    try:
        results = run_study(subjects, options, progress=on_done)
    except KeyboardInterrupt:
        print("\ninterrupted — partial results kept in the resume file",
              file=sys.stderr)
        return EXIT_ERROR

    summary = summarise(results, label, started)

    if args.html_out:
        pathlib.Path(args.html_out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.html_out).write_text(
            study_html.render(summary, title=args.title or ""), encoding="utf-8")
        printer.write(printer.paint(f"  wrote report: {args.html_out}", _DIM))

    if args.json_out:
        pathlib.Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.json_out).write_text(
            _json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
        printer.write(printer.paint(f"  wrote summary: {args.json_out}", _DIM))

    if args.annex_out:
        # Names organisations. Never publish this file — it exists so you
        # can tell each body what you found before anything goes public.
        pathlib.Path(args.annex_out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.annex_out).write_text(
            _json.dumps({
                "WARNING": "CONFIDENTIAL — identifies individual organisations. "
                           "For coordinated disclosure only. Do not publish.",
                "subjects": disclosure_annex(results),
            }, indent=2, default=str), encoding="utf-8")
        printer.write(printer.paint(
            f"  wrote disclosure annex: {args.annex_out} (confidential)", _DIM))

    out = Printer(sys.stdout)
    out.write("")
    out.write(out.paint("=" * 68, _DIM))
    out.write(out.paint(f" {label}", _BOLD))
    out.write(out.paint("=" * 68, _DIM))
    out.write(f"  Assessed              {summary.scanned}/{summary.total}"
              + (f"  ({summary.failed} failed)" if summary.failed else ""))
    out.write(f"  Offer PQC key exchange {summary.pct(summary.pqc_ready):5.1f}%")
    out.write(f"  TLS 1.3                {summary.pct(summary.tls13):5.1f}%")
    out.write(f"  Forward secrecy        {summary.pct(summary.forward_secrecy):5.1f}%")
    out.write(f"  Deprecated TLS         {summary.pct(summary.deprecated_tls):5.1f}%")
    out.write(f"  Weak ciphers           {summary.pct(summary.weak_ciphers):5.1f}%")
    out.write(f"  CAA / DNSSEC / DMARC   {summary.pct(summary.caa):.0f}% / "
              f"{summary.pct(summary.dnssec):.0f}% / {summary.pct(summary.dmarc_enforcing):.0f}%")
    out.write(f"  Median readiness       {summary.median_readiness:g}/100")
    out.write("")
    if summary.findings:
        out.write(out.paint("  Most common findings", _BOLD))
        for fid, count in summary.findings.most_common(6):
            out.write(f"    {count:3d}  {fid}")
        out.write("")
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve

    try:
        serve(host=args.host, port=args.port, open_browser=not args.no_browser)
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
    except OSError as exc:
        print(f"error: could not start server: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def cmd_algorithms(args: argparse.Namespace) -> int:
    """Print the recommended tooling, so the advice is available offline."""
    if args.json:
        payload = {
            category: [tool._asdict() for tool in tools]
            for category, tools in remediation.PQC_TOOLING.items()
        }
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    printer = Printer(sys.stdout)
    printer.write(printer.paint("Post-quantum tooling that is shipping today", _BOLD))
    printer.write("")
    for category, tools in remediation.PQC_TOOLING.items():
        printer.write(printer.paint(f"  {category}", _BOLD))
        for tool in tools:
            printer.write(f"    {tool.name}  {printer.paint('(' + tool.availability + ')', _DIM)}")
            printer.write(f"      supports: {tool.supports}")
            printer.write(f"      {tool.note}")
            printer.write(f"      {printer.paint(tool.url, _DIM)}")
            printer.write("")
    return EXIT_OK


def cmd_mosca(args: argparse.Namespace) -> int:
    result = quantum.assess_mosca(
        args.shelf_life, args.migration_years,
        scenario=args.scenario, quantum_year=args.quantum_year,
    )
    printer = Printer(sys.stdout)
    printer.write(printer.paint(f"  {result.formula}  →  {result.verdict}", _BOLD))
    printer.write("")
    printer.write(f"  {result.explanation}")
    printer.write("")
    printer.write(printer.paint("  Assumptions", _BOLD))
    for assumption in result.assumptions:
        printer.write(f"    - {assumption}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quantumready",
        description="Post-quantum readiness, certificate, licence and "
                    "cryptographic risk scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  quantumready scan acme.co.uk --org "Acme Ltd" --sector finance
  quantumready scan acme.co.uk --html-out report.html --json-out result.json
  quantumready scan acme.co.uk --fail-on high        # gate a CI pipeline
  quantumready serve --port 8080                     # live dashboard
  quantumready mosca --shelf-life 25 --migration-years 5
  quantumready study --preset councils --html-out study.html
""",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="assess a domain")
    scan.add_argument("domain", help="domain or URL to assess")
    scan.add_argument("--org", help="organisation name for the report")
    scan.add_argument(
        "--sector", default="general",
        choices=sorted(quantum.SECTOR_SHELF_LIFE),
        help="sets a sensible default data shelf life (default: general)",
    )
    scan.add_argument(
        "--shelf-life", type=int, default=None, metavar="YEARS",
        help="Mosca's X: how long the data must stay confidential",
    )
    scan.add_argument(
        "--migration-years", type=int, default=5, metavar="YEARS",
        help="Mosca's Y: how long migration will take (default: 5)",
    )
    scan.add_argument(
        "--scenario", default="central", choices=sorted(quantum.QUANTUM_SCENARIOS),
        help="quantum threat timeline assumption (default: central, 2035)",
    )
    scan.add_argument(
        "--quantum-year", type=int, default=None,
        help="override the threat year outright",
    )
    scan.add_argument("--max-hosts", type=int, default=12, help="host cap (default: 12)")
    scan.add_argument("--timeout", type=float, default=7.0, help="per-connection timeout")
    scan.add_argument("--workers", type=int, default=8, help="parallel host scans")
    scan.add_argument("--fast", action="store_true", help="skip deep protocol probing")
    scan.add_argument("--no-ct", action="store_true", help="skip Certificate Transparency discovery")
    scan.add_argument("--no-licences", action="store_true", help="skip component and licence scan")
    scan.add_argument("--no-dns", action="store_true", help="skip DNS posture checks")
    scan.add_argument(
        "--format", default="text", choices=("text", "json", "markdown", "html", "cbom"),
        help="stdout format (default: text)",
    )
    scan.add_argument("--html-out", metavar="PATH", help="write the HTML report here")
    scan.add_argument("--json-out", metavar="PATH", help="write JSON here")
    scan.add_argument("--markdown-out", metavar="PATH", help="write Markdown here")
    scan.add_argument("--cbom-out", metavar="PATH", help="write a CycloneDX CBOM here")
    scan.add_argument(
        "--fail-on", choices=("critical", "high", "medium", "low"), default=None,
        help="exit 1 if a finding at this severity or worse is present",
    )
    scan.add_argument("--quiet", action="store_true", help="suppress progress output")
    scan.set_defaults(func=cmd_scan)


    study = subparsers.add_parser(
        "study", help="benchmark a cohort of organisations and publish aggregates")
    study.add_argument("--preset", action="append",
                       help="built-in cohort: councils, universities, listed, nhs "
                            "(repeatable)")
    study.add_argument("--targets", metavar="CSV",
                       help="CSV of subjects: name,domain[,sector,region]")
    study.add_argument("--domain", action="append",
                       help="scan an individual domain (repeatable)")
    study.add_argument("--cohort", help="label used in the report")
    study.add_argument("--title", help="report title")
    study.add_argument("--sector", default="general",
                       choices=sorted(quantum.SECTOR_SHELF_LIFE),
                       help="sector for --domain subjects (default: general)")
    study.add_argument("--limit", type=int, help="cap the number of subjects")
    study.add_argument("--workers", type=int, default=3,
                       help="concurrent subjects (default: 3, deliberately low)")
    study.add_argument("--delay", type=float, default=1.0,
                       help="seconds between subject starts (default: 1.0)")
    study.add_argument("--timeout", type=float, default=8.0)
    study.add_argument("--max-hosts", type=int, default=2,
                       help="hosts per subject (default: 2 — apex and www)")
    study.add_argument("--fast", action="store_true", help="skip cipher enumeration")
    study.add_argument("--scenario", default="central",
                       choices=sorted(quantum.QUANTUM_SCENARIOS))
    study.add_argument("--resume", metavar="JSONL",
                       help="checkpoint file; re-run with the same path to resume")
    study.add_argument("--html-out", metavar="PATH", help="publishable aggregate report")
    study.add_argument("--json-out", metavar="PATH", help="aggregate summary as JSON")
    study.add_argument("--annex-out", metavar="PATH",
                       help="CONFIDENTIAL per-organisation annex for disclosure")
    study.add_argument("--quiet", action="store_true")
    study.set_defaults(func=cmd_study)

    serve = subparsers.add_parser("serve", help="run the live web dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--no-browser", action="store_true", help="do not open a browser")
    serve.set_defaults(func=cmd_serve)

    algorithms = subparsers.add_parser(
        "algorithms", help="list post-quantum tooling that is available today"
    )
    algorithms.add_argument("--json", action="store_true")
    algorithms.set_defaults(func=cmd_algorithms)

    mosca = subparsers.add_parser("mosca", help="run the X + Y > Z calculation alone")
    mosca.add_argument("--shelf-life", type=int, required=True, metavar="YEARS")
    mosca.add_argument("--migration-years", type=int, default=5, metavar="YEARS")
    mosca.add_argument("--scenario", default="central", choices=sorted(quantum.QUANTUM_SCENARIOS))
    mosca.add_argument("--quantum-year", type=int, default=None)
    mosca.set_defaults(func=cmd_mosca)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
