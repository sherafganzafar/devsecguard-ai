#!/usr/bin/env python3
"""DevSecGuard AI command line scanner.

Examples
    python agent.py --demo                      # scan a built-in vulnerable sample
    python agent.py --file app.py               # scan one file
    python agent.py --repo . --fail-on high     # scan a repository (used by CI)
    python agent.py --repo . --no-llm           # offline, regex layer only
    python agent.py --list-models               # show Nemotron models on your account

Exit codes
    0  scan passed
    1  push should be blocked (a finding met the --fail-on threshold)
    2  usage or configuration error
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional

import core

try:  # .env support is optional
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent.py",
        description="DevSecGuard AI: scan code for secrets and vulnerabilities and block risky pushes.",
    )
    target = p.add_argument_group("what to scan")
    target.add_argument("--file", help="Path of a single file to scan.")
    target.add_argument("--repo", help="Directory to scan recursively.")
    target.add_argument("--demo", action="store_true", help="Scan a built-in vulnerable sample.")
    target.add_argument("--exclude", action="append", default=[], help="Path or glob to skip (repeatable).")
    policy = p.add_argument_group("blocking policy")
    policy.add_argument(
        "--fail-on", choices=core.SEVERITIES, default="high",
        help="Block (exit 1) when a finding of this severity or higher exists. Default: high.",
    )
    policy.add_argument("--strict", action="store_true", help="Shortcut for --fail-on medium.")
    model = p.add_argument_group("model")
    model.add_argument("--model", help="Model id on Nebius Token Factory (default: auto-pick a Nemotron model).")
    model.add_argument("--no-llm", action="store_true", help="Skip the LLM layer (regex only, works offline).")
    model.add_argument("--require-llm", action="store_true", help="Exit 2 if the LLM layer cannot run.")
    model.add_argument("--max-llm-files", type=int, default=20, help="Max files sent to the model in --repo mode.")
    model.add_argument("--list-models", action="store_true", help="List Nemotron models available to your key and exit.")
    out = p.add_argument_group("output")
    out.add_argument("--json-out", help="Write a JSON report to this path.")
    return p


def _setup_llm(args) -> tuple:
    """Return (client, model, warning). client is None when the LLM layer is off."""
    if args.no_llm:
        return None, "", ""
    try:
        client = core.make_client()
        model = core.pick_model(client, args.model)
        return client, model, ""
    except Exception as exc:
        return None, "", f"LLM layer unavailable ({exc}). Running regex-only."


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_models:
        try:
            client = core.make_client()
            names = core.list_nemotron_models(client)
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print("\n".join(names) if names else "No Nemotron models found for this key.")
        return 0

    fail_on = "medium" if args.strict else args.fail_on

    # Decide what to scan.
    targets: List[tuple] = []  # (display_path, text)
    root = ""
    if args.file:
        if not os.path.isfile(args.file):
            print(f"Error: file '{args.file}' not found.", file=sys.stderr)
            return 2
        targets.append((args.file, core.read_text(args.file)))
    elif args.repo:
        if not os.path.isdir(args.repo):
            print(f"Error: directory '{args.repo}' not found.", file=sys.stderr)
            return 2
        root = os.path.abspath(args.repo)
        for path in core.collect_files(root, args.exclude):
            targets.append((path, core.read_text(path)))
    else:
        targets.append(("<demo>", core.demo_code()))

    client, model, warning = _setup_llm(args)
    if warning:
        print(f"Warning: {warning}", file=sys.stderr)
        if args.require_llm:
            return 2

    print(f"DevSecGuard AI scanning {len(targets)} file(s) | model: {model or 'regex-only'} | block at: {fail_on}+")

    started = time.perf_counter()
    results: List[core.FileResult] = []
    llm_budget = args.max_llm_files if (args.repo and client) else len(targets)
    for index, (path, text) in enumerate(targets):
        use_client = client if index < llm_budget else None
        results.append(core.scan_text(text, path=path, client=use_client, model=model))
    total = time.perf_counter() - started

    blocked = core.is_blocked(results, fail_on)
    print(core.render_console(results, root))
    llm_files = [r for r in results if r.llm_used]
    if llm_files:
        avg = sum(r.llm_seconds for r in llm_files) / len(llm_files)
        print(f"\nModel latency: {avg:.2f}s average over {len(llm_files)} file(s).")
    print(f"Total scan time: {total:.2f}s")
    print("RESULT: BLOCKED" if blocked else "RESULT: PASSED")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(core.to_json(results, blocked, fail_on, model, total))

    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(core.render_markdown(results, blocked, fail_on, model, total))

    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
