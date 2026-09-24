#!/usr/bin/env python3
"""
process-results.py

Runs the OPA policy bundle (policies/) against a scan payload, then renders
a human-readable triage report to stdout and a machine-readable JSON summary
to scan-results/. Exits non-zero (blocking the pipeline) if the policy
returns allow == false.

Usage:
    python3 scripts/process-results.py [path/to/input.json]

If no input path is given, defaults to policies/test_data.json so the
script works out of the box for local testing.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_DIR = os.path.join(REPO_ROOT, "policies")
RESULTS_DIR = os.path.join(REPO_ROOT, "scan-results")
QUERY = "data.devsecops.triage"


def resolve_opa_binary() -> str:
    """Find an OPA executable: system PATH first, then common local drop
    locations, so this script behaves the same on Linux CI runners, macOS,
    and Windows dev machines (Git Bash / PowerShell) without editing paths."""
    if shutil.which("opa"):
        return "opa"

    candidates = [
        os.path.join(REPO_ROOT, "opa.exe"),
        os.path.join(REPO_ROOT, "opa"),
        os.path.join(os.path.expanduser("~"), "bin", "opa.exe"),
        os.path.join(os.path.expanduser("~"), "bin", "opa"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path

    print("[ERROR] Could not find an OPA executable on PATH or in common "
          "local locations (./opa.exe, ~/bin/opa.exe). Install OPA and "
          "re-run.")
    sys.exit(1)


def run_opa(input_path: str) -> dict:
    """Runs OPA and returns the triage decision."""
    opa_cmd = resolve_opa_binary()
    cmd = [opa_cmd, "eval", "--data", POLICY_DIR, "--input", input_path,
           "--format", "json", QUERY]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("[ERROR] OPA evaluation failed:")
        print(result.stderr)
        sys.exit(1)

    try:
        parsed = json.loads(result.stdout)
        return parsed["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, json.JSONDecodeError):
        print("[ERROR] Unexpected OPA output. Check that policies/ "
              "returns the expected structure.")
        print("Raw OPA output:\n", result.stdout)
        sys.exit(1)


def render_report(decision: dict) -> bool:
    """Prints the triage report. Returns True if the build should pass."""
    allow = decision.get("allow", False)
    violated_policies = decision.get("violated_policies", [])
    noise = decision.get("noise_statistics", {})
    sla = decision.get("sla_compliance_report", {})

    print("=" * 60)
    print("DevSecOps Governance Gate - Triage Report")
    print("=" * 60)

    print(f"\nScanned findings : {noise.get('total_findings', 0)}")
    print(f"Actionable        : {noise.get('actionable_findings', 0)}")
    print(f"False positives   : {noise.get('false_positives_filtered', 0)}")
    print(f"Excluded packages : {noise.get('excluded_packages_filtered', 0)}")
    print(f"Noise reduction   : {noise.get('noise_reduction_percentage', 0)}%")

    if sla:
        print(f"\nSLA status        : {sla.get('overall_status', 'UNKNOWN')}")
        print(f"SLA compliance    : {sla.get('compliance_percentage', 0)}%")
        for v in sla.get("violations_detail", []):
            print(f"  [SLA BREACH] {v['vulnerability_id']} ({v['severity']}) "
                  f"in '{v['package']}' — {v['overdue_by_days']}d over "
                  f"the {v['sla_days']}d window")

    if violated_policies:
        print("\n--- POLICY VIOLATIONS (blocking) ---")
        for msg in violated_policies:
            print(f"  [FAIL] {msg}")
    else:
        print("\nNo blocking policy violations.")

    print(f"\nGate decision: {'PASS' if allow else 'BLOCK'}")
    print("=" * 60)

    return allow


def write_summary(decision: dict) -> str:
    """Writes summary to JSON and returns the path."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "triage-summary.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(decision, f, indent=2)
    print(f"\nFull JSON summary written to: {out_path}")
    return out_path


def create_ticket(summary_path: str) -> bool:
    """Calls create-ticket.py to file a Jira issue or log locally."""
    create_ticket_script = os.path.join(
        os.path.dirname(__file__), "create-ticket.py")
    
    if not os.path.exists(create_ticket_script):
        print("[WARNING] create-ticket.py not found. Skipping ticket creation.")
        return True
    
    print("\n--> Creating issue ticket...")
    result = subprocess.run(
        [sys.executable, create_ticket_script, summary_path],
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    
    return result.returncode == 0


def main() -> None:
    input_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        POLICY_DIR, "test_data.json")

    if not os.path.exists(input_path):
        print(f"[ERROR] Input file not found: {input_path}")
        sys.exit(1)

    decision = run_opa(input_path)
    summary_path = write_summary(decision)
    allow = render_report(decision)

    if not allow:
        print()
        create_ticket(summary_path)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()