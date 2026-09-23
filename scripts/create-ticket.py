#!/usr/bin/env python3
"""
create-ticket.py

Opens a Jira ticket for a blocked build, using the triage summary produced
by process-results.py. Reads Jira credentials from environment variables so
no secrets ever live in the repo:

    JIRA_BASE_URL   e.g. https://your-domain.atlassian.net
    JIRA_EMAIL
    JIRA_API_TOKEN
    JIRA_PROJECT_KEY

If credentials are not set, the script prints what it *would* have filed
and exits 0 rather than failing the pipeline on missing secrets — this
keeps local/demo runs working without a live Jira instance.

Usage:
    python3 scripts/create-ticket.py scan-results/triage-summary.json
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request


def build_ticket_payload(summary: dict, project_key: str) -> dict:
    violations = summary.get("violated_policies", [])
    sla = summary.get("sla_compliance_report", {})
    sla_breaches = sla.get("violations_detail", [])

    lines = ["Automated DevSecOps Governance Gate failure.", "", "Policy violations:"]
    lines += [f"- {msg}" for msg in violations] or ["- (none)"]
    lines += ["", "SLA breaches:"]
    lines += [
        f"- {v['vulnerability_id']} ({v['severity']}) in {v['package']}: "
        f"{v['overdue_by_days']}d overdue"
        for v in sla_breaches
    ] or ["- (none)"]

    return {
        "fields": {
            "project": {"key": project_key},
            "summary": "DevSecOps Gate Blocked Build - Security Policy Violation",
            "description": "\n".join(lines),
            "issuetype": {"name": "Bug"},
            "labels": ["devsecops", "automated", "security-gate"],
        }
    }


def file_ticket(payload: dict, base_url: str, email: str, token: str) -> None:
    import base64

    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    req = urllib.request.Request(
        url=f"{base_url.rstrip('/')}/rest/api/2/issue",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            print(f"Jira ticket created: {body.get('key')}")
    except urllib.error.HTTPError as e:
        print(f"[ERROR] Jira API returned {e.code}: {e.read().decode('utf-8')}")
        sys.exit(1)


def main() -> None:
    summary_path = sys.argv[1] if len(sys.argv) > 1 else "scan-results/triage-summary.json"
    if not os.path.exists(summary_path):
        print(f"[ERROR] Triage summary not found: {summary_path}")
        sys.exit(1)

    with open(summary_path, "r", encoding="utf-8") as f:
        summary = json.load(f)

    base_url = os.environ.get("JIRA_BASE_URL")
    email = os.environ.get("JIRA_EMAIL")
    token = os.environ.get("JIRA_API_TOKEN")
    project_key = os.environ.get("JIRA_PROJECT_KEY", "SEC")

    payload = build_ticket_payload(summary, project_key)

    if not all([base_url, email, token]):
        print("[INFO] JIRA_BASE_URL / JIRA_EMAIL / JIRA_API_TOKEN not set — "
              "skipping live ticket creation. Payload that would be sent:")
        print(json.dumps(payload, indent=2))
        return

    file_ticket(payload, base_url, email, token)


if __name__ == "__main__":
    main()
