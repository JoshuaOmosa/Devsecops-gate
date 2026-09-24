#!/usr/bin/env python3
"""
create-ticket.py

Creates a Jira ticket for policy violations. If Jira not configured,
logs to a file instead.

Environment variables (optional):
    JIRA_URL, JIRA_USER, JIRA_TOKEN, JIRA_PROJECT_KEY
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def create_ticket_in_jira(summary_data: dict) -> bool:
    """Attempts to create a Jira ticket. Returns True if successful or gracefully skipped."""
    
    jira_url = os.getenv("JIRA_URL")
    jira_user = os.getenv("JIRA_USER")
    jira_token = os.getenv("JIRA_TOKEN")
    jira_project = os.getenv("JIRA_PROJECT_KEY", "DEVSECOPS")
    
    # If Jira not configured, log locally and return success
    if not (jira_url and jira_user and jira_token):
        print("[INFO] Jira not configured (missing env vars). "
              "Logging to local file instead.")
        log_locally(summary_data)
        return True
    
    try:
        import requests
    except ImportError:
        print("[WARNING] requests library not installed. "
              "Falling back to local logging.")
        log_locally(summary_data)
        return True
    
    # Build Jira ticket
    violations = summary_data.get("violated_policies", [])
    sla_breaches = summary_data.get("sla_compliance_report", {}).get(
        "violations_detail", [])
    noise = summary_data.get("noise_statistics", {})
    
    description = format_ticket_description(violations, sla_breaches, noise)
    
    payload = {
        "fields": {
            "project": {"key": jira_project},
            "issuetype": {"name": "Bug"},
            "summary": f"[DevSecOps] Security gate violations detected "
                       f"({len(violations)} blocking, "
                       f"{len(sla_breaches)} SLA breaches)",
            "description": description,
            "labels": ["devsecops", "security-gate", "auto-created"],
            "priority": {"name": "High" if violations else "Medium"}
        }
    }
    
    # Create ticket
    auth = (jira_user, jira_token)
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(
            f"{jira_url}/rest/api/3/issue",
            json=payload,
            auth=auth,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 201:
            ticket = response.json()
            ticket_key = ticket.get("key", "UNKNOWN")
            print(f"[SUCCESS] Jira ticket created: {ticket_key}")
            return True
        else:
            print(f"[ERROR] Jira API returned {response.status_code}: "
                  f"{response.text}")
            log_locally(summary_data)
            return False
            
    except Exception as e:
        print(f"[ERROR] Failed to create Jira ticket: {e}")
        log_locally(summary_data)
        return False


def format_ticket_description(violations: list, sla_breaches: list, 
                               noise: dict) -> str:
    """Formats the ticket description from findings."""
    
    lines = [
        "DevSecOps Governance Gate Violation Report",
        "",
        "h2. Summary",
        f"* Total findings: {noise.get('total_findings', 0)}",
        f"* Actionable: {noise.get('actionable_findings', 0)}",
        f"* Noise reduction: {noise.get('noise_reduction_percentage', 0)}%",
        "",
    ]
    
    if violations:
        lines.extend([
            "h2. Blocking Policy Violations",
            "",
        ])
        for v in violations:
            lines.append(f"* {v}")
        lines.append("")
    
    if sla_breaches:
        lines.extend([
            "h2. SLA Breaches",
            "",
        ])
        for breach in sla_breaches:
            lines.append(
                f"* {breach['vulnerability_id']} ({breach['severity']}) "
                f"in {breach['package']}: "
                f"{breach['overdue_by_days']}d overdue "
                f"(SLA: {breach['sla_days']}d)"
            )
        lines.append("")
    
    lines.extend([
        "h2. Next Steps",
        "* Review the full triage report in scan-results/triage-summary.json",
        "* Remediate blocking vulnerabilities to unblock the pipeline",
        "* Update SLA tracking for overdue findings",
    ])
    
    return "\n".join(lines)


def log_locally(summary_data: dict) -> None:
    """Logs findings to a local file instead of Jira."""
    os.makedirs("scan-results", exist_ok=True)
    
    ticket_log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "security_gate_violation",
        "summary_data": summary_data
    }
    
    log_file = "scan-results/security-gate-violations.log.json"
    with open(log_file, "w") as f:
        json.dump(ticket_log, f, indent=2)
    
    print(f"[INFO] Violation log written to: {log_file}")


def main() -> None:
    if len(sys.argv) < 2:
        print("[ERROR] Usage: python3 scripts/create-ticket.py "
              "<path/to/triage-summary.json>")
        sys.exit(1)
    
    summary_path = sys.argv[1]
    
    if not os.path.exists(summary_path):
        print(f"[ERROR] Summary file not found: {summary_path}")
        sys.exit(1)
    
    with open(summary_path, "r") as f:
        summary_data = json.load(f)
    
    success = create_ticket_in_jira(summary_data)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()