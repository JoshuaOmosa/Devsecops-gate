# policies/policy_test.rego
#
# Unit tests for the gate's decisions. Run with:  opa test policies -v
package devsecops_test

import rego.v1

import data.devsecops
import data.devsecops.triage

scan_date := "2024-09-14T00:00:00Z"

finding(overrides) := object.union({
	"id": "CVE-TEST-0001",
	"package_name": "lib",
	"package_version": "1.0.0",
	"severity": "MEDIUM",
	"cvss_score": 5.0,
	"description": "test finding",
	"discovered_date": "2024-09-10T00:00:00Z",
	"exploit_available": false,
	"public_exploit": false,
	"active_exploitation": false,
	"false_positive": false,
}, overrides)

scan(findings) := {"scan_date": scan_date, "vulnerabilities": findings}

# --- Blocking rules ---------------------------------------------------------

test_empty_scan_passes if {
	devsecops.allow with input as scan([])
}

test_unmitigated_critical_blocks if {
	not devsecops.allow with input as scan([finding({"severity": "CRITICAL", "cvss_score": 9.8})])
}

test_critical_confirmed_false_positive_passes if {
	devsecops.allow with input as scan([finding({"severity": "CRITICAL", "cvss_score": 9.8, "false_positive": true})])
}

test_critical_blocks_if_any_critical_is_real if {
	not devsecops.allow with input as scan([
		finding({"id": "a", "severity": "CRITICAL", "false_positive": true}),
		finding({"id": "b", "severity": "CRITICAL"}),
	])
}

test_high_exploitable_blocks if {
	not devsecops.allow with input as scan([finding({"severity": "HIGH", "cvss_score": 6.0, "exploit_available": true})])
}

test_high_high_cvss_blocks if {
	not devsecops.allow with input as scan([finding({"severity": "HIGH", "cvss_score": 8.1})])
}

test_high_not_exploitable_passes if {
	devsecops.allow with input as scan([finding({"severity": "HIGH", "cvss_score": 6.5})])
}

# Regression: a HIGH that is a confirmed false positive used to block anyway.
test_high_false_positive_does_not_block if {
	devsecops.allow with input as scan([finding({"severity": "HIGH", "cvss_score": 7.5, "false_positive": true})])
}

test_high_noise_pattern_does_not_block if {
	devsecops.allow with input as scan([finding({"severity": "HIGH", "cvss_score": 7.5, "description": "dev dependency only"})])
}

test_medium_and_low_never_block if {
	devsecops.allow with input as scan([
		finding({"severity": "MEDIUM", "cvss_score": 6.9, "exploit_available": true}),
		finding({"severity": "LOW", "cvss_score": 3.1}),
	])
}

test_violation_messages if {
	msgs := devsecops.violated_policies with input as scan([
		finding({"severity": "CRITICAL"}),
		finding({"severity": "HIGH", "cvss_score": 9.0}),
	])
	msgs == {"CRITICAL vulnerability detected - must be remediated", "HIGH exploitable vulnerability detected"}
}

# --- SLA reporting (reported, does not block) ---------------------------------

test_sla_breach_reported if {
	report := triage.sla_compliance_report with input as scan([
		finding({"severity": "MEDIUM", "discovered_date": "2024-08-01T00:00:00Z"}),
	])
	report.overall_status == "VIOLATED"
	report.violations_detail[_].overdue_by_days == 30
}

test_sla_breach_alone_does_not_block if {
	devsecops.allow with input as scan([finding({"severity": "LOW", "cvss_score": 3.0, "discovered_date": "2024-01-01T00:00:00Z"})])
}

test_sla_within_window_compliant if {
	report := triage.sla_compliance_report with input as scan([finding({"severity": "HIGH", "cvss_score": 5.0})])
	report.overall_status == "COMPLIANT"
	report.compliance_percentage == 100
}

test_sla_windows_by_severity if {
	triage.sla_for_severity("CRITICAL") == 3
	triage.sla_for_severity("HIGH") == 7
	triage.sla_for_severity("MEDIUM") == 14
	triage.sla_for_severity("LOW") == 30
	triage.sla_for_severity("UNKNOWN") == 9
}
