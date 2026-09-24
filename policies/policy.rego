# policies/policy.rego
#
# Core exploitability triage policy. Consumes raw vulnerability findings
# (normalized from Trivy / Snyk / SonarQube) and decides whether a finding
# is an actionable, build-blocking risk or filterable noise.
#
# Design principle: block on exploitability + severity, not raw CVE count.
package devsecops.triage

import rego.v1

default allow := false

allow if {
	count(violated_policies) == 0
}

# --- Blocking rules -----------------------------------------------------

violated_policies contains msg if {
	not critical_vulnerability_allowed
	msg := "CRITICAL vulnerability detected - must be remediated"
}

violated_policies contains msg if {
	not high_exploitable_vulnerability_allowed
	msg := "HIGH severity vulnerability with active exploit path detected"
}

# A CRITICAL finding is only "allowed" (non-blocking) if every CRITICAL
# in the batch resolves to a known false positive.
critical_vulnerability_allowed if {
	critical_vulns := [v | some v in input.vulnerabilities; v.severity == "CRITICAL"]
	count(critical_vulns) == 0
}

critical_vulnerability_allowed if {
	critical_vulns := [v | some v in input.vulnerabilities; v.severity == "CRITICAL"]
	count(critical_vulns) > 0
	all_false_positives := [v | some v in critical_vulns; is_false_positive(v)]
	count(all_false_positives) == count(critical_vulns)
}

# A HIGH finding only blocks if it is also exploitable.
high_exploitable_vulnerability_allowed if {
	high_vulns := [v | some v in input.vulnerabilities; v.severity == "HIGH"]
	count(high_vulns) == 0
}

high_exploitable_vulnerability_allowed if {
	high_vulns := [v | some v in input.vulnerabilities; v.severity == "HIGH"]
	count(high_vulns) > 0
	exploitable_high := [v | some v in high_vulns; is_exploitable(v)]
	count(exploitable_high) == 0
}

# --- Exploitability heuristics -------------------------------------------

is_exploitable(vuln) if { vuln.cvss_score >= 7.0 }
is_exploitable(vuln) if { vuln.exploit_available == true }
is_exploitable(vuln) if { vuln.public_exploit == true }
is_exploitable(vuln) if { vuln.active_exploitation == true }

# --- False-positive / noise heuristics -----------------------------------

false_positive_patterns := [
	"no fix available",
	"dev dependency only",
	"test dependency only",
	"build-time only",
	"not in executable path",
]

is_false_positive(vuln) if {
	lower_description := lower(vuln.description)
	matches := [p | some p in false_positive_patterns; contains(lower_description, p)]
	count(matches) > 0
}

is_false_positive(vuln) if { vuln.false_positive == true }

is_false_positive(vuln) if {
	vuln.severity == "LOW"
	vuln.cvss_score < 4.0
	not vuln.exploit_available
}

# --- Package exclusion list ----------------------------------------------

excluded_packages := {
	"node:12",
	"test-package@1.0.0",
	"deprecated-lib",
}

is_excluded_package(vuln) if {
	pkg_name := sprintf("%s:%s", [vuln.package_name, vuln.package_version])
	pkg_name in excluded_packages
}

# --- Reporting -------------------------------------------------------------

# Noise-reduction telemetry. Guards against divide-by-zero on empty scans.
noise_statistics := stat if {
	total_findings := count(input.vulnerabilities)
	total_findings > 0

	high_risk := [v |
		some v in input.vulnerabilities
		v.severity in ["CRITICAL", "HIGH"]
		is_exploitable(v)
	]
	false_positives := [v | some v in input.vulnerabilities; is_false_positive(v)]
	excluded := [v | some v in input.vulnerabilities; is_excluded_package(v)]

	filtered_out := count(false_positives) + count(excluded)
	reduction_percentage := round((filtered_out / total_findings) * 100)

	stat := {
		"total_findings": total_findings,
		"high_risk_exploitable": count(high_risk),
		"false_positives_filtered": count(false_positives),
		"excluded_packages_filtered": count(excluded),
		"total_filtered": filtered_out,
		"noise_reduction_percentage": reduction_percentage,
		"actionable_findings": count(high_risk),
	}
}

noise_statistics := stat if {
	count(input.vulnerabilities) == 0
	stat := {
		"total_findings": 0,
		"high_risk_exploitable": 0,
		"false_positives_filtered": 0,
		"excluded_packages_filtered": 0,
		"total_filtered": 0,
		"noise_reduction_percentage": 0,
		"actionable_findings": 0,
	}
}

violation_report := report if {
	actionable := [v |
		some v in input.vulnerabilities
		v.severity in ["CRITICAL", "HIGH"]
		is_exploitable(v)
		not is_excluded_package(v)
	]
	false_positives_filtered := [v | some v in input.vulnerabilities; is_false_positive(v)]

	report := {
		"total_vulnerabilities": count(input.vulnerabilities),
		"actionable_vulnerabilities": count(actionable),
		"false_positives_filtered": count(false_positives_filtered),
		"details": {
			"actionable": actionable,
			"filtered_false_positives": false_positives_filtered,
		},
	}
}

triage[output] {
    output := {
        "allow": allow,
        "violated_policies": violated_policies,
        "noise_statistics": noise_statistics,
        "sla_compliance_report": sla_compliance_report
    }
}
