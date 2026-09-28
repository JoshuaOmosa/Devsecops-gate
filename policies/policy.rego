package devsecops

default allow = false

allow {
    count(violated_policies) == 0
}

violated_policies[msg] {
    not critical_vulnerability_allowed
    msg := "CRITICAL vulnerability detected - must be remediated"
}

violated_policies[msg] {
    not high_exploitable_vulnerability_allowed
    msg := "HIGH exploitable vulnerability detected"
}

critical_vulnerability_allowed {
    critical_vulns := [v | v := input.vulnerabilities[_]; v.severity == "CRITICAL"]
    count(critical_vulns) == 0
}

critical_vulnerability_allowed {
    critical_vulns := [v | v := input.vulnerabilities[_]; v.severity == "CRITICAL"]
    all_false_positives := [v | v := critical_vulns[_]; is_false_positive(v)]
    count(all_false_positives) == count(critical_vulns)
}

high_exploitable_vulnerability_allowed {
    high_vulns := [v | v := input.vulnerabilities[_]; v.severity == "HIGH"]
    count(high_vulns) == 0
}

high_exploitable_vulnerability_allowed {
    high_vulns := [v | v := input.vulnerabilities[_]; v.severity == "HIGH"]
    exploitable_high := [v | v := high_vulns[_]; is_exploitable(v)]
    count(exploitable_high) == 0
}

is_exploitable(vuln) {
    vuln.cvss_score >= 7.0
}

is_exploitable(vuln) {
    vuln.exploit_available == true
}

is_exploitable(vuln) {
    vuln.public_exploit == true
}

is_exploitable(vuln) {
    vuln.active_exploitation == true
}

is_false_positive(vuln) {
    false_positive_patterns := [
        "no fix available",
        "dev dependency only",
        "test dependency only",
        "build-time only",
        "not in executable path"
    ]
    
    lower_description := lower(vuln.description)
    contains_pattern := [p | p := false_positive_patterns[_]; contains(lower_description, p)]
    count(contains_pattern) > 0
}

is_false_positive(vuln) {
    vuln.false_positive == true
}

is_false_positive(vuln) {
    vuln.severity == "LOW"
    vuln.cvss_score < 4.0
    not vuln.exploit_available
}

is_excluded_package(vuln) {
    excluded := {
        "node:12",
        "test-package@1.0.0",
        "deprecated-lib"
    }
    
    pkg_name := sprintf("%s:%s", [vuln.package_name, vuln.package_version])
    excluded[pkg_name]
}

noise_statistics[stat] {
    total_findings := count(input.vulnerabilities)
    high_risk := [v | v := input.vulnerabilities[_]; v.severity in ["CRITICAL", "HIGH"]; is_exploitable(v)]
    false_positives := [v | v := input.vulnerabilities[_]; is_false_positive(v)]
    excluded := [v | v := input.vulnerabilities[_]; is_excluded_package(v)]
    filtered_out := count(false_positives) + count(excluded)
    reduction_percentage := (filtered_out / total_findings) * 100
    
    stat := {
        "total_findings": total_findings,
        "high_risk_exploitable": count(high_risk),
        "false_positives_filtered": count(false_positives),
        "excluded_packages_filtered": count(excluded),
        "total_filtered": filtered_out,
        "noise_reduction_percentage": reduction_percentage,
        "actionable_findings": count(high_risk)
    }
}

violation_report[report] {
    actionable := [v | 
        v := input.vulnerabilities[_]
        v.severity in ["CRITICAL", "HIGH"]
        is_exploitable(v)
        not is_excluded_package(v)
    ]
    
    false_positives_filtered := [v | 
        v := input.vulnerabilities[_]
        is_false_positive(v)
    ]
    
    report := {
        "total_vulnerabilities": count(input.vulnerabilities),
        "actionable_vulnerabilities": count(actionable),
        "false_positives_filtered": count(false_positives_filtered),
        "details": {
            "actionable": actionable,
            "filtered_false_positives": false_positives_filtered
        }
    }
}
