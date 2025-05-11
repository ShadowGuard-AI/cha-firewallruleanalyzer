# cha-FirewallRuleAnalyzer
Analyzes firewall rule sets (iptables, firewalld) to identify overly permissive rules or rules that conflict with each other, potentially exposing vulnerabilities. Outputs a report with suggested improvements. Relies on parsing firewall configuration files with regular expressions. - Focused on Evaluates system configurations against a defined set of security hardening benchmarks (e.g., CIS benchmarks, NIST standards) using YAML/JSON-based rule sets. Identifies deviations from recommended settings and provides actionable remediation recommendations. Focuses on automatically checking config files against compliance benchmarks.

## Install
`git clone https://github.com/ShadowStrikeHQ/cha-firewallruleanalyzer`

## Usage
`./cha-firewallruleanalyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--output`: No description provided
- `--schema`: No description provided
- `--output`: No description provided

## License
Copyright (c) ShadowStrikeHQ
