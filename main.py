import argparse
import logging
import yaml
import json
import jsonschema
import os
import re
import sys


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define exception class for custom exceptions
class FirewallAnalyzerError(Exception):
    """Base class for exceptions in this module."""
    pass


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes firewall rules (iptables, firewalld) and system configurations against security hardening benchmarks."
    )

    # Subparsers for firewall and benchmark analysis
    subparsers = parser.add_subparsers(dest='mode', help='Select analysis mode: firewall or benchmark')

    # Firewall analysis subparser
    firewall_parser = subparsers.add_parser('firewall', help='Analyze firewall rules (iptables, firewalld)')
    firewall_parser.add_argument('firewall_config', type=str, help='Path to the firewall configuration file (iptables or firewalld)')
    firewall_parser.add_argument('--output', type=str, default='firewall_report.txt', help='Path to save the firewall analysis report (default: firewall_report.txt)')

    # Benchmark analysis subparser
    benchmark_parser = subparsers.add_parser('benchmark', help='Analyze system configurations against security hardening benchmarks')
    benchmark_parser.add_argument('config_file', type=str, help='Path to the system configuration file to analyze')
    benchmark_parser.add_argument('benchmark_file', type=str, help='Path to the YAML/JSON benchmark file')
    benchmark_parser.add_argument('--schema', type=str, help='Path to the JSON schema file (optional for validation)')
    benchmark_parser.add_argument('--output', type=str, default='benchmark_report.txt', help='Path to save the benchmark analysis report (default: benchmark_report.txt)')

    return parser


def validate_json_schema(json_data, schema_file):
    """
    Validates JSON data against a JSON schema.

    Args:
        json_data (dict): The JSON data to validate.
        schema_file (str): Path to the JSON schema file.

    Returns:
        bool: True if validation is successful, False otherwise.
    """
    try:
        with open(schema_file, 'r') as f:
            schema = json.load(f)

        jsonschema.validate(instance=json_data, schema=schema)
        return True
    except jsonschema.exceptions.ValidationError as e:
        logging.error(f"JSON Schema Validation Error: {e}")
        return False
    except FileNotFoundError:
        logging.error(f"Schema file not found: {schema_file}")
        return False
    except Exception as e:
        logging.error(f"Error loading or validating schema: {e}")
        return False


def analyze_firewall_rules(firewall_config_file):
    """
    Analyzes firewall rules from a configuration file (iptables or firewalld).

    Args:
        firewall_config_file (str): Path to the firewall configuration file.

    Returns:
        list: A list of findings (dict) about the firewall rules.
    """
    findings = []

    try:
        with open(firewall_config_file, 'r') as f:
            config_content = f.read()

        # Basic check for common firewall commands. Extend as needed
        if "iptables" in config_content:
            logging.info("Analyzing iptables configuration.")
            # Example: Detect overly permissive rules (allowing all traffic)
            overly_permissive_rules = re.findall(r"-A INPUT -j ACCEPT", config_content)
            if overly_permissive_rules:
                findings.append({"rule": "Overly permissive INPUT rule found (ACCEPT all)", "severity": "High", "recommendation": "Review and restrict the INPUT chain to specific ports/protocols."})

            #Example: detect rules allowing all traffic from anywhere to a port
            potential_vulnerable_rules = re.findall(r"-A INPUT -p (tcp|udp) --dport (\d+) -j ACCEPT",config_content)
            for rule in potential_vulnerable_rules:
                findings.append({"rule": f"Potential vulnerable rule: All traffic accepted on port {rule[1]}", "severity":"Medium", "recommendation": "Restrict to specific source IPs"})

        elif "firewall-cmd" in config_content:
            logging.info("Analyzing firewalld configuration.")
            # Example: Detect public zone usage (generally discouraged)
            public_zone_rules = re.findall(r"zone=public", config_content)
            if public_zone_rules:
                findings.append({"rule": "Public zone is in use", "severity": "Medium", "recommendation": "Review and restrict the public zone or use a more restrictive zone."})
        else:
            logging.warning("Firewall configuration type not detected.  Basic analysis only.")

    except FileNotFoundError:
        logging.error(f"Firewall configuration file not found: {firewall_config_file}")
        raise FirewallAnalyzerError(f"Firewall configuration file not found: {firewall_config_file}")

    except Exception as e:
        logging.error(f"Error analyzing firewall configuration: {e}")
        raise FirewallAnalyzerError(f"Error analyzing firewall configuration: {e}")

    return findings


def analyze_system_configuration(config_file, benchmark_file, schema_file=None):
    """
    Analyzes a system configuration file against a security hardening benchmark.

    Args:
        config_file (str): Path to the system configuration file.
        benchmark_file (str): Path to the YAML/JSON benchmark file.
        schema_file (str, optional): Path to the JSON schema file (for validation). Defaults to None.

    Returns:
        list: A list of findings (dict) indicating deviations from the benchmark.
    """
    findings = []

    try:
        # Load benchmark file (YAML or JSON)
        with open(benchmark_file, 'r') as f:
            if benchmark_file.endswith('.yaml') or benchmark_file.endswith('.yml'):
                benchmark_data = yaml.safe_load(f)
            elif benchmark_file.endswith('.json'):
                benchmark_data = json.load(f)
            else:
                raise ValueError("Benchmark file must be YAML or JSON format.")

        # Validate benchmark data if schema is provided
        if schema_file:
            if not validate_json_schema(benchmark_data, schema_file):
                raise FirewallAnalyzerError("Benchmark file validation failed against the schema.")

        # Load configuration file (treat as plain text for now, enhance with specific parsers as needed)
        with open(config_file, 'r') as f:
            config_content = f.read()

        # Iterate through benchmark rules and check against configuration
        for rule in benchmark_data.get('rules', []):
            description = rule.get('description', 'No Description')
            check = rule.get('check')
            severity = rule.get('severity', 'Info')
            recommendation = rule.get('recommendation', 'No Recommendation')

            if check:
                # Perform the check (basic string search for now, enhance with regex/parsing)
                if isinstance(check, str):
                    if re.search(check, config_content, re.MULTILINE):
                        logging.debug(f"Check '{check}' passed for rule: {description}")
                    else:
                        findings.append({"description": description, "severity": severity, "recommendation": recommendation, "check_failed": check})
                        logging.warning(f"Check '{check}' failed for rule: {description}")
                elif isinstance(check, dict): #Example: more complex check
                    # Example: check if file exists
                    file_exists = check.get("file_exists")
                    if file_exists:
                        if os.path.exists(file_exists):
                            logging.debug(f"File '{file_exists}' exists for rule: {description}")
                        else:
                            findings.append({"description": description, "severity": severity, "recommendation": recommendation, "check_failed": f"File not found: {file_exists}"})
                            logging.warning(f"File '{file_exists}' not found for rule: {description}")

                else:
                    logging.warning(f"Unsupported check type: {type(check)} for rule: {description}")

    except FileNotFoundError as e:
        logging.error(f"File not found: {e.filename}")
        raise FirewallAnalyzerError(f"File not found: {e.filename}")
    except yaml.YAMLError as e:
        logging.error(f"YAML parsing error: {e}")
        raise FirewallAnalyzerError(f"YAML parsing error: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing error: {e}")
        raise FirewallAnalyzerError(f"JSON parsing error: {e}")
    except ValueError as e:
        logging.error(e)
        raise FirewallAnalyzerError(e)

    except Exception as e:
        logging.error(f"Error analyzing system configuration: {e}")
        raise FirewallAnalyzerError(f"Error analyzing system configuration: {e}")

    return findings


def generate_report(findings, output_file):
    """
    Generates a report from the findings and saves it to a file.

    Args:
        findings (list): A list of findings (dict).
        output_file (str): Path to the output report file.
    """
    try:
        with open(output_file, 'w') as f:
            if not findings:
                f.write("No issues found.\n")
                return

            for finding in findings:
                f.write(f"Description: {finding.get('description', finding.get('rule', 'No Description'))}\n")
                f.write(f"Severity: {finding.get('severity', 'Info')}\n")
                f.write(f"Recommendation: {finding.get('recommendation', 'No Recommendation')}\n")
                if "check_failed" in finding:
                    f.write(f"Check Failed: {finding['check_failed']}\n")
                f.write("-" * 20 + "\n")

        logging.info(f"Report saved to: {output_file}")

    except Exception as e:
        logging.error(f"Error generating report: {e}")
        print(f"Error generating report: {e}") #Fallback print in case logging fails




def main():
    """
    Main function to parse arguments, analyze, and generate a report.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        if args.mode == 'firewall':
            logging.info("Starting firewall analysis...")
            findings = analyze_firewall_rules(args.firewall_config)
            generate_report(findings, args.output)
            logging.info("Firewall analysis completed.")
        elif args.mode == 'benchmark':
            logging.info("Starting benchmark analysis...")
            findings = analyze_system_configuration(args.config_file, args.benchmark_file, args.schema)
            generate_report(findings, args.output)
            logging.info("Benchmark analysis completed.")
        else:
            parser.print_help()
            sys.exit(1)

    except FirewallAnalyzerError as e:
        logging.error(e)
        print(f"Error: {e}") #Fallback print in case logging fails
        sys.exit(1)

    except Exception as e:
        logging.exception("An unexpected error occurred:")
        print(f"An unexpected error occurred: {e}") #Fallback print in case logging fails
        sys.exit(1)


if __name__ == "__main__":
    # Example usage:
    # To analyze a firewall configuration:
    # python main.py firewall firewall_config.txt --output firewall_report.txt

    # To analyze a system configuration against a benchmark:
    # python main.py benchmark system_config.txt benchmark.yaml --schema benchmark_schema.json --output benchmark_report.txt
    main()