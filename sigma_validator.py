import os
import yaml

class CyberionSigmaValidator:
    """Automated Validation Engine for Cyberion Defense Labs Sigma Rules."""
    def __init__(self):
        self.required_fields = ['title', 'id', 'status', 'description', 'references', 'tags', 'logsource', 'detection', 'falsepositives', 'level']
        self.valid_levels = ['informational', 'low', 'medium', 'high', 'critical']

    def validate_rule_file(self, file_path: str) -> dict:
        results = {"file": os.path.basename(file_path), "valid": True, "errors": []}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
        except Exception as e:
            results["valid"] = False
            results["errors"].append(f"YAML Parsing Failure: {str(e)}")
            return results

        if not rule_data:
            results["valid"] = False
            results["errors"].append("Empty rule file.")
            return results

        for field in self.required_fields:
            if field not in rule_data:
                results["valid"] = False
                results["errors"].append(f"Missing Mandatory PRD Field: '{field}'")

        tags = rule_data.get('tags', [])
        if not isinstance(tags, list) or len(tags) == 0:
            results["valid"] = False
            results["errors"].append("Missing or invalid 'tags' block.")
        else:
            attack_tags = [tag for tag in tags if tag.startswith('attack.t')]
            if not attack_tags:
                results["valid"] = False
                results["errors"].append("Framework Defect: No valid MITRE ATT&CK Technique ID found.")

        level = str(rule_data.get('level', '')).lower()
        if level not in self.valid_levels:
            results["valid"] = False
            results["errors"].append(f"Invalid Severity Level '{level}'.")

        return results

    def execute_library_audit(self, directory_path: str):
        print(f"[*] Commencing Automated Security Audit of Directory: {directory_path}\n" + "="*70)
        passed_count, failed_count = 0, 0
        for root, _, files in os.walk(directory_path):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    audit_res = self.validate_rule_file(os.path.join(root, file))
                    if audit_res["valid"]:
                        print(f"[PASSED] -> {audit_res['file']}")
                        passed_count += 1
                    else:
                        print(f"[FAILED] -> {audit_res['file']}")
                        for error in audit_res["errors"]:
                            print(f"   └── ERROR: {error}")
                        failed_count += 1
        print("="*70 + f"\n[*] Audit Complete. Passed: {passed_count} | Failed: {failed_count}")

if __name__ == "__main__":
    validator = CyberionSigmaValidator()
    validator.execute_library_audit("sigma_library")
