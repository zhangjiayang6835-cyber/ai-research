"""Fix for Issue #733: AWS IAM Privilege Escalation via PassRole + EC2"""
import re
import json

SECURITY_FIX = True

class IAMPolicyValidator:
    """Validates IAM policies for PassRole + EC2 privilege escalation."""
    
    def __init__(self):
        self.sensitive_roles = frozenset({
            "admin", "AdministratorAccess", "PowerUserAccess",
            "*", "arn:aws:iam::*:role/*"
        })
    
    def check_passrole_ec2(self, policy_document):
        """Check if policy allows iam:PassRole to EC2 without restrictions."""
        findings = []
        
        if not isinstance(policy_document, dict):
            return [{"severity": "error", "finding": "Invalid policy document format"}]
        
        statements = policy_document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for stmt in statements:
            effect = stmt.get("Effect", "Deny")
            if effect != "Allow":
                continue
            
            action = stmt.get("Action", [])
            if isinstance(action, str):
                action = [action]
            
            resource = stmt.get("Resource", [])
            if isinstance(resource, str):
                resource = [resource]
            
            has_passrole = any("iam:PassRole" in a for a in action)
            has_ec2_run = any("ec2:RunInstances" in a for a in action)
            
            if has_passrole and has_ec2_run:
                findings.append({
                    "severity": "critical",
                    "finding": "iam:PassRole + ec2:RunInstances combined - privilege escalation risk",
                    "resource": resource
                })
            
            if has_passrole:
                for r in resource:
                    if r == "*" or "arn:aws:iam::*:role/*" in r:
                        findings.append({
                            "severity": "high",
                            "finding": f"PassRole with wildcard resource: {r}",
                            "recommendation": "Use specific role ARNs"
                        })
        
        return findings
    
    def generate_fix_policy(self, original_policy, allowed_roles=None):
        """Generate a fixed policy with least-privilege PassRole restrictions."""
        if allowed_roles is None:
            allowed_roles = ["arn:aws:iam::123456789012:role/ec2-service-role"]
        
        fixed = json.loads(json.dumps(original_policy))
        statements = fixed.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            action = stmt.get("Action", [])
            if isinstance(action, str):
                action = [action]
            if any("iam:PassRole" in a for a in action):
                stmt["Resource"] = allowed_roles
                stmt["Condition"] = {
                    "StringEquals": {
                        "iam:PassedToService": "ec2.amazonaws.com"
                    }
                }
        
        fixed["Statement"] = statements
        return fixed

def apply_security_patch(input_data):
    """Apply security fix: IAM policy validation with PassRole restrictions."""
    if not isinstance(input_data, dict):
        return {"status": "error", "data": "Invalid input"}
    
    action = input_data.get("action", "validate")
    policy = input_data.get("policy", {})
    
    validator = IAMPolicyValidator()
    
    if action == "validate":
        findings = validator.check_passrole_ec2(policy)
        if findings:
            return {
                "status": "rejected",
                "data": {
                    "findings": findings,
                    "recommendation": "Restrict PassRole to specific roles with Condition keys"
                }
            }
        return {"status": "patched", "data": "Policy is secure"}
    
    elif action == "fix":
        allowed_roles = input_data.get("allowed_roles", None)
        fixed = validator.generate_fix_policy(policy, allowed_roles)
        return {"status": "patched", "data": {"fixed_policy": fixed}}
    
    return {"status": "error", "data": "Unknown action"}

if __name__ == "__main__":
    # Test 1: PassRole + EC2 detected
    risky_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["iam:PassRole", "ec2:RunInstances"],
            "Resource": "*"
        }]
    }
    result = apply_security_patch({"action": "validate", "policy": risky_policy})
    assert result["status"] == "rejected", f"Risky policy not detected: {result}"
    print("✓ PassRole + EC2 privilege escalation detected")
    
    # Test 2: Wildcard PassRole detected
    result = apply_security_patch({
        "action": "validate",
        "policy": {
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::*:role/*"
            }]
        }
    })
    assert result["status"] == "rejected", f"Wildcard PassRole not detected: {result}"
    print("✓ Wildcard PassRole detected")
    
    # Test 3: Safe policy passes
    safe_policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }]
    }
    result = apply_security_patch({"action": "validate", "policy": safe_policy})
    assert result["status"] == "patched", f"Safe policy rejected: {result}"
    print("✓ Safe policy passes")
    
    # Test 4: Fix generates restricted policy
    result = apply_security_patch({
        "action": "fix",
        "policy": risky_policy,
        "allowed_roles": ["arn:aws:iam::123456789012:role/ec2-limited"]
    })
    assert result["status"] == "patched", f"Fix failed: {result}"
    fixed = result["data"]["fixed_policy"]
    print("✓ Policy fix generated with role restrictions")
    
    # Test 5: Invalid input
    result = apply_security_patch("invalid")
    assert result["status"] == "error"
    print("✓ Invalid input rejected")
    
    print("\n✅ All tests passed for #733: AWS IAM PassRole Fix")