#!/usr/bin/env python3
"""
Kubernetes RBAC Audit Script
Checks for common misconfigurations that could lead to RBAC bypass.
Specifically, flags ClusterRoleBindings/RoleBindings that grant
cluster-admin or wildcard privileges to unauthenticated users.
"""

import os
from kubernetes import client, config
from kubernetes.client.rest import ApiException

def load_kube_config():
    """Load in-cluster config or default kubeconfig."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

def get_privileged_cluster_roles(v1):
    """Return list of ClusterRole names that are considered privileged."""
    # Common privileged roles: cluster-admin, full-access, etc.
    privileged = ['cluster-admin', 'system:masters']
    try:
        cluster_roles = v1.list_cluster_role()
        for cr in cluster_roles.items:
            # Also flag roles with wildcard rules
            if cr.rules:
                for rule in cr.rules:
                    if '*' in (rule.verbs or []) and '*' in (rule.resources or []):
                        privileged.append(cr.metadata.name)
    except ApiException as e:
        print(f"Error listing ClusterRoles: {e}")
    return list(set(privileged))

def check_bindings(v1, rbac_v1):
    """Check ClusterRoleBindings and RoleBindings for dangerous assignments."""
    findings = []
    privileged_roles = get_privileged_cluster_roles(v1)

    # Check ClusterRoleBindings
    try:
        crbs = rbac_v1.list_cluster_role_binding()
        for crb in crbs.items:
            if crb.role_ref.name in privileged_roles:
                for subject in (crb.subjects or []):
                    if subject.kind == 'User' and subject.name in ['system:anonymous', 'system:unauthenticated']:
                        findings.append(f"WARNING: ClusterRoleBinding '{crb.metadata.name}' grants privileged role '{crb.role_ref.name}' to subject '{subject.name}' (kind: {subject.kind})")
    except ApiException as e:
        print(f"Error listing ClusterRoleBindings: {e}")

    # Check RoleBindings across all namespaces
    try:
        namespaces = v1.list_namespace()
        for ns in namespaces.items:
            try:
                rbs = rbac_v1.list_namespaced_role_binding(ns.metadata.name)
                for rb in rbs.items:
                    # Check if role is privileged (by name) - for RoleBindings, ClusterRole may be used
                    role_name = rb.role_ref.name
                    crb_check = rbac_v1.read_cluster_role(name=role_name)  # may fail if not a ClusterRole
                    if crb_check and role_name in privileged_roles:
                        for subject in (rb.subjects or []):
                            if subject.kind == 'User' and subject.name in ['system:anonymous', 'system:unauthenticated']:
                                findings.append(f"WARNING: RoleBinding '{rb.metadata.name}' in namespace '{ns.metadata.name}' grants privileged ClusterRole '{role_name}' to subject '{subject.name}'")
            except ApiException:
                # RoleBinding references a Role, not ClusterRole, so ignore
                pass
    except ApiException as e:
        print(f"Error listing namespaces: {e}")

    return findings

def main():
    load_kube_config()
    v1 = client.CoreV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()

    print("Running RBAC audit for potential bypass misconfigurations...")
    issues = check_bindings(v1, rbac_v1)
    if issues:
        print("Issues found:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("No obvious RBAC bypass misconfigurations detected.")

if __name__ == "__main__":
    main()
