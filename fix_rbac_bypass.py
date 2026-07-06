#!/usr/bin/env python3

"""
Script to fix Kubernetes RBAC bypass vulnerabilities.
Checks for and removes ClusterRoleBindings that grant high-privilege roles
(such as cluster-admin) to unauthenticated users (system:anonymous, system:unauthenticated).
Also verifies that the API server has RBAC authorization mode enabled.
"""

import os
import sys
from kubernetes import client, config

def main():
    # Load Kubernetes config (assumes in-cluster or ~/.kube/config)
    try:
        config.load_incluster_config()
    except config.ConfigException:
        try:
            config.load_kube_config()
        except config.ConfigException as e:
            print(f"Error loading Kubernetes config: {e}")
            sys.exit(1)

    rbac_api = client.RbacAuthorizationV1Api()
    core_api = client.CoreV1Api()

    # 1. Check API server authorization mode (optional, best-effort)
    # This could be read from a ConfigMap or Pod spec; here we just warn.
    try:
        # Attempt to read API server Pod's command args (if accessible)
        api_server_pod = core_api.read_namespaced_pod(
            name="kube-apiserver",
            namespace="kube-system"
        )
        args = api_server_pod.spec.containers[0].command or []
        if "--authorization-mode=RBAC" not in args and "--authorization-mode=Node,RBAC" not in args:
            print("WARNING: API server does not appear to have RBAC authorization mode enabled.")
            print("Consider adding '--authorization-mode=Node,RBAC' to the kube-apiserver arguments.")
    except Exception:
        # Cannot access API server pod; skip check
        pass

    # 2. Remove dangerous ClusterRoleBindings
    dangerous_subjects = ["system:anonymous", "system:unauthenticated"]
    high_privilege_roles = ["cluster-admin", "system:master", "admin"]

    cluster_role_bindings = rbac_api.list_cluster_role_binding().items
    for crb in cluster_role_bindings:
        for subject in crb.subjects or []:
            if subject.kind == "User" and subject.name in dangerous_subjects:
                # Check what role is being bound
                role_ref_name = crb.role_ref.name
                if role_ref_name in high_privilege_roles:
                    print(f"Removing dangerous ClusterRoleBinding: {crb.metadata.name} (role: {role_ref_name})")
                    try:
                        rbac_api.delete_cluster_role_binding(crb.metadata.name)
                        print(f"  -> Deleted {crb.metadata.name}")
                    except Exception as e:
                        print(f"  -> Failed to delete {crb.metadata.name}: {e}")
                else:
                    print(f"WARNING: ClusterRoleBinding {crb.metadata.name} binds {subject.name} to role {role_ref_name} (not automatically removed)")
                break  # only one subject needs to match

    # 3. Optionally, disable anonymous auth by setting a flag via a ConfigMap?
    # This is more involved; recommend manual check
    print("\nFix completed. For additional security, ensure '--anonymous-auth=false' is set on the API server.")

if __name__ == "__main__":
    main()
