import os
import sys
import yaml
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# Load kube configuration (default location ~/.kube/config)
try:
    config.load_kube_config()
except Exception as e:
    print(f"Error loading kubeconfig: {e}")
    sys.exit(1)

apps_v1 = client.AppsV1Api()
rbac_v1 = client.RbacAuthorizationV1Api()
core_v1 = client.CoreV1Api()

# Step 1: Ensure --anonymous-auth=false on kube-apiserver
print("Step 1: Checking kube-apiserver configuration...")
try:
    deployments = apps_v1.list_namespaced_deployment(namespace="kube-system", label_selector="component=kube-apiserver")
    if not deployments.items:
        # Try deployment name directly
        deployment = apps_v1.read_namespaced_deployment("kube-apiserver", "kube-system")
        items = [deployment]
    else:
        items = deployments.items
    for dep in items:
        container = dep.spec.template.spec.containers[0]
        command = container.command if container.command else []
        # Check if anonymous-auth is set
        anonymous_auth_set = any("--anonymous-auth=" in arg for arg in command)
        if not anonymous_auth_set:
            # Add the flag
            command.append("--anonymous-auth=false")
            container.command = command
            apps_v1.patch_namespaced_deployment(dep.metadata.name, "kube-system", dep)
            print(f"  Fixed: Added --anonymous-auth=false to deployment '{dep.metadata.name}'.")
        else:
            # Verify it's set to false
            for arg in command:
                if arg.startswith("--anonymous-auth="):
                    value = arg.split("=")[1]
                    if value.lower() == "true":
                        print(f"  Warning: --anonymous-auth is set to true in deployment '{dep.metadata.name}', changing to false.")
                        # Replace the argument
                        command[command.index(arg)] = "--anonymous-auth=false"
                        container.command = command
                        apps_v1.patch_namespaced_deployment(dep.metadata.name, "kube-system", dep)
                    else:
                        print(f"  OK: --anonymous-auth is already set to {value}.")
                    break
        # Also check if the pod is running and restart it? Not needed, but the deployment update will trigger a rollout.
except ApiException as e:
    print(f"  Error checking kube-apiserver: {e}")

# Step 2: Remove ClusterRoleBindings that grant elevated privileges to system:anonymous or system:unauthenticated
print("\nStep 2: Auditing RBAC bindings for anonymous/unauthenticated subjects...")
protected_cluster_bindings = ["system:basic-user", "system:discovery", "system:public-info-viewer"]
try:
    cluster_role_bindings = rbac_v1.list_cluster_role_binding().items
    for crb in cluster_role_bindings:
        if crb.metadata.name in protected_cluster_bindings:
            continue
        for subject in crb.subjects or []:
            if subject.name in ["system:anonymous", "system:unauthenticated"] and subject.kind == "User":
                print(f"  Found binding '{crb.metadata.name}' with subject {subject.name} (kind={subject.kind}).")
                # Determine if it's a high-risk binding: check if it references cluster-admin or other dangerous roles
                if crb.role_ref.kind == "ClusterRole":
                    if crb.role_ref.name in ["cluster-admin", "admin", "edit"]:
                        print(f"  Deleting dangerous binding '{crb.metadata.name}' (role = {crb.role_ref.name}).")
                        try:
                            rbac_v1.delete_cluster_role_binding(crb.metadata.name)
                            print(f"  Deleted ClusterRoleBinding '{crb.metadata.name}'.")
                        except Exception as e:
                            print(f"  Error deleting: {e}")
                else:
                    print(f"  Warning: RoleBinding '{crb.metadata.name}' with subject {subject.name}, role {crb.role_ref}. Recommend manual review.")
except ApiException as e:
    print(f"  Error listing ClusterRoleBindings: {e}")

# Step 3: Also check RoleBindings in all namespaces (same logic, but only for cluster-scoped? Actually, we want to catch any)
print("\nStep 3: Checking RoleBindings across namespaces...")
try:
    namespaces = core_v1.list_namespace().items
    for ns in namespaces:
        ns_name = ns.metadata.name
        role_bindings = rbac_v1.list_namespaced_role_binding(ns_name).items
        for rb in role_bindings:
            for subject in rb.subjects or []:
                if subject.name in ["system:anonymous", "system:unauthenticated"] and subject.kind == "User":
                    if rb.role_ref.kind == "ClusterRole":
                        if rb.role_ref.name in ["cluster-admin", "admin", "edit"]:
                            print(f"  Found dangerous RoleBinding '{rb.metadata.name}' in namespace '{ns_name}' with subject {subject.name}, role {rb.role_ref.name}. Deleting...")
                            try:
                                rbac_v1.delete_namespaced_role_binding(rb.metadata.name, ns_name)
                                print(f"  Deleted RoleBinding '{rb.metadata.name}' in namespace '{ns_name}'.")
                            except Exception as e:
                                print(f"  Error deleting: {e}")
                    # For Role references, also warn
                    else:
                        print(f"  Warning: RoleBinding '{rb.metadata.name}' in namespace '{ns_name}' with subject {subject.name}, role {rb.role_ref}. Recommend manual review.")
except ApiException as e:
    print(f"  Error listing namespaces/rolebindings: {e}")

print("\nRBAC bypass fix applied. Review summary above.")
