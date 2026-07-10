# Docker Container Escape Fix (#792, $200 Expert)

## Vulnerability
Container runs with `--privileged` or `--cap-add=SYS_ADMIN`, allowing:
- Mounting cgroup filesystem inside container
- Writing to `notify_on_release` to execute commands on host
- Full host kernel access

## Fix 1: Docker Compose Configuration

### Before (vulnerable)
```yaml
services:
  app:
    image: myapp:latest
    privileged: true  # ❌ Full host access
    cap_add:
      - SYS_ADMIN    # ❌ Dangerous capability
```

### After (secure)
```yaml
services:
  app:
    image: myapp:latest
    privileged: false  # ✅ Never use privileged
    cap_drop:
      - ALL           # Drop all capabilities first
    cap_add:
      - NET_BIND_SERVICE  # Only what's needed
    security_opt:
      - seccomp:seccomp-profile.json  # System call filtering
      - apparmor:docker-default       # MAC profile
    read_only: true    # Read-only root filesystem
    tmpfs:
      - /tmp:noexec,nosuid,size=64M  # No exec tmpfs
```

## Fix 2: Seccomp Profile

Create `seccomp-profile.json`:
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["accept", "bind", "connect", "listen", "read", "write", "open", "close", "fstat", "mmap", "munmap", "brk", "exit", "exit_group"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

## Fix 3: Kubernetes Pod Security

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: runtime/default
    apparmor.security.beta.kubernetes.io/pod: runtime/default
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]
      runAsNonRoot: true
      runAsUser: 1000
      seccompProfile:
        type: RuntimeDefault
```

## Testing

```bash
# Test that privileged mode is not used
docker inspect $(docker ps -q) --format '{{.HostConfig.Privileged}}'
# Should output: false

# Test capability restriction
docker run --rm --cap-drop=ALL alpine sh -c "cat /proc/1/environ"
# Should fail: permission denied

# Test seccomp blocking
docker run --rm --security-opt seccomp:seccomp-profile.json alpine sh -c "unshare -r sh"
# Should fail: operation not permitted
```
