# Linux SSH-agent and local IPC supervisor

This package provides static Linux x64 and arm64 executables for a filesystem-isolated
workload. Sources derive from [upstream PR #510](https://github.com/anthropics/sandbox-runtime/pull/510),
commit `dd41a418d1efff88448ff9780d2043425ccb5696`, under Apache-2.0.

An executable wrapper supplies the socket allowlist:

```sh
#!/bin/bash -p
exec /protected/path/x64.bin --allow-local-ipc \
  --allow-unix-connect /absolute/job-directory \
  --allow-unix-connect /absolute/agent.sock -- "$@"
```

Select `arm64.bin` on Linux arm64. Allowlist entries must already exist. An existing
directory permits connections to stream/seqpacket sockets throughout its subtree;
an individual socket permits only that endpoint. Unrelated host sockets remain denied.
The supervisor requires Linux 5.7+, user namespaces, seccomp notifications, and permission
to use `pidfd_getfd` for brokered Unix connections.

`--allow-local-ipc` supports reviewer experiments and local services. Pathname Unix
binds run in the workload so the enclosing read-only mounts enforce their write
boundary. Abstract Unix binds are denied. TCP/IPv6 calls and listen operations
continue in the workload without a broker thread or duplicated socket descriptor.
Unix connections still use the allowlist. Unix datagram sockets remain unsupported.
The caller must provide filesystem isolation, such as bubblewrap with a read-only
root and writable job directories. Protect the binary, wrapper, and SSH-agent relay
from workload writes. Keep operator files and other jobs outside writable mounts.

This mode is an accident boundary: it does not defend against another workload
thread deliberately changing syscall arguments between inspection and execution.
Without `--allow-local-ipc`, the supervisor brokers TCP too and refuses Unix binds
and listens. Brokered calls admit 128 in-flight requests and return `EAGAIN` above
that limit. A kernel that cannot initialize brokering blocks Unix sockets entirely.

## Build and distribute

From the fork repository:

```sh
mise install
mise exec -- bun run --cwd packages/ssh-agent build
mkdir -p .tmp
mise exec -- bun pm pack --cwd packages/ssh-agent --destination ../../.tmp
```

`prepack` rebuilds both architectures with Zig 0.16.0 and static musl linkage.
The Linux boundary check runs as a non-root user with working namespaces:

```sh
python3 packages/ssh-agent/test/unit/localIpc.py
```

After merging changes to `main`, push `ssh-agent-v<package version>` on the merged
commit. The artifact workflow tests, builds and publishes the GitHub Release.
Pin that asset URL in consumers. Published assets are immutable; every update
needs a new package version. Installs require no compiler or lifecycle script.

`unix-block-bpf.h` contains x64/arm64 filters generated with Debian bookworm's
libseccomp 2.5.4. To regenerate them on Linux:

```sh
mkdir -p .tmp
cc packages/ssh-agent/src/seccomp-unix-block.c -lseccomp -o .tmp/seccomp-unix-block
.tmp/seccomp-unix-block .tmp/x64.bpf x86_64
.tmp/seccomp-unix-block .tmp/arm64.bpf aarch64
```

Encode the filters as the header's `__x86_64__` and `__aarch64__` arrays, then rebuild.
