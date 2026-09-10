# Linux SSH-agent supervisor

This package provides static Linux x64 and arm64 executables for sandbox-runtime's
`seccompConfig.applyPath`. The C sources in `packages/ssh-agent/src` come from
[upstream PR #510](https://github.com/anthropics/sandbox-runtime/pull/510), commit
`dd41a418d1efff88448ff9780d2043425ccb5696`, under Apache-2.0.

Invoke the executable with `--allow-unix-connect /absolute/agent.sock --` followed
by the arguments supplied by sandbox-runtime. The caller must protect the socket,
executable, and launcher from sandbox writes. The supervisor requires Linux 5.6+,
user namespaces, seccomp notifications, and permission to use `pidfd_getfd`.
It fails closed when those prerequisites are unavailable. While active, it mediates
TCP as well as Unix `connect`, `bind`, and `listen`, admits 128 in-flight calls,
and returns `EAGAIN` above that limit.

## Build and distribute

From the [fork repository](https://github.com/WillBooster/sandbox-runtime):

```sh
mise install
mise exec -- bun run --cwd packages/ssh-agent build
mkdir -p .tmp
mise exec -- bun pm pack --cwd packages/ssh-agent --destination ../../.tmp
```

`prepack` rebuilds both architectures with Zig 0.16.0 and static musl linkage.
After merging the package changes to `main`, push a tag named
`ssh-agent-v<package version>` on that merged commit. The SSH-agent artifacts
workflow rebuilds and publishes the package to a GitHub Release. Pin that Release
asset URL in consumers. Never replace assets of a published version; change the
package version for every new artifact.

`unix-block-bpf.h` contains x64/arm64 filters generated with Debian bookworm's
libseccomp 2.5.4. To regenerate them on Linux with libseccomp development headers:

```sh
mkdir -p .tmp
cc packages/ssh-agent/src/seccomp-unix-block.c -lseccomp -o .tmp/seccomp-unix-block
.tmp/seccomp-unix-block .tmp/x64.bpf x86_64
.tmp/seccomp-unix-block .tmp/arm64.bpf aarch64
```

Encode the resulting filters as the header's `__x86_64__` and `__aarch64__` arrays,
then rebuild the package. Installs require no compiler or lifecycle script.
