# `secwrap`

Watch what a process does, and decide what it's allowed to do.

`secwrap` runs a command (or a whole shell) under eBPF and covers three kinds of access by the process and its children.
For each one, you can **log** it, **ask** before allowing it, or **deny** it:

| Access | Flag | What it covers | `log` | `ask` | `deny` |
| --- | --- | --- | --- | --- | --- |
| Network | `--net` | TCP connections, UDP sends (DNS, QUIC) | records every connection | asks for each new IP:port | blocks all network access |
| Files | `--filesystem` | Every file opened | records every open | asks for each write or sensitive read | blocks writes and sensitive reads |
| Execution | `--exec` | Every program started | records every program | asks for each new program | only the launched command may run |

![requests waiting for an answer](.github/assets/requests.png)

## Why

Most of the damage a dependency or a script does happens in the open: it connects somewhere, reads a secret, or
runs another program. `secwrap` puts those three moments under your control for any command — a one-line
`npm install`, a `curl | sh`, a build step, or an AI coding agent running shell commands on your machine — without
changing the command or trusting it.

- **Vet an install script** before it touches your keys: `secwrap monitor --net ask --filesystem ask -- ./install.sh`
- **Keep a coding agent on a leash**: approve every connection, write and exec it attempts.
- **Record what a build really does**, then turn it into a JSON report or a CycloneDX SBOM for an audit.

## Install

```sh
go install github.com/noboruma/secwrap/cmd/secwrap@latest
```

or download a static binary from the [releases](https://github.com/noboruma/secwrap/releases/latest), built for
`amd64`, `386`, `arm64`, `arm`, `mips`, `mipsle`, `mips64`, `mips64le`, `riscv64`, `ppc64le`, `s390x` and `loong64`:

```sh
arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/i.86/386/;s/armv.*/arm/;s/loongarch64/loong64/')
case $arch in mips*) [ "$(printf '\1\0' | od -An -tu2 | tr -d ' ')" = 1 ] && arch=${arch}le ;; esac
curl -fsSL -o secwrap "https://github.com/noboruma/secwrap/releases/latest/download/secwrap-linux-$arch"
chmod +x secwrap
```

`uname -m` doesn't say whether a mips CPU is little-endian, so the second line checks that.

`make dist` builds them all into `dist/`.

### Running as root

`secwrap` needs root to load its eBPF programs. Run it as yourself: it asks `sudo` for your password once and
re-runs itself as root. Who holds root after that:

- **`secwrap` keeps root for the whole session.** It doesn't drop root after loading: the eBPF programs stop when it
  exits, and it uses root to clean up at the end.
- **The command drops root before it starts.** It runs as you, with your groups and your environment. In `ask` mode,
  a small `secwrap` helper first installs the seccomp filter as root, then drops to you and starts the command.
- **The command can still get root the normal way.** `secwrap` doesn't set `NO_NEW_PRIVS`, so `sudo` and other
  setuid programs work, and their children stay watched in every mode: the kernel hooks follow the process tree,
  not the user. The one exception: if `secwrap` was given only `CAP_BPF` and `CAP_PERFMON` instead of root, `ask`
  mode has to set `NO_NEW_PRIVS` to install its filter, and `sudo` then can't raise privileges.

Started as root, `sudo secwrap …` included, `secwrap` takes it that you want the command to run as root.

| How `secwrap` is started | Who the command runs as |
| --- | --- |
| As you | You |
| As root (`sudo secwrap`, a root login, a container entrypoint) | Root |
| Either way, with `--user NAME` | `NAME` |

### Requirements

`secwrap cap` checks this kernel, without root, and says what is available and what is missing:

```
$ secwrap cap
Linux 5.15.0 (armv7l)
  network     log deny      (ask needs cgroup v2 and Linux 5.19+ to freeze the command)
  filesystem  unavailable   (armv7l kernels can't run BPF LSM programs)
  exec        unavailable   (armv7l kernels can't run BPF LSM programs)
  sbom        unavailable   (armv7l kernels can't run BPF LSM programs)
```

Every session runs the same check at startup and refuses what the kernel can't do, saying why.

- Linux 5.10+ with BTF (`/sys/kernel/btf/vmlinux`), on any architecture listed above.
- **Root access through `sudo`** (or running as root). `secwrap` asks for your password once, at startup. It then
  keeps root until the session ends. The command you monitor runs as you (see [Running as root](#running-as-root)).
- `ask` (and so `secwrap shell`): Linux 5.19+ with cgroup v2, to freeze the command while a question is up. Older
  kernels can only log and deny.
- The **BPF LSM**, for file and exec monitoring. Check that `bpf` is listed in `/sys/kernel/security/lsm` (it is by
  default on Debian 13). Otherwise add it to the kernel command line, e.g. `lsm=...,bpf`.
- BPF LSM programs also need a 64-bit kernel whose BPF JIT has trampolines: x86_64, arm64, riscv64, s390x,
  loongarch64 or ppc64. **32-bit x86, arm and mips kernels (and mips64) can only monitor the network.**

| Architecture | `--net` | `--filesystem`, `--exec`, `--sbom` |
| --- | --- | --- |
| amd64, arm64, riscv64, s390x, loong64, ppc64le | Yes | Yes, with the BPF LSM |
| 386, arm, mips, mipsle, mips64, mips64le | Yes | No |

A 32-bit `secwrap` can run on a 64-bit kernel (e.g. `arm` on an arm64 kernel). What it can do depends on the kernel.

Without the BPF LSM, or on a kernel that can't run it:

| Feature | Without the BPF LSM |
| --- | --- |
| `--net` (log, ask, deny) | Works: it uses cgroup and kprobe hooks, not the LSM |
| `--filesystem` | Refused at startup, with the reason |
| `--exec` | Refused at startup, with the reason |
| `--sbom` | Refused at startup, with the reason |
| `secwrap shell` | Watches the network only, and says why (`--filesystem` is only its default) |
| Binaries and SBOMs on the web page | Not collected; the page lists no binaries |

## Usage

Set a mode for each kind of access: `log`, `ask`, `deny` or `off`. A flag given without a mode logs.

| Flag | `log` | `ask` | `deny` |
| --- | --- | --- | --- |
| `--net` | `--net log` | `--net ask` | `--net deny` |
| `--filesystem` | `--filesystem log` | `--filesystem ask` | `--filesystem deny` |
| `--exec` | `--exec log` | `--exec ask` | `--exec deny` |

`--ask` or `--deny` sets the mode of every flag given without one: `--net --filesystem --ask` asks about both.

```sh
# Network
secwrap monitor --net log -- ./mybinary                     # log every connection
secwrap monitor --net ask -- ./install.sh                   # ask before each new connection
secwrap monitor --net deny -- curl https://example.com      # block all network access

# Files
secwrap monitor --filesystem log -- ./mybinary              # log every file opened
secwrap monitor --filesystem ask -- ./install.sh            # ask before each write or sensitive read
secwrap monitor --filesystem deny -- ./mybinary             # block writes and sensitive reads

# Execution
secwrap monitor --exec log -- ./mybinary                    # log every program started
secwrap monitor --exec ask -- ./install.sh                  # ask before each new program
secwrap monitor --exec deny -- ./mybinary                   # block starting any other program

# Combined
secwrap monitor --net ask --filesystem log -- ./install.sh  # ask about the network, log files
secwrap shell                                               # an interactive shell that asks about network and files
```

#### Which file reads are asked about

Files work differently from the network and programs. Any program reads hundreds of files just to start (libraries,
locale data, configuration), so asking about or blocking every read would bury you in questions and break most
programs. Instead, `ask` and `deny` cover:

- **every write** (including creating or truncating a file), except in `/proc`, `/sys` and `/dev`;
- **reads of sensitive paths only**, where secrets usually live:
  - your home directory (SSH keys, tokens, browser profiles, `.env` files…)
  - `/root`
  - `/etc/shadow` and `/etc/gshadow`
  - `/etc/sudoers` and `/etc/sudoers.d/`
  - `/etc/ssh/`

Other reads are never asked about or blocked. With `log`, every open is still recorded, reads included.

Add your own sensitive files or folders with `--sensitive` (repeatable). It only changes which **reads** are asked
about or blocked: writes are covered everywhere already, sensitive or not. The list holds 16 paths in total, the
defaults included, so you can add up to 9. A folder covers everything inside it:

```sh
secwrap monitor --filesystem ask --sensitive /srv/secrets --sensitive /opt/app/config.yml -- ./install.sh
```

### Answering

When you use `ask`, the process waits until you answer:

```
[ask] Allow curl (pid 4242) tcp connect to 93.184.215.14:443? [y/N]
[ask] Allow python3 (pid 4242) to WRITE /home/me/project/out.txt? [y/N/f]
[ask] Allow sh (pid 4242) to EXEC /usr/bin/curl? [y/N/f]
```

If you deny an access, or don't answer, the call fails with `EPERM`. Press `f` to allow everything under that folder.
You can also allow folders up front with `--allow`, for example `--allow rw:./build` or `--allow x:/usr/bin`.

Every question can be answered in three places at once; the first answer wins:

| Where | | Turn off with |
| --- | --- | --- |
| Inline | In the terminal running the command, as shown above. The command and its children are frozen while the question is on screen, so their output doesn't get in the way. | `--no-inline` |
| Web page | `http://127.0.0.1:9000` by default; `--web-addr ADDR` changes the address. | `--no-web` |
| `secwrap session` | In another terminal: `secwrap session attach`, or the terminal UI. | Always on |

Without a terminal, inline questions step aside and wait for the web page or `secwrap session`.

## As a login shell

`secwrap` can replace a user's default shell through `chsh`, so everything they do (console, SSH, `su -`) is monitored
from the first process. A login shell gets no flags and `secwrap` needs root, so use a wrapper that runs a root-owned
script through sudo:

`/usr/local/bin/secwrap-login`:

```sh
#!/bin/sh
[ $# -eq 0 ] && set -- -l
exec sudo -n /usr/local/sbin/secwrap-session "$@"
```

`/usr/local/sbin/secwrap-session`, owned by root:

```sh
#!/bin/sh
exec /usr/local/bin/secwrap shell --user "$SUDO_USER" --net --filesystem --exec -- /bin/bash "$@"
```

```sh
echo '%monitored ALL=(root) NOPASSWD: /usr/local/sbin/secwrap-session' | sudo tee /etc/sudoers.d/secwrap
echo /usr/local/bin/secwrap-login | sudo tee -a /etc/shells
sudo usermod -aG monitored alice && sudo chsh -s /usr/local/bin/secwrap-login alice
```

> [!WARNING]
> Never allow `secwrap` itself in sudoers: `sudo secwrap shell` gives a root shell. Allow only the script, which
> fixes every flag and runs the shell as the user (`--user "$SUDO_USER"`).

## Attaching to running processes

`secwrap attach PID` (or `--name NAME`) watches a process that is already running and all its descendants: the ones
already running when you attach and the ones started later. Only what they do from the moment of attaching is seen.
"Descendants" follows the process tree as it is when you attach: a daemon that detached earlier (forked twice, so it now
belongs to init) is no longer a child, so attach to it by its own PID. The session ends when every watched process has
exited, or on Ctrl-C.

`log` and `deny` work on an attached process directly, through the kernel hooks. For `deny`, each process is moved into
a `secwrap-deny-<pid>` cgroup created under the cgroup it was already in, so its container or systemd unit limits keep
applying, and it is moved back when `secwrap` stops. Where no child cgroup can be created there, the `deny` cgroup is
made at the root instead. If `secwrap` is killed outright (`kill -9`, a crash), the kernel drops the blocking with it
and the processes get their network back, but they stay in that `secwrap-deny-<pid>` cgroup, which is left behind.
Stopping the unit removes the leftover cgroup with it. To move the processes back by hand, write their PIDs to the
parent cgroup's `cgroup.procs`.

`ask` is different. To pause a syscall until you answer, `secwrap` installs a seccomp filter, and the filter can only
be installed from inside the process itself. For a command `secwrap` launches it does this before the command starts.
For a process that is already running, `secwrap` would have to install the filter into it after the fact, which the
kernel only allows once the process has `NO_NEW_PRIVS` set. So ask-on-attach carries a cost the launch case doesn't:

> **The attached process can no longer gain privileges.** `NO_NEW_PRIVS` is permanent and inherited, so for the rest
> of the life of that process and its children, `sudo` and setuid programs can't raise privileges. This is the one
> place `secwrap` changes how the watched process behaves, so it is opt-in: pass `--allow-ask`.

In practice this is rarely a problem — a process you attach to in order to watch it usually isn't about to run `sudo`
— and for many it is a feature. It is still a real change, so `secwrap` never does it without `--allow-ask`.

> [!NOTE]
> Pausing a running process's syscalls is not wired up in this build: `--allow-ask` is accepted and validated, but
> `secwrap attach --filesystem ask --allow-ask` reports that ask-on-attach is unavailable rather than silently
> falling back to `deny`.

## Containers

`secwrap` loads eBPF into the host kernel, so it can't run in an ordinary container. There are two ways to use it
with one:

- **Inside a privileged container.** Run it with `--privileged` and `/sys/kernel/security` mounted, and add
  `--cgroupns=host` if `secwrap` can't create its cgroup. Root in a privileged container is root on the host.
- **From the host.** Run `secwrap attach` on the host, with the PID of a process in the container, and the container
  stays unprivileged. It follows that process and its children. Processes started later with `docker exec` aren't
  among those children, so they aren't watched.

## Other options

- `-o report.json` writes a JSON report of every endpoint and path the process accessed.
- `--log FILE` writes a live event log (JSON lines if the file name ends in `.jsonl`).
- `secwrap attach PID` monitors processes that are already running.
- `--sbom DIR` generates a CycloneDX SBOM for every binary the process runs.

Run `secwrap --help` to see all options.

## SBOM

`secwrap sbom BINARY` writes a CycloneDX 1.6 SBOM for one binary, **without root**: Go and Rust build info, the ELF
shared libraries it links, and the Debian packages that own them, each with SHA-256/SHA-1 hashes and a PURL.
`--sbom DIR` does the same for every binary a monitored process runs. Verified on Debian 13 (kernel 6.12, x86_64):

```sh
$ secwrap sbom /usr/bin/curl | jq '.components | length'
28        # libcurl4t64, libssl3t64, libnghttp2-14, zlib1g, … resolved back to dpkg

$ secwrap sbom ./secwrap | jq -r '.components[].purl'
pkg:golang/stdlib@v1.27.3
pkg:golang/github.com/cilium/ebpf@v0.22.0
pkg:golang/golang.org/x/sys@v0.43.0
pkg:deb/debian/libc6@2.41-12+deb13u4?arch=amd64&distro=debian-13
```

`secwrap cap` reports what the running kernel supports; on the same box it prints `log ask deny` for all three of
network, filesystem and exec, plus `sbom yes` and `pause yes`.

## Compared to other tools

`secwrap` wraps one command, on a workstation or in CI, and lets it run, as root if it needs to, while it logs,
asks about or blocks each connection, file write and exec. Every decision and every log line names the real path.
Static sandboxes (Firejail, bubblewrap, Landlock wrappers) decide everything up front. eBPF monitors (Tetragon,
Falco) watch whole hosts and clusters, not a single command.

| Tool | Mechanism | Net | Files | Exec | Ask, live | Needs root | Attach / login shell |
| --- | --- | :-: | :-: | :-: | --- | --- | --- |
| **secwrap** | eBPF (kprobe, cgroup, BPF LSM) + seccomp | ✓ | ✓ | ✓ | terminal, web, 2nd terminal | yes (sudo) | both |
| [OpenSnitch](https://github.com/evilsocket/opensnitch) | eBPF / NFQUEUE | ✓ | — | — | system-wide popups | daemon | system-wide |
| [mori](https://github.com/gmh5225/mori) | eBPF | ✓ | ✓ | — | — (static rules) | yes | launch only |
| [sandlock](https://github.com/multikernel/sandlock) | Landlock + seccomp-notify | ✓ | ✓ | ✓ | callback, no file paths | **no** | launch only |
| Firejail / bubblewrap | namespaces + seccomp | ~ | ✓ | ~ | — | setuid / userns | launch only |
| Tetragon / Falco | eBPF | ✓ | ✓ | ✓ | — (policy, alerts) | yes | system-wide |

### secwrap and sandlock

[sandlock](https://github.com/multikernel/sandlock) is the closest tool: log/ask/deny over network, files and exec
for one command. It needs no root, because it uses Landlock and seccomp user notification. `secwrap` needs root to
load its eBPF programs. Most of the differences follow from that.

**Where `secwrap` is stronger**

- **Commands that really need root.** Installers like `./install.sh` often have to write to `/usr` or `/etc`.
  `sudo secwrap monitor --filesystem ask -- ./install.sh` runs the script as root and still stops at each write:
  *allow WRITE /etc/systemd/system/foo.service?* Run as yourself, a script that calls `sudo` partway through gets
  root too and stays watched, in every mode: the kernel hooks follow the process tree, not the user. sandlock always
  sets `NO_NEW_PRIVS`, so nothing inside it can gain root. When it is started as root it doesn't drop capabilities,
  and its file grants are fixed before the command starts.
- **Real paths, for auditing and live decisions.** Each event records the path, process, PID and UID.
  `-o report.json` summarises what was accessed, `--log events.jsonl` streams events live, and `--sbom DIR`
  inventories every binary that ran. sandlock deliberately keeps path strings out of its callbacks, to stay safe from
  TOCTOU races, so its file prompts and policy events can't say which file is being opened.
- **io_uring.** `secwrap`'s hooks run on the kernel operation (`lsm/file_open`, `cgroup/connect4`), so opens and
  connects issued through io_uring are still enforced, though they don't trigger a prompt. sandlock blocks io_uring
  completely.
- **Attach and login shell.** `secwrap` can attach to running processes or act as a login shell. sandlock only
  launches new sandboxes.

**Where sandlock is stronger**

- **No root, no password, no eBPF.** It runs in locked-down CI and rootless containers.
- **Deny by default.** Files and network are blocked unless granted. `secwrap` asks about writes and sensitive reads
  but lets other reads through.
- **Undo.** With a copy-on-write work directory and `--dry-run`, an installer's writes can be reviewed, then kept
  or thrown away. In `secwrap`, a write you allow happens straight away.
- **Extras:** resource limits, HTTP method and path rules, credential injection.

Kernel floors: `secwrap` needs Linux 5.10+ with BTF, plus the BPF LSM for files and exec, and 5.19+ with cgroup v2
for `ask`. sandlock targets Linux 6.12 (Landlock ABI v6) and can run with fewer protections on older kernels.

## How it works

The rules are enforced in the kernel by eBPF programs, so io_uring, static binaries and raw syscalls are covered too.
In `ask` mode, seccomp pauses the call until you answer, and your answer is stored in a map the eBPF programs check.

The eBPF code is built once per byte order (`bpfel`, `bpfeb`), not per CPU. Kernel structures are relocated at load
time (CO-RE), and at startup `secwrap` reads where the kprobe arguments sit in `struct pt_regs` from the kernel's BTF.

| File | Watches | Hooks |
| --- | --- | --- |
| [`netmon.bpf.c`](internal/monitor/netmon.bpf.c) | Network | `kprobe/tcp_connect`, `kretprobe/inet_csk_accept`, `kprobe/udp_sendmsg`, `kprobe/udpv6_sendmsg`; blocking with `cgroup/connect4/6`, `cgroup/sendmsg4/6`, `cgroup_skb/egress/ingress` |
| [`filemon.bpf.c`](internal/monitor/filemon.bpf.c) | Files | `lsm/file_open` |
| [`execmon.bpf.c`](internal/monitor/execmon.bpf.c) | Execution | `lsm/bprm_creds_for_exec` |

## Development

```sh
make build      # eBPF objects + binary (needs clang and libbpf-dev)
go test ./...   # unit tests, no root needed
make vmtest     # end-to-end tests as root in a throwaway VM, no root needed
```

`make vmtest` runs [`test/vm/tests.sh`](test/vm/tests.sh) as root inside QEMU. The tests cover attach (by PID, thread
ID and name, across several cgroups, with the root fallback, and with the unit stopped while attached), deny with real
cgroups and systemd units, launched commands, and each mode cleaning up after itself. The VM boots your own kernel
(`/boot/vmlinuz-$(uname -r)`, or set `KERNEL=`) with systemd, and sees your filesystem read-only under an overlay that
lives in memory, so it can't change anything on the host and reads only what your user can read. It takes about a
minute with KVM. It needs an x86-64 host with `qemu-system-x86_64`, `busybox`, `cpio` and `xz`, and access to
`/dev/kvm` (the `kvm` group), otherwise it falls back to much slower emulation.

## License

`secwrap` is licensed under the [Apache License 2.0](LICENSE).

The eBPF programs in [`internal/monitor`](internal/monitor) (`*.bpf.c`, `*.bpf.h`) are dual-licensed under the
[GPL-2.0](internal/monitor/LICENSE.GPL-2.0) or the [BSD-2-Clause](internal/monitor/LICENSE.BSD-2-Clause) license, at
your option, so the kernel accepts them as GPL-compatible. `vmlinux.h` is generated from kernel BTF.
