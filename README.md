# secwrap

Watch what a process does, and decide what it's allowed to do.

secwrap runs a command (or a whole shell) under eBPF and covers three kinds of access by the process and its children.
For each one, you can **log** it, **ask** before allowing it, or **deny** it:

| Access | Flag | What it covers | `log` | `ask` | `deny` |
| --- | --- | --- | --- | --- | --- |
| Network | `--net` | TCP connections, UDP sends (DNS, QUIC) | records every connection | asks for each new IP:port | blocks all network access |
| Files | `--filesystem` | Every file opened | records every open | asks for each write or sensitive read | blocks writes and sensitive reads |
| Execution | `--exec` | Every program started | records every program | asks for each new program | only the launched command may run |

![requests waiting for an answer](.github/assets/requests.png)

## Install

```sh
go install github.com/noboruma/secwrap/cmd/secwrap@latest
```

or download a binary from the [releases](https://github.com/noboruma/secwrap/releases/latest):

```sh
curl -fsSL -o secwrap "https://github.com/noboruma/secwrap/releases/latest/download/secwrap-linux-amd64"
chmod +x secwrap
```

Requires root, Linux 5.10+ (amd64) and the BPF LSM enabled (`bpf` in `/sys/kernel/security/lsm`, the default on Debian 13).

## Usage

Set a mode for each kind of access with `--net`, `--filesystem` and `--exec`: `log`, `ask`, `deny` or `off`.

```sh
sudo secwrap monitor --net --filesystem -- ./mybinary            # observe: log network and file access
sudo secwrap monitor --net deny -- curl https://example.com      # block all network access
sudo secwrap monitor --exec deny -- ./mybinary                   # block starting any other program
sudo secwrap monitor --net ask --filesystem log -- ./install.sh  # ask about network access, log file access
sudo secwrap shell                                               # an interactive shell where you approve each access
```

When you use `ask`, the process waits until you answer:

```
[ask] Allow curl (pid 4242) tcp connect to 93.184.215.14:443? [y/N]
[ask] Allow python3 (pid 4242) to WRITE /home/me/project/out.txt? [y/N/f]
[ask] Allow sh (pid 4242) to EXEC /usr/bin/curl? [y/N/f]
```

If you deny an access, or don't answer, the call fails with `EPERM`. Press `f` to allow everything under that folder.
You can also allow folders up front with `--allow`, for example `--allow rw:./build` or `--allow x:/usr/bin`.

You can also answer from the web page at `http://127.0.0.1:9000`, or from another terminal with `sudo secwrap session`.

## Other options

- `-o report.json` writes a JSON report of every endpoint and path the process accessed.
- `--log FILE` writes a live event log (JSON lines if the file name ends in `.jsonl`).
- `secwrap attach PID` monitors processes that are already running.
- `--sbom DIR` generates a CycloneDX SBOM for every binary the process runs.

Run `secwrap --help` to see all options.

## How it works

The rules are enforced in the kernel by eBPF programs (cgroup socket hooks and LSM hooks), so io_uring, static
binaries and raw syscalls are covered too. In `ask` mode, seccomp pauses the call until you answer. The eBPF code is in
[`internal/monitor/netmon.bpf.c`](internal/monitor/netmon.bpf.c).
