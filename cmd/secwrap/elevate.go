package main

// Started as a normal user, secwrap re-runs itself through sudo for the
// commands that need root (loading eBPF, answering questions), then runs the
// monitored command as that user again: only secwrap itself runs as root.
//
// sudo resets the environment, so the user's is handed over in a file only
// they can read: the root side opens it without following symlinks, checks
// it is a plain file owned by the sudo user, reads it and deletes it. It is
// only used for the command, which runs as that user.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/noboruma/secwrap/internal/monitor"
)

// invokerEnvArg is the hidden argv[1] of the re-run: invokerEnvArg FILE CMD ARGS...
const invokerEnvArg = "__secwrap-invoker-env"

// elevated: this secwrap is the re-run through sudo, started by a normal
// user. The command then runs as that user. Started as root (sudo secwrap,
// a root login), it runs as root unless --user says otherwise.
var elevated bool

// envCleanupArg is the hidden argv[1] of the cleaner: envCleanupArg PID FILE.
// It deletes FILE when PID (sudo, which secwrap became) exits, in case the
// root side never got to read it (wrong password, sudo refused).
const envCleanupArg = "__secwrap-env-cleanup"

// needsRoot: the subcommands that load eBPF, answer questions or serve the
// web page (not their -h).
func needsRoot(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args[1:] {
		if a == "--" {
			break
		}
		if a == "-h" || a == "-help" || a == "--help" {
			return false
		}
	}
	switch args[0] {
	case "monitor", "run", "attach", "shell":
		return true
	case "sessions":
		if len(args) == 1 {
			return stdinTTY() // the terminal UI; without a terminal it only lists
		}
		return args[1] == "attach" || args[1] == "delete"
	}
	return false
}

var stdinTTY = func() bool { return isTerminal(os.Stdin) } // tests

// elevate re-runs secwrap through sudo when args need root and we are not.
// It only returns on error, or when nothing needs doing.
func elevate(args []string) error {
	if os.Geteuid() == 0 || !needsRoot(args) {
		return nil
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("%s needs root: run it as root, or install sudo", args[0])
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	envFile, err := saveEnv()
	if err != nil {
		return fmt.Errorf("save the environment for sudo: %w", err)
	}
	startEnvCleaner(self, envFile)
	if args[0] == "sessions" {
		fmt.Fprintln(os.Stderr, "secwrap: needs root to answer questions and serve the web page; asking sudo")
	} else {
		fmt.Fprintln(os.Stderr, "secwrap: needs root to load eBPF; asking sudo (the command still runs as you)")
	}
	argv := append([]string{"sudo", "--", self, invokerEnvArg, envFile}, args...)
	err = syscall.Exec(sudo, argv, os.Environ())
	os.Remove(envFile)
	return fmt.Errorf("run sudo: %w", err)
}

// startEnvCleaner starts the cleaner for envFile, detached (its own session,
// no terminal) so that it neither gets the terminal's signals nor holds it.
func startEnvCleaner(self, envFile string) {
	c := exec.Command(self, envCleanupArg, strconv.Itoa(os.Getpid()), envFile)
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if c.Start() == nil {
		c.Process.Release()
	}
}

// runEnvCleaner waits for pid to exit, then deletes file if still there.
func runEnvCleaner(args []string) {
	if len(args) != 2 {
		os.Exit(2)
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		os.Exit(2)
	}
	if fd, err := unix.PidfdOpen(pid, 0); err == nil {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			if _, err := unix.Poll(fds, -1); err != unix.EINTR {
				break
			}
		}
	}
	os.Remove(args[1])
	os.Exit(0)
}

// saveEnv writes our environment, NUL-separated, to a new file only we can
// read: in XDG_RUNTIME_DIR (a per-user tmpfs) when there is one.
func saveEnv() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if st, err := os.Stat(dir); dir == "" || err != nil || !st.IsDir() {
		dir = ""
	}
	f, err := os.CreateTemp(dir, "secwrap-env-*") // mode 0600
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	for _, kv := range os.Environ() {
		b.WriteString(kv)
		b.WriteByte(0)
	}
	if _, err := f.Write(b.Bytes()); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), f.Close()
}

// takeInvokerEnv handles the re-run's hidden arguments: it loads and
// deletes the saved environment and returns the remaining args.
func takeInvokerEnv(args []string) ([]string, error) {
	if len(args) < 1 {
		return nil, errors.New("missing environment file")
	}
	path, rest := args[0], args[1:]
	env, err := readInvokerEnv(path)
	if err != nil {
		return nil, fmt.Errorf("environment from before sudo: %w", err)
	}
	monitor.SetInvokerEnv(env)
	elevated = true
	return rest, nil
}

func readInvokerEnv(path string) ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("not root")
	}
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil {
		return nil, errors.New("not run through sudo")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	// Only a file of the sudo user's own: never a way to read someone else's.
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != uid || st.Nlink != 1 || st.Mode&0o077 != 0 {
		return nil, fmt.Errorf("%s: not a private file of uid %d", path, uid)
	}
	const maxEnv = 1 << 20
	b, err := io.ReadAll(io.LimitReader(f, maxEnv+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxEnv {
		return nil, errors.New("too large")
	}
	os.Remove(path)
	var env []string
	for _, kv := range bytes.Split(b, []byte{0}) {
		if len(kv) > 0 && bytes.IndexByte(kv, '=') > 0 {
			env = append(env, string(kv))
		}
	}
	return env, nil
}
