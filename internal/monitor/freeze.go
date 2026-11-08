package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Freezing the launched command's tree while a question is asked on the
// terminal (Options.FreezeOnAsk): nothing in it can read the keyboard, or
// react to secwrap taking the terminal, until the answer. The cgroup v2
// freezer is invisible to the processes and their parents: no SIGSTOP, no
// "Stopped" job in the shell; a blocked read is restarted on thaw. The
// paused task stays paused: its filter waits killably (see
// seccompWaitKillableRecv), so being frozen doesn't withdraw the question.

// plainCgroup is a cgroup v2 for the launched command when there is no
// deny cgroup to freeze. Like the deny cgroups it is a child of secwrap's
// own cgroup, so the limits secwrap runs under keep applying, with one at
// the root as the fallback.
type plainCgroup struct {
	path string
	dir  *os.File
}

func newPlainCgroup() (*plainCgroup, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("freezing on inline questions needs cgroup v2 mounted at %s", cgroupRoot)
	}
	name := fmt.Sprintf("secwrap-ask-%d", os.Getpid())
	parents := []string{cgroupRoot}
	if own, err := cgroupOf(os.Getpid()); err == nil && own != cgroupRoot {
		parents = []string{own, cgroupRoot}
	}
	var err error
	for _, parent := range parents {
		c := &plainCgroup{path: filepath.Join(parent, name)}
		if err = os.Mkdir(c.path, 0o755); err != nil {
			err = fmt.Errorf("create cgroup: %w", err)
			continue
		}
		if c.dir, err = os.Open(c.path); err != nil {
			os.Remove(c.path)
			continue
		}
		return c, nil
	}
	return nil, err
}

func (c *plainCgroup) FD() int { return int(c.dir.Fd()) }

// Close thaws the cgroup, moves what is left in it to secwrap's own cgroup
// and removes it.
func (c *plainCgroup) Close() {
	setFrozen(c.path, false)
	if home, err := cgroupOf(os.Getpid()); err == nil {
		for _, pid := range readProcs(c.path) {
			_ = writeProcs(home, pid)
		}
	}
	c.dir.Close()
	for i := 0; i < 20; i++ { // EBUSY while exiting tasks are still accounted
		if err := os.Remove(c.path); err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func setFrozen(path string, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return os.WriteFile(filepath.Join(path, "cgroup.freeze"), []byte(v), 0)
}

// freezer returns the Freeze function of AskRequest for the cgroup at path.
func freezer(path string) func() (thaw func()) {
	return func() func() {
		if setFrozen(path, true) != nil {
			return func() {}
		}
		// Wait (briefly) for the tasks to stop. The paused task never
		// counts as frozen (it waits killably), so "frozen 1" may not come.
		for deadline := time.Now().Add(100 * time.Millisecond); time.Now().Before(deadline); {
			if ev, err := os.ReadFile(filepath.Join(path, "cgroup.events")); err == nil &&
				strings.Contains(string(ev), "frozen 1") {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		return func() { setFrozen(path, false) }
	}
}
