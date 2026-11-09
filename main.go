// Command ssh-agent-guard is an ssh-agent proxy that unlocks the default
// Secret Service collection when the real agent reports no identities.
//
// It is meant to run as a socket activated systemd user service. Clients
// point SSH_AUTH_SOCK at the proxy socket; every request is forwarded
// verbatim to the upstream agent. When a REQUEST_IDENTITIES reply contains
// zero keys, the proxy asks the Secret Service (via busctl) to unlock the
// default collection, waits for the unlock to finish, and then retries the
// request so the client sees the keys that were loaded as a result.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(0) // journald adds timestamps

	defUpstream := os.Getenv("SSH_AGENT_GUARD_UPSTREAM")
	if defUpstream == "" {
		if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
			defUpstream = filepath.Join(rt, "ssh-agent.socket")
		}
	}

	var (
		upstream      = flag.String("upstream", defUpstream, "path to the real ssh-agent socket (env SSH_AGENT_GUARD_UPSTREAM)")
		listen        = flag.String("listen", "", "unix socket path to listen on when not socket activated")
		busctl        = flag.String("busctl", "busctl", "busctl binary")
		unlockTimeout = flag.Duration("unlock-timeout", 2*time.Minute, "how long to wait for the unlock prompt to complete")
		keyWait       = flag.Duration("key-wait", 3*time.Second, "after an unlock, how long to keep retrying REQUEST_IDENTITIES until keys appear")
		cooldown      = flag.Duration("cooldown", 10*time.Second, "after a dismissed/failed unlock, do not prompt again for this long")
		debug         = flag.Bool("debug", false, "verbose logging")
	)
	flag.Parse()

	if *upstream == "" {
		log.Fatal("no upstream agent socket: set -upstream or SSH_AGENT_GUARD_UPSTREAM")
	}

	l, err := listener(*listen)
	if err != nil {
		log.Fatal(err)
	}
	if sameSocket(l.Addr().String(), *upstream) {
		log.Fatalf("upstream %q is our own listening socket", *upstream)
	}

	p := &Proxy{
		Upstream: *upstream,
		KeyWait:  *keyWait,
		Debug:    *debug,
		Unlocker: &Unlocker{
			SecretService: &Busctl{Path: *busctl},
			Timeout:       *unlockTimeout,
			Cooldown:      *cooldown,
			Debug:         *debug,
		},
	}
	log.Printf("ssh-agent-guard listening on %s, upstream %s", l.Addr(), *upstream)
	if err := p.Serve(l); err != nil {
		log.Fatal(err)
	}
}

// listener returns the systemd-provided socket if we were socket activated,
// otherwise it listens on path.
func listener(path string) (net.Listener, error) {
	l, err := activationListener()
	if err != nil || l != nil {
		return l, err
	}
	if path == "" {
		return nil, errors.New("not socket activated and no -listen path given")
	}
	// Remove a stale socket from a previous run, but never a non-socket file.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		os.Remove(path)
	}
	l, err = net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	l.(*net.UnixListener).SetUnlinkOnClose(true)
	return l, nil
}

// activationListener implements the sd_listen_fds(3) protocol. It returns
// nil, nil when the process was not socket activated.
func activationListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	// Don't leak these into busctl or anything else we exec.
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	if err != nil || n < 1 {
		return nil, nil
	}
	if n > 1 {
		return nil, fmt.Errorf("expected 1 socket from systemd, got %d", n)
	}
	const fd = 3 // SD_LISTEN_FDS_START
	syscall.CloseOnExec(fd)
	f := os.NewFile(fd, "systemd-socket")
	defer f.Close() // FileListener dups the fd
	l, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("socket activation: %w", err)
	}
	return l, nil
}

func sameSocket(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}
