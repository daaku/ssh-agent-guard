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
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// Agent protocol constants (draft-miller-ssh-agent).
const (
	msgRequestIdentities = 11
	msgIdentitiesAnswer  = 12

	// Same limit OpenSSH uses for agent messages (AGENT_MAX_LEN).
	maxMsgLen = 256 * 1024
)

// Proxy forwards agent connections to Upstream. Messages are relayed as raw
// frames, so every request type (including extensions, constraints and key
// types this program knows nothing about) passes through untouched. Only
// REQUEST_IDENTITIES replies are inspected.
type Proxy struct {
	Upstream string
	Unlocker *Unlocker
	KeyWait  time.Duration
	Debug    bool
}

func (p *Proxy) Serve(l net.Listener) error {
	var tempDelay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Back off on transient errors such as EMFILE.
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else if tempDelay *= 2; tempDelay > time.Second {
				tempDelay = time.Second
			}
			log.Printf("accept: %v", err)
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
		go p.handle(c)
	}
}

// handle serves a single client. The agent protocol is strictly
// request/response, so each client gets its own upstream connection and
// requests on it are processed in order.
func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	up, err := net.Dial("unix", p.Upstream)
	if err != nil {
		log.Printf("dial upstream: %v", err)
		return
	}
	defer up.Close()

	for {
		req, err := readMsg(client)
		if err != nil {
			if !errors.Is(err, io.EOF) && p.Debug {
				log.Printf("read client: %v", err)
			}
			return
		}
		resp, err := roundTrip(up, req)
		if err != nil {
			log.Printf("upstream: %v", err)
			return
		}
		if len(req) > 0 && req[0] == msgRequestIdentities && emptyIdentities(resp) {
			if resp, err = p.retryIdentities(up, req, resp); err != nil {
				log.Printf("upstream: %v", err)
				return
			}
		}
		if err := writeMsg(client, resp); err != nil {
			if p.Debug {
				log.Printf("write client: %v", err)
			}
			return
		}
	}
}

// retryIdentities is called when the agent has no identities. It triggers
// an unlock and re-issues the request. If an unlock actually happened, keys
// may be loaded into the agent asynchronously (e.g. KeePassXC adds them
// after the database opens), so it keeps polling for up to KeyWait.
func (p *Proxy) retryIdentities(up net.Conn, req, resp []byte) ([]byte, error) {
	res, err := p.Unlocker.Unlock()
	if err != nil {
		if !errors.Is(err, errCooldown) {
			log.Printf("unlock: %v", err)
		}
		return resp, nil
	}
	deadline := time.Now().Add(p.KeyWait)
	delay := 50 * time.Millisecond
	for {
		resp, err = roundTrip(up, req)
		if err != nil || !emptyIdentities(resp) {
			return resp, err
		}
		// Already unlocked: the empty answer is genuine, one retry is enough
		// (it covers losing a race with a concurrent unlock).
		if res == alreadyUnlocked || time.Now().Add(delay).After(deadline) {
			if p.Debug {
				log.Printf("still no identities after unlock (%v)", res)
			}
			return resp, nil
		}
		time.Sleep(delay)
		delay = min(delay*2, 500*time.Millisecond)
	}
}

// emptyIdentities reports whether resp is an IDENTITIES_ANSWER with nkeys=0.
func emptyIdentities(resp []byte) bool {
	return len(resp) >= 5 && resp[0] == msgIdentitiesAnswer &&
		binary.BigEndian.Uint32(resp[1:5]) == 0
}

func roundTrip(up net.Conn, req []byte) ([]byte, error) {
	if err := writeMsg(up, req); err != nil {
		return nil, err
	}
	return readMsg(up)
}

// readMsg reads one length-prefixed agent message and returns its body.
func readMsg(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxMsgLen {
		return nil, fmt.Errorf("message too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf, nil
}

func writeMsg(w io.Writer, body []byte) error {
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err := w.Write(buf)
	return err
}

type unlockResult int

const (
	alreadyUnlocked unlockResult = iota // collection was not locked
	unlocked                            // we (or a concurrent caller) unlocked it
)

func (r unlockResult) String() string {
	if r == alreadyUnlocked {
		return "already unlocked"
	}
	return "unlocked"
}

var (
	errCooldown  = errors.New("recent unlock failed, not prompting again yet")
	errDismissed = errors.New("unlock prompt dismissed")
)

// SecretService is the subset of org.freedesktop.Secret.* the Unlocker uses.
type SecretService interface {
	DefaultCollection(ctx context.Context) (string, error)
	Locked(ctx context.Context, collection string) (bool, error)
	// Unlock unlocks collection, blocking until any prompt has completed.
	Unlock(ctx context.Context, collection string) error
}

// Unlocker coalesces concurrent unlock requests: only one unlock flow runs
// at a time and every caller that arrives while it is running waits for and
// shares its result. The default collection's object path is resolved
// lazily on first use and cached for the life of the process.
type Unlocker struct {
	SecretService SecretService
	Timeout       time.Duration
	Cooldown      time.Duration
	Debug         bool

	mu         sync.Mutex
	inflight   *unlockCall
	failedAt   time.Time
	collection string // cached; guarded by mu
}

type unlockCall struct {
	done chan struct{}
	res  unlockResult
	err  error
}

func (u *Unlocker) Unlock() (unlockResult, error) {
	u.mu.Lock()
	if c := u.inflight; c != nil {
		u.mu.Unlock()
		<-c.done
		return c.res, c.err
	}
	c := &unlockCall{done: make(chan struct{})}
	u.inflight = c
	// Inside the cooldown window we still check whether the collection was
	// unlocked by other means, but we don't pop up another prompt.
	prompt := u.failedAt.IsZero() || time.Since(u.failedAt) >= u.Cooldown
	u.mu.Unlock()

	// The flow is deliberately not tied to any one client: if the client
	// that started it goes away, the others waiting on it still benefit.
	ctx, cancel := context.WithTimeout(context.Background(), u.Timeout)
	c.res, c.err = u.run(ctx, prompt)
	cancel()

	u.mu.Lock()
	u.inflight = nil
	if c.err != nil && !errors.Is(c.err, errCooldown) {
		u.failedAt = time.Now()
	} else if c.err == nil {
		u.failedAt = time.Time{}
	}
	u.mu.Unlock()
	close(c.done)
	return c.res, c.err
}

// run is only ever executed by the single in-flight caller.
func (u *Unlocker) run(ctx context.Context, prompt bool) (unlockResult, error) {
	coll, err := u.defaultCollection(ctx)
	if err != nil {
		return 0, err
	}
	locked, err := u.SecretService.Locked(ctx, coll)
	if err != nil {
		return 0, err
	}
	if !locked {
		return alreadyUnlocked, nil
	}
	if !prompt {
		return 0, errCooldown
	}
	start := time.Now()
	if u.Debug {
		log.Printf("unlocking %s", coll)
	}
	if err := u.SecretService.Unlock(ctx, coll); err != nil {
		return 0, err
	}
	log.Printf("unlocked %s in %v", coll, time.Since(start).Round(time.Millisecond))
	return unlocked, nil
}

func (u *Unlocker) defaultCollection(ctx context.Context) (string, error) {
	u.mu.Lock()
	coll := u.collection
	u.mu.Unlock()
	if coll != "" {
		return coll, nil
	}
	coll, err := u.SecretService.DefaultCollection(ctx)
	if err != nil {
		return "", err // not cached; retried on next use
	}
	if u.Debug {
		log.Printf("default collection is %s", coll)
	}
	u.mu.Lock()
	u.collection = coll
	u.mu.Unlock()
	return coll, nil
}

// Busctl talks to the Secret Service by exec'ing busctl(1). Unlocks are rare
// and interactive, so the cost of a few process spawns is irrelevant and we
// avoid carrying a D-Bus implementation.
type Busctl struct {
	Path string
}

const (
	ssDest    = "org.freedesktop.secrets"
	ssPath    = "/org/freedesktop/secrets"
	ssService = "org.freedesktop.Secret.Service"
	ssColl    = "org.freedesktop.Secret.Collection"
	ssPrompt  = "org.freedesktop.Secret.Prompt"
)

func (b *Busctl) DefaultCollection(ctx context.Context) (string, error) {
	var out struct{ Data []string }
	if err := b.json(ctx, &out, "call", ssDest, ssPath, ssService, "ReadAlias", "s", "default"); err != nil {
		return "", fmt.Errorf("ReadAlias(default): %w", err)
	}
	if len(out.Data) != 1 || out.Data[0] == "" || out.Data[0] == "/" {
		return "", errors.New("secret service has no default collection")
	}
	return out.Data[0], nil
}

func (b *Busctl) Locked(ctx context.Context, coll string) (bool, error) {
	var out struct{ Data bool }
	if err := b.json(ctx, &out, "get-property", ssDest, coll, ssColl, "Locked"); err != nil {
		return false, fmt.Errorf("%s Locked: %w", coll, err)
	}
	return out.Data, nil
}

func (b *Busctl) Unlock(ctx context.Context, coll string) error {
	// Unlock(ao objects) -> (ao unlocked, o prompt)
	var out struct{ Data []json.RawMessage }
	if err := b.json(ctx, &out, "call", ssDest, ssPath, ssService, "Unlock", "ao", "1", coll); err != nil {
		return fmt.Errorf("Unlock: %w", err)
	}
	var prompt string
	if len(out.Data) != 2 || json.Unmarshal(out.Data[1], &prompt) != nil {
		return fmt.Errorf("Unlock: unexpected reply %v", out.Data)
	}
	if prompt == "/" {
		return nil // unlocked without needing a prompt
	}
	return b.prompt(ctx, coll, prompt)
}

// prompt invokes Prompt.Prompt and waits for it to finish. Completion is
// detected two ways: the Prompt.Completed signal (via busctl monitor), which
// also tells us about dismissal, and polling the collection's Locked
// property as a fallback in case the monitor can't run or misses the signal.
func (b *Busctl) prompt(ctx context.Context, coll, prompt string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	completed := make(chan bool, 1) // carries "dismissed"
	mon := exec.CommandContext(ctx, b.Path, "--user", "--json=short", "monitor", "--match",
		fmt.Sprintf("type='signal',interface='%s',member='Completed',path='%s'", ssPrompt, prompt))
	monOut, err := mon.StdoutPipe()
	if err == nil {
		err = mon.Start()
	}
	if err != nil {
		log.Printf("busctl monitor unavailable, falling back to polling: %v", err)
	} else {
		defer func() { cancel(); mon.Wait() }()
		go func() {
			sc := bufio.NewScanner(monOut)
			sc.Buffer(nil, 1<<20)
			for sc.Scan() {
				var m struct {
					Type, Path, Member string
					Payload            struct{ Data []json.RawMessage }
				}
				if json.Unmarshal(sc.Bytes(), &m) != nil || m.Type != "signal" ||
					m.Member != "Completed" || m.Path != prompt || len(m.Payload.Data) < 1 {
					continue
				}
				var dismissed bool
				json.Unmarshal(m.Payload.Data[0], &dismissed)
				completed <- dismissed
				return
			}
		}()
	}

	if err := b.run(ctx, nil, "call", ssDest, prompt, ssPrompt, "Prompt", "s", ""); err != nil {
		return fmt.Errorf("Prompt: %w", err)
	}

	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	for {
		select {
		case dismissed := <-completed:
			if dismissed {
				return errDismissed
			}
			return nil
		case <-poll.C:
			if locked, err := b.Locked(ctx, coll); err == nil && !locked {
				return nil
			}
		case <-ctx.Done():
			return fmt.Errorf("waiting for prompt: %w", ctx.Err())
		}
	}
}

func (b *Busctl) json(ctx context.Context, v any, args ...string) error {
	var out bytes.Buffer
	if err := b.run(ctx, &out, append([]string{"--json=short"}, args...)...); err != nil {
		return err
	}
	if err := json.Unmarshal(out.Bytes(), v); err != nil {
		return fmt.Errorf("parsing busctl output %q: %w", out.String(), err)
	}
	return nil
}

func (b *Busctl) run(ctx context.Context, stdout io.Writer, args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, b.Path, append([]string{"--user"}, args...)...)
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}
