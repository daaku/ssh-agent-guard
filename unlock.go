package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

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
