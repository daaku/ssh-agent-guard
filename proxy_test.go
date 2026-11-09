package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// gatedAgent hides its keys until the fake secret service has been unlocked,
// simulating e.g. KeePassXC loading keys into ssh-agent on unlock.
type gatedAgent struct {
	agent.Agent
	unlockedFile string
}

func (g *gatedAgent) List() ([]*agent.Key, error) {
	if _, err := os.Stat(g.unlockedFile); err != nil {
		return nil, nil
	}
	return g.Agent.List()
}

type env struct {
	state string
	sock  string
	pub   ssh.PublicKey
}

func setup(t *testing.T, cooldown time.Duration) *env {
	t.Helper()
	// Unix socket paths are length-limited, so avoid the long t.TempDir().
	dir, err := os.MkdirTemp("", "sag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "state")
	os.Mkdir(state, 0o700)
	t.Setenv("FAKE_STATE", state)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)

	upSock := filepath.Join(dir, "up")
	ul, err := net.Listen("unix", upSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })
	ga := &gatedAgent{Agent: kr, unlockedFile: filepath.Join(state, "unlocked")}
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			go func() { agent.ServeAgent(ga, c); c.Close() }()
		}
	}()

	busctl, _ := filepath.Abs("testdata/fake-busctl")
	p := &Proxy{
		Upstream: upSock,
		KeyWait:  2 * time.Second,
		Unlocker: &Unlocker{
			SecretService: &Busctl{Path: busctl},
			Timeout:       10 * time.Second,
			Cooldown:      cooldown,
		},
	}
	sock := filepath.Join(dir, "guard")
	pl, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pl.Close() })
	go p.Serve(pl)
	return &env{state: state, sock: sock, pub: signer.PublicKey()}
}

func (e *env) client(t *testing.T) agent.ExtendedAgent {
	c, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return agent.NewClient(c)
}

func (e *env) calls(t *testing.T) map[string]int {
	b, _ := os.ReadFile(filepath.Join(e.state, "calls"))
	m := map[string]int{}
	for _, l := range strings.Fields(string(b)) {
		m[l]++
	}
	return m
}

func TestUnlockAndRetry(t *testing.T) {
	e := setup(t, time.Minute)
	a := e.client(t)
	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	// Other requests pass through on the same connection.
	sig, err := a.Sign(e.pub, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.pub.Verify([]byte("hello"), sig); err != nil {
		t.Fatal(err)
	}
	// Second list: keys present, no secret service involvement.
	if keys, _ := a.List(); len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	c := e.calls(t)
	if c["Unlock"] != 1 || c["Prompt"] != 1 || c["ReadAlias"] != 1 {
		t.Fatalf("calls = %v", c)
	}
}

func TestConcurrentClientsShareOneUnlock(t *testing.T) {
	e := setup(t, time.Minute)
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for range n {
		a := e.client(t)
		wg.Go(func() {
			keys, err := a.List()
			if err != nil || len(keys) != 1 {
				errs <- "bad result"
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	c := e.calls(t)
	if c["Unlock"] != 1 || c["Prompt"] != 1 || c["ReadAlias"] != 1 {
		t.Fatalf("calls = %v", c)
	}
}

func TestDismissedPromptCoolsDown(t *testing.T) {
	t.Setenv("FAKE_DISMISS", "1")
	e := setup(t, time.Minute)
	for range 3 {
		keys, err := e.client(t).List()
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 0 {
			t.Fatalf("got %d keys, want 0", len(keys))
		}
	}
	// Only the first attempt prompts; the rest are within the cooldown.
	c := e.calls(t)
	if c["Prompt"] != 1 || c["ReadAlias"] != 1 {
		t.Fatalf("calls = %v", c)
	}
}

func TestAlreadyUnlockedNoPrompt(t *testing.T) {
	e := setup(t, time.Minute)
	// Collection is unlocked but the agent genuinely has no keys.
	os.WriteFile(filepath.Join(e.state, "unlocked"), nil, 0o600)
	a := e.client(t)
	if err := a.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys, want 0", len(keys))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v; should not wait for keys when already unlocked", d)
	}
	c := e.calls(t)
	if c["Unlock"] != 0 || c["Prompt"] != 0 || c["Locked"] != 1 {
		t.Fatalf("calls = %v", c)
	}
}
