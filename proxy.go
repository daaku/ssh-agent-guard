package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

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
