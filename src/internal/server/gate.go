package server

import "sync"

type ClientGate struct {
	mu            sync.Mutex
	allowMultiple bool
	active        bool
}

func NewClientGate(allowMultiple bool) *ClientGate {
	return &ClientGate{allowMultiple: allowMultiple}
}

func (g *ClientGate) TryAcquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.allowMultiple {
		return true
	}

	if g.active {
		return false
	}

	g.active = true
	return true
}

func (g *ClientGate) Release() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.allowMultiple {
		g.active = false
	}
}
