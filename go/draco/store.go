package draco

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store keeps counters, the block list and verified crawlers. The keys are the same as in the
// JavaScript and Python editions, so one Redis can serve apps in several languages.
type Store interface {
	// Bump adds one and returns the new value; the counter disappears after ttl seconds.
	Bump(key string, ttl int) int
	Get(key string) (string, bool)
	// Set keeps a value for ttl seconds; 0 = for good.
	Set(key, value string, ttl int)
	Delete(key string)
}

type item struct {
	value string
	until float64
}

// MemoryStore serves one process. Safe for concurrent use; lost on restart.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]item
	now   func() float64
}

// NewMemoryStore makes an empty store; now may be nil (the wall clock).
func NewMemoryStore(now func() float64) *MemoryStore {
	if now == nil {
		now = wallClock
	}
	return &MemoryStore{items: map[string]item{}, now: now}
}

func wallClock() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (s *MemoryStore) live(key string) (item, bool) {
	it, ok := s.items[key]
	if !ok {
		return item{}, false
	}
	if it.until != 0 && it.until <= s.now() {
		delete(s.items, key)
		return item{}, false
	}
	return it, true
}

func (s *MemoryStore) sweep() {
	if len(s.items) < 50000 {
		return
	}
	for k := range s.items {
		s.live(k)
	}
}

func (s *MemoryStore) Bump(key string, ttl int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.live(key)
	n := 1
	until := s.now() + float64(ttl)
	if ok {
		v, _ := strconv.Atoi(it.value)
		n, until = v+1, it.until
	}
	s.items[key] = item{strconv.Itoa(n), until}
	s.sweep()
	return n
}

func (s *MemoryStore) Get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.live(key)
	return it.value, ok
}

func (s *MemoryStore) Set(key, value string, ttl int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	until := 0.0
	if ttl != 0 {
		until = s.now() + float64(ttl)
	}
	s.items[key] = item{value, until}
	s.sweep()
}

func (s *MemoryStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
}

// Event is a line of evidence: the same fields as the PHP events table and the JS/Python DracoEvent.
type Event struct {
	Time      int64    `json:"time"`
	IP        string   `json:"ip"`
	Remote    string   `json:"remote"`
	Endpoint  string   `json:"endpoint"`
	Verdict   string   `json:"verdict"`
	Reasons   []string `json:"reasons"`
	UserAgent string   `json:"userAgent"`
	Detail    string   `json:"detail"`
	Email     string   `json:"email,omitempty"`
}

// Forever is the "until" of a block that never ends.
const Forever = 253402300799

var netRe = regexp.MustCompile(`(?i)^([0-9a-f.:]+)/(\d+)$`)

// ValidNet reports whether a network may be blocked: no wider than /16 (IPv4) or /32 (IPv6).
func ValidNet(cidr string) bool {
	m := netRe.FindStringSubmatch(strings.TrimSpace(cidr))
	if m == nil {
		return false
	}
	b := toBytes(m[1])
	bits, _ := strconv.Atoi(m[2])
	if b == nil {
		return false
	}
	if len(b) == 16 {
		return bits >= 32 && bits <= 128
	}
	return bits >= 16 && bits <= 32
}

// BlockEntry is one blocked address or network.
type BlockEntry struct {
	Value     string `json:"value"`
	Until     int64  `json:"until"`
	Reason    string `json:"reason"`
	Automatic bool   `json:"automatic"`
}

// Blocks is the block list on any Store: one key per address, one key holding the blocked networks.
type Blocks struct{ Store Store }

func (b Blocks) write(e BlockEntry, now float64, ttl int) bool {
	if strings.Contains(e.Value, "/") {
		if !ValidNet(e.Value) {
			return false
		}
		var nets []BlockEntry
		for _, n := range b.Nets(now) {
			if n.Value != e.Value {
				nets = append(nets, n)
			}
		}
		raw, _ := json.Marshal(append(nets, e))
		b.Store.Set("draco:nets", string(raw), 0)
		return true
	}
	raw, _ := json.Marshal(e)
	b.Store.Set("draco:block:"+e.Value, string(raw), ttl)
	return true
}

// Add blocks an address or network for days (0 = for good).
func (b Blocks) Add(value string, days int, reason string, automatic bool, now float64) bool {
	until, ttl := int64(Forever), 0
	if days != 0 {
		until, ttl = int64(now)+int64(days)*86400, days*86400
	}
	return b.write(BlockEntry{value, until, reason, automatic}, now, ttl)
}

// AddUntil blocks until a given moment, for lists that bring their own duration (CrowdSec).
func (b Blocks) AddUntil(value string, until int64, reason string, automatic bool, now float64) bool {
	ttl := int(until - int64(now))
	return ttl > 0 && b.write(BlockEntry{value, until, reason, automatic}, now, ttl)
}

// Remove lifts a block.
func (b Blocks) Remove(value string, now float64) {
	if strings.Contains(value, "/") {
		var nets []BlockEntry
		for _, n := range b.Nets(now) {
			if n.Value != value {
				nets = append(nets, n)
			}
		}
		raw, _ := json.Marshal(nets)
		b.Store.Set("draco:nets", string(raw), 0)
		return
	}
	b.Store.Delete("draco:block:" + value)
}

// Nets lists the blocked networks still in force.
func (b Blocks) Nets(now float64) []BlockEntry {
	raw, ok := b.Store.Get("draco:nets")
	if !ok {
		return nil
	}
	var all, out []BlockEntry
	if json.Unmarshal([]byte(raw), &all) != nil {
		return nil
	}
	for _, n := range all {
		if float64(n.Until) > now {
			out = append(out, n)
		}
	}
	return out
}

// Entry is the block in force on exactly this address or network.
func (b Blocks) Entry(value string, now float64) (BlockEntry, bool) {
	if strings.Contains(value, "/") {
		for _, n := range b.Nets(now) {
			if n.Value == value {
				return n, true
			}
		}
		return BlockEntry{}, false
	}
	raw, ok := b.Store.Get("draco:block:" + value)
	var e BlockEntry
	if !ok || json.Unmarshal([]byte(raw), &e) != nil {
		return BlockEntry{}, false
	}
	return e, true
}

// IsBlocked reports whether the address, or a network holding it, is blocked.
func (b Blocks) IsBlocked(ip string, now float64) bool {
	if _, ok := b.Store.Get("draco:block:" + ip); ok {
		return true
	}
	for _, n := range b.Nets(now) {
		if InNet(n.Value, ip) {
			return true
		}
	}
	return false
}
