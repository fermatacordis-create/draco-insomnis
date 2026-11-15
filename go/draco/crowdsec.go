package draco

import (
	"encoding/json"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CrowdSec makes Draco a bouncer of the owner's own CrowdSec Local API, like server/src/CrowdSec.php:
// bans on an address or a range (no wider than /16 or /32) join the block list, synced in the
// background at most once a minute. Admin addresses are never imported; blocks the owner set are
// never lifted by it.
type CrowdSec struct {
	URL, APIKey string
	Timeout     time.Duration
	store       Store
	blocks      Blocks
	admins      func() []string
	now         func() float64
	running     sync.Mutex
}

// SyncResult tells what one sync did.
type SyncResult struct {
	Added, Removed int
	Error          string
}

var goDuration = regexp.MustCompile(`(\d+(?:\.\d+)?)(h|ms|m|s)`)

// GoSeconds reads Go durations as CrowdSec sends them: "3h59m40.5s", "45m"…
func GoSeconds(d string) int {
	if strings.HasPrefix(strings.TrimSpace(d), "-") {
		return 0
	}
	total, any := 0.0, false
	for _, m := range goDuration.FindAllStringSubmatch(d, -1) {
		any = true
		n, _ := strconv.ParseFloat(m[1], 64)
		total += n * map[string]float64{"h": 3600, "m": 60, "s": 1, "ms": 0.001}[m[2]]
	}
	if !any {
		return 0
	}
	return int(math.Ceil(total))
}

// MaybeSync starts a sync in the background when none ran this minute.
func (c *CrowdSec) MaybeSync() {
	if !c.running.TryLock() {
		return
	}
	c.running.Unlock()
	if c.store.Bump("draco:crowdsec:sync", 60) != 1 {
		return
	}
	go c.Sync()
}

// Sync copies the decisions stream into the block list.
func (c *CrowdSec) Sync() SyncResult {
	c.running.Lock()
	defer c.running.Unlock()
	// Any sync, also one called by hand, counts as this minute's.
	c.store.Set("draco:crowdsec:sync", "1", 60)
	out := SyncResult{}
	_, started := c.store.Get("draco:crowdsec:started")
	startup := !started
	req, _ := http.NewRequest("GET", strings.TrimRight(c.URL, "/")+"/v1/decisions/stream?startup="+strconv.FormatBool(startup)+"&scopes=ip,range", nil)
	req.Header.Set("X-Api-Key", c.APIKey)
	req.Header.Set("User-Agent", "Draco-Insomnis")
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	var data struct {
		New     []map[string]interface{} `json:"new"`
		Deleted []map[string]interface{} `json:"deleted"`
	}
	res, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		out.Error = "no answer"
	} else {
		defer res.Body.Close()
		if res.StatusCode != 200 {
			out.Error = "HTTP " + strconv.Itoa(res.StatusCode)
		} else if json.NewDecoder(res.Body).Decode(&data) != nil {
			out.Error = "not JSON"
		}
	}
	now := c.now()
	if out.Error != "" {
		c.store.Set("draco:crowdsec:last", strconv.FormatInt(int64(now), 10)+"|"+out.Error, 86400*30)
		return out
	}
	imported := c.imported()
	if startup {
		for _, v := range imported {
			if c.removeIfOurs(v, now) {
				out.Removed++
			}
		}
		imported = nil
	}
	for _, d := range data.Deleted {
		value := strings.ToLower(str(d["value"]))
		if i := indexOf(imported, value); value != "" && i >= 0 && c.removeIfOurs(value, now) {
			out.Removed++
			imported = append(imported[:i], imported[i+1:]...)
		}
	}
	admins := c.admins()
	for _, d := range data.New {
		if strings.ToLower(str(d["type"])) != "ban" {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(str(d["value"])))
		ttl := GoSeconds(str(d["duration"]))
		allowed := IsIP(value)
		if strings.Contains(value, "/") {
			allowed = ValidNet(value)
		}
		if ttl <= 0 || !allowed || indexOf(admins, value) >= 0 {
			continue
		}
		scenario := str(d["scenario"])
		if scenario == "" {
			scenario = str(d["origin"])
		}
		if len(scenario) > 150 {
			scenario = scenario[:150]
		}
		if c.blocks.AddUntil(value, int64(now)+int64(ttl), "CrowdSec: "+scenario, true, now) {
			out.Added++
			if indexOf(imported, value) < 0 {
				imported = append(imported, value)
			}
		}
	}
	if len(imported) > 20000 {
		imported = imported[len(imported)-20000:]
	}
	raw, _ := json.Marshal(imported)
	c.store.Set("draco:crowdsec:imported", string(raw), 0)
	c.store.Set("draco:crowdsec:started", "1", 86400*365)
	c.store.Set("draco:crowdsec:last", strconv.FormatInt(int64(now), 10)+"|ok +"+strconv.Itoa(out.Added)+" -"+strconv.Itoa(out.Removed), 86400*30)
	return out
}

func (c *CrowdSec) imported() []string {
	raw, _ := c.store.Get("draco:crowdsec:imported")
	var list []string
	json.Unmarshal([]byte(raw), &list)
	return list
}

func (c *CrowdSec) removeIfOurs(value string, now float64) bool {
	e, ok := c.blocks.Entry(value, now)
	if !ok || !strings.HasPrefix(e.Reason, "CrowdSec") {
		return false
	}
	c.blocks.Remove(value, now)
	return true
}

// CrowdSecLine is one evidence line in the format of the CrowdSec parser in server/crowdsec.
func CrowdSecLine(e Event, host string) string {
	raw, _ := json.Marshal(map[string]string{
		"time": time.Unix(e.Time, 0).UTC().Format("2006-01-02T15:04:05Z"), "ip": e.IP, "host": host,
		"endpoint": e.Endpoint, "verdict": e.Verdict, "reasons": strings.Join(e.Reasons, ","), "user_agent": e.UserAgent,
	})
	return string(raw)
}

func str(v interface{}) string {
	s, _ := v.(string)
	return s
}

func indexOf(list []string, v string) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}
