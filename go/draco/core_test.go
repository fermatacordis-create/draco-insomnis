package draco

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const now0 = 1_800_000_000.0

type noDNS struct{}

func (noDNS) LookupAddr(string) ([]string, error) { return nil, io.EOF }
func (noDNS) LookupHost(string) ([]string, error) { return nil, io.EOF }

func gate(c Config) *Gatekeeper {
	g := NewGatekeeper(c, NewMemoryStore(func() float64 { return now0 }))
	g.Resolver = noDNS{}
	g.Now = func() float64 { return now0 }
	return g
}

func req(over func(*Request)) Request {
	r := Request{Method: "GET", Path: "/", UserAgent: "Mozilla/5.0 Chrome/131.0", RemoteAddr: "198.51.100.20"}
	if over != nil {
		over(&r)
	}
	return r
}

func attack(r *Request) { r.Query = "../../etc/passwd"; r.Params = []string{"../../etc/passwd"} }

func TestNetLikePHP(t *testing.T) {
	if IsIP("01.2.3.4") || IsIP("fe80::1%eth0") || !IsIP("2001:db8::1") {
		t.Fatal("address parsing differs from PHP's filter_var")
	}
	if network("2001:db8:1:2:3:4:5:6") != "2001:db8:1:2::/64" || network("203.0.113.9") != "203.0.113.0/24" {
		t.Fatal(network("2001:db8:1:2:3:4:5:6"))
	}
	if !ValidNet("203.0.113.0/24") || ValidNet("10.0.0.0/8") {
		t.Fatal("ValidNet")
	}
	g := gate(Config{Proxy: "xff"})
	if ip := g.IP(req(func(r *Request) { r.RemoteAddr = "203.0.113.5"; r.ForwardedFor = "1.2.3.4" })); ip != "203.0.113.5" {
		t.Fatal("a forged X-Forwarded-For counted:", ip)
	}
	if ip := g.IP(req(func(r *Request) { r.RemoteAddr = "10.0.0.2"; r.ForwardedFor = "1.2.3.4, 198.51.100.7, 10.0.0.9" })); ip != "198.51.100.7" {
		t.Fatal("X-Forwarded-For not read from the right:", ip)
	}
}

func TestReviewVectorsLikePHP(t *testing.T) {
	raw, _ := os.ReadFile("../../tests/vectors/review.json")
	var v struct {
		Secret string
		Cases  []struct {
			IP, Rule, Opened, Sealed, Sig string
			Ts                            json.Number
		}
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Cases) == 0 {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		ts := c.Ts.String()
		if Seal(v.Secret, c.IP, ts, c.Rule) != c.Sealed || OpenSealed(v.Secret, c.IP, ts, c.Sealed) != c.Opened || Sign(v.Secret, c.IP, c.Rule, ts) != c.Sig {
			t.Errorf("%s: signatures differ from PHP", c.IP)
		}
	}
}

var hiddenRe = regexp.MustCompile(`<input type="hidden" name="([a-z_]+)" value="([^"]*)">`)

func hidden(html string) map[string]string {
	out := map[string]string{}
	for _, m := range hiddenRe.FindAllStringSubmatch(html, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func TestReviewFlow(t *testing.T) {
	var asked []ReviewRequest
	g := gate(Config{WAF: "block", Review: ReviewConfig{Secret: "owner-secret-0123456789"}})
	g.OnReview = func(r ReviewRequest) { asked = append(asked, r) }
	a := g.Decide(req(attack))
	status, _, body := g.Render(a)
	if status != 403 || !strings.Contains(body, "Ask for a review") || strings.Contains(body, "traversal") {
		t.Fatal("block page", status)
	}
	form := hidden(body)
	form["draco_email"], form["draco_message"], form["draco_website"] = "Ana@Example.org", "I was <b>reading</b>", ""
	for i := 0; i < 5; i++ {
		if a := g.Decide(req(func(r *Request) { r.Method = "POST"; r.Form = form })); a == nil || a.Status != 200 {
			t.Fatal("no thanks page")
		}
	}
	if len(asked) != 3 || asked[0].Email != "ana@example.org" || asked[0].Message != "I was reading" || asked[0].Rule != "traversal" {
		t.Fatalf("review requests: %+v", asked)
	}
	bad := map[string]string{}
	for k, v := range form {
		bad[k] = v
	}
	bad["draco_sig"] = strings.Repeat("0", 64)
	g2 := gate(Config{WAF: "block"})
	g2.Config.Review.Secret = "owner-secret-0123456789"
	var none []ReviewRequest
	g2.OnReview = func(r ReviewRequest) { none = append(none, r) }
	g2.Decide(req(func(r *Request) { r.Method = "POST"; r.Form = bad }))
	g2.Decide(req(func(r *Request) { r.Method = "POST"; r.Form = form; r.RemoteAddr = "203.0.113.7" }))
	if len(none) != 0 {
		t.Fatal("a forged request reached the owner")
	}
}

func TestFirewallPaceAndBlocks(t *testing.T) {
	var seen []string
	g := gate(Config{WAF: "block"})
	g.OnEvent = func(e Event) { seen = append(seen, e.Endpoint) }
	if g.Decide(req(func(r *Request) {
		r.Query = "q=european union select committee"
		r.Params = []string{"european union select committee"}
	})) != nil {
		t.Fatal("ordinary search blocked")
	}
	if a := g.Decide(req(attack)); a == nil || a.Why != "traversal" {
		t.Fatal("traversal not blocked")
	}
	if a := g.Decide(req(func(r *Request) { r.Path = "/.env" })); a == nil || a.Why != "probe" {
		t.Fatal("probe not blocked")
	}
	for i := 0; i < 4; i++ {
		g.Decide(req(attack))
	}
	if !g.Blocks.IsBlocked("198.51.100.20", now0) {
		t.Fatal("5 attacks in 10 minutes did not block")
	}
	if g.Decide(req(nil)) != nil {
		t.Fatal("a blocked address must still read")
	}
	if a := g.Decide(req(func(r *Request) { r.Method = "POST"; r.Path = "/contact" })); a == nil || a.Why != "blocked" {
		t.Fatal("a blocked address posted")
	}
	if seen[0] != "waf:traversal" || seen[1] != "waf:probe" {
		t.Fatal(seen)
	}
	if gate(Config{WAF: "block", AdminIPs: []string{"198.51.100.20"}}).Decide(req(attack)) != nil {
		t.Fatal("admin inspected")
	}
	if gate(Config{WAF: "block", Except: []string{"webhooks"}}).Decide(req(func(r *Request) { attack(r); r.Path = "/webhooks/stripe" })) != nil {
		t.Fatal("excepted path inspected")
	}
	p := gate(Config{WAF: "off", Pace: "block", RateIP: 10})
	var got []*Answer
	for i := 0; i < 12; i++ {
		got = append(got, p.Decide(req(func(r *Request) { r.Accept = "text/html" })))
	}
	if got[9] != nil || got[10] == nil || got[10].Status != 429 || got[10].Retry < 1 {
		t.Fatal("pace limit")
	}
	if p.Decide(req(func(r *Request) { r.Accept = "application/json" })) != nil {
		t.Fatal("API calls counted as pages")
	}
}

func geoFixture(built string) []byte {
	v4 := [][2]string{{"0.0.0.0", "--"}, {"1.0.0.0", "AU"}, {"1.0.1.0", "CN"}, {"1.0.4.0", "--"}, {"203.0.113.0", "ES"}, {"203.0.114.0", "--"}}
	v6 := [][2]string{{"::", "--"}, {"2a00::", "ES"}, {"2a01::", "--"}}
	out := []byte("DRGEO1" + built)
	out = binary.BigEndian.AppendUint32(out, uint32(len(v4)))
	out = binary.BigEndian.AppendUint32(out, uint32(len(v6)))
	for _, x := range append(v4, v6...) {
		out = append(append(out, toBytes(x[0])...), x[1]...)
	}
	return out
}

func TestGeoLikeGeoPHP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "g.bin")
	os.WriteFile(path, geoFixture("20261113"), 0o644)
	geo := NewGeoFile(path, false)
	for ip, want := range map[string]string{"1.0.0.200": "AU", "1.0.3.255": "CN", "1.0.4.0": "", "::ffff:203.0.113.10": "ES", "2a00:1450::1": "ES", "2a01::1": "", "x": ""} {
		if got := geo.Country(ip); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	if geo.Built() != "20261113" {
		t.Fatal(geo.Built())
	}
	g := gate(Config{WAF: "block"})
	g.Config.Geo.Mode, g.Config.Geo.Countries, g.Config.Geo.Action = "block", []string{"CN"}, "block"
	g.Geo = geo
	if a := g.Decide(req(func(r *Request) { r.Path = "/login"; r.RemoteAddr = "1.0.2.3" })); a == nil || a.Why != "geo" {
		t.Fatal("country not refused")
	}
	if g.Decide(req(func(r *Request) { r.RemoteAddr = "1.0.2.3" })) != nil {
		t.Fatal("only sensitive pages by default")
	}
	// Download with the published checksum; a wrong one keeps the old file.
	body := geoFixture("20991231")
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			io.WriteString(w, want+"  draco-geo.bin\n")
			return
		}
		w.Write(body)
	}))
	defer srv.Close()
	dl := &GeoFile{Path: filepath.Join(t.TempDir(), "sub", "g.bin"), Source: srv.URL + "/draco-geo.bin"}
	if e := dl.Refresh(); e != "" || dl.Built() != "20991231" {
		t.Fatal("download", e)
	}
	want = strings.Repeat("0", 64)
	if dl.Update() != "download" || dl.Built() != "20991231" {
		t.Fatal("a bad checksum replaced the file")
	}
}

func TestCrowdSecBridge(t *testing.T) {
	if GoSeconds("3h59m40.5s") != 14381 || GoSeconds("250ms") != 1 || GoSeconds("-3s") != 0 {
		t.Fatal("durations")
	}
	answer := `{"new":[{"type":"ban","value":"198.51.100.66","duration":"4h","scenario":"crowdsecurity/http-probing"},
	{"type":"ban","value":"203.0.113.0/24","duration":"1h"},{"type":"ban","value":"10.0.0.0/8","duration":"1h"},
	{"type":"ban","value":"192.0.2.1","duration":"4h"},{"type":"captcha","value":"198.51.100.67","duration":"4h"}],"deleted":null}`
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.RawQuery+" "+r.Header.Get("X-Api-Key"))
		io.WriteString(w, answer)
	}))
	defer srv.Close()
	g := gate(Config{WAF: "block", AdminIPs: []string{"192.0.2.1"}})
	g.Config.CrowdSec.URL, g.Config.CrowdSec.APIKey = srv.URL, "k3y"
	g = func() *Gatekeeper {
		n := NewGatekeeper(g.Config, NewMemoryStore(func() float64 { return now0 }))
		n.Resolver = noDNS{}
		n.Now = g.Now
		return n
	}()
	g.Blocks.Add("203.0.113.200", 7, "Manual", false, now0)
	if r := g.CrowdSec.Sync(); r.Added != 2 || r.Removed != 0 || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	if asked[0] != "startup=true&scopes=ip,range k3y" {
		t.Fatal(asked)
	}
	if a := g.Decide(req(func(r *Request) { r.Path = "/login"; r.RemoteAddr = "198.51.100.66" })); a == nil || a.Why != "blocked" {
		t.Fatal("ban not enforced")
	}
	if a := g.Decide(req(func(r *Request) { r.Method = "POST"; r.RemoteAddr = "203.0.113.9" })); a == nil || a.Why != "blocked" {
		t.Fatal("range not enforced")
	}
	if g.Decide(req(func(r *Request) { r.Path = "/login"; r.RemoteAddr = "10.1.2.3" })) != nil {
		t.Fatal("a /8 was imported")
	}
	answer = `{"new":[],"deleted":[{"value":"198.51.100.66"},{"value":"203.0.113.200"}]}`
	if r := g.CrowdSec.Sync(); r.Removed != 1 {
		t.Fatalf("%+v", r)
	}
	if !g.Blocks.IsBlocked("203.0.113.200", now0) || g.Blocks.IsBlocked("198.51.100.66", now0) {
		t.Fatal("deletions")
	}
	line := CrowdSecLine(Event{Time: 1_800_000_000, IP: "198.51.100.9", Endpoint: "waf:sqli", Verdict: "bot", Reasons: []string{"waf_sqli"}, UserAgent: "curl/8"}, "shop.example")
	if line != `{"endpoint":"waf:sqli","host":"shop.example","ip":"198.51.100.9","reasons":"waf_sqli","time":"2027-01-15T08:00:00Z","user_agent":"curl/8","verdict":"bot"}` {
		t.Fatal(line)
	}
}

func TestHTTPMiddleware(t *testing.T) {
	g := NewGatekeeper(Config{WAF: "block", Headers: true}, nil)
	g.Resolver = noDNS{}
	g.Config.Review.Secret = "owner-secret-0123456789"
	var asked []string
	g.OnReview = func(r ReviewRequest) { asked = append(asked, r.Email) }
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/own" {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		if r.Method == "POST" {
			r.ParseForm()
			io.WriteString(w, "name="+r.PostForm.Get("name"))
			return
		}
		io.WriteString(w, "page")
	})
	srv := httptest.NewServer(g.Handler(app))
	defer srv.Close()
	get := func(path string) *http.Response {
		r, _ := http.NewRequest("GET", srv.URL+path, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/131.0")
		res, _ := http.DefaultClient.Do(r)
		return res
	}
	if res := get("/"); res.StatusCode != 200 || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("ordinary page", res.StatusCode)
	}
	if get("/own").Header.Get("X-Frame-Options") != "DENY" {
		t.Fatal("the app's own header must win")
	}
	res := get("/search?q=1%27%20union%20select%20password%20from%20users--%20")
	page, _ := io.ReadAll(res.Body)
	if res.StatusCode != 403 || strings.Contains(string(page), "sqli") {
		t.Fatal("sqli", res.StatusCode)
	}
	post := func(body, kind string) *http.Response {
		r, _ := http.NewRequest("POST", srv.URL+"/echo", strings.NewReader(body))
		r.Header.Set("Content-Type", kind)
		r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/131.0")
		res, _ := http.DefaultClient.Do(r)
		return res
	}
	if post(url.Values{"message": {"x'; DROP TABLE users; --"}}.Encode(), "application/x-www-form-urlencoded").StatusCode != 403 {
		t.Fatal("form not inspected")
	}
	if post(`{"q": "' OR '1'='1"}`, "application/json").StatusCode != 403 {
		t.Fatal("JSON not inspected")
	}
	ok := post(url.Values{"name": {"Ana"}}.Encode(), "application/x-www-form-urlencoded")
	b, _ := io.ReadAll(ok.Body)
	if string(b) != "name=Ana" {
		t.Fatal("the app could not read the body Draco read:", string(b))
	}
	form := url.Values{}
	for k, v := range hidden(string(page)) {
		form.Set(k, v)
	}
	form.Set("draco_email", "ana@example.org")
	form.Set("draco_message", "I was searching")
	r, _ := http.NewRequest("POST", srv.URL+"/search?q=1%27%20union%20select%20password%20from%20users--%20", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	thanks, _ := http.DefaultClient.Do(r)
	if thanks.StatusCode != 200 || len(asked) != 1 {
		t.Fatal("review through HTTP", thanks.StatusCode, asked)
	}
}
