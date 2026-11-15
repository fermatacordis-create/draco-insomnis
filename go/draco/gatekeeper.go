package draco

import (
	"crypto/rand"
	"encoding/hex"
	"html"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Config is every setting, in the shape Caddy (JSON or Caddyfile) and Traefik (YAML, labels) read.
type Config struct {
	// WAF: "off", "log" (default) or "block". Pace: "off" (default), "log" or "block".
	WAF     string `json:"waf,omitempty"`
	Pace    string `json:"pace,omitempty"`
	RateIP  int    `json:"rateIp,omitempty"`
	RateNet int    `json:"rateNet,omitempty"`
	// Proxy: "" (the connection), "cf" (CF-Connecting-IP) or "xff" (X-Forwarded-For), believed only
	// from TrustedProxies (default: this machine and private networks; Cloudflare's ranges for cf).
	Proxy          string         `json:"proxy,omitempty"`
	TrustedProxies []string       `json:"trustedProxies,omitempty"`
	AdminIPs       []string       `json:"adminIps,omitempty"`
	Sensitive      []string       `json:"sensitive,omitempty"`
	Except         []string       `json:"except,omitempty"`
	Geo            GeoConfig      `json:"geo,omitempty"`
	Headers        bool           `json:"headers,omitempty"`
	HSTS           bool           `json:"hsts,omitempty"`
	Review         ReviewConfig   `json:"review,omitempty"`
	CrowdSec       CrowdSecConfig `json:"crowdsec,omitempty"`
	// LogEvents writes every line of evidence (and every review request) as JSON to the log.
	LogEvents bool              `json:"logEvents,omitempty"`
	Texts     map[string]string `json:"texts,omitempty"`
}

// GeoConfig is the country filter: Mode "block" (refuse Countries) or "allow" (only those), Action
// "log" or "block", Scope "sensitive" (default) or "site". File: where the country list is kept; it is
// downloaded there and refreshed.
type GeoConfig struct {
	Mode      string   `json:"mode,omitempty"`
	Countries []string `json:"countries,omitempty"`
	Action    string   `json:"action,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	File      string   `json:"file,omitempty"`
}

// ReviewConfig switches on review requests from the 403 page (Secret: 16+ characters).
type ReviewConfig struct {
	Secret string `json:"secret,omitempty"`
}

// CrowdSecConfig is the owner's CrowdSec Local API and the key from "cscli bouncers add draco".
type CrowdSecConfig struct {
	URL    string `json:"url,omitempty"`
	APIKey string `json:"apiKey,omitempty"`
}

// Version is the Draco Insomnis release this engine belongs to.
const Version = "0.1.30"

// Sensitive path endings, besides any POST.
var Sensitive = []string{
	"/wp-login.php", "/login", "/register", "/signup", "/user/login", "/user/register", "/admin",
	"/auth/login", "/api/auth/local", "/api/auth/local/register", "/admin/login",
	"/accounts/login/", "/accounts/signup/", "/token", "/auth/token",
}

// Texts of the pages.
var Texts = map[string]string{
	"title":             "Request blocked",
	"text":              "This request was blocked by the site's security. If you think this is a mistake, contact the site owner.",
	"too_many":          "Too many pages in a short time. Please wait a moment and try again.",
	"text_with_review":  "This request was blocked by the site's security. If you think this is a mistake, tell the site owner what you were doing:",
	"review_email":      "Your e-mail",
	"review_message":    "What were you doing?",
	"review_button":     "Ask for a review",
	"review_sent_title": "Request sent",
	"review_sent_text":  "Thank you. The owner of the site will look at it and, if it was a mistake, let you through.",
}

// Request is one visitor request in plain values.
type Request struct {
	Method, Path, Query string
	// Params: decoded query and body values (and keys), for the firewall only.
	Params                                []string
	UserAgent, RemoteAddr                 string
	CFConnectingIP, ForwardedFor, Country string
	Accept                                string
	Ajax                                  bool
	// Form: the text fields of a posted form, for the review form.
	Form map[string]string
}

// Answer is what stops a request: 403 (rule), 429 (pace) or 200 (the review thanks page).
type Answer struct {
	Status int
	Why    string
	Retry  int
	Form   string
}

// Resolver proves search engines through the reverse DNS.
type Resolver interface {
	LookupAddr(ip string) ([]string, error)
	LookupHost(host string) ([]string, error)
}

type systemResolver struct{}

func (systemResolver) LookupAddr(ip string) ([]string, error)   { return net.LookupAddr(ip) }
func (systemResolver) LookupHost(host string) ([]string, error) { return net.LookupHost(host) }

// Gatekeeper decides, in the same order as every edition: block list → country → signatures → pace.
type Gatekeeper struct {
	Config   Config
	Store    Store
	Blocks   Blocks
	Resolver Resolver
	Geo      *GeoFile
	CrowdSec *CrowdSec
	OnEvent  func(Event)
	OnReview func(ReviewRequest)
	Now      func() float64
	texts    map[string]string
	trusted  []string
	admins   []string
}

// NewGatekeeper makes a gatekeeper; store may be nil (memory).
func NewGatekeeper(c Config, store Store) *Gatekeeper {
	g := &Gatekeeper{Config: c, Now: wallClock, Resolver: systemResolver{}}
	if store == nil {
		store = NewMemoryStore(nil)
	}
	// Two statements: Yaegi (Traefik plugins) mis-assigns the tuple form.
	g.Store = store
	g.Blocks = Blocks{Store: store}
	g.texts = map[string]string{}
	for k, v := range Texts {
		g.texts[k] = v
	}
	for k, v := range c.Texts {
		g.texts[k] = v
	}
	g.trusted = ParseList(c.TrustedProxies...)
	for _, ip := range c.AdminIPs {
		if ip = strings.TrimSpace(ip); ip != "" {
			g.admins = append(g.admins, ip)
		}
	}
	if c.Geo.File != "" {
		g.Geo = NewGeoFile(c.Geo.File, true)
	}
	if c.CrowdSec.URL != "" && c.CrowdSec.APIKey != "" {
		g.CrowdSec = &CrowdSec{URL: c.CrowdSec.URL, APIKey: c.CrowdSec.APIKey, store: store, blocks: g.Blocks,
			admins: func() []string { return g.admins }, now: func() float64 { return g.Now() }}
	}
	return g
}

func remote(r Request) string {
	ip := unmap(strings.TrimSpace(r.RemoteAddr))
	if IsIP(ip) {
		return ip
	}
	return "0.0.0.0"
}

func (g *Gatekeeper) proxies() []string {
	if len(g.trusted) > 0 {
		return g.trusted
	}
	return LocalProxies
}

// IP is the visitor's address: the connection's own, unless a proxy header is chosen AND the
// connection comes from a trusted proxy. X-Forwarded-For is read from the right.
func (g *Gatekeeper) IP(r Request) string {
	addr := remote(r)
	switch g.Config.Proxy {
	case "cf":
		if r.CFConnectingIP != "" && (Contains(Cloudflare, addr) || Contains(g.trusted, addr)) {
			if ip := strings.TrimSpace(r.CFConnectingIP); IsIP(ip) {
				return ip
			}
		}
	case "xff":
		if strings.TrimSpace(r.ForwardedFor) == "" || !Contains(g.proxies(), addr) {
			return addr
		}
		hops := strings.Split(r.ForwardedFor, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop := strings.TrimSpace(hops[i])
			if !IsIP(hop) {
				return addr
			}
			if !Contains(g.proxies(), hop) {
				return hop
			}
			addr = hop
		}
	}
	return addr
}

func (g *Gatekeeper) reviewing() bool { return len(g.Config.Review.Secret) >= 16 }

// Decide returns the answer that stops the request, or nil to let it through.
func (g *Gatekeeper) Decide(r Request) *Answer {
	a := g.rules(r)
	if a != nil && a.Status == 403 && g.reviewing() {
		a.Form = reviewForm(g.Config.Review.Secret, g.IP(r), a.Why, g.Now(), g.texts)
	}
	return a
}

var twoLetters = regexp.MustCompile(`^[A-Z]{2}$`)

func (g *Gatekeeper) rules(r Request) *Answer {
	if g.CrowdSec != nil {
		g.CrowdSec.MaybeSync()
	}
	c := g.Config
	ip := g.IP(r)
	for _, p := range c.Except {
		prefix := "/" + strings.TrimLeft(p, "/")
		if prefix != "/" && strings.HasPrefix(r.Path, prefix) {
			return nil
		}
	}
	if g.reviewing() && r.Method == "POST" && r.Form[reviewField] == "1" {
		if req, ok := acceptReview(g.Store, c.Review.Secret, ip, r.UserAgent, r.Form, g.Now()); ok {
			rule := req.Rule
			if rule == "" {
				rule = "blocked"
			}
			g.log(r, ip, "review", "pending", []string{"review_" + rule}, req.Message, req.Email)
			if g.OnReview != nil {
				g.OnReview(req)
			}
		}
		// The same answer either way, so a script learns nothing.
		return &Answer{Status: 200, Why: "review"}
	}
	if indexOf(g.admins, ip) >= 0 {
		return nil
	}
	waf := c.WAF
	if waf == "" {
		waf = "log"
	}
	if waf != "off" {
		if g.sensitive(r) && g.Blocks.IsBlocked(ip, g.Now()) {
			return &Answer{Status: 403, Why: "blocked"}
		}
		if country := g.refusedCountry(r, ip); country != "" {
			blocking := c.Geo.Action == "block"
			verdict := "doubtful"
			if blocking {
				verdict = "bot"
			}
			g.log(r, ip, "waf:geo", verdict, []string{"waf_geo"}, country+" "+r.Path, "")
			if blocking {
				return &Answer{Status: 403, Why: "geo"}
			}
		}
		if rule := Inspect(r.Path, r.Query, r.Params, r.UserAgent); rule != "" {
			g.record(r, ip, rule, waf == "block")
			if waf == "block" {
				return &Answer{Status: 403, Why: rule}
			}
		}
	}
	if c.Pace != "" && c.Pace != "off" && wantsPage(r) {
		now := g.Now()
		minute := strconv.FormatInt(int64(now)/60, 10)
		ipHits := g.Store.Bump("draco:rl:i:"+ip+":"+minute, 120)
		netHits := g.Store.Bump("draco:rl:n:"+network(ip)+":"+minute, 120)
		ipLimit, netLimit := limit(c.RateIP, 120), limit(c.RateNet, 600)
		over := ""
		if ipHits > ipLimit {
			over = "ip"
		} else if netHits > netLimit {
			over = "net"
		}
		if over != "" && !g.verifiedCrawler(ip, r.UserAgent) {
			block := c.Pace == "block"
			if ipHits == ipLimit+1 || netHits == netLimit+1 {
				mode := "log"
				if block {
					mode = "block"
				}
				g.log(r, ip, "anticopy:"+over, "doubtful", []string{"anticopy_" + over + "_" + mode}, r.Path, "")
			}
			if block {
				retry := 60 - int(now)%60
				if retry < 1 {
					retry = 1
				}
				return &Answer{Status: 429, Why: "pace", Retry: retry}
			}
		}
	}
	return nil
}

func limit(v, fallback int) int {
	if v >= 10 {
		return v
	}
	return fallback
}

func wantsPage(r Request) bool {
	accept := strings.ToLower(r.Accept)
	return (r.Method == "GET" || r.Method == "HEAD") && (accept == "" || strings.Contains(accept, "text/html")) && !r.Ajax
}

func (g *Gatekeeper) sensitive(r Request) bool {
	if r.Method == "POST" {
		return true
	}
	endings := g.Config.Sensitive
	if len(endings) == 0 {
		endings = Sensitive
	}
	for _, e := range endings {
		if e != "" && strings.HasSuffix(r.Path, e) {
			return true
		}
	}
	return false
}

func (g *Gatekeeper) refusedCountry(r Request, ip string) string {
	geo := g.Config.Geo
	var list []string
	for _, c := range geo.Countries {
		if c = strings.ToUpper(strings.TrimSpace(c)); twoLetters.MatchString(c) {
			list = append(list, c)
		}
	}
	if geo.Mode == "" || geo.Mode == "off" || len(list) == 0 {
		return ""
	}
	if geo.Scope != "site" && !g.sensitive(r) {
		return ""
	}
	country := strings.ToUpper(r.Country)
	if !twoLetters.MatchString(country) && g.Geo != nil {
		country = g.Geo.Country(ip)
	}
	// Unknown, Tor ("T1") or anonymous ("XX"): not refused for its country.
	if !twoLetters.MatchString(country) || country == "XX" || country == "T1" {
		return ""
	}
	listed := indexOf(list, country) >= 0
	if (geo.Mode == "block" && !listed) || (geo.Mode == "allow" && listed) {
		return ""
	}
	if g.verifiedCrawler(ip, r.UserAgent) {
		return ""
	}
	return country
}

func (g *Gatekeeper) record(r Request, ip, rule string, blocking bool) {
	detail := r.Path
	if r.Query != "" {
		detail += "?" + r.Query
	}
	verdict := "doubtful"
	if blocking {
		verdict = "bot"
	}
	g.log(r, ip, "waf:"+rule, verdict, []string{"waf_" + rule}, detail, "")
	if !blocking {
		return
	}
	hits := g.Store.Bump("draco:waf:"+ip, 600)
	// An address read from a header nobody vouches for is never blocked: it could be anybody's.
	trusted := ip == remote(r) || g.Config.Proxy != ""
	if hits >= 5 && trusted && !g.Blocks.IsBlocked(ip, g.Now()) {
		g.Blocks.Add(ip, 7, "Firewall: "+strconv.Itoa(hits)+" attacks in 10 minutes", true, g.Now())
	}
}

var crawlers = map[string][]string{
	"googlebot": {"googlebot.com", "google.com", "googleusercontent.com"}, "google-inspectiontool": {"googlebot.com", "google.com", "googleusercontent.com"},
	"googleother": {"googlebot.com", "google.com", "googleusercontent.com"}, "adsbot-google": {"googlebot.com", "google.com", "googleusercontent.com"},
	"mediapartners-google": {"googlebot.com", "google.com", "googleusercontent.com"}, "bingbot": {"search.msn.com"}, "msnbot": {"search.msn.com"},
	"adidxbot": {"search.msn.com"}, "applebot": {"applebot.apple.com"}, "yandex": {"yandex.ru", "yandex.net", "yandex.com"},
}

// Same order as the other editions, so "googlebot" wins over "googleother" in one User-Agent.
var crawlerOrder = []string{"googlebot", "google-inspectiontool", "googleother", "adsbot-google", "mediapartners-google", "bingbot", "msnbot", "adidxbot", "applebot", "yandex"}

func (g *Gatekeeper) verifiedCrawler(ip, userAgent string) bool {
	ua := strings.ToLower(userAgent)
	token := ""
	for _, t := range crawlerOrder {
		if strings.Contains(ua, t) {
			token = t
			break
		}
	}
	if token == "" || g.Resolver == nil {
		return false
	}
	key := "draco:crawler:" + ip + ":" + token
	if v, ok := g.Store.Get(key); ok && (v == "y" || v == "n") {
		return v == "y"
	}
	ok := g.resolvesBack(ip, token)
	v := "n"
	if ok {
		v = "y"
	}
	g.Store.Set(key, v, 86400)
	return ok
}

func (g *Gatekeeper) resolvesBack(ip, token string) bool {
	names, err := g.Resolver.LookupAddr(ip)
	if err != nil {
		return false
	}
	want := fromBytes(toBytes(ip))
	for i, name := range names {
		if i >= 3 {
			break
		}
		h := strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
		match := false
		for _, d := range crawlers[token] {
			if h == d || strings.HasSuffix(h, "."+d) {
				match = true
			}
		}
		if !match {
			continue
		}
		addrs, err := g.Resolver.LookupHost(h)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if b := toBytes(a); b != nil && fromBytes(b) == want {
				return true
			}
		}
	}
	return false
}

func (g *Gatekeeper) log(r Request, ip, endpoint, verdict string, reasons []string, detail, email string) {
	ua := r.UserAgent
	if len(ua) > 255 {
		ua = ua[:255]
	}
	max := 200
	if endpoint == "review" {
		max = 500
	}
	if d := []rune(detail); len(d) > max {
		detail = string(d[:max])
	}
	if g.OnEvent != nil {
		g.OnEvent(Event{int64(g.Now()), ip, remote(r), endpoint, verdict, reasons, ua, detail, email})
	}
}

// SecurityHeaders to add, unless the application already set them.
func (g *Gatekeeper) SecurityHeaders(https bool) [][2]string {
	var out [][2]string
	if g.Config.Headers {
		out = append(out, [2]string{"X-Content-Type-Options", "nosniff"}, [2]string{"X-Frame-Options", "SAMEORIGIN"},
			[2]string{"Referrer-Policy", "strict-origin-when-cross-origin"},
			[2]string{"Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"})
	}
	if https && g.Config.HSTS {
		out = append(out, [2]string{"Strict-Transport-Security", "max-age=15552000"})
	}
	return out
}

// Render is the status, headers and body of an answer.
func (g *Gatekeeper) Render(a *Answer) (int, [][2]string, string) {
	t := g.texts
	if a.Status == 429 {
		return 429, [][2]string{{"Retry-After", strconv.Itoa(a.Retry)}, {"Content-Type", "text/plain; charset=UTF-8"},
			{"Cache-Control", "no-store"}, {"X-Robots-Tag", "noindex"}}, t["too_many"]
	}
	h := [][2]string{{"Content-Type", "text/html; charset=UTF-8"}, {"Cache-Control", "no-store"}, {"X-Robots-Tag", "noindex, nofollow"}}
	if a.Status == 200 {
		return 200, h, Page(t["review_sent_title"], t["review_sent_text"], "")
	}
	if a.Form != "" {
		return 403, h, Page(t["title"], t["text_with_review"], a.Form)
	}
	return 403, h, Page(t["title"], t["text"], "")
}

// Page is the 403 page: it never says which rule matched; the reference ties it to the evidence.
func Page(title, text, extra string) string {
	ref := make([]byte, 5)
	rand.Read(ref)
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>403</title>` +
		`<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box}main{background:#fff;border-radius:12px;padding:32px;max-width:440px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}form{text-align:left;margin-top:20px}label{display:block;font-size:14px;margin:10px 0 4px}input,textarea{width:100%;box-sizing:border-box;padding:8px;border:1px solid #c3c4c7;border-radius:6px;font:inherit}button{margin-top:12px;padding:9px 16px;border:0;border-radius:6px;background:#2271b1;color:#fff;font:inherit;cursor:pointer}.hp{position:absolute;left:-9999px}</style></head><body><main>` +
		`<h1 style="font-size:20px">` + html.EscapeString(title) + `</h1><p>` + html.EscapeString(text) + `</p>` + extra +
		`<p style="color:#64748b;font-size:13px">Ref. ` + hex.EncodeToString(ref) + `</p></main></body></html>`
}
