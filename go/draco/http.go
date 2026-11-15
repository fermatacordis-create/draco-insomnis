package draco

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const maxBody = 65536

// ReadRequest reads an http.Request the way Draco needs it. Forms and JSON bodies up to 64 KB are
// read once and put back, so the next handler reads them unchanged.
func ReadRequest(r *http.Request) Request {
	raw := r.URL.EscapedPath()
	path, err := url.PathUnescape(raw)
	if err != nil {
		path = raw
	}
	query, err := url.QueryUnescape(r.URL.RawQuery)
	if err != nil {
		query = r.URL.RawQuery
	}
	params := Flatten(map[string][]string(r.URL.Query()), 200)
	var form map[string]string
	kind := strings.ToLower(r.Header.Get("Content-Type"))
	if (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") && r.Body != nil &&
		r.ContentLength >= 0 && r.ContentLength <= maxBody && (strings.Contains(kind, "json") || strings.Contains(kind, "x-www-form-urlencoded")) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		if strings.Contains(kind, "json") {
			var data interface{}
			if json.Unmarshal(body, &data) == nil {
				params = append(params, Flatten(data, 200)...)
				if m, ok := data.(map[string]interface{}); ok {
					form = map[string]string{}
					for k, v := range m {
						if s, ok := v.(string); ok {
							form[k] = s
						}
					}
				}
			} else {
				params = append(params, string(body))
			}
		} else if values, err := url.ParseQuery(string(body)); err == nil {
			params = append(params, Flatten(map[string][]string(values), 200)...)
			form = map[string]string{}
			for k, v := range values {
				if len(v) > 0 {
					form[k] = v[len(v)-1]
				}
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	req := Request{
		Method: strings.ToUpper(r.Method), Path: path, Query: query, Params: params,
		UserAgent: r.UserAgent(), RemoteAddr: host,
		CFConnectingIP: r.Header.Get("CF-Connecting-IP"), ForwardedFor: strings.Join(r.Header.Values("X-Forwarded-For"), ", "),
		Accept: r.Header.Get("Accept"), Ajax: strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest"), Form: form,
	}
	// Cloudflare's country header, only when the connection really comes from Cloudflare.
	if Contains(Cloudflare, remote(req)) {
		req.Country = r.Header.Get("CF-IPCountry")
	}
	return req
}

// Handler is Draco as net/http middleware: it answers first, next only sees what it lets through.
// If Draco itself fails, the request goes through.
func (g *Gatekeeper) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var answer *Answer
		func() {
			defer func() {
				if recover() != nil {
					answer = nil
				}
			}()
			answer = g.Decide(ReadRequest(r))
		}()
		if answer != nil {
			status, headers, body := g.Render(answer)
			for _, h := range headers {
				w.Header().Set(h[0], h[1])
			}
			w.WriteHeader(status)
			io.WriteString(w, body)
			return
		}
		extra := g.SecurityHeaders(r.TLS != nil)
		if len(extra) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&withHeaders{ResponseWriter: w, extra: extra}, r)
	})
}

// AddMissingHeaders sets the security headers the response does not carry yet. Called when the
// answer starts, after the application (or the proxied server) set its own, so its own always win.
func AddMissingHeaders(h http.Header, extra [][2]string) {
	for _, kv := range extra {
		if h.Get(kv[0]) == "" {
			h.Set(kv[0], kv[1])
		}
	}
}

// withHeaders adds the security headers when the answer starts. It keeps Flush, Hijack and Unwrap,
// so streaming, server-sent events and WebSockets keep working.
type withHeaders struct {
	http.ResponseWriter
	extra [][2]string
	done  bool
}

func (w *withHeaders) start() {
	if !w.done {
		w.done = true
		AddMissingHeaders(w.ResponseWriter.Header(), w.extra)
	}
}

func (w *withHeaders) WriteHeader(code int) {
	w.start()
	w.ResponseWriter.WriteHeader(code)
}

func (w *withHeaders) Write(b []byte) (int, error) {
	w.start()
	return w.ResponseWriter.Write(b)
}

func (w *withHeaders) Flush() {
	w.start()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *withHeaders) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *withHeaders) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// LogTo makes the gatekeeper write every line of evidence and review request as JSON to logger.
func (g *Gatekeeper) LogTo(logger *log.Logger) {
	g.OnEvent = func(e Event) {
		raw, _ := json.Marshal(map[string]interface{}{"draco": "event", "event": e})
		logger.Println(string(raw))
	}
	g.OnReview = func(r ReviewRequest) {
		raw, _ := json.Marshal(map[string]interface{}{"draco": "review", "review": r})
		logger.Println(string(raw))
	}
}

// Traefik plugin entry points (Yaegi): CreateConfig and New.

// CreateConfig is Traefik's default configuration for the plugin.
func CreateConfig() *Config { return &Config{WAF: "log"} }

// New is Traefik's constructor for the plugin; in Go code use NewGatekeeper(...).Handler(next).
func New(_ context.Context, next http.Handler, c *Config, name string) (http.Handler, error) {
	g := NewGatekeeper(*c, nil)
	if c.LogEvents {
		// Standard output: Traefik shows it as information, standard error as errors.
		g.LogTo(log.New(os.Stdout, "["+name+"] ", 0))
	}
	return g.Handler(next), nil
}
