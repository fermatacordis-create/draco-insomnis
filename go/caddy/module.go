// Package caddy is Draco Insomnis as a Caddy module: the http.handlers.draco_insomnis handler and the
// draco_insomnis Caddyfile directive. Build Caddy with it:
//
//	xcaddy build --with github.com/fermatacordis-create/draco-insomnis/go/caddy
//
// Caddyfile:
//
//	example.com {
//		draco_insomnis {
//			waf block
//			pace block
//			headers
//		}
//		reverse_proxy localhost:8080
//	}
package caddy

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	draco "github.com/fermatacordis-create/draco-insomnis/go/draco"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("draco_insomnis", parseCaddyfile)
	// Before anything that answers or proxies: Draco sees every request first.
	httpcaddyfile.RegisterDirectiveOrder("draco_insomnis", httpcaddyfile.Before, "header")
}

// Handler runs Draco in front of the rest of the route.
type Handler struct {
	draco.Config
	gate *draco.Gatekeeper
}

// CaddyModule returns the module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.draco_insomnis", New: func() caddy.Module { return new(Handler) }}
}

// Provision builds the gatekeeper; evidence and review requests go to Caddy's log when LogEvents is on.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.gate = draco.NewGatekeeper(h.Config, nil)
	if h.LogEvents {
		logger := ctx.Logger()
		h.gate.OnEvent = func(e draco.Event) {
			logger.Info("draco evidence", zap.String("ip", e.IP), zap.String("endpoint", e.Endpoint), zap.String("verdict", e.Verdict),
				zap.Strings("reasons", e.Reasons), zap.String("user_agent", e.UserAgent), zap.String("detail", e.Detail))
		}
		h.gate.OnReview = func(r draco.ReviewRequest) {
			logger.Warn("draco review request", zap.String("ip", r.IP), zap.String("rule", r.Rule), zap.String("email", r.Email), zap.String("message", r.Message))
		}
	}
	return nil
}

// ServeHTTP answers first; the next handler only sees what Draco lets through.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var answer *draco.Answer
	func() {
		defer func() {
			if recover() != nil {
				answer = nil // Draco failing never takes the site with it.
			}
		}()
		answer = h.gate.Decide(draco.ReadRequest(r))
	}()
	if answer != nil {
		status, headers, body := h.gate.Render(answer)
		for _, kv := range headers {
			w.Header().Set(kv[0], kv[1])
		}
		w.WriteHeader(status)
		_, err := w.Write([]byte(body))
		return err
	}
	extra := h.gate.SecurityHeaders(r.TLS != nil)
	if len(extra) == 0 {
		return next.ServeHTTP(w, r)
	}
	// Added when the answer starts, so the headers of the app behind Caddy always win; Caddy's own
	// ResponseWriterWrapper keeps Flush, Hijack and Unwrap working.
	return next.ServeHTTP(&withHeaders{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}, extra: extra}, r)
}

type withHeaders struct {
	*caddyhttp.ResponseWriterWrapper
	extra [][2]string
	done  bool
}

func (w *withHeaders) start() {
	if !w.done {
		w.done = true
		draco.AddMissingHeaders(w.ResponseWriter.Header(), w.extra)
	}
}

func (w *withHeaders) WriteHeader(code int) {
	w.start()
	w.ResponseWriterWrapper.WriteHeader(code)
}

func (w *withHeaders) Write(b []byte) (int, error) {
	w.start()
	return w.ResponseWriterWrapper.Write(b)
}

// UnmarshalCaddyfile reads the draco_insomnis block. Each line is "option value…"; flags (headers,
// hsts, log_events) take no value.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	for d.NextBlock(0) {
		key := d.Val()
		args := d.RemainingArgs()
		one := func() (string, error) {
			if len(args) != 1 {
				return "", d.ArgErr()
			}
			return args[0], nil
		}
		number := func() (int, error) {
			v, err := one()
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(v)
		}
		var err error
		switch key {
		case "waf":
			h.WAF, err = one()
		case "pace":
			h.Pace, err = one()
		case "rate_ip":
			h.RateIP, err = number()
		case "rate_net":
			h.RateNet, err = number()
		case "proxy":
			h.Proxy, err = one()
		case "trusted_proxies":
			h.TrustedProxies = append(h.TrustedProxies, args...)
		case "admin_ips":
			h.AdminIPs = append(h.AdminIPs, args...)
		case "sensitive":
			h.Sensitive = append(h.Sensitive, args...)
		case "except":
			h.Except = append(h.Except, args...)
		case "headers":
			h.Headers = true
		case "hsts":
			h.HSTS = true
		case "log_events":
			h.LogEvents = true
		case "geo_mode":
			h.Geo.Mode, err = one()
		case "geo_countries":
			for _, a := range args {
				h.Geo.Countries = append(h.Geo.Countries, strings.Split(a, ",")...)
			}
		case "geo_action":
			h.Geo.Action, err = one()
		case "geo_scope":
			h.Geo.Scope, err = one()
		case "geo_file":
			h.Geo.File, err = one()
		case "review_secret":
			h.Review.Secret, err = one()
		case "crowdsec_url":
			h.CrowdSec.URL, err = one()
		case "crowdsec_api_key":
			h.CrowdSec.APIKey, err = one()
		default:
			return d.Errf("unknown draco_insomnis option %q", key)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h := new(Handler)
	err := h.UnmarshalCaddyfile(helper.Dispenser)
	return h, err
}

// MarshalJSON keeps the JSON config flat (the fields of draco.Config).
func (h Handler) MarshalJSON() ([]byte, error) { return json.Marshal(h.Config) }

// UnmarshalJSON reads the flat JSON config.
func (h *Handler) UnmarshalJSON(b []byte) error { return json.Unmarshal(b, &h.Config) }

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
