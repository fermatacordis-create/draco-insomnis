package draco

import (
	"encoding/json"
	"os"
	"testing"
)

// The shared firewall cases (tests/vectors/waf.json): PHP, JavaScript, Python and Go must agree.
func TestWafVectors(t *testing.T) {
	raw, err := os.ReadFile("../../tests/vectors/waf.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Attacks []struct {
			Name    string
			Rule    string
			Request struct {
				Path, Query, UserAgent string
				Params                 []string
			}
		}
		Ordinary []struct {
			Name    string
			Request struct {
				Path, Query, UserAgent string
				Params                 []string
			}
		}
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Attacks {
		if got := Inspect(c.Request.Path, c.Request.Query, c.Request.Params, c.Request.UserAgent); got != c.Rule {
			t.Errorf("%s: got %q, want %q", c.Name, got, c.Rule)
		}
	}
	for _, c := range v.Ordinary {
		if got := Inspect(c.Request.Path, c.Request.Query, c.Request.Params, c.Request.UserAgent); got != "" {
			t.Errorf("%s: ordinary request matched %q", c.Name, got)
		}
	}
	if len(v.Attacks) < 30 || len(v.Ordinary) < 15 {
		t.Fatalf("too few cases read: %d attacks, %d ordinary", len(v.Attacks), len(v.Ordinary))
	}
}
