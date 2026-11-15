package draco

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// "This is a mistake": a person the firewall stopped asks the owner to look again, from the 403
// page — the same form, signatures and limits as src/Core/Review.php (tests/vectors/review.json).

const reviewField = "draco_review"

// ReviewRequest is one accepted request, for the owner.
type ReviewRequest struct {
	Time      int64  `json:"time"`
	IP        string `json:"ip"`
	Rule      string `json:"rule"`
	Email     string `json:"email"`
	Message   string `json:"message"`
	UserAgent string `json:"userAgent"`
}

func mac(secret, data string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return h.Sum(nil)
}

var ruleClean = regexp.MustCompile(`[^a-z0-9_]`)

func cleanRule(rule string) string { return ruleClean.ReplaceAllString(strings.ToLower(rule), "") }

// Seal hides the rule from the visitor: XOR with a key from the secret, the address and the moment.
func Seal(secret, ip, ts, rule string) string {
	plain := make([]byte, 32)
	r := cleanRule(rule)
	if len(r) > 32 {
		r = r[:32]
	}
	copy(plain, r)
	key := mac(secret, "review-rule|"+ip+"|"+ts)
	for i := range plain {
		plain[i] ^= key[i]
	}
	return hex.EncodeToString(plain)
}

var ruleOK = regexp.MustCompile(`^[a-z0-9_]*$`)

// OpenSealed returns the rule from Seal, or "" when the value is not one.
func OpenSealed(secret, ip, ts, sealed string) string {
	b, err := hex.DecodeString(sealed)
	if err != nil || len(b) != 32 {
		return ""
	}
	key := mac(secret, "review-rule|"+ip+"|"+ts)
	for i := range b {
		b[i] ^= key[i]
	}
	rule := strings.TrimRight(string(b), "\x00")
	if !ruleOK.MatchString(rule) {
		return ""
	}
	return rule
}

// Sign is the signature of a form shown to ip at ts for rule.
func Sign(secret, ip, rule, ts string) string {
	return hex.EncodeToString(mac(secret, "review|"+ip+"|"+rule+"|"+ts))
}

func reviewForm(secret, ip, why string, now float64, t map[string]string) string {
	h := html.EscapeString
	ts := strconv.FormatInt(int64(now), 10)
	rule := cleanRule(why)
	return `<form method="post" action="">` +
		`<input type="hidden" name="` + reviewField + `" value="1">` +
		`<input type="hidden" name="draco_rule" value="` + h(Seal(secret, ip, ts, rule)) + `">` +
		`<input type="hidden" name="draco_ts" value="` + h(ts) + `">` +
		`<input type="hidden" name="draco_sig" value="` + h(Sign(secret, ip, rule, ts)) + `">` +
		`<p class="hp"><label>Website <input type="text" name="draco_website" tabindex="-1" autocomplete="off"></label></p>` +
		`<label for="draco-r-email">` + h(t["review_email"]) + `</label>` +
		`<input id="draco-r-email" type="email" name="draco_email" required maxlength="190">` +
		`<label for="draco-r-msg">` + h(t["review_message"]) + `</label>` +
		`<textarea id="draco-r-msg" name="draco_message" rows="3" maxlength="500" required></textarea>` +
		`<button type="submit">` + h(t["review_button"]) + `</button>` +
		`</form>`
}

var (
	emailRe   = regexp.MustCompile("(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
	scriptRe  = regexp.MustCompile(`(?is)<script[^>]*?>.*?</script>|<style[^>]*?>.*?</style>|<[^>]*>`)
	controlRe = regexp.MustCompile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
)

func acceptReview(store Store, secret, ip, userAgent string, post map[string]string, now float64) (ReviewRequest, bool) {
	ts := post["draco_ts"]
	rule := OpenSealed(secret, ip, ts, post["draco_rule"])
	email := strings.ToLower(strings.TrimSpace(post["draco_email"]))
	message := strings.TrimSpace(controlRe.ReplaceAllString(scriptRe.ReplaceAllString(post["draco_message"], ""), ""))
	if r := []rune(message); len(r) > 500 {
		message = string(r[:500])
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	fresh := err == nil && ts != "" && float64(n) <= now && now-float64(n) < 86400
	ok := fresh && hmac.Equal([]byte(Sign(secret, ip, rule, ts)), []byte(post["draco_sig"])) &&
		post["draco_website"] == "" && emailRe.MatchString(email) && len(email) <= 190 && message != ""
	if !ok {
		return ReviewRequest{}, false
	}
	day := time.Unix(int64(now), 0).UTC().Format("20060102")
	if store.Bump("draco:review:ip:"+ip, 86400) > 3 || store.Bump("draco:review:day:"+day, 86400) > 50 {
		return ReviewRequest{}, false
	}
	if len(userAgent) > 255 {
		userAgent = userAgent[:255]
	}
	return ReviewRequest{int64(now), ip, rule, email, message, userAgent}, true
}
