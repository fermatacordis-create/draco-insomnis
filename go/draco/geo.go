package draco

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GeoSource is the monthly country list (DB-IP "IP to Country Lite", CC BY 4.0) built by this project.
const GeoSource = "https://github.com/fermatacordis-create/draco-insomnis/releases/download/geo/draco-geo.bin"

const geoHeader = 22

// GeoFile is the visitor's country without Cloudflare: the same file and binary search as
// src/Core/Geo.php. Local: nothing is sent anywhere. Private and unknown addresses have no country.
type GeoFile struct {
	Path   string
	Source string
	mu     sync.Mutex
	f      *os.File
	v4, v6 uint32
	built  string
	tried  time.Time
}

// NewGeoFile opens path; with update it downloads the list when missing or older than 35 days, now
// and then once a day (only replacing the old file when the published SHA-256 matches).
func NewGeoFile(path string, update bool) *GeoFile {
	g := &GeoFile{Path: path, Source: GeoSource}
	if update {
		go func() {
			for {
				g.Refresh()
				time.Sleep(24 * time.Hour)
			}
		}()
	}
	return g
}

func readGeoHead(head []byte, size int64) (uint32, uint32, string, bool) {
	if len(head) < geoHeader || string(head[:6]) != "DRGEO1" {
		return 0, 0, "", false
	}
	v4, v6 := binary.BigEndian.Uint32(head[14:18]), binary.BigEndian.Uint32(head[18:22])
	if size != int64(geoHeader)+int64(v4)*6+int64(v6)*18 {
		return 0, 0, "", false
	}
	return v4, v6, string(head[6:14]), true
}

func (g *GeoFile) open() bool {
	if g.f != nil {
		return true
	}
	if time.Since(g.tried) < time.Minute {
		return false
	}
	g.tried = time.Now()
	f, err := os.Open(g.Path)
	if err != nil {
		return false
	}
	st, _ := f.Stat()
	head := make([]byte, geoHeader)
	if _, err := io.ReadFull(f, head); err != nil {
		f.Close()
		return false
	}
	v4, v6, built, ok := readGeoHead(head, st.Size())
	if !ok {
		f.Close()
		return false
	}
	g.f, g.v4, g.v6, g.built = f, v4, v6, built
	return true
}

// Country is the two-letter country of the address, or "".
func (g *GeoFile) Country(ip string) string {
	addr := toBytes(unmap(strings.TrimSpace(ip)))
	if addr == nil {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.open() {
		return ""
	}
	is4 := len(addr) == 4
	count, size, base := int64(g.v6), int64(18), int64(geoHeader)+int64(g.v4)*6
	if is4 {
		count, size, base = int64(g.v4), 6, geoHeader
	}
	width := size - 2
	buf := make([]byte, width)
	lo, hi, found := int64(0), count-1, int64(-1)
	for lo <= hi {
		mid := (lo + hi) / 2
		if _, err := g.f.ReadAt(buf, base+mid*size); err != nil {
			return ""
		}
		if bytes.Compare(buf, addr) <= 0 {
			found, lo = mid, mid+1
		} else {
			hi = mid - 1
		}
	}
	if found < 0 {
		return ""
	}
	cc := make([]byte, 2)
	if _, err := g.f.ReadAt(cc, base+found*size+width); err != nil {
		return ""
	}
	if cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return ""
	}
	return string(cc)
}

// Built is the date the file was built (YYYYMMDD), or "".
func (g *GeoFile) Built() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.open() {
		return ""
	}
	return g.built
}

// Stale reports whether the list is missing or older than 35 days.
func (g *GeoFile) Stale() bool {
	b := g.Built()
	t, err := time.Parse("20060102", b)
	return err != nil || time.Since(t) > 35*24*time.Hour
}

// Refresh downloads the list when it is missing or stale; "" when done or not needed.
func (g *GeoFile) Refresh() string {
	if !g.Stale() {
		return ""
	}
	return g.Update()
}

// Update downloads the list and replaces the old one only when the SHA-256 matches.
// "" when done; otherwise "checksum", "download", "format" or "folder".
func (g *GeoFile) Update() string {
	client := &http.Client{Timeout: 2 * time.Minute}
	get := func(url string) []byte {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "Draco-Insomnis")
		res, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil
		}
		b, _ := io.ReadAll(res.Body)
		return b
	}
	sum := strings.ToLower(strings.TrimSpace(string(get(g.Source + ".sha256"))))
	if len(sum) < 64 {
		return "checksum"
	}
	want := sum[:64]
	if _, err := hex.DecodeString(want); err != nil {
		return "checksum"
	}
	body := get(g.Source)
	got := sha256.Sum256(body)
	if body == nil || hex.EncodeToString(got[:]) != want {
		return "download"
	}
	if len(body) < geoHeader {
		return "format"
	}
	if _, _, _, ok := readGeoHead(body[:geoHeader], int64(len(body))); !ok {
		return "format"
	}
	part := g.Path + ".part"
	if os.MkdirAll(filepath.Dir(g.Path), 0o755) != nil || os.WriteFile(part, body, 0o644) != nil || os.Rename(part, g.Path) != nil {
		os.Remove(part)
		return "folder"
	}
	g.Close()
	return ""
}

// Close releases the file; the next lookup opens it again.
func (g *GeoFile) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.f != nil {
		g.f.Close()
	}
	g.f, g.tried = nil, time.Time{}
}
