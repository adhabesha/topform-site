package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static
var content embed.FS

var (
	dataDir   = env("DATA_DIR", "data")
	upDir     string
	secret    []byte
	adminPass = os.Getenv("ADMIN_PASSWORD")
	maxUpload = int64(envInt("MAX_UPLOAD_MB", 40)) << 20
	cmu       sync.RWMutex
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$`)

	ghToken  = os.Getenv("GITHUB_TOKEN")
	ghRepo   = os.Getenv("GITHUB_REPO")
	ghBranch = env("GITHUB_BRANCH", "main")
	pmu      sync.Mutex
	pending  = map[string]string{}
	timer    *time.Timer
	syncMsg  = "GitHub sync is off (changes reset when the server restarts)"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return d
}

func rnd(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------- auth ----------

func sign(exp int64) string {
	m := strconv.FormatInt(exp, 10)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(m))
	return m + "." + hex.EncodeToString(h.Sum(nil))
}

func valid(tok string) bool {
	p := strings.SplitN(tok, ".", 2)
	if len(p) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(p[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(tok), []byte(sign(exp)))
}

func authed(r *http.Request) bool {
	c, err := r.Cookie("tf_admin")
	return err == nil && valid(c.Value)
}

func isLocal(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-For") != "" {
		return false
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Requested-With") != "tf" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h(w, r)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password string }
	if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	want := adminPass
	if want == "" {
		if !isLocal(r) {
			http.Error(w, "Set the ADMIN_PASSWORD environment variable to enable the admin on this server", http.StatusForbidden)
			return
		}
		want = "admin"
	}
	a, b := sha256.Sum256([]byte(in.Password)), sha256.Sum256([]byte(want))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		time.Sleep(700 * time.Millisecond)
		http.Error(w, "wrong password", http.StatusUnauthorized)
		return
	}
	exp := time.Now().Add(8 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name: "tf_admin", Value: sign(exp.Unix()), Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Expires: exp,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
	w.Write([]byte(`{"ok":true}`))
}

func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "tf_admin", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	w.Write([]byte(`{"ok":true}`))
}

// ---------- content ----------

func contentPath() string { return filepath.Join(dataDir, "content.json") }

func getContent(w http.ResponseWriter, r *http.Request) {
	cmu.RLock()
	b, err := os.ReadFile(contentPath())
	cmu.RUnlock()
	if err != nil {
		b = []byte("{}")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}

func putContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil || !json.Valid(b) {
		http.Error(w, "invalid or too large JSON", http.StatusBadRequest)
		return
	}
	cmu.Lock()
	tmp := contentPath() + ".tmp"
	err = os.WriteFile(tmp, b, 0o644)
	if err == nil {
		err = os.Rename(tmp, contentPath())
	}
	cmu.Unlock()
	if err != nil {
		http.Error(w, "could not save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	queue("put", "data/content.json")
	w.Write([]byte(`{"ok":true}`))
}

// ---------- media ----------

// sniff returns the extension for allowed file types based on the file's first bytes.
func sniff(h []byte) string {
	switch {
	case bytes.HasPrefix(h, []byte("\x89PNG\r\n\x1a\n")):
		return ".png"
	case bytes.HasPrefix(h, []byte{0xFF, 0xD8, 0xFF}):
		return ".jpg"
	case bytes.HasPrefix(h, []byte("GIF87a")), bytes.HasPrefix(h, []byte("GIF89a")):
		return ".gif"
	case len(h) >= 12 && bytes.HasPrefix(h, []byte("RIFF")) && bytes.Equal(h[8:12], []byte("WEBP")):
		return ".webp"
	case len(h) >= 12 && bytes.Equal(h[4:8], []byte("ftyp")):
		return ".mp4"
	case bytes.HasPrefix(h, []byte{0x1A, 0x45, 0xDF, 0xA3}):
		return ".webm"
	}
	return ""
}

func upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, "upload invalid or larger than "+strconv.FormatInt(maxUpload>>20, 10)+" MB", http.StatusBadRequest)
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file", http.StatusBadRequest)
		return
	}
	defer f.Close()
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	ext := sniff(head[:n])
	if ext == "" {
		http.Error(w, "unsupported file type (use PNG, JPG, GIF, WEBP, MP4 or WEBM)", http.StatusUnsupportedMediaType)
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	name := fmt.Sprintf("%d-%s%s", time.Now().Unix(), rnd(3), ext)
	dst := filepath.Join(upDir, name)
	out, err := os.Create(dst)
	if err != nil {
		http.Error(w, "could not store file", http.StatusInternalServerError)
		return
	}
	size, err := io.Copy(out, f)
	out.Close()
	if err != nil {
		os.Remove(dst)
		http.Error(w, "could not store file", http.StatusInternalServerError)
		return
	}
	queue("put", "data/uploads/"+name)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"url": "/uploads/" + name, "name": name, "size": size})
}

func media(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		type item struct {
			Name string `json:"name"`
			URL  string `json:"url"`
			Size int64  `json:"size"`
			Mod  int64  `json:"mod"`
		}
		out := []item{}
		es, _ := os.ReadDir(upDir)
		for _, e := range es {
			if e.IsDir() || !nameRe.MatchString(e.Name()) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, item{e.Name(), "/uploads/" + e.Name(), info.Size(), info.ModTime().Unix()})
		}
		sort.Slice(out, func(a, b int) bool { return out[a].Mod > out[b].Mod })
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	case http.MethodDelete:
		n := r.URL.Query().Get("name")
		if !nameRe.MatchString(n) {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		if err := os.Remove(filepath.Join(upDir, n)); err != nil && !os.IsNotExist(err) {
			http.Error(w, "could not delete", http.StatusInternalServerError)
			return
		}
		queue("del", "data/uploads/"+n)
		w.Write([]byte(`{"ok":true}`))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func status(w http.ResponseWriter, r *http.Request) {
	pmu.Lock()
	msg := syncMsg
	pmu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"github": ghToken != "" && ghRepo != "", "msg": msg})
}

// ---------- GitHub sync (keeps edits after Render restarts/redeploys) ----------

func queue(op, path string) {
	if ghToken == "" || ghRepo == "" {
		return
	}
	pmu.Lock()
	defer pmu.Unlock()
	pending[path] = op
	if timer != nil {
		timer.Stop()
	}
	timer = time.AfterFunc(25*time.Second, flush)
	syncMsg = "changes queued for GitHub"
}

func flush() {
	pmu.Lock()
	batch := pending
	pending = map[string]string{}
	pmu.Unlock()
	var errs []string
	for p, op := range batch {
		var err error
		if op == "del" {
			err = ghDelete(p)
		} else {
			err = ghPut(p)
		}
		if err != nil {
			errs = append(errs, p+": "+err.Error())
			log.Println("github sync:", p, err)
		}
	}
	pmu.Lock()
	if len(errs) > 0 {
		syncMsg = "GitHub sync error: " + strings.Join(errs, "; ")
	} else {
		syncMsg = "synced to GitHub at " + time.Now().Format("15:04:05")
	}
	pmu.Unlock()
}

func short(b []byte) string {
	if len(b) > 160 {
		b = b[:160]
	}
	return string(b)
}

func gh(method, p string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "https://api.github.com/repos/"+ghRepo+"/contents/"+p, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ghToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "topform-admin")
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func ghSha(p string) string {
	code, b, err := gh("GET", p+"?ref="+ghBranch, nil)
	if err != nil || code != http.StatusOK {
		return ""
	}
	var o struct {
		Sha string `json:"sha"`
	}
	json.Unmarshal(b, &o)
	return o.Sha
}

func ghPut(p string) error {
	lp := filepath.Join(dataDir, strings.TrimPrefix(p, "data/"))
	data, err := os.ReadFile(lp)
	if err != nil {
		return err
	}
	body := map[string]any{
		"message": "admin: update " + p,
		"content": base64.StdEncoding.EncodeToString(data),
		"branch":  ghBranch,
	}
	if sha := ghSha(p); sha != "" {
		body["sha"] = sha
	}
	code, rb, err := gh("PUT", p, body)
	if err != nil {
		return err
	}
	if code != http.StatusOK && code != http.StatusCreated {
		return fmt.Errorf("HTTP %d %s", code, short(rb))
	}
	return nil
}

func ghDelete(p string) error {
	sha := ghSha(p)
	if sha == "" {
		return nil
	}
	code, rb, err := gh("DELETE", p, map[string]any{"message": "admin: delete " + p, "sha": sha, "branch": ghBranch})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("HTTP %d %s", code, short(rb))
	}
	return nil
}

// ---------- contact form ----------

type enquiry struct {
	Name, Mobile, Email, Device, Subject, Description string
}

func contact(w http.ResponseWriter, r *http.Request) {
	var e enquiry
	if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&e) != nil ||
		strings.TrimSpace(e.Name) == "" || !strings.Contains(e.Email, "@") {
		http.Error(w, "Please enter your name and a valid email.", http.StatusBadRequest)
		return
	}
	log.Printf("ENQUIRY %+v", e) // TODO: forward to info@topformtechnologies.com (SMTP/Resend)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// ---------- main ----------

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(r.URL.Path, "/admin") || strings.HasPrefix(r.URL.Path, "/api/admin") {
			h.Set("X-Robots-Tag", "noindex, nofollow")
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	upDir = filepath.Join(dataDir, "uploads")
	if err := os.MkdirAll(upDir, 0o755); err != nil {
		log.Fatal(err)
	}
	def := rnd(32)
	if adminPass != "" {
		d := sha256.Sum256([]byte("tf-session:" + adminPass))
		def = hex.EncodeToString(d[:])
	}
	secret = []byte(env("SESSION_SECRET", def))
	mime.AddExtensionType(".mp4", "video/mp4")
	mime.AddExtensionType(".webm", "video/webm")

	site, err := fs.Sub(content, "static")
	if err != nil {
		log.Fatal(err)
	}
	adminPage, err := fs.ReadFile(site, "admin.html")
	if err != nil {
		log.Fatal(err)
	}
	serveAdmin := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(adminPage)
	}
	uploads := http.StripPrefix("/uploads/", http.FileServer(http.Dir(upDir)))

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(site)))
	// Home 1 = the classic page, Home 2 = the new landing (also served at "/")
	homePage := func(file string) http.HandlerFunc {
		b, err := fs.ReadFile(site, file)
		if err != nil {
			log.Fatal(err)
		}
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(b)
		}
	}
	mux.HandleFunc("/home-1", homePage("home-1.html"))
	mux.HandleFunc("/home-2", homePage("home-2.html"))
	mux.HandleFunc("/home-3", homePage("home-3.html"))
	mux.HandleFunc("/home-4", homePage("home-4.html"))
	mux.HandleFunc("/home-5", homePage("home-5.html"))
	mux.HandleFunc("/home-6", homePage("home-6.html"))
	mux.HandleFunc("/home-7", homePage("home-7.html"))
	mux.HandleFunc("/home-8", homePage("home-8.html"))
	mux.HandleFunc("/admin", serveAdmin)
	mux.HandleFunc("/admin/", serveAdmin)
	mux.HandleFunc("/uploads/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=604800")
		uploads.ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/content", getContent)
	mux.HandleFunc("/api/contact", contact)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/api/admin/login", login)
	mux.HandleFunc("/api/admin/logout", logout)
	mux.HandleFunc("/api/admin/me", guard(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ok":true}`)) }))
	mux.HandleFunc("/api/admin/status", guard(status))
	mux.HandleFunc("/api/admin/content", guard(putContent))
	mux.HandleFunc("/api/admin/upload", guard(upload))
	mux.HandleFunc("/api/admin/media", guard(media))

	port := env("PORT", "8080")
	if adminPass == "" {
		log.Println("ADMIN_PASSWORD is not set: the admin only works on localhost (password: admin)")
	}
	log.Println("Topform site on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, secure(mux)))
}
