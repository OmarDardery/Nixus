package main

// Root configuration broker (private unix socket) and the authenticated,
// bounded HTTPS portal that forwards to it.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

var brokerSocket = envPath("NIXUS_SOCKET", "/run/nixus-admin/backend.sock")

const maxBody = 262144

var actorName = re(`[a-z][a-z0-9_-]{0,31}`)

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'"

type header struct{ k, v string }

func reply(w http.ResponseWriter, status int, data any, contentType string, extra ...header) {
	var body []byte
	if contentType == "" {
		contentType = "application/json"
		body = []byte(canonicalSpaced(data))
	} else {
		body = data.([]byte)
	}
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", csp)
	for _, e := range extra {
		h.Add(e.k, e.v)
	}
	w.WriteHeader(status)
	w.Write(body)
}

func replyError(w http.ResponseWriter, status int, msg string) { reply(w, status, M{"error": msg}, "") }

// checkFraming rejects ambiguous HTTP framing on every route.
func checkFraming(r *http.Request) (int64, error) {
	if len(r.TransferEncoding) > 0 || r.Header.Get("Transfer-Encoding") != "" {
		return 0, Public("Transfer encoding is not accepted")
	}
	lengths := r.Header.Values("Content-Length")
	if r.Method != http.MethodPost {
		if len(lengths) > 0 || r.ContentLength > 0 {
			return 0, Public("Request body is not accepted for this method")
		}
		return 0, nil
	}
	if len(lengths) != 1 || !fullmatch(re(`[0-9]+`), strings.TrimSpace(lengths[0])) {
		return 0, Public("Exactly one valid request length is required")
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(lengths[0]), 10, 64)
	if n <= 0 || n > maxBody {
		return 0, Public("Request body is missing or too large")
	}
	return n, nil
}

func jsonBody(r *http.Request) (M, error) {
	n, err := checkFraming(r)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, n+1))
	if err != nil {
		return nil, Public("Request body could not be read")
	}
	if int64(len(raw)) != n {
		return nil, Public("Incomplete request body")
	}
	v, err := parseJSON(raw)
	if err != nil {
		return nil, Public("Invalid JSON request body")
	}
	body, ok := v.(M)
	if !ok {
		return nil, Public("Request body must be an object")
	}
	return body, nil
}

func ack(v any) bool { return v == true }

// --- broker ----------------------------------------------------------------------

func brokerGet(p string, query url.Values) (any, error) {
	m := NewManager("", "")
	switch {
	case p == "/status":
		return m.status()
	case p == "/setup-progress":
		s, err := m.status()
		if err != nil {
			return nil, err
		}
		return setupProgress(s), nil
	case p == "/inventory":
		return m.hostInventory(), nil
	case p == "/main-revision":
		r, err := mainRevision()
		return M{"revision": r}, err
	case p == "/guest-network":
		s, err := m.effectiveSettings(nil)
		if err != nil {
			return nil, err
		}
		if !isTrue(s["ready"]) {
			return M{"available": false, "guests": []any{}, "conflicts": []any{}}, nil
		}
		return guestNetworkInventory()
	case p == "/oci/status":
		return NewOCIBuilds("", nil).status("")
	case p == "/project/status":
		return NewProjectTransactions("", "").status("")
	case p == "/project-secrets":
		return NewSecrets("", "", "").inventory()
	case p == "/apps":
		return appJobs(), nil
	case p == "/apps/env":
		return envNames(query.Get("project"))
	case p == "/apps/drafts":
		return listDrafts(), nil
	case p == "/devices":
		return hostDevices(), nil
	case p == "/apps-repo":
		return appsRepoView(), nil
	case p == "/backups/snapshots":
		return backupSnapshots()
	case p == "/backups/restore-status":
		return readObj(restoreReportPath()), nil
	case p == "/image-updates":
		return imageUpdatesView(), nil
	case p == "/project-overview":
		return projectOverview(), nil
	case p == "/project-file":
		return projectFile(query.Get("path"))
	case p == "/project-logs":
		return projectLog(query.Get("project"), query.Get("instance"))
	case p == "/project-backups":
		return projectBackupStatus(), nil
	case p == "/browser-certificates":
		return browserInventory(STATE)
	case p == "/health":
		return health(), nil
	case p == "/access":
		s, err := m.effectiveSettings(nil)
		if err != nil {
			return nil, err
		}
		hosts := []any{jget(s, "management", "address"), s["hostName"], "localhost", "127.0.0.1"}
		if out, err := check([]string{"ip", "-j", "-4", "address", "show", "dev", str(jget(s, "management", "interface"))}, nil, 5*time.Second); err == nil {
			links, _ := parseJSON(out)
			for _, l := range list(links) {
				for _, a := range list(obj(l)["addr_info"]) {
					if str(obj(a)["family"]) == "inet" {
						hosts = append(hosts, obj(a)["local"])
					}
				}
			}
		}
		return M{"networks": jget(s, "management", "trustedCIDRs"), "hosts": hosts}, nil
	case p == "/ca":
		raw, err := os.ReadFile(filepath.Join(STATE, "ca.crt"))
		return M{"certificate": string(raw)}, err
	}
	return nil, errNotFound
}

var errNotFound = errors.New("not found")

func required(body M, key string) (string, error) {
	v, ok := body[key]
	if !ok {
		return "", errMissing
	}
	return str(v), nil
}

var errMissing = errors.New("missing")

func brokerPost(p string, body M, actor string) (any, error) {
	m := NewManager("", "")
	switch p {
	case "/auth/linux":
		return linuxLogin(body["username"], body["password"])
	case "/oci/review":
		return NewOCIBuilds("", nil).review(body["project"], body["revision"], actor)
	case "/project-import/prepare", "/project-import/chunk", "/project-import/finish", "/project-import/review", "/project-import/publish", "/project-import/plan":
		return lockedValue(false, func() (any, error) {
			staging, err := NewImportStaging("")
			if err != nil {
				return nil, err
			}
			switch p {
			case "/project-import/prepare":
				archive := body["archive"]
				if archive == nil {
					archive = false
				}
				return staging.prepare(actor, body["project"], body["files"], archive)
			case "/project-import/chunk":
				return staging.chunk(body["id"], actor, body["path"], body["offset"], body["data"])
			case "/project-import/finish":
				return staging.finish(body["id"], actor, body["manifestHash"])
			case "/project-import/plan":
				return sourcePlan(body["project"], body["revision"], nil)
			case "/project-import/review":
				return NewPublishedSources("").review(staging, body["id"], actor, body["manifestHash"])
			}
			return NewPublishedSources("").publish(staging, body["id"], actor, body["reviewId"], ack(body["acknowledge"]))
		})
	case "/project-secrets/enroll", "/project-secrets/review", "/project-secrets/publish",
		"/project-secrets/reindex", "/project-secrets/recovery-export", "/project-secrets/recovery-verify", "/project-secrets/recovery-restore":
		return lockedValue(false, func() (any, error) {
			s := NewSecrets("", "", "")
			kit := NewRecoveryKit(s)
			switch p {
			case "/project-secrets/enroll":
				return s.enrollIdentity(actor, str(body["mode"]), body["privateKey"], ack(body["acknowledge"]))
			case "/project-secrets/review":
				return s.review(actor, body["project"], body["key"], str(body["action"]), body["value"], body["expectedRevision"])
			case "/project-secrets/publish":
				result, err := s.publish(actor, body["reviewId"], ack(body["acknowledge"]))
				if err == nil {
					result["delivery"] = deliverPublishedSecrets(str(result["project"]))
				}
				return result, err
			case "/project-secrets/reindex":
				return s.reindex(actor, body["project"], ack(body["acknowledge"]))
			case "/project-secrets/recovery-export":
				return kit.export(actor, body["passphrase"], ack(body["includeBackup"]))
			case "/project-secrets/recovery-verify":
				return kit.inspect(actor, body["encrypted"], body["passphrase"])
			}
			return kit.restore(actor, body["encrypted"], body["passphrase"], ack(body["acknowledge"]))
		})
	case "/review":
		settings, ok := body["settings"]
		if !ok {
			return nil, errMissing
		}
		secrets := obj(body["secrets"])
		return m.review(obj(settings), ReviewOptions{Secrets: secrets, UpdateInputs: ack(body["updateInputs"]), Modules: obj(body["modules"]),
			Revision: body["revision"], Principal: actor})
	case "/apply", "/cancel", "/confirm", "/rollback":
		id, err := required(body, "id")
		if err != nil {
			return nil, err
		}
		switch p {
		case "/apply":
			return m.apply(id)
		case "/cancel":
			return m.cancel(id)
		case "/confirm":
			return m.confirm(id)
		}
		return m.rollback(id)
	case "/project/initialize", "/project/review", "/project/publish", "/project/deploy":
		t := NewProjectTransactions("", "")
		switch p {
		case "/project/initialize":
			return t.initialize(body["flake"], body["lock"], actor)
		case "/project/review":
			return t.review(body["changes"], actor, body["sourceRevisions"])
		case "/project/publish":
			return t.publish(body["id"], body["planHash"])
		}
		return t.deploy(body["id"], body["planHash"], ack(body["resume"]))
	case "/browser-certificate":
		fullAdmin := body["fullAdmin"]
		if fullAdmin == nil {
			fullAdmin = false
		}
		return browserIssue(STATE, body["device"], body["passphrase"], actor, fullAdmin, body["renew"])
	case "/image-updates/check":
		return checkImageUpdates()
	case "/apps/deploy":
		return startAppDeploy(actor, body)
	case "/apps/backup-policy":
		return saveBackupPolicy(actor, body["policy"])
	case "/apps/backup-setup":
		return setupBackups(actor, body)
	case "/backups/restore":
		return startRestore(actor, body)
	case "/apps/import-data/start":
		return startDataImport(actor, body)
	case "/apps/import-data/chunk":
		return chunkDataImport(body)
	case "/apps/import-data/finish":
		return finishDataImport(actor, body)
	case "/apps/draft-save":
		return saveDraft(actor, body)
	case "/apps/draft-read":
		return readDraft(body["name"], ack(body["withEnv"]))
	case "/apps/draft-delete":
		return deleteDraft(body["name"])
	case "/apps/env-read":
		return readEnv(body["project"])
	case "/apps/env":
		return saveEnv(actor, body["project"], body["vars"], body["revision"])
	case "/apps/power":
		return appPower(actor, body)
	case "/apps/delete":
		return deleteApp(actor, body)
	case "/apps-repo/key":
		return ensureAppsRepoKey()
	case "/apps-repo/scan":
		return scanAppsRepo(body)
	case "/apps-repo/connect":
		return withRepoLock(func() (M, error) { return connectAppsRepo(actor, body) })
	case "/apps-repo/check":
		return withRepoLock(checkAppsRepo)
	case "/apps-repo/deploy":
		return startAppsRepoDeploy(actor, body)
	case "/apps-repo/disconnect":
		return withRepoLock(func() (M, error) { return disconnectAppsRepo(actor) })
	case "/image-updates/pin":
		return pinSources(body["files"])
	case "/apps/backup-run":
		return startProjectBackup(actor)
	case "/image-updates/apply":
		return startImageUpdate(actor, body["project"])
	case "/image-updates/apply-all":
		return startAllImageUpdates(actor)
	case "/image-updates/hold":
		return setHold(actor, body["project"], body["digest"], ack(body["hold"]), "held by an administrator")
	case "/revoke-browser-certificate":
		return browserRevoke(STATE, body["fingerprint"], actor)
	}
	return nil, errNotFound
}

func brokerHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recover() != nil {
			replyError(w, 500, "Operation failed; inspect the root broker journal")
		}
	}()
	switch r.Method {
	case http.MethodGet:
		if _, err := checkFraming(r); err != nil {
			replyError(w, 400, publicError(err))
			return
		}
		result, err := brokerGet(r.URL.Path, r.URL.Query())
		switch {
		case errors.Is(err, errNotFound):
			replyError(w, 404, "Unknown endpoint")
		case err != nil:
			var p *PublicError
			if errors.As(err, &p) {
				replyError(w, 400, p.msg)
			} else {
				replyError(w, 500, "Could not retrieve management status; inspect the host services")
			}
		default:
			reply(w, 200, result, "")
		}
	case http.MethodPost:
		body, err := jsonBody(r)
		if err != nil {
			w.Header().Set("Connection", "close")
			replyError(w, 400, publicError(err))
			return
		}
		actor := "root"
		if v, ok := body["_actor"]; ok {
			actor, _ = v.(string)
			delete(body, "_actor")
		}
		if !fullmatch(actorName, actor) {
			replyError(w, 400, "Invalid audit identity")
			return
		}
		audit("broker-request", M{"principal": actor, "operation": r.URL.Path})
		result, err := brokerPost(r.URL.Path, body, actor)
		switch {
		case errors.Is(err, errNotFound):
			replyError(w, 404, "Unknown action")
		case errors.Is(err, errMissing):
			replyError(w, 400, "A required request field or configuration value is missing")
		case err != nil:
			var p *PublicError
			var a *AuthorizationError
			var q *PermissionError
			if errors.As(err, &p) || errors.As(err, &a) || errors.As(err, &q) {
				replyError(w, 400, publicError(err))
			} else {
				replyError(w, 500, "Operation failed; inspect the root broker journal")
			}
		default:
			reply(w, 200, result, "")
		}
	default:
		replyError(w, 405, "Method not allowed")
	}
}

func backendMain() int {
	os.MkdirAll(filepath.Dir(brokerSocket), 0o755)
	os.Remove(brokerSocket)
	listener, err := net.Listen("unix", brokerSocket)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Broker socket unavailable")
		return 1
	}
	os.Chmod(brokerSocket, 0o660)
	server := &http.Server{Handler: http.HandlerFunc(brokerHandler), ReadHeaderTimeout: 15 * time.Second,
		MaxHeaderBytes: 16384, ErrorLog: nilLogger()}
	server.Serve(listener)
	return 1
}

var brokerClient = &http.Client{Timeout: 150 * time.Second, Transport: &http.Transport{
	DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", brokerSocket)
	}}}

func brokerRequest(method, p string, value any) (M, error) {
	var body io.Reader
	if value != nil {
		body = bytes.NewReader([]byte(canonicalSpaced(value)))
	}
	req, _ := http.NewRequest(method, "http://localhost"+p, body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := brokerClient.Do(req)
	if err != nil {
		return nil, Public("Management broker unavailable")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	payload, err := parseObject(raw)
	if err != nil {
		return nil, Public("Invalid broker response")
	}
	if resp.StatusCode != 200 {
		msg := str(payload["error"])
		if msg == "" {
			msg = "Broker request failed"
		}
		return nil, Public(msg)
	}
	return payload, nil
}

// --- portal sessions -------------------------------------------------------------------

type session struct {
	csrf, username, role, identity string
	created, used                  time.Time
	authenticatedAt                float64
	issuing                        bool
	download                       *pendingDownload
}

type pendingDownload struct {
	data              []byte
	name, fingerprint string
	deadline          time.Time
}

type Auth struct {
	mu       sync.Mutex
	sessions map[string]*session
	failures map[string][]time.Time
}

func NewAuth() *Auth {
	return &Auth{sessions: map[string]*session{}, failures: map[string][]time.Time{}}
}

func (a *Auth) login(password any, address, username string) (string, string, error) {
	// Rate-limit per address. The password check runs outside the lock: a
	// Linux (PAM) check takes a moment and must not stall other sessions.
	a.mu.Lock()
	nowT := time.Now()
	var attempts []time.Time
	for _, t := range a.failures[address] {
		if nowT.Sub(t) < 5*time.Minute {
			attempts = append(attempts, t)
		}
	}
	a.failures[address] = attempts
	// Count this attempt up front so parallel guesses share the limit.
	a.failures[address] = append(attempts, nowT)
	a.mu.Unlock()
	if len(attempts) >= 5 {
		return "", "", Public("Too many sign-in attempts; wait five minutes")
	}
	// Single-user console: a Linux account with sudo, checked by the root
	// broker through PAM.
	if _, err := linuxVerify(username, password); err != nil {
		return "", "", Public("Invalid username or password")
	}
	role, identity := "admin", "linux:"+username
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.failures, address)
	if len(a.sessions) > 128 {
		a.sessions = map[string]*session{}
	}
	token, csrf := tokenURLSafe(32), tokenURLSafe(32)
	a.sessions[token] = &session{csrf: csrf, username: username, role: role, identity: identity,
		created: nowT, used: nowT, authenticatedAt: now()}
	return token, csrf, nil
}

func cookieValue(headerValue, name string) []string {
	var values []string
	for _, part := range strings.Split(headerValue, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, name+"=") {
			values = append(values, strings.SplitN(part, "=", 2)[1])
		}
	}
	return values
}

// linuxVerify asks the broker to check a Linux account's password.
var linuxVerify = func(username string, password any) (M, error) {
	pw, ok := password.(string)
	if !ok || !fullmatch(hostUser, username) {
		return nil, Public("Invalid username or password")
	}
	return brokerRequest("POST", "/auth/linux", M{"username": username, "password": pw})
}

// passwordOK re-checks the signed-in user's Linux password before sensitive actions.
func passwordOK(s *session, password any) bool {
	_, err := linuxVerify(s.username, password)
	return err == nil
}

func (a *Auth) get(cookie string) *session {
	token := ""
	if v := cookieValue(cookie, "nixus_session"); len(v) > 0 {
		token = v[len(v)-1]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	nowT := time.Now()
	for _, s := range a.sessions {
		if s.download != nil && nowT.After(s.download.deadline) {
			s.download = nil
		}
	}
	item := a.sessions[token]
	if item == nil || nowT.Sub(item.used) > 30*time.Minute || nowT.Sub(item.created) > 8*time.Hour {
		delete(a.sessions, token)
		return nil
	}
	item.used = nowT
	return item
}

var browserIdentityName = re(`nixus-browser-[A-Za-z0-9_-]{1,64}`)

func (a *Auth) stageCertificate(s *session, result M) (M, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	alive := false
	for _, item := range a.sessions {
		alive = alive || item == s
	}
	if !alive {
		return nil, Public("Session ended; inspect the identity list before reissuing")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(str(result["pkcs12"]))
	if err != nil || len(data) > 65536 || !fullmatch(browserIdentityName, str(result["name"])) {
		return nil, Public("Invalid private certificate download; inspect the identity list")
	}
	s.download = &pendingDownload{data, str(result["name"]), str(result["fingerprint"]), time.Now().Add(2 * time.Minute)}
	out := M{"downloadSeconds": 120}
	for _, k := range []string{"name", "device", "fingerprint", "owner", "issuedAt", "expiresAt", "restricted", "projects", "status", "validDays"} {
		out[k] = result[k]
	}
	return out, nil
}

// --- portal ------------------------------------------------------------------------------

var staticAssets = map[string][2]string{
	"/": {"index.html", "text/html; charset=utf-8"}, "/app.js": {"app.js", "text/javascript; charset=utf-8"},
	"/projects.js": {"projects.js", "text/javascript; charset=utf-8"}, "/apps.js": {"apps.js", "text/javascript; charset=utf-8"}, "/quick.js": {"quick.js", "text/javascript; charset=utf-8"}, "/backups.js": {"backups.js", "text/javascript; charset=utf-8"}, "/repo.js": {"repo.js", "text/javascript; charset=utf-8"},
	"/incus-secrets.js": {"incus-secrets.js", "text/javascript; charset=utf-8"}, "/api.js": {"api.js", "text/javascript; charset=utf-8"},
	"/events.js": {"events.js", "text/javascript; charset=utf-8"}, "/operations.js": {"operations.js", "text/javascript; charset=utf-8"},
	"/commands.js": {"commands.js", "text/javascript; charset=utf-8"}, "/setup.js": {"setup.js", "text/javascript; charset=utf-8"},
	"/foundation.js": {"foundation.js", "text/javascript; charset=utf-8"}, "/style.css": {"style.css", "text/css; charset=utf-8"},
	"/brand.css": {"brand.css", "text/css; charset=utf-8"}, "/favicon.svg": {"favicon.svg", "image/svg+xml"},
	"/fonts/dm-sans-latin.woff2":       {"fonts/dm-sans-latin.woff2", "font/woff2"},
	"/fonts/geist-variable.woff2":      {"fonts/geist-variable.woff2", "font/woff2"},
	"/fonts/geist-mono-variable.woff2": {"fonts/geist-mono-variable.woff2", "font/woff2"},
	"/fonts/space-grotesk-latin.woff2": {"fonts/space-grotesk-latin.woff2", "font/woff2"},
}

var adminGets = map[string]bool{"/api/main-revision": true,
	"/api/project-secrets": true, "/api/project-backups": true, "/api/project-overview": true, "/api/image-updates": true, "/api/apps": true, "/api/apps/env": true, "/api/apps/drafts": true, "/api/devices": true, "/api/apps-repo": true, "/api/backups/snapshots": true, "/api/backups/restore-status": true, "/api/project-file": true, "/api/project-logs": true, "/api/setup-progress": true}
var sharedGets = map[string]bool{"/api/status": true, "/api/inventory": true, "/api/ca": true,
	"/api/guest-network": true, "/api/health": true}
var portalActions = map[string]bool{}

func init() {
	for _, a := range strings.Fields(`/api/project-import/prepare /api/project-import/chunk /api/project-import/finish
		/api/review /api/apply /api/confirm /api/rollback /api/cancel
		/api/project-secrets/enroll /api/project-secrets/review /api/project-secrets/publish /api/project-secrets/reindex
		/api/project-secrets/recovery-export /api/project-secrets/recovery-verify /api/project-secrets/recovery-restore /api/image-updates/check
		/api/image-updates/apply /api/image-updates/hold /api/apps/deploy /api/apps/backup-run /api/apps/backup-setup /api/image-updates/apply-all
		/api/backups/restore /api/apps/import-data/start /api/apps/import-data/chunk /api/apps/import-data/finish /api/image-updates/pin /api/apps/env-read /api/apps/draft-save /api/apps/draft-read /api/apps/draft-delete /api/apps/env /api/apps/power /api/apps/delete /api/apps-repo/key /api/apps-repo/scan /api/apps-repo/connect /api/apps-repo/check /api/apps-repo/deploy /api/apps-repo/disconnect`) {
		portalActions[a] = true
	}
}

type portal struct {
	auth *Auth
	port int
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (p *portal) access(r *http.Request) (string, error) {
	settings, err := brokerRequest("GET", "/access", nil)
	if err != nil {
		return "", err
	}
	addr, err := netip.ParseAddr(clientIP(r))
	if err != nil {
		return "", &PermissionError{"Management source network is not trusted"}
	}
	addr = addr.Unmap()
	trusted := addr.IsLoopback()
	for _, n := range list(settings["networks"]) {
		if prefix, err := netip.ParsePrefix(str(n)); err == nil && prefix.Contains(addr) {
			trusted = true
		}
	}
	if !trusted {
		return "", &PermissionError{"Management source network is not trusted"}
	}
	hosts := r.Header.Values("Host")
	if len(hosts) == 0 && r.Host != "" {
		hosts = []string{r.Host}
	}
	if len(hosts) != 1 {
		return "", &PermissionError{"Exactly one management hostname is required"}
	}
	host := hosts[0]
	parsed, err := url.Parse("https://" + host)
	valid := err == nil && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" &&
		(parsed.Port() == "" || parsed.Port() == strconv.Itoa(p.port))
	if valid {
		known := false
		for _, h := range list(settings["hosts"]) {
			known = known || str(h) == parsed.Hostname()
		}
		valid = known
	}
	if !valid {
		return "", &PermissionError{"Invalid management hostname"}
	}
	return host, nil
}

func (p *portal) session(r *http.Request, mutation bool) (*session, error) {
	host, err := p.access(r)
	if err != nil {
		return nil, err
	}
	if mutation && r.Header.Get("Origin") != "https://"+host {
		return nil, &PermissionError{"Same-origin request required"}
	}
	s := p.auth.get(r.Header.Get("Cookie"))
	if s == nil {
		return nil, &PermissionError{"Sign in to continue"}
	}
	if mutation && !compareDigest(r.Header.Get("X-Nixus-CSRF"), s.csrf) {
		return nil, &PermissionError{"Invalid request token"}
	}
	return s, nil
}

func portalError(w http.ResponseWriter, err error, closeConn bool) {
	if closeConn {
		w.Header().Set("Connection", "close")
	}
	var a *AuthorizationError
	var q *PermissionError
	switch {
	case errors.As(err, &a):
		replyError(w, 403, a.msg)
	case errors.As(err, &q):
		replyError(w, 401, q.msg)
	default:
		replyError(w, 400, publicError(err))
	}
}

var guideName = re(`[a-z0-9-]+\.md`)
var markdown = goldmark.New(goldmark.WithExtensions(extension.Table))

func renderGuide(name string) ([]byte, int) {
	if !fullmatch(guideName, name) {
		return nil, 404
	}
	directory := filepath.Join(SOURCE, "docs")
	if !isDir(directory) {
		directory = filepath.Join(filepath.Dir(SOURCE), "docs")
	}
	text, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		return nil, 410
	}
	var buf bytes.Buffer
	if markdown.Convert(text, &buf) != nil {
		buf.Reset()
		buf.WriteString("<pre>" + html.EscapeString(string(text)) + "</pre>")
	}
	page := `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<meta name="theme-color" content="#111310"><title>Nixus · Offline guide</title>` +
		`<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/brand.css"><link rel="stylesheet" href="/style.css">` +
		`<body><main class="page offline-guide"><header class="guide-bar"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true">[n]</span><span>nixus<span class="brand-cursor" aria-hidden="true">_</span></span></a><a href="/">Back to host console →</a></header><article class="card">` +
		buf.String() + `</article></main></body></html>`
	return []byte(page), 200
}

const sessionCookie = "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age="

func (p *portal) get(w http.ResponseWriter, r *http.Request) error {
	_, err := p.access(r)
	if err != nil {
		return err
	}
	path := r.URL.Path
	if asset, ok := staticAssets[path]; ok {
		data, err := os.ReadFile(filepath.Join(SOURCE, "static", asset[0]))
		if err != nil {
			return Public("Asset unavailable")
		}
		reply(w, 200, data, asset[1])
		return nil
	}
	switch path {
	case "/ca.crt":
		ca, err := brokerRequest("GET", "/ca", nil)
		if err != nil {
			return err
		}
		reply(w, 200, []byte(str(ca["certificate"])), "application/x-x509-ca-cert", header{"Content-Disposition", "attachment; filename=nixus-ca.crt"})
		return nil
	}
	s, err := p.session(r, false)
	if err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(path, "/docs/"):
		page, status := renderGuide(strings.TrimPrefix(path, "/docs/"))
		if status == 404 {
			replyError(w, 404, "Choose a packaged Markdown guide")
		} else if status != 200 {
			replyError(w, 404, "Guide not found")
		} else {
			reply(w, 200, page, "text/html; charset=utf-8")
		}
		return nil
	case path == "/api/session":
		reply(w, 200, M{"csrf": s.csrf, "username": s.username, "role": s.role}, "")
		return nil
	case path == "/api/browser-certificates" || adminGets[path]:
		if s.role != "admin" {
			return &AuthorizationError{"Administrator account required"}
		}
		result, err := brokerRequest("GET", strings.TrimPrefix(path, "/api")+forwardedQuery(path, r), nil)
		if err != nil {
			return err
		}
		reply(w, 200, result, "")
		return nil
	case strings.HasPrefix(path, "/api/deployment/") || sharedGets[path]:
		result, err := brokerRequest("GET", strings.TrimPrefix(path, "/api"), nil)
		if err != nil {
			return err
		}
		if path == "/api/status" && s.role != "admin" && result["job"] != nil {
			job := cloneM(obj(result["job"]))
			delete(job, "log")
			delete(job, "moduleChanges")
			delete(job, "platformChanges")
			result["job"] = job
		}
		reply(w, 200, result, "")
		return nil
	}
	replyError(w, 404, "Unknown endpoint")
	return nil
}

func requireFreshWebConfirmation(s *session, job M, address string) error {
	if job == nil || str(job["status"]) != "awaiting-confirmation" {
		return Public("No active transaction is awaiting access confirmation")
	}
	addr, err := netip.ParseAddr(address)
	if err != nil || addr.Unmap().IsLoopback() {
		return &PermissionError{"Loopback access cannot confirm remote management; use a fresh LAN login or local console"}
	}
	ready, ok := num(job["awaitingAt"])
	if !ok {
		ready, ok = num(job["appliedAt"])
	}
	if !ok || s.authenticatedAt <= ready {
		return &PermissionError{"Sign out, reconnect to the new management address, and sign in again before confirming"}
	}
	return nil
}

func (p *portal) post(w http.ResponseWriter, r *http.Request) error {
	host, err := p.access(r)
	if err != nil {
		return err
	}
	if r.Header.Get("Origin") != "https://"+host {
		return &PermissionError{"Same-origin request required"}
	}
	path := r.URL.Path
	switch path {
	case "/api/login":
		body, err := jsonBody(r)
		if err != nil {
			return err
		}
		username := body["username"]
		if username == nil {
			username = "admin"
		}
		token, csrf, err := p.auth.login(body["password"], clientIP(r), str(username))
		if err != nil {
			return err
		}
		reply(w, 200, M{"csrf": csrf, "username": username, "role": p.auth.get("nixus_session=" + token).role}, "",
			header{"Set-Cookie", "nixus_session=" + token + sessionCookie + "28800"})
		return nil
	}
	s, err := p.session(r, true)
	if err != nil {
		return err
	}
	body, err := jsonBody(r)
	if err != nil {
		return err
	}
	reauth := func(field, message string) error {
		current := body[field]
		delete(body, field)
		if !passwordOK(s, current) {
			return Public(message)
		}
		return nil
	}
	if strings.HasPrefix(path, "/api/project-secrets/") {
		if err := reauth("current", "Reauthenticate to manage encrypted project secrets"); err != nil {
			return err
		}
	}
	switch path {
	case "/api/project-import/prepare", "/api/image-updates/apply", "/api/apps/deploy", "/api/apps/delete", "/api/apps/backup-setup", "/api/image-updates/apply-all", "/api/backups/restore", "/api/apps/import-data/start", "/api/apps/env-read", "/api/apps/env", "/api/apps-repo/connect", "/api/apps-repo/deploy", "/api/apps-repo/disconnect":
		if err := reauth("current", "Reauthenticate before changing project source"); err != nil {
			return err
		}
	case "/api/apps/draft-read":
		// Saved variables are only returned after the password is checked.
		delete(body, "withEnv")
		if body["current"] != nil {
			if err := reauth("current", "Reauthenticate to open saved variables"); err != nil {
				return err
			}
			body["withEnv"] = true
		}
	case "/api/browser-certificate/download":
		p.auth.mu.Lock()
		pending := s.download
		s.download = nil
		p.auth.mu.Unlock()
		if pending == nil || time.Now().After(pending.deadline) {
			return Public("Certificate download expired or was already claimed; inspect the identity list to revoke or reissue")
		}
		reply(w, 200, pending.data, "application/x-pkcs12", header{"Content-Disposition", `attachment; filename="` + pending.name + `.p12"`})
		return nil
	case "/api/browser-certificate", "/api/revoke-browser-certificate":
		if err := reauth("current", "Reauthenticate before issuing or revoking browser identities"); err != nil {
			return err
		}
		if path == "/api/revoke-browser-certificate" {
			result, err := brokerRequest("POST", "/revoke-browser-certificate", M{"fingerprint": body["fingerprint"], "_actor": s.username})
			if err != nil {
				return err
			}
			p.auth.mu.Lock()
			for _, other := range p.auth.sessions {
				if other.download != nil && other.download.fingerprint == str(body["fingerprint"]) {
					other.download = nil
				}
			}
			p.auth.mu.Unlock()
			reply(w, 200, result, "")
			return nil
		}
		fullAdmin := body["fullAdmin"]
		acknowledged := body["acknowledgeFullAdmin"]
		delete(body, "acknowledgeFullAdmin")
		if fullAdmin != nil && fullAdmin != false && acknowledged != true {
			return Public("Explicitly acknowledge that unrestricted Incus access grants host administration")
		}
		p.auth.mu.Lock()
		if s.download != nil && time.Now().After(s.download.deadline) {
			s.download = nil
		}
		if s.issuing || s.download != nil {
			p.auth.mu.Unlock()
			return Public("Claim the pending certificate download before issuing another identity")
		}
		s.issuing = true
		p.auth.mu.Unlock()
		defer func() { p.auth.mu.Lock(); s.issuing = false; p.auth.mu.Unlock() }()
		body["_actor"] = s.username
		result, err := brokerRequest("POST", "/browser-certificate", body)
		if err != nil {
			return err
		}
		if p.auth.get(r.Header.Get("Cookie")) == nil {
			return Public("Session ended; inspect the identity list before reissuing")
		}
		metadata, err := p.auth.stageCertificate(s, result)
		if err != nil {
			return err
		}
		reply(w, 200, metadata, "")
		return nil
	case "/api/logout":
		p.auth.mu.Lock()
		s.download = nil
		s.created = time.Time{}
		p.auth.mu.Unlock()
		reply(w, 200, M{"ok": true}, "", header{"Set-Cookie", "nixus_session=" + sessionCookie + "0"})
		return nil
	case "/api/review":
		password := body["adminPassword"]
		delete(body, "adminPassword")
		if (body["modules"] != nil && len(obj(body["modules"])) > 0) || (body["revision"] != nil && body["revision"] != "") {
			if !ack(body["acknowledgePrivilegedModules"]) {
				return Public("Explicitly approve the privileged platform revision or Nix modules before building")
			}
			if !passwordOK(s, password) {
				return Public("Reauthenticate with your password before building privileged code")
			}
		}
	case "/api/confirm":
		state, err := brokerRequest("GET", "/status", nil)
		if err != nil {
			return err
		}
		active := obj(state["job"])
		if active == nil || str(active["id"]) != str(body["id"]) {
			return Public("Confirm the current reviewed transaction only")
		}
		if err := requireFreshWebConfirmation(s, active, clientIP(r)); err != nil {
			return err
		}
	}
	if !portalActions[path] {
		replyError(w, 404, "Unknown action")
		return nil
	}
	body["_actor"] = s.username
	result, err := brokerRequest("POST", strings.TrimPrefix(path, "/api"), body)
	if err != nil {
		return err
	}
	reply(w, 200, result, "")
	return nil
}

func (p *portal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recover() != nil {
			w.Header().Set("Connection", "close")
			replyError(w, 400, "Request rejected; check inputs and authentication, then retry")
		}
	}()
	if !strings.HasPrefix(r.RequestURI, "/") || strings.HasPrefix(r.RequestURI, "//") || len(r.RequestURI) > 4096 {
		w.Header().Set("Connection", "close")
		http.Error(w, "Bad Request", 400)
		return
	}
	if _, err := checkFraming(r); err != nil {
		w.Header().Set("Connection", "close")
		http.Error(w, "Bad Request", 400)
		return
	}
	if r.Header.Get("Expect") != "" {
		w.Header().Set("Connection", "close")
		http.Error(w, "Expectation Failed", 417)
		return
	}
	var err error
	switch r.Method {
	case http.MethodGet:
		err = p.get(w, r)
		if err != nil {
			portalError(w, err, false)
		}
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		err = p.post(w, r)
		if err != nil {
			portalError(w, err, true)
		}
	default:
		w.Header().Set("Connection", "close")
		http.Error(w, "Method Not Allowed", 405)
	}
}

// limitListener bounds concurrently served clients; extras are dropped.
type limitListener struct {
	net.Listener
	slots chan struct{}
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}

// redirectHandler redirects plain HTTP entry requests on port 80 to the HTTPS
// portal with 308 Permanent Redirect, replacing nginx.
func redirectHandler(httpsPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.RequestURI, "/") || strings.HasPrefix(r.RequestURI, "//") || len(r.RequestURI) > 4096 {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host == "" || strings.ContainsAny(host, "/\\ \t\r\n@") {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		target := fmt.Sprintf("https://%s:%d%s", host, httpsPort, r.RequestURI)
		w.Header().Set("Location", target)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusPermanentRedirect)
	})
}

func webMain() int {
	port := 9440
	if v, err := strconv.Atoi(os.Getenv("NIXUS_PORT")); err == nil {
		port = v
	}
	credentials := os.Getenv("CREDENTIALS_DIRECTORY")
	if credentials == "" {
		credentials = STATE
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(credentials, "tls.crt"), filepath.Join(credentials, "tls.key"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "TLS credentials unavailable")
		return 1
	}
	if redirectPort, err := strconv.Atoi(os.Getenv("NIXUS_REDIRECT_PORT")); err == nil && redirectPort > 0 && redirectPort < 65536 {
		if redirLn, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", redirectPort)); err != nil {
			fmt.Fprintln(os.Stderr, "Portal redirect port unavailable:", err)
		} else {
			redirSrv := &http.Server{
				Handler:           redirectHandler(port),
				ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 10 * time.Second,
				MaxHeaderBytes: 8192, ErrorLog: nilLogger(),
			}
			go redirSrv.Serve(&limitListener{redirLn, make(chan struct{}, 32)})
		}
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Portal port unavailable")
		return 1
	}
	limited := &limitListener{listener, make(chan struct{}, 32)}
	server := &http.Server{
		Handler:           &portal{auth: NewAuth(), port: port},
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 15 * time.Second, ReadTimeout: 45 * time.Second, IdleTimeout: 20 * time.Second,
		MaxHeaderBytes: 16384, ErrorLog: nilLogger(),
	}
	server.ServeTLS(limited, "", "")
	return 1
}

// forwardedQuery passes only the reviewed query parameters of read-only views.
func forwardedQuery(path string, r *http.Request) string {
	allowed := map[string][]string{"/api/apps/env": {"project"}, "/api/project-file": {"path"}, "/api/project-logs": {"project", "instance"}}
	names, ok := allowed[path]
	if !ok {
		return ""
	}
	q := url.Values{}
	for _, n := range names {
		if v := r.URL.Query().Get(n); v != "" {
			q.Set(n, v)
		}
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}
