package main

// Shared helpers for the dynamic JSON documents that make up Nixus state and
// the broker API. Keys and shapes match the files the previous implementation
// wrote, so existing hosts and the browser UI keep working unchanged.

import (
	"bytes"
	"encoding/base64"
	"syscall"
	"unsafe"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// M is a JSON object.
type M = map[string]any

// PublicError carries a fixed, reviewed message that may be shown to users.
type PublicError struct{ msg string }

func (e *PublicError) Error() string { return e.msg }

// Public returns an error whose message is safe to show to the browser.
func Public(format string, args ...any) error {
	if len(args) == 0 {
		return &PublicError{format}
	}
	return &PublicError{fmt.Sprintf(format, args...)}
}

// Hidden returns an error whose message is never shown to the browser.
func Hidden(msg string) error { return errors.New(msg) }

// AuthorizationError marks a request by an authenticated but insufficient role.
type AuthorizationError struct{ msg string }

func (e *AuthorizationError) Error() string { return e.msg }

// PermissionError marks a missing or invalid authentication.
type PermissionError struct{ msg string }

func (e *PermissionError) Error() string { return e.msg }

func publicError(err error) string {
	var p *PublicError
	var a *AuthorizationError
	var q *PermissionError
	switch {
	case errors.As(err, &p):
		return p.msg
	case errors.As(err, &a):
		return a.msg
	case errors.As(err, &q):
		return q.msg
	}
	return "Request rejected; check inputs and authentication, then retry"
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// --- dynamic JSON access -------------------------------------------------

func str(v any) string {
	s, _ := v.(string)
	return s
}

func isStr(v any) bool { _, ok := v.(string); return ok }

func obj(v any) M {
	m, _ := v.(M)
	return m
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func num(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func isInt(v any) bool {
	f, ok := num(v)
	return ok && f == math.Trunc(f)
}

func boolean(v any) bool { b, _ := v.(bool); return b }

func isTrue(v any) bool { b, ok := v.(bool); return ok && b }

// path walks nested objects: path(m, "a", "b").
func path(m M, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		o, ok := cur.(M)
		if !ok {
			return nil
		}
		cur = o[k]
	}
	return cur
}

func keys(m M) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func strings2any(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func anyStrings(v any) ([]string, bool) {
	l, ok := v.([]any)
	if !ok {
		if s, ok := v.([]string); ok {
			return s, true
		}
		return nil, false
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func clone(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

func cloneM(m M) M { return obj(clone(m)) }

// equalJSON compares two values by canonical JSON encoding.
func equalJSON(a, b any) bool { return canonical(a) == canonical(b) }

// canonical encodes with sorted keys and compact separators.
func canonical(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(normalize(v))
	return strings.TrimSuffix(buf.String(), "\n")
}

// normalize round-trips Go values into plain JSON types (maps sort on encode).
func normalize(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&out) != nil {
		return v
	}
	return out
}

// digestJSON is sha256 over canonical JSON (sorted keys, compact).
func digestJSON(v any) string { return sha256hex([]byte(canonical(v))) }

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func parseJSON(raw []byte) (any, error) {
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseObject(raw []byte) (M, error) {
	v, err := parseJSON(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(M)
	if !ok {
		return nil, Hidden("not a JSON object")
	}
	return m, nil
}

func pretty(v any) string {
	raw, _ := json.MarshalIndent(v, "", "  ")
	return string(raw)
}

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// monotonic returns CLOCK_MONOTONIC seconds, shared by every process on a boot
// (deadlines stored in state files are compared across processes).
func monotonic() float64 {
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		return float64(time.Now().UnixNano()) / 1e9
	}
	return float64(ts.Sec) + float64(ts.Nsec)/1e9
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// --- randomness ------------------------------------------------------------

func tokenHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func tokenURLSafe(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64url(b)
}

func compareDigest(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func fullmatch(re *regexp.Regexp, s string) bool {
	loc := re.FindStringIndex(s)
	return loc != nil && loc[0] == 0 && loc[1] == len(s)
}

func re(pattern string) *regexp.Regexp { return regexp.MustCompile(`^(?:` + pattern + `)$`) }

// --- subprocesses ----------------------------------------------------------

type CmdResult struct {
	Stdout, Stderr []byte
	Code           int
}

// run executes argv with an optional stdin and timeout. It never uses a shell.
func run(argv []string, stdin []byte, timeout time.Duration, env []string, dir string) (CmdResult, error) {
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if env != nil {
		cmd.Env = env
	}
	cmd.Dir = dir
	err := cmd.Run()
	res := CmdResult{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	if cmd.ProcessState != nil {
		res.Code = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		return res, Hidden("command timed out")
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return res, err
	}
	return res, nil
}

// check runs argv and returns stdout, failing on a non-zero status.
func check(argv []string, stdin []byte, timeout time.Duration) ([]byte, error) {
	res, err := run(argv, stdin, timeout, nil, "")
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return res.Stdout, fmt.Errorf("%s exited with status %d", argv[0], res.Code)
	}
	return res.Stdout, nil
}

func environ(extra ...string) []string { return append(os.Environ(), extra...) }
