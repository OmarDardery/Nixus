// Command website renders repository Markdown into the searchable GitHub
// Pages site and, with -check, verifies internal links, anchors and assets.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	ghtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

const domain = "https://nixus.dardery.work"
const repo = "https://github.com/OmarDardery/Nixus"

type item struct{ slug, label string }
type group struct {
	title string
	items []item
}

var groups = []group{
	{"GET STARTED", []item{{"index", "Overview"}, {"plain-nixos", "Install Nixus"}, {"start", "First steps"}, {"home-server-scenario", "Homelab acceptance"}, {"architecture", "Architecture"}, {"target-architecture", "Target architecture (planned)"}, {"homelab", "Meet the current stack"}}},
	{"USE YOUR SERVER", []item{{"administration", "Accounts & access"}, {"networking", "Networking"}, {"guest-deployments", "Guest updates"}, {"file-modules", "File configuration"}, {"hardware", "Hardware & disks"}, {"helpers", "Application helpers"}, {"setup", "Optional web wizard"}}},
	{"WHEN THINGS HAPPEN", []item{{"troubleshooting", "Troubleshooting"}, {"recovery", "Backups & recovery"}, {"operations", "Operations & updates"}, {"commissioning", "Commissioning"}, {"trial", "Trial checklist"}, {"validation", "What is tested"}}},
	{"INCUS-NATIVE REBUILD", []item{{"migration-plan", "NixLab → Nixus migration"}, {"incus-native-architecture", "Architecture contract"}, {"incus-native-structure", "Repository and host layout"}, {"incus-native-plan", "Execution plan"}, {"incus-native-secrets-ui", "Declarative secrets UI"}, {"oci-source-intake", "OCI source uploads & build safety"}, {"incus-native-file-inventory", "Full source-file inventory"}}},
	{"PROJECT NOTES", []item{{"deployment", "Manual deployment"}, {"configuration-contract", "Configuration contract"}, {"ownership", "Ownership"}, {"credential-lifecycle", "Credential lifecycle"}, {"staged-transaction-secrets", "Staged credential lifetime"}, {"migration", "Migration"}, {"beta", "Beta candidate"}, {"projects", "Upstream credits"}, {"qualification", "Release qualification"}, {"roadmap", "Roadmap"}, {"website", "Website & DNS"}, {"go-runtime", "Go runtime"}}},
}

var descriptions = map[string]string{
	"index":               "Find the install guide, understand the stack, or skip directly to whatever is currently broken.",
	"plain-nixos":         "One command on an installed NixOS server. Preserve the machine, configure the stack and verify access.",
	"troubleshooting":     "Symptoms, checks and recovery commands from actual installation failures. Fewer guesses, better logs.",
	"recovery":            "NixOS can roll back code. Your databases would like a separate plan.",
	"commissioning":       "Prove the stack works on your hardware, including the very important second boot.",
	"website":             "Publish the docs with GitHub Pages and connect nixus.dardery.work.",
	"target-architecture": "Clean-slate Nixus: Incus projects, independent Nix flakes, Compose Web UI and one-time declarative backups. No historical server migration.",
}

var root, source string

func docURL(base, slug string) string {
	if slug == "index" {
		return base + "/docs/"
	}
	return base + "/docs/" + slug + "/"
}

func navigation(base, current string, pages map[string]bool) string {
	var b strings.Builder
	for _, g := range groups {
		b.WriteString("<section><h2>" + g.title + "</h2>")
		for _, it := range g.items {
			if !pages[it.slug] {
				continue
			}
			b.WriteString(`<a href="` + docURL(base, it.slug) + `"`)
			if it.slug == current {
				b.WriteString(` aria-current="page"`)
			}
			b.WriteString(">" + html.EscapeString(it.label) + "</a>")
		}
		b.WriteString("</section>")
	}
	return b.String()
}

func rewriteLink(target, from, base string) string {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "/") {
		return target
	}
	p := filepath.Clean(filepath.Join(filepath.Dir(from), parsed.Path))
	suffix := ""
	if parsed.RawQuery != "" {
		suffix += "?" + parsed.RawQuery
	}
	if parsed.Fragment != "" {
		suffix += "#" + parsed.Fragment
	}
	if filepath.Dir(p) == filepath.Join(root, "docs") && filepath.Ext(p) == ".md" {
		return docURL(base, strings.TrimSuffix(filepath.Base(p), ".md")) + suffix
	}
	if p == filepath.Join(root, "README.md") {
		return repo + "/blob/main/README.md" + suffix
	}
	if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
		if info, err := os.Stat(p); err == nil {
			kind := "blob"
			if info.IsDir() {
				kind = "tree"
			}
			return repo + "/" + kind + "/main/" + filepath.ToSlash(rel) + suffix
		}
	}
	return target
}

// slugIDs mirrors Python-Markdown's toc slugify so existing anchors keep working.
type slugIDs struct{ seen map[string]bool }

var nonWord = regexp.MustCompile(`[^\w\s-]`)
var dashes = regexp.MustCompile(`[-\s]+`)

func (s *slugIDs) Generate(value []byte, _ ast.NodeKind) []byte {
	var ascii strings.Builder
	for _, r := range string(value) {
		if r < 128 {
			ascii.WriteRune(r)
		} else if unicode.IsSpace(r) {
			ascii.WriteRune(' ')
		}
	}
	id := strings.ToLower(strings.TrimSpace(nonWord.ReplaceAllString(ascii.String(), "")))
	id = dashes.ReplaceAllString(id, "-")
	base := id
	for i := 1; s.seen[id]; i++ {
		id = base + "_" + strconv.Itoa(i)
	}
	s.seen[id] = true
	return []byte(id)
}

func (s *slugIDs) Put(value []byte) { s.seen[string(value)] = true }

type heading struct {
	level     int
	id, text_ string
}

var tableOpen = regexp.MustCompile(`<table>`)
var preCode = regexp.MustCompile(`<pre><code([^>]*)>`)

func nodeText(n ast.Node, src []byte) string {
	var b strings.Builder
	ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			switch t := c.(type) {
			case *ast.Text:
				b.Write(t.Segment.Value(src))
				if t.SoftLineBreak() || t.HardLineBreak() {
					b.WriteByte(' ')
				}
			case *ast.String:
				b.Write(t.Value)
			case *ast.CodeSpan:
				for child := t.FirstChild(); child != nil; child = child.NextSibling() {
					if tx, ok := child.(*ast.Text); ok {
						b.Write(tx.Segment.Value(src))
					}
				}
				return ast.WalkSkipChildren, nil
			case *ast.FencedCodeBlock, *ast.CodeBlock:
				lines := c.Lines()
				for i := 0; i < lines.Len(); i++ {
					seg := lines.At(i)
					b.Write(seg.Value(src))
				}
			}
		}
		return ast.WalkContinue, nil
	})
	return b.String()
}

func render(path, base string) (string, string, string, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", "", err
	}
	lines := strings.Split(string(raw), "\n")
	title := strings.TrimSpace(strings.TrimLeft(lines[0], "# "))
	body := []byte(strings.TrimLeft(strings.Join(lines[1:], "\n"), " \t\n"))
	md := goldmark.New(goldmark.WithExtensions(extension.Table), goldmark.WithParserOptions(parser.WithAutoHeadingID()),
		goldmark.WithRendererOptions(ghtml.WithXHTML()))
	ctx := parser.NewContext(parser.WithIDs(&slugIDs{seen: map[string]bool{}}))
	doc := md.Parser().Parse(text.NewReader(body), parser.WithContext(ctx))
	var headings []heading
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch t := n.(type) {
		case *ast.Link:
			t.Destination = []byte(rewriteLink(string(t.Destination), path, base))
		case *ast.Image:
			t.Destination = []byte(rewriteLink(string(t.Destination), path, base))
		case *ast.Heading:
			if id, ok := t.AttributeString("id"); ok && t.Level >= 2 && t.Level <= 3 {
				headings = append(headings, heading{t.Level, string(id.([]byte)), nodeText(t, body)})
			}
		}
		return ast.WalkContinue, nil
	})
	var buf bytes.Buffer
	if err := md.Renderer().Render(&buf, body, doc); err != nil {
		return "", "", "", "", err
	}
	out := tableOpen.ReplaceAllString(buf.String(), `<div class="table-scroll" tabindex="0" role="region" aria-label="Scrollable table"><table>`)
	out = strings.ReplaceAll(out, "</table>", "</table></div>")
	counter := 0
	out = preCode.ReplaceAllStringFunc(out, func(match string) string {
		counter++
		id := "nixus-code-" + strconv.Itoa(counter)
		attrs := preCode.FindStringSubmatch(match)[1]
		return `<div class="code-wrap"><button type="button" class="copy-button" data-copy="` + id + `" aria-label="Copy code block ` +
			strconv.Itoa(counter) + `">Copy</button><pre><code id="` + id + `"` + attrs + ">"
	})
	out = strings.ReplaceAll(out, "</code></pre>", "</code></pre></div>")
	var toc strings.Builder
	if len(headings) > 0 {
		toc.WriteString(`<div class="toc"><ul>`)
		level := headings[0].level
		open := 0
		for i, h := range headings {
			if i > 0 {
				switch {
				case h.level > level:
					toc.WriteString("<ul>")
					open++
				case h.level < level && open > 0:
					toc.WriteString("</li></ul></li>")
					open--
				default:
					toc.WriteString("</li>")
				}
			}
			level = h.level
			toc.WriteString(`<li><a href="#` + h.id + `">` + html.EscapeString(h.text_) + "</a>")
		}
		toc.WriteString("</li>")
		for ; open > 0; open-- {
			toc.WriteString("</ul></li>")
		}
		toc.WriteString("</ul></div>")
	}
	plain := strings.Join(strings.Fields(nodeText(doc, body)), " ")
	return title, out, toc.String(), plain, nil
}

var directive = regexp.MustCompile(`@@([A-Z]+)@@`)

func template(values map[string]string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(source, "templates/doc.html"))
	if err != nil {
		return "", err
	}
	return directive.ReplaceAllStringFunc(string(raw), func(m string) string { return values[m[2:len(m)-2]] }), nil
}

func copyFile(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(to), 0o755)
	return os.WriteFile(to, data, 0o644)
}

func copyDir(from, to string) error {
	return filepath.WalkDir(from, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		return copyFile(p, filepath.Join(to, rel))
	})
}

func runeTruncate(s string, n int) (string, bool) {
	r := []rune(s)
	if len(r) <= n {
		return s, false
	}
	return string(r[:n]), true
}

func build(output, base string) error {
	if entries, err := os.ReadDir(output); err == nil {
		if len(entries) > 0 {
			if _, err := os.Stat(filepath.Join(output, ".nojekyll")); err != nil {
				return errors.New("Refusing to replace a directory not owned by the website build: " + output)
			}
		}
		os.RemoveAll(output)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return err
	}
	if err := copyDir(filepath.Join(source, "assets"), filepath.Join(output, "assets")); err != nil {
		return err
	}
	shared := filepath.Join(root, "admin/static")
	for _, name := range []string{"brand.css", "favicon.svg"} {
		if err := copyFile(filepath.Join(shared, name), filepath.Join(output, "assets", name)); err != nil {
			return err
		}
	}
	if err := copyDir(filepath.Join(shared, "fonts"), filepath.Join(output, "assets/fonts")); err != nil {
		return err
	}
	os.WriteFile(filepath.Join(output, ".nojekyll"), nil, 0o644)
	landing, err := os.ReadFile(filepath.Join(source, "index.html"))
	if err != nil {
		return err
	}
	os.WriteFile(filepath.Join(output, "index.html"), []byte(strings.ReplaceAll(string(landing), "@@BASE@@", base)), 0o644)
	sources, _ := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	sort.Strings(sources)
	pages := map[string]bool{"index": true}
	for _, p := range sources {
		pages[strings.TrimSuffix(filepath.Base(p), ".md")] = true
	}
	registered := map[string]bool{}
	for _, g := range groups {
		for _, it := range g.items {
			registered[it.slug] = true
		}
	}
	var missing []string
	for p := range pages {
		if !registered[p] {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return errors.New("Add new docs to navigation: " + strings.Join(missing, ", "))
	}
	type entry struct {
		Title string `json:"title"`
		URL   string `json:"url"`
		Text  string `json:"text"`
	}
	var search []entry
	for _, p := range sources {
		title, body, toc, plain, err := render(p, base)
		if err != nil {
			return err
		}
		slug := strings.TrimSuffix(filepath.Base(p), ".md")
		description, ok := descriptions[slug]
		if !ok {
			short, cut := runeTruncate(plain, 165)
			description = strings.TrimSpace(short)
			if cut {
				description += "…"
			}
		}
		page, err := template(map[string]string{"BASE": base, "TITLE": html.EscapeString(title), "DESCRIPTION": html.EscapeString(description),
			"CANONICAL": "/docs/" + slug + "/", "NAV": navigation(base, slug, pages), "BODY": body, "TOC": toc,
			"SOURCE": repo + "/blob/main/docs/" + filepath.Base(p)})
		if err != nil {
			return err
		}
		destination := filepath.Join(output, "docs", slug, "index.html")
		os.MkdirAll(filepath.Dir(destination), 0o755)
		os.WriteFile(destination, []byte(page), 0o644)
		search = append(search, entry{title, docURL(base, slug), plain})
	}
	var cards strings.Builder
	for _, c := range [][2]string{{"plain-nixos", "Install Nixus ↗"}, {"troubleshooting", "Troubleshoot ↗"}, {"recovery", "Back up & recover ↗"}, {"commissioning", "Verify your hardware ↗"}} {
		cards.WriteString(`<a href="` + docURL(base, c[0]) + `"><h2>` + html.EscapeString(c[1]) + "</h2><p>" + html.EscapeString(descriptions[c[0]]) + "</p></a>")
	}
	body := "<p>Start with a plain installed NixOS server. The default installer configures Incus, Cockpit and the Nixus console, then verifies the enabled interfaces.</p><div class=\"docs-intro-grid\">" + cards.String() + "</div>"
	for _, g := range groups[1:] {
		body += "<h2>" + html.EscapeString(strings.Title(strings.ToLower(g.title))) + "</h2><ul>"
		for _, it := range g.items {
			body += `<li><a href="` + docURL(base, it.slug) + `">` + html.EscapeString(it.label) + "</a></li>"
		}
		body += "</ul>"
	}
	home, err := template(map[string]string{"BASE": base, "TITLE": "Read this before improvising.", "DESCRIPTION": descriptions["index"],
		"CANONICAL": "/docs/", "NAV": navigation(base, "index", pages), "BODY": body,
		"TOC": `<a href="` + docURL(base, "plain-nixos") + `">Start with installation →</a>`, "SOURCE": repo + "/tree/main/docs"})
	if err != nil {
		return err
	}
	os.WriteFile(filepath.Join(output, "docs", "index.html"), []byte(home), 0o644)
	index, _ := json.Marshal(search)
	os.WriteFile(filepath.Join(output, "search-index.json"), index, 0o644)
	notFound := `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>404 · Nixus</title><link rel="stylesheet" href="` + base + `/assets/brand.css"><link rel="stylesheet" href="` + base + `/assets/style.css"></head><body><main class="not-found section-wrap"><p class="eyebrow">404 / UNDECLARED RESOURCE</p><h1>This page failed to evaluate.</h1><p>Or the link moved. Either way, a rebuild of your server will not help.</p><a class="button button-primary" href="` + docURL(base, "index") + `">Back to the docs →</a></main></body></html>`
	os.WriteFile(filepath.Join(output, "404.html"), []byte(notFound), 0o644)
	urls := []string{domain + "/", domain + "/docs/"}
	for _, p := range sources {
		urls = append(urls, domain+"/docs/"+strings.TrimSuffix(filepath.Base(p), ".md")+"/")
	}
	var sitemap strings.Builder
	sitemap.WriteString(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
	for _, u := range urls {
		sitemap.WriteString("<url><loc>" + html.EscapeString(u) + "</loc></url>")
	}
	sitemap.WriteString("</urlset>")
	os.WriteFile(filepath.Join(output, "sitemap.xml"), []byte(sitemap.String()), 0o644)
	return os.WriteFile(filepath.Join(output, "robots.txt"), []byte("User-agent: *\nAllow: /\nSitemap: "+domain+"/sitemap.xml\n"), 0o644)
}

var idAttr = regexp.MustCompile(`\sid="([^"]*)"`)
var linkAttr = regexp.MustCompile(`<(?:a|link)\b[^>]*\shref="([^"]*)"|<(?:img|script)\b[^>]*\ssrc="([^"]*)"`)
var cssURL = regexp.MustCompile(`url\(['"]?([^)'"]+)`)
var unresolved = regexp.MustCompile(`@@[A-Z]+@@`)

func check(output, base string) error {
	type page struct {
		ids   map[string]bool
		links []string
	}
	pages := map[string]*page{}
	filepath.WalkDir(output, func(p string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(p, ".html") {
			raw, _ := os.ReadFile(p)
			text := string(raw)
			pg := &page{ids: map[string]bool{}}
			for _, m := range idAttr.FindAllStringSubmatch(text, -1) {
				pg.ids[html.UnescapeString(m[1])] = true
			}
			for _, m := range linkAttr.FindAllStringSubmatch(text, -1) {
				pg.links = append(pg.links, html.UnescapeString(m[1]+m[2]))
			}
			pages[p] = pg
			if unresolved.MatchString(text) {
				err = errors.New("Unresolved template: " + p)
			}
		}
		return err
	})
	var failures []string
	sheets, _ := filepath.Glob(filepath.Join(output, "assets", "*.css"))
	for _, sheet := range sheets {
		raw, _ := os.ReadFile(sheet)
		for _, m := range cssURL.FindAllStringSubmatch(string(raw), -1) {
			asset := m[1]
			if u, err := url.Parse(asset); (err == nil && u.Scheme != "") || strings.HasPrefix(asset, "data:") {
				continue
			}
			if info, err := os.Stat(filepath.Join(filepath.Dir(sheet), asset)); err != nil || info.IsDir() {
				failures = append(failures, "Missing CSS asset: "+asset)
			}
		}
	}
	for p, pg := range pages {
		rel, _ := filepath.Rel(output, p)
		relative := "/" + filepath.ToSlash(rel)
		for _, target := range pg.links {
			part, err := url.Parse(target)
			if err != nil || part.Scheme != "" || part.Host != "" {
				continue
			}
			var resolved string
			switch {
			case strings.HasPrefix(part.Path, "/"):
				if base != "" && !(part.Path == base || strings.HasPrefix(part.Path, base+"/")) {
					failures = append(failures, relative+": link escapes base path: "+target)
					continue
				}
				resolved = filepath.Join(output, strings.TrimLeft(strings.TrimPrefix(part.Path, base), "/"))
			case part.Path != "":
				resolved = filepath.Join(filepath.Dir(p), part.Path)
			default:
				resolved = p
			}
			if info, err := os.Stat(resolved); err == nil && info.IsDir() {
				resolved = filepath.Join(resolved, "index.html")
			}
			if info, err := os.Stat(resolved); err != nil || info.IsDir() {
				failures = append(failures, relative+": missing target: "+target)
				continue
			}
			if part.Fragment != "" && strings.HasSuffix(resolved, ".html") && pages[resolved] != nil && !pages[resolved].ids[part.Fragment] {
				failures = append(failures, relative+": missing anchor: "+target)
			}
		}
	}
	home, _ := os.ReadFile(filepath.Join(output, "index.html"))
	if !strings.Contains(string(home), "github:OmarDardery/Nixus#install") {
		failures = append(failures, "Missing canonical installation command")
	}
	raw, _ := os.ReadFile(filepath.Join(output, "search-index.json"))
	var index []map[string]string
	json.Unmarshal(raw, &index)
	for _, it := range index {
		if it["title"] == "" || it["text"] == "" {
			failures = append(failures, "Empty search entry")
		}
		target := filepath.Join(output, strings.TrimLeft(strings.TrimPrefix(it["url"], base), "/"), "index.html")
		if _, err := os.Stat(target); err != nil {
			failures = append(failures, "Search target missing: "+it["url"])
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return errors.New(strings.Join(failures, "\n"))
	}
	shown := base
	if shown == "" {
		shown = "/"
	}
	fmt.Printf("Checked %d HTML pages, internal links/anchors/assets and %d search entries (%s).\n", len(pages), len(index), shown)
	return nil
}

var basePath = regexp.MustCompile(`^(?:/[A-Za-z0-9_.-]+)*$`)

func main() {
	wd, _ := os.Getwd()
	flagRoot := flag.String("root", wd, "Repository root")
	output := flag.String("output", "", "Disposable build directory (default ROOT/_site)")
	baseArg := flag.String("base-path", "", "URL base path")
	doCheck := flag.Bool("check", false, "Verify links, anchors and assets")
	flag.Parse()
	root, _ = filepath.Abs(*flagRoot)
	source = filepath.Join(root, "website")
	if *output == "" {
		*output = filepath.Join(root, "_site")
	}
	out, _ := filepath.Abs(*output)
	base := ""
	if trimmed := strings.Trim(*baseArg, "/"); trimmed != "" {
		base = "/" + trimmed
	}
	if !basePath.MatchString(base) || strings.Contains(base, "..") {
		fmt.Fprintln(os.Stderr, "Use a simple URL base path")
		os.Exit(2)
	}
	within := func(child, parent string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && !strings.HasPrefix(rel, "..")
	}
	if out == root || within(root, out) || out == filepath.Join(root, "docs") || within(out, source) {
		fmt.Fprintln(os.Stderr, "Output must be a disposable build directory")
		os.Exit(2)
	}
	if err := build(out, base); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *doCheck {
		if err := check(out, base); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

var _ = util.Prioritized
