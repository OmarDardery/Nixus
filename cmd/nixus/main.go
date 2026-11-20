package main

// Multi-call entry point. The binary dispatches on its invoked name
// (nixus-admin, nixus-install, nixus-update, nixus-helpers, nixus, ...) or,
// when called as "nixus-go", on its first argument.

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func nilLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func printJSON(v any) { fmt.Print(string(jsonFile(v))) }

func fail(msg string) int { fmt.Fprintln(os.Stderr, msg); return 1 }

var commands map[string]func([]string) int

func init() {
	commands = map[string]func([]string) int{
		"nixus-admin":          adminMain,
		"admin":                adminMain,
		"nixus-install":        installMain,
		"install":              installMain,
		"nixus-update":         updateMain,
		"update":               updateMain,
		"nixus-helpers":        helpersMain,
		"helpers":              helpersMain,
		"nixus":                homelabMain,
		"homelab":              homelabMain,
		"nixus-console-status": func([]string) int { return consoleStatusMain() },
		"console-status":       func([]string) int { return consoleStatusMain() },
		"nixus-notify":         notifyMain,
		"notify":               notifyMain,
		"nixus-backup":         backupMain,
		"backup":               backupMain,
		"nixus-backup-verify":  backupVerificationMain,
		"backup-verify":        backupVerificationMain,
		"nixus-reconcile":      reconcileCommand,
		"reconcile":            reconcileCommand,
		"oci-child":            ociChildMain,
		"release":              releaseCommand,
		"nixus-release":        releaseCommand,
		"preflight":            preflightCommand,
		"infrastructure":       infrastructureCommand,
		"backup-health":        backupHealthCommand,
		"kvm-check":            kvmCheckCommand,
	}
}

func main() {
	name := filepath.Base(os.Args[0])
	args := os.Args[1:]
	run, ok := commands[name]
	if !ok {
		if len(args) == 0 || commands[args[0]] == nil {
			fmt.Fprintln(os.Stderr, "usage: nixus-go {admin|install|update|helpers|homelab|console-status|notify|backup|backup-verify|reconcile|release} ...")
			os.Exit(2)
		}
		run, args = commands[args[0]], args[1:]
	}
	os.Exit(run(args))
}

func reconcileCommand(args []string) int {
	if len(args) != 1 {
		return fail("usage: nixus-reconcile DESIRED.json")
	}
	if err := reconcileMain(args[0]); err != nil {
		return fail(publicError(err))
	}
	return 0
}

func releaseCommand(args []string) int {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	tag := fs.String("tag", "", "")
	evidence := fs.String("evidence", "", "")
	runs := fs.String("runs", "", "")
	repository := fs.String("repository", "OmarDardery/Nixus", "")
	output := fs.String("output", "", "")
	if fs.Parse(args) != nil || *tag == "" || *evidence == "" || *runs == "" || *output == "" {
		return 2
	}
	if err := releasePrepare(*tag, *evidence, *runs, *repository, *output); err != nil {
		return fail("Release blocked: " + publicError(err))
	}
	return 0
}

// --- terminal helpers ----------------------------------------------------------

func readSecret(promptText string) (string, error) {
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", Public("A private terminal is required")
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return "", Public("A private terminal is required")
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
	fmt.Fprint(os.Stderr, promptText)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && line == "" {
		return "", Public("Input ended")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// sshLoginEpoch is the start time of the nearest SSH/Cockpit session ancestor.
func sshLoginEpoch() (float64, bool) {
	var boot int64
	for _, line := range strings.Split(readText("/proc/stat"), "\n") {
		if strings.HasPrefix(line, "btime ") {
			boot, _ = strconv.ParseInt(strings.Fields(line)[1], 10, 64)
		}
	}
	if boot == 0 {
		return 0, false
	}
	const ticks = 100.0
	pid := os.Getpid()
	for i := 0; i < 64; i++ {
		proc := filepath.Join("/proc", strconv.Itoa(pid))
		name := readText(filepath.Join(proc, "comm"))
		if strings.HasPrefix(name, "sshd") || strings.HasPrefix(name, "cockpit-") {
			raw := readText(filepath.Join(proc, "stat"))
			idx := strings.LastIndex(raw, ")")
			fields := strings.Fields(raw[idx+1:])
			if len(fields) < 20 {
				return 0, false
			}
			start, err := strconv.ParseFloat(fields[19], 64)
			if err != nil {
				return 0, false
			}
			return float64(boot) + start/ticks, true
		}
		parent := 0
		for _, line := range strings.Split(readText(filepath.Join(proc, "status")), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				parent, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			}
		}
		if parent <= 1 || parent == pid {
			break
		}
		pid = parent
	}
	return 0, false
}

var physicalTTY = regexp.MustCompile(`^/dev/(?:tty[0-9]+|ttyS[0-9]+|hvc[0-9]+)$`)

func requireFreshCLIConfirmation(job M) error {
	if str(job["status"]) != "awaiting-confirmation" {
		return Public("No transaction is awaiting access confirmation")
	}
	ready, ok := num(job["awaitingAt"])
	if !ok {
		ready, ok = num(job["appliedAt"])
	}
	if !ok {
		return Public("Cannot establish activation time; inspect recovery at the host console")
	}
	if !isTerminal() {
		return Public("Use an interactive NEW SSH login or the physical host console to confirm access")
	}
	tty, err := os.Readlink("/proc/self/fd/0")
	if err != nil {
		return Public("Cannot verify operator terminal; use physical host console")
	}
	if physicalTTY.MatchString(tty) {
		return nil
	}
	if !strings.HasPrefix(tty, "/dev/pts/") {
		return Public("Unrecognized terminal; use a new SSH login or the physical host console")
	}
	started, ok := sshLoginEpoch()
	if !ok || started <= ready {
		return Public("This terminal predates activation; open a NEW SSH/Cockpit terminal and confirm there")
	}
	return nil
}

// --- nixus-admin subcommands -------------------------------------------------------

func configCLI(args []string) error {
	if len(args) == 0 {
		return Public("usage: nixus-admin config {status|plan|migrate-layout|review|apply|confirm|cancel|rollback}")
	}
	var result any
	var err error
	switch args[0] {
	case "migrate-layout":
		result, err = migrateIdleLayout(ROOT, STATE)
	case "status", "plan":
		var state M
		if state, err = brokerRequest("GET", "/status", nil); err != nil {
			return err
		}
		result = state
		if args[0] == "plan" {
			result = jget(state, "job", "impactPlan")
			if result == nil {
				return Public("Build a new review to generate an impact plan")
			}
		}
	case "review":
		fs := flag.NewFlagSet("review", flag.ContinueOnError)
		var modulesArg multiFlag
		fs.Var(&modulesArg, "module", "NAME=FILE")
		settingsPath := fs.String("settings", "", "")
		updateInputs := fs.Bool("update-inputs", false, "")
		revision := fs.String("revision", "", "Full reviewed upstream platform commit SHA")
		if err := fs.Parse(args[1:]); err != nil {
			return Public("Invalid review arguments")
		}
		modules := M{}
		for _, item := range modulesArg {
			name, file, ok := strings.Cut(item, "=")
			if _, dup := modules[name]; !ok || dup {
				return Public("Use distinct NAME=FILE module arguments")
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				return Public("Unable to read module file")
			}
			modules[name] = string(raw)
		}
		if _, err := validateModules(modules); err != nil {
			return err
		}
		settings := M{}
		if *settingsPath != "" {
			raw, err := os.ReadFile(*settingsPath)
			if err != nil {
				return Public("Unable to read settings file")
			}
			if settings, err = parseObject(raw); err != nil {
				return Public("Settings file must be a JSON object")
			}
		}
		request := M{"settings": settings, "modules": modules, "updateInputs": *updateInputs}
		if *revision != "" {
			request["revision"] = *revision
		}
		result, err = brokerRequest("POST", "/review", request)
	case "apply", "confirm", "cancel", "rollback":
		if len(args) != 2 {
			return Public("Supply one transaction ID")
		}
		if args[0] == "confirm" {
			state, err := brokerRequest("GET", "/status", nil)
			if err != nil {
				return err
			}
			job := obj(state["job"])
			if str(job["id"]) != args[1] {
				return Public("Confirm the active transaction only")
			}
			if err := requireFreshCLIConfirmation(job); err != nil {
				return err
			}
		}
		result, err = brokerRequest("POST", "/"+args[0], M{"id": args[1]})
	default:
		return Public("Unknown config command")
	}
	if err != nil {
		return err
	}
	printJSON(result)
	return nil
}

func readBounded(p string, limit int64) ([]byte, error) {
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, Public("Supply a regular, bounded local file")
	}
	return os.ReadFile(p)
}

func projectCLI(args []string) int {
	fs := flag.NewFlagSet("projects", flag.ContinueOnError)
	changes := fs.String("changes", "", "UTF-8 JSON map of relative Nix file edits")
	sourceRevisions := fs.String("source-revisions", "", "")
	flakePath := fs.String("flake-path", "", "")
	lockPath := fs.String("lock-path", "", "")
	id := fs.String("id", "", "")
	planHash := fs.String("plan-hash", "", "")
	resume := fs.Bool("resume", false, "")
	if len(args) == 0 {
		return fail("usage: nixus-admin projects {status|initialize|review|publish|rollback|cancel|recover|deploy}")
	}
	command := args[0]
	if fs.Parse(args[1:]) != nil {
		return 2
	}
	t := NewProjectTransactions("", "")
	var result any
	err := func() error {
		var err error
		switch command {
		case "status":
			result, err = t.status(*id)
		case "initialize":
			flake, err1 := readBounded(*flakePath, 32768)
			lock, err2 := readBounded(*lockPath, 131072)
			if err1 != nil || err2 != nil {
				return Public("Supply regular, bounded workspace flake.nix and flake.lock")
			}
			result, err = t.initialize(string(flake), string(lock), "root-console")
		case "review":
			raw, rerr := readBounded(*changes, 131072)
			if rerr != nil {
				return Public("Provide a bounded local JSON edit file")
			}
			edits, perr := parseJSON(raw)
			if perr != nil {
				return Public("Provide a bounded local JSON edit file")
			}
			var refs any
			if *sourceRevisions != "" {
				raw, err := readBounded(*sourceRevisions, 4096)
				if err != nil {
					return Public("Provide a bounded local source revision map")
				}
				if refs, err = parseJSON(raw); err != nil {
					return Public("Provide a bounded local source revision map")
				}
			}
			result, err = t.review(edits, "root-console", refs)
		case "publish":
			result, err = t.publish(*id, *planHash)
		case "rollback":
			result, err = t.rollback(*id, *planHash)
		case "cancel":
			result, err = t.cancel(*id)
		case "deploy":
			result, err = t.deploy(*id, *planHash, *resume)
		case "recover":
			result, err = t.recover(*id)
		default:
			return Public("Unknown projects command")
		}
		return err
	}()
	if err != nil {
		return fail("Project transaction failed; inspect source integrity, approvals and recovery state: " + publicError(err))
	}
	printJSON(result)
	return 0
}

func deployCLI(args []string) error {
	if len(args) == 0 {
		return Public("usage: nixus-admin deploy {status [id]|start id|resume id|abandon id}")
	}
	var result any
	var err error
	switch args[0] {
	case "status":
		if len(args) > 1 {
			result, err = brokerRequest("GET", "/deployment/"+args[1], nil)
		} else {
			state, serr := brokerRequest("GET", "/status", nil)
			if serr != nil {
				return serr
			}
			job := obj(state["job"])
			result = M{"plan": job["guestPlan"], "deployment": job["guestDeployment"]}
		}
	case "start", "resume", "abandon":
		if len(args) != 2 {
			return Public("Supply one deployment ID")
		}
		result, err = brokerRequest("POST", "/deploy-guests", M{"id": args[1], "resume": args[0] == "resume", "abandon": args[0] == "abandon"})
	default:
		return Public("Unknown deploy command")
	}
	if err != nil {
		return err
	}
	printJSON(result)
	return nil
}

func guestsCLI(args []string) error {
	if len(args) == 0 {
		return Public("usage: nixus-admin guests ACTION [--name N] [--project P] ...")
	}
	action := args[0]
	fs := flag.NewFlagSet("guests", flag.ContinueOnError)
	file := fs.String("file", "", "")
	project := fs.String("project", "lab", "")
	values := map[string]*string{}
	for _, k := range []string{"name", "snapshot", "target", "archive"} {
		values[k] = fs.String(k, "", "")
	}
	acknowledge := fs.Bool("acknowledge", false, "")
	if err := fs.Parse(args[1:]); err != nil {
		return Public("Invalid guest arguments")
	}
	var result any
	var err error
	switch action {
	case "register-export":
		if *file == "" {
			return Public("Use --file with the recovered local Incus export")
		}
		result, err = NewOperations().registerArchive(*file, *project, *values["name"])
	case "list":
		result, err = brokerRequest("GET", "/guests", nil)
	case "status":
		result, err = brokerRequest("GET", "/operations", nil)
	case "start", "stop", "restart", "snapshot", "snapshot-copy", "export", "restore", "backup", "backup-check", "release-restore":
		request := M{"action": action, "project": *project, "acknowledge": *acknowledge}
		for k, v := range values {
			if *v != "" {
				request[k] = *v
			}
		}
		result, err = brokerRequest("POST", "/operation", request)
	default:
		return Public("Unknown guests action")
	}
	if err != nil {
		return err
	}
	printJSON(result)
	return nil
}

func recoveryCLI(args []string) error {
	if len(args) == 0 {
		return Public("usage: nixus-admin recovery {coverage|export|inspect|stage|approve|plan|status|resume|release|export-report}")
	}
	fs := flag.NewFlagSet("recovery", flag.ContinueOnError)
	recipient := fs.String("recipient", "", "")
	includeSecrets := fs.Bool("include-secrets", false, "")
	user := fs.String("user", "", "")
	mappings := fs.String("mappings", "", "")
	confirm := fs.Bool("confirm", false, "")
	dataVerified := fs.Bool("data-verified", false, "")
	acknowledgeExclusions := fs.Bool("acknowledge-exclusions", false, "")
	command := args[0]
	if err := fs.Parse(reorderFlags(args[1:])); err != nil {
		return Public("Invalid recovery arguments")
	}
	positional := fs.Args()
	need := func(n int) error {
		if len(positional) != n {
			return Public("Missing recovery argument")
		}
		return nil
	}
	var result any
	var err error
	switch command {
	case "approve":
		if err := need(1); err != nil {
			return err
		}
		if _, err := recoveryApprove(positional[0], *user); err != nil {
			return err
		}
		fmt.Println("Approved; return to the browser to choose a new portal password.")
		return nil
	case "coverage":
		result = recoveryCoverage()
	case "export":
		if err := need(1); err != nil {
			return err
		}
		result, err = lockedValue(false, func() (M, error) { return recoveryExport(positional[0], *recipient, *includeSecrets) })
	case "inspect":
		if err := need(1); err != nil {
			return err
		}
		result, _, err = recoveryInspect(positional[0])
	case "stage":
		if err := need(2); err != nil {
			return err
		}
		result, err = recoveryStage(positional[0], positional[1])
	case "status":
		result, err = replacementStatus(nil)
	case "export-report":
		result, err = replacementReport()
	case "plan", "resume", "release":
		result, err = lockedValue(false, func() (M, error) {
			release, err := lockFile(incusLock, false)
			if err != nil {
				return nil, err
			}
			defer release()
			switch command {
			case "plan":
				if err := need(1); err != nil {
					return nil, err
				}
				raw, err := boundedJSON(*mappings)
				if err != nil {
					return nil, err
				}
				return replacementPlan(positional[0], obj(raw))
			case "resume":
				return replacementResume(*confirm)
			}
			return replacementRelease(*confirm, *dataVerified, *acknowledgeExclusions)
		})
	default:
		return Public("Unknown recovery command")
	}
	if err != nil {
		return err
	}
	printJSON(result)
	return nil
}

// reorderFlags lets flags follow positional arguments, as argparse allows.
func reorderFlags(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				switch strings.TrimPrefix(a, "--") {
				case "recipient", "user", "mappings", "mode", "environment", "check", "status", "revision":
					flags = append(flags, args[i+1])
					i++
				}
			}
		} else {
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}

func commissioningCLI(args []string) error {
	if len(args) == 0 {
		return Public("usage: nixus-admin commissioning {collect|record|status|export|matrix} ...")
	}
	action := args[0]
	fs := flag.NewFlagSet("commissioning", flag.ContinueOnError)
	mode := fs.String("mode", "", "")
	environment := fs.String("environment", "installed-host", "")
	checkName := fs.String("check", "", "")
	status := fs.String("status", "", "")
	acknowledge := fs.Bool("acknowledge", false, "")
	revision := fs.String("revision", "", "")
	if err := fs.Parse(reorderFlags(args[1:])); err != nil {
		return Public("Invalid commissioning arguments")
	}
	if action == "matrix" {
		out, err := evidenceMatrix(fs.Args(), *revision)
		if err != nil {
			return err
		}
		fmt.Print(out)
		return nil
	}
	if (*mode != "fresh" && *mode != "upgrade") || !environments[*environment] {
		return Public("Use --mode fresh|upgrade and a documented --environment")
	}
	switch action {
	case "collect", "record", "status", "export":
	default:
		return Public("Unknown commissioning action")
	}
	result, err := commissioningRun(action, *mode, *environment, *checkName, *status, *acknowledge)
	if err != nil {
		return err
	}
	printJSON(result)
	return nil
}

func renew() error {
	settings := effectiveSettingsFile()
	res, _ := run([]string{"openssl", "x509", "-checkend", "2592000", "-noout", "-in", filepath.Join(STATE, "tls.crt")}, nil, 30*time.Second, nil, "")
	if res.Code == 0 {
		return nil
	}
	address, err := managementAddress(settings)
	if err != nil {
		return err
	}
	if err := issueTLS(address, str(settings["hostName"])); err != nil {
		return err
	}
	services := []string{"nixus-ui.service"}
	if isTrue(settings["ready"]) {
		services = append(services, "incus.service")
		if isTrue(jget(settings, "cockpit", "enable")) {
			services = append(services, "cockpit.service")
		}
	}
	_, err = check(append([]string{"systemctl", "try-restart"}, services...), nil, 5*time.Minute)
	return err
}

func enrollKey(m *Manager, publicKeyFile string, settings M) error {
	raw, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return Public("Unable to read the public key file")
	}
	var keys []string
	for _, line := range strings.Split(string(raw), "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "#") {
			keys = append(keys, l)
		}
	}
	if len(keys) == 0 {
		return Public("The public key file is empty")
	}
	candidate, err := m.settings()
	if err != nil {
		return err
	}
	set := map[string]bool{}
	for _, k := range list(candidate["adminKeys"]) {
		set[str(k)] = true
	}
	for _, k := range keys {
		set[k] = true
	}
	candidate["adminKeys"] = strings2any(sortedKeys(set))
	reviewed, err := m.review(candidate, ReviewOptions{Principal: "root-key-enrollment"})
	if err != nil {
		return err
	}
	id := str(reviewed["id"])
	fmt.Println("Building key enrollment transaction: " + id)
	var record M
	for {
		m.status()
		if record, err = m.job(id); err != nil {
			return err
		}
		if str(record["status"]) != "building" {
			break
		}
		time.Sleep(time.Second)
	}
	if str(record["status"]) != "ready" {
		return Public("Key enrollment build did not complete: " + str(record["status"]))
	}
	if _, err := m.apply(id); err != nil {
		return err
	}
	for {
		if record, err = m.job(id); err != nil {
			return err
		}
		if str(record["status"]) != "applying" {
			break
		}
		time.Sleep(time.Second)
	}
	if str(record["status"]) != "awaiting-confirmation" {
		return Public("Key enrollment activation did not complete: " + str(record["status"]))
	}
	effective := obj(record["effectiveSettings"])
	if effective == nil {
		effective = candidate
	}
	if _, err := waitReady(effective, 0); err != nil {
		return err
	}
	address, _ := managementAddress(settings)
	fmt.Println("Test the new key in a fresh session: ssh operator@" + address)
	pendingAccess(id, record)
	return nil
}

const adminUsage = "Usage: nixus-admin {doctor|identity|enroll-key|backend|web|guard|renew|approve-enrollment|reset-password|config|projects|deploy|guests|recovery|commissioning|install-plan|prune-jobs|disk prepare}"

func adminMain(argv []string) int {
	syscall.Umask(0o027)
	if len(argv) > 0 && argv[0] == "admin" {
		argv = argv[1:]
	}
	action := ""
	if len(argv) > 0 {
		action = argv[0]
	}
	rest := []string{}
	if len(argv) > 1 {
		rest = argv[1:]
	}
	root := os.Geteuid() == 0
	generic := func(err error) int {
		if err != nil {
			return fail("Command failed; check inputs and host status before retrying: " + publicError(err))
		}
		return 0
	}
	switch {
	case (action == "doctor" || action == "identity" || action == "enroll-key") && root:
		m := NewManager("", "")
		settings, err := m.effectiveSettings(nil)
		if err != nil {
			return generic(err)
		}
		switch action {
		case "doctor":
			if len(rest) == 1 && rest[0] == "--wait" {
				waitReady(settings, 0)
			}
			result := doctor(settings)
			printJSON(result)
			if isTrue(result["ok"]) {
				return 0
			}
			return 1
		case "identity":
			deadline := time.Now().Add(90 * time.Second)
			for {
				_, err := identityRefresh(settings)
				if err == nil {
					return 0
				}
				if time.Now().After(deadline) {
					return generic(err)
				}
				time.Sleep(2 * time.Second)
			}
		default:
			if len(rest) != 1 {
				return fail("Usage: sudo nixus enroll-key laptop.pub")
			}
			return generic(enrollKey(m, rest[0], settings))
		}
	case action == "backend":
		return backendMain()
	case action == "web":
		return webMain()
	case action == "guard":
		return generic(guard())
	case action == "job" && len(rest) == 2:
		return generic(workerJob(rest[0], rest[1]))
	case action == "operation-job" && root && len(rest) == 1:
		return generic(NewOperations().run(rest[0]))
	case action == "deployment-job" && root && len(rest) == 1:
		_, err := NewDeployments("", "").run(rest[0])
		return generic(err)
	case action == "oci-build-job" && root:
		if len(rest) != 1 {
			return fail("Expected one OCI build review ID")
		}
		_, err := NewOCIBuilds("", nil).run(rest[0])
		return generic(err)
	case action == "project-deploy-job" && root:
		if len(rest) != 1 {
			return fail("Expected one project deployment ID")
		}
		_, err := NewProjectTransactions("", "").runDeployment(rest[0])
		return generic(err)
	case action == "network-identity":
		return networkIdentityMain(rest)
	case action == "deploy" && root:
		return generic(deployCLI(rest))
	case action == "projects" && root:
		return projectCLI(rest)
	case action == "recovery" && root:
		return generic(recoveryCLI(rest))
	case action == "install-plan" && root:
		installation := readObj(machinePath(ROOT, "installation"))
		pending := installation["pendingTasks"]
		if pending == nil {
			pending = []any{}
		}
		printJSON(M{"intent": installation["intent"], "pendingTasks": pending,
			"note": "Pending tasks are not proof of physical completion; use commissioning evidence."})
		return 0
	case action == "commissioning":
		if err := commissioningCLI(rest); err != nil {
			return fail("Commissioning report unavailable or invalid: " + publicError(err))
		}
		return 0
	case action == "guests" && root:
		return generic(guestsCLI(rest))
	case action == "disk" && root && len(rest) == 1 && rest[0] == "prepare":
		return generic(diskPrepare())
	case action == "recovery-backup" && root && len(rest) == 1:
		return generic(recoveryBackup(rest[0]))
	case action == "recovery-coverage" && root:
		fmt.Println(canonicalSpaced(recoveryCoverage()))
		return 0
	case action == "config" && root:
		return generic(configCLI(rest))
	case action == "prune-jobs" && root:
		fs := flag.NewFlagSet("prune-jobs", flag.ContinueOnError)
		apply := fs.Bool("apply", false, "")
		keep := fs.Int("keep", 20, "")
		if fs.Parse(rest) != nil {
			return 2
		}
		result, err := NewManager("", "").pruneJobs(*apply, *keep)
		if err != nil {
			return generic(err)
		}
		printJSON(result)
		return 0
	case action == "renew":
		return generic(renew())
	case action == "approve-enrollment" && root:
		if len(rest) != 0 || !isTerminal() {
			return fail("Run sudo nixus-admin approve-enrollment from a private host terminal")
		}
		code, err := readSecret("Code displayed in your browser: ")
		if err == nil {
			err = enrollmentApprove(code)
		}
		if err != nil {
			return fail("Browser approval did not complete; check enrollment state from a private host terminal")
		}
		fmt.Println("Browser approved for up to ten minutes. Return to that browser to create its independent portal account.")
		return 0
	case action == "reset-password" && root:
		if !isTerminal() {
			return fail("Run sudo nixus-admin reset-password from a private host terminal")
		}
		value, err := readSecret("New Nixus administrator password (16–256 characters): ")
		if err == nil {
			err = recoverPassword(value)
		}
		if err != nil {
			return fail("Password change did not complete; check host account state from a private terminal before retrying")
		}
		fmt.Println("Password changed for the recovery administrator. Its old sessions will be rejected; sign in as admin.")
		return 0
	}
	if tool := commands[action]; tool != nil && action != "admin" && action != "nixus-admin" {
		return tool(rest)
	}
	return fail(adminUsage)
}

func readObjectFile(p string) (M, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return parseObject(raw)
}

// preflightCommand validates explicit inventory before Incus changes bridges or pools.
func preflightCommand(args []string) int {
	if len(args) != 1 {
		return fail("usage: preflight INVENTORY.json")
	}
	site, err := readObjectFile(args[0])
	if err == nil {
		err = validateNetwork(site)
	}
	if err != nil {
		return fail(publicError(err))
	}
	return 0
}

func infrastructureCommand(args []string) int {
	syscall.Umask(0o077)
	if len(args) != 2 || (args[0] != "check" && args[0] != "record") {
		return fail("usage: infrastructure {check|record} PRESEED.json")
	}
	preseed, err := readObjectFile(args[1])
	if err == nil {
		if args[0] == "check" {
			err = infraCheck(preseed)
		} else {
			err = infraRecord(preseed)
		}
	}
	if err != nil {
		return fail(publicError(err))
	}
	return 0
}

func backupHealthCommand(args []string) int {
	if backupHealth(true) == "overdue" {
		fmt.Println("1")
	} else {
		fmt.Println("0")
	}
	return 0
}

func kvmCheckCommand([]string) int {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fail("KVM API unavailable")
	}
	defer f.Close()
	v, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0xAE00, 0)
	if errno != 0 || v != 12 {
		return fail("KVM API unavailable")
	}
	return 0
}
