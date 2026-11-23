package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const incusLock = "/run/lock/nixus-incus.lock"

// checkIdle refuses host changes during project deployments.
func checkIdle(state, allowProject string) error {
	if id := activeProjectDeployment(state); id != "" && id != allowProject {
		return Public("Finish or recover the active project deployment before changing host configuration")
	}
	return nil
}

func opIncus(timeout time.Duration, args ...string) (string, error) {
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	out, err := incusRun(args, timeout, 4096)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nixus: incus", strings.Join(args, " "), "failed:", err)
		return "", Failed("Incus operation failed", err)
	}
	return out, nil
}

func checkConfigIdle(state string) error {
	active := readObj(filepath.Join(state, "active.json"))
	id := str(active["id"])
	if id == "" {
		id = "-"
	}
	job, _ := readJobRecord(filepath.Join(state, "jobs", id, "job.json"), M{})
	pending, _ := readJSON(filepath.Join(state, "pending.json"), nil)
	switch str(job["status"]) {
	case "building", "applying", "awaiting-confirmation", "rolling-back":
		pending = true
	}
	if pending != nil && !equalJSON(pending, M{}) {
		return Public("Finish the configuration transaction before changing guest state")
	}
	if activeProjectDeployment(state) != "" {
		return Public("Finish or recover the project deployment before changing guest state")
	}
	return nil
}
