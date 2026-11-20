package main

// Run restic check without publishing repository or credential output, and
// project the recorded evidence read-only for the portal and recovery.

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const verificationPolicy = "/etc/nixus/backup-verification.json"
const verificationState = "/var/lib/nixus/backup-verification.json"

var verificationModes = map[string]bool{"metadata": true, "full": true}

func repositoryFingerprint(repository string) any {
	if repository == "" {
		return nil
	}
	return sha256hex([]byte(repository))
}

func validTimestamp(v any) (float64, bool) {
	f, ok := num(v)
	return f, ok && f > 0 && !math.IsInf(f, 0)
}

func clockObservation() M {
	c := clockStatus(0)
	return M{"state": c["state"], "evidenceWarning": c["evidenceWarning"]}
}

func verificationLastSuccess(record M, latest float64) any {
	item := obj(record["lastSuccess"])
	at, ok := validTimestamp(item["at"])
	if item == nil || !ok || at > latest || !verificationModes[str(item["mode"])] {
		return nil
	}
	clock := obj(item["clock"])
	state := str(clock["state"])
	warning, isBool := clock["evidenceWarning"].(bool)
	if clock == nil || !isBool || (state != "synchronized" && state != "plausible-but-unsynchronized" && state != "invalid-clock") {
		return nil
	}
	return M{"at": at, "mode": item["mode"], "clock": M{"state": state, "evidenceWarning": warning || state != "synchronized"}}
}

func readSmallDocument(p string) M {
	raw, err := os.ReadFile(p)
	if err != nil || len(raw) > 16384 {
		return nil
	}
	m, err := parseObject(raw)
	if err != nil {
		return nil
	}
	return m
}

func readVerificationRecord(p string) M {
	r := readSmallDocument(p)
	if v, _ := num(r["version"]); r == nil || v != 1 || !isInt(r["version"]) {
		return nil
	}
	return r
}

func verificationCheck(mode, state string) (int, error) {
	if !verificationModes[mode] {
		return 1, Public("Unsupported repository verification mode")
	}
	if state == "" {
		state = verificationState
	}
	repository := repositoryFingerprint(os.Getenv("RESTIC_REPOSITORY"))
	if repository == nil {
		return 1, Public("Repository target is unavailable")
	}
	previous := readVerificationRecord(state)
	if previous == nil || str(previous["repositoryFingerprint"]) != repository {
		previous = M{}
	}
	started := now()
	record := M{"version": 1, "phase": "running", "mode": mode, "startedAt": started, "finishedAt": nil,
		"lastSuccess": verificationLastSuccess(previous, started), "repositoryFingerprint": repository}
	if err := writeJSON(state, record); err != nil {
		return 1, err
	}
	args := []string{"restic", "--no-cache", "check"}
	if mode == "full" {
		args = append(args, "--read-data")
	}
	var code any
	var failure any
	res, err := run(args, nil, 43140*time.Second, nil, "")
	switch {
	case err != nil && strings.Contains(err.Error(), "timed out"):
		failure = "timeout"
	case err != nil:
		failure = "unavailable"
	default:
		code = res.Code
		if res.Code != 0 {
			failure = "restic-failed"
		}
	}
	phase := "failed"
	if failure == nil {
		phase = "successful"
	}
	record["phase"], record["finishedAt"], record["exitCode"], record["failure"], record["clock"] = phase, now(), code, failure, clockObservation()
	if failure == nil {
		record["lastSuccess"] = M{"at": record["finishedAt"], "mode": mode, "clock": record["clock"]}
	}
	if err := writeJSON(state, record); err != nil {
		return 1, err
	}
	if failure == nil {
		return 0, nil
	}
	return 1, nil
}

func verificationStatus(enabled bool, policyPath, statePath, repository string) M {
	if !enabled {
		return M{"state": "disabled"}
	}
	if policyPath == "" {
		policyPath = verificationPolicy
	}
	if statePath == "" {
		statePath = verificationState
	}
	policy := readSmallDocument(policyPath)
	_, enableBool := policy["enable"].(bool)
	if v, _ := num(policy["version"]); policy == nil || v != 1 || !enableBool || !verificationModes[str(policy["mode"])] || !isStr(policy["schedule"]) {
		return M{"state": "unknown"}
	}
	result := M{"state": "unknown", "scheduled": policy["enable"], "mode": policy["mode"], "schedule": policy["schedule"]}
	unit := systemctlUnix("nixus-backup-check.service", "LoadState,ActiveState,Result")
	active := str(unit["ActiveState"])
	if str(unit["LoadState"]) != "loaded" || unit["Result"] == nil ||
		(active != "active" && active != "activating" && active != "deactivating" && active != "inactive" && active != "failed") {
		return result
	}
	record := readVerificationRecord(statePath)
	at := now()
	if record != nil && (repositoryFingerprint(repository) == nil || str(record["repositoryFingerprint"]) != repositoryFingerprint(repository)) {
		result["reason"] = "repository-unverified"
		return result
	}
	phase := str(record["phase"])
	switch {
	case active == "active" || active == "activating" || active == "deactivating":
		result["state"] = "running"
	case record == nil:
		if _, err := os.Lstat(statePath); os.IsNotExist(err) {
			if isTrue(policy["enable"]) {
				result["state"] = "never-run"
			} else {
				result["state"] = "disabled"
			}
		}
	case phase == "running":
		result["state"] = "interrupted"
	case (phase == "successful" || phase == "failed") && verificationModes[str(record["mode"])]:
		started, ok1 := validTimestamp(record["startedAt"])
		finished, ok2 := validTimestamp(record["finishedAt"])
		if !ok1 || !ok2 || started > finished || finished > at {
			return result
		}
		limit := started
		if phase == "successful" {
			limit = finished
		}
		success := obj(verificationLastSuccess(record, limit))
		if phase == "successful" && (success == nil || success["at"] != finished || str(success["mode"]) != str(record["mode"])) {
			return result
		}
		result["state"], result["lastMode"], result["finishedAt"] = phase, record["mode"], finished
		if success != nil {
			result["lastSuccess"] = success
			result["timeWarning"] = path(success, "clock", "evidenceWarning")
		} else {
			result["lastSuccess"] = nil
		}
	}
	if r := str(unit["Result"]); r != "" && r != "success" {
		if s := str(result["state"]); s != "running" && s != "interrupted" {
			result["state"] = "failed"
		}
	}
	if isTrue(policy["enable"]) {
		timer := systemctlUnix("nixus-backup-check.timer", "LoadState,ActiveState,LastTriggerUSec")
		state := str(result["state"])
		if str(timer["LoadState"]) != "loaded" || str(timer["ActiveState"]) != "active" || timer["LastTriggerUSec"] == nil {
			if state != "running" && state != "failed" && state != "interrupted" {
				result["state"] = "unknown"
			}
		} else if state == "successful" || state == "never-run" {
			raw := str(timer["LastTriggerUSec"])
			trigger := 0.0
			if raw != "" && raw != "n/a" {
				var err error
				if trigger, err = strconv.ParseFloat(strings.TrimPrefix(raw, "@"), 64); err != nil {
					result["state"] = "unknown"
					return result
				}
			}
			finished, _ := validTimestamp(record["finishedAt"])
			if trigger < 0 || trigger > at {
				result["state"] = "unknown"
			} else if trigger > finished {
				if at >= trigger+7200 {
					result["state"] = "overdue"
				} else {
					result["state"] = "queued"
				}
			}
		}
	}
	return result
}

func backupVerificationMain(args []string) int {
	mode := ""
	for i, a := range args {
		if a == "--mode" && i+1 < len(args) {
			mode = args[i+1]
		} else if strings.HasPrefix(a, "--mode=") {
			mode = strings.TrimPrefix(a, "--mode=")
		}
	}
	code, err := verificationCheck(mode, "")
	if err != nil {
		fmt.Println("Repository verification evidence could not be recorded; integrity remains unverified.")
		return 1
	}
	if code != 0 {
		fmt.Println("Repository verification failed; check connectivity, credentials, repository locks and repository integrity from the host console.")
	}
	return code
}
