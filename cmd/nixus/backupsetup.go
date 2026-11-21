package main

// Backup setup from the console: choose a destination, paste its
// credentials once, and Nixus writes the root-only credential files,
// generates the repository password and saves the backups.nix policy.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	backupSecretsDir  = "/var/lib/nixus-secrets"
	backupPasswordPth = "/var/lib/nixus-secrets/project-restic-password"
	backupEnvPath     = "/var/lib/nixus-secrets/project-restic-environment"
	backupRclonePath  = "/var/lib/nixus-secrets/rclone.conf"
)

var rcloneRemote = re(`[A-Za-z0-9_-]{1,64}`)
var bucketPath = re(`[A-Za-z0-9._/-]{1,200}`)
var s3Endpoint = re(`[A-Za-z0-9.-]{1,200}(?::[0-9]{1,5})?`)

func writeSecretFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	os.Chmod(filepath.Dir(path), 0o700)
	return atomic(path, data, 0o600, "")
}

// backupDestination turns a destination form into a restic repository and
// credential files. It never returns stored credentials.
func backupDestination(body M) (repository string, env []string, rcloneConf string, err error) {
	field := func(k string) string { return strings.TrimSpace(str(body[k])) }
	switch str(body["kind"]) {
	case "local":
		repository = field("path")
		if !fullmatch(re(`/[A-Za-z0-9._/-]{1,200}`), repository) || strings.Contains(repository+"/", "/../") {
			return "", nil, "", Public("Enter an absolute folder path, e.g. /mnt/backup/nixus")
		}
	case "s3":
		endpoint, bucket := field("endpoint"), field("bucket")
		if !fullmatch(s3Endpoint, endpoint) || !fullmatch(bucketPath, bucket) || field("accessKey") == "" || field("secretKey") == "" {
			return "", nil, "", Public("Enter the S3 endpoint, bucket and both keys")
		}
		repository = "s3:" + endpoint + "/" + bucket
		env = []string{"AWS_ACCESS_KEY_ID=" + field("accessKey"), "AWS_SECRET_ACCESS_KEY=" + field("secretKey")}
	case "b2":
		bucket := field("bucket")
		if !fullmatch(bucketPath, bucket) || field("accountId") == "" || field("accountKey") == "" {
			return "", nil, "", Public("Enter the B2 bucket, key ID and application key")
		}
		repository = "b2:" + bucket
		env = []string{"B2_ACCOUNT_ID=" + field("accountId"), "B2_ACCOUNT_KEY=" + field("accountKey")}
	case "rclone":
		remote, folder := field("remote"), field("folder")
		if !fullmatch(rcloneRemote, remote) || !fullmatch(bucketPath, folder) {
			return "", nil, "", Public("Enter the rclone remote name and a folder")
		}
		rcloneConf = str(body["config"])
		if rcloneConf != "" && (len(rcloneConf) > 65536 || !strings.Contains(rcloneConf, "["+remote+"]")) {
			return "", nil, "", Public("The pasted rclone config has no [" + remote + "] section")
		}
		if rcloneConf == "" && !isFile(backupRclonePath) {
			return "", nil, "", Public("Paste the rclone config for this remote")
		}
		repository = "rclone:" + remote + ":" + folder
	default:
		return "", nil, "", Public("Choose a backup destination")
	}
	for _, line := range env {
		if strings.ContainsAny(line, "\n\r\x00") {
			return "", nil, "", Public("Credentials must be single-line values")
		}
	}
	return repository, env, rcloneConf, nil
}

func backupPolicyText(repository, schedule, verification string, data bool, rclone, envFile string) string {
	var b strings.Builder
	b.WriteString("{ ... }: {\n  nixus.backups = {\n    enable = true;\n    includeProjects = \"all\";\n")
	fmt.Fprintf(&b, "    schedule = %q;\n    data = %t;\n    verification = %q;\n    restic = {\n      repository = %q;\n", schedule, data, verification, repository)
	if rclone != "" {
		fmt.Fprintf(&b, "      rcloneConfigFile = %q;\n", rclone)
	}
	if envFile != "" {
		fmt.Fprintf(&b, "      environmentFile = %q;\n", envFile)
	}
	b.WriteString("      initialize = true;\n    };\n")
	b.WriteString("  };\n}\n")
	return b.String()
}

// setupBackups writes credentials, ensures a repository password and saves
// the policy. The generated password is returned once, on first setup.
func setupBackups(actor string, body M) (M, error) {
	repository, env, rcloneConf, err := backupDestination(body)
	if err != nil {
		return nil, err
	}
	schedule, verification := str(body["schedule"]), str(body["verification"])
	if schedule != "hourly" && schedule != "weekly" {
		schedule = "daily"
	}
	if verification != "none" && verification != "full" {
		verification = "metadata"
	}
	result := M{"repository": repository}
	if !isFile(backupPasswordPth) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		password := base64.RawURLEncoding.EncodeToString(raw)
		if err := writeSecretFile(backupPasswordPth, []byte(password+"\n")); err != nil {
			return nil, err
		}
		result["password"] = password
	}
	envFile, rcloneFile := "", ""
	if len(env) > 0 {
		if err := writeSecretFile(backupEnvPath, []byte(strings.Join(env, "\n")+"\n")); err != nil {
			return nil, err
		}
		envFile = backupEnvPath
	}
	if strings.HasPrefix(repository, "rclone:") {
		if rcloneConf != "" {
			if err := writeSecretFile(backupRclonePath, []byte(rcloneConf)); err != nil {
				return nil, err
			}
		}
		rcloneFile = backupRclonePath
	}
	if strings.HasPrefix(repository, "/") {
		if err := os.MkdirAll(repository, 0o700); err != nil {
			return nil, Public("Could not create " + repository)
		}
	}
	policy := backupPolicyText(repository, schedule, verification, body["data"] != false, rcloneFile, envFile)
	if _, err := saveBackupPolicy(actor, policy); err != nil && !strings.Contains(publicError(err), "no changes") {
		return nil, err
	}
	audit("backup-destination-set", M{"principal": actor, "kind": body["kind"]})
	return result, nil
}
